
import os, sys, time, pickle, bz2
signal = None
try:
    import signal
except ImportError:
    pass
from zope.interface import implements
from twisted.internet import reactor, defer, task, utils
from twisted.python import usage, procutils, filepath
from twisted.application import service
import foolscap
from foolscap.eventual import fireEventually
from foolscap.logging.interfaces import RILogGatherer, RILogObserver
from foolscap.util import get_local_ip_for
from foolscap import base32

class BadTubID(Exception):
    pass

class GatheringBase(foolscap.Referenceable):
    def __init__(self, basedir):
        self.basedir = basedir

    def run(self):
        d = fireEventually()
        d.addCallback(self.start)
        d.addErrback(self._error)
        if self.verbose:
            print "starting.."
        reactor.run()

    def _error(self, f):
        if self.verbose:
            print "ERROR", f
        reactor.stop()

    def start(self, res):
        d = self.setup_tub()
        d.addCallback(self._tub_ready)
        return d

    def setup_tub(self):
        self._tub = foolscap.Tub(certFile="gatherer.pem")
        self._tub.startService()
        portnumfile = "portnum"
        try:
            portnum = int(open(portnumfile, "r").read())
        except (EnvironmentError, ValueError):
            portnum = 0
        self._tub.listenOn("tcp:%d" % portnum)
        d = defer.maybeDeferred(get_local_ip_for)
        d.addCallback(self._set_location)
        d.addCallback(lambda res: self._tub)
        return d

    def _set_location(self, local_address):
        if local_address is None:
            local_addresses = ["127.0.0.1"]
        else:
            local_addresses = [local_address, "127.0.0.1"]
        l = self._tub.getListeners()[0]
        portnum = l.getPortnum()
        portnumfile = "portnum"
        open(portnumfile, "w").write("%d\n" % portnum)
        local_addresses = [ "%s:%d" % (addr, portnum,)
                            for addr in local_addresses ]
        assert len(local_addresses) >= 1
        location = ",".join(local_addresses)
        self._tub.setLocation(location)

    def _tub_ready(self, tub):
        me = tub.registerReference(self, furlFile=self.furlFile)
        if self.verbose:
            print "Gatherer waiting at:", me

class CreateGatherOptions(usage.Options):
    """flogtool create-gatherer GATHERER_DIRECTORY"""

    optFlags = [
        ("bzip", "b", "Compress each output file with bzip2"),
        ("quiet", "q", "Don't print instructions to stdout"),
        ]
    optParameters = [
        ("rotate", "r", None,
         "Rotate the output file every N seconds."),
        ]

    def parseArgs(self, gatherer_dir):
        self["basedir"] = gatherer_dir


class Observer(foolscap.Referenceable):
    implements(RILogObserver)

    def __init__(self, nodeid_s, gatherer):
        self.nodeid_s = nodeid_s # printable string
        self.gatherer = gatherer

    def remote_msg(self, d):
        self.gatherer.msg(self.nodeid_s, d)

class LogGatherer(GatheringBase):
    """Run a service that gathers logs from multiple applications.

    The LogGatherer sits in a corner and receives log events from many
    applications at once. At startup, it runs a Tub and emits the gatherer's
    long-term FURL. You can then configure your applications to connect to
    this FURL when they start and pass it a reference to their LogPublisher.
    The gatherer will subscribe to the publisher and save all the resulting
    messages in a logs.pickle file.

    Applications can use code like the following to create a LogPublisher and
    pass it to the gatherer::

     def tub_ready(self):
         # called when the Tub is available for registerReference
         lp = LogPublisher('logport.furl')
         lp.setServiceParent(self.tub)
         log_gatherer_furl = self.get_config('log_gatherer.furl')
         if log_gatherer_furl:
             self.tub.connectTo(log_gatherer_furl,
                                self._log_gatherer_connected, lp)

     def _log_gatherer_connected(self, rref, lp):
         rref.callRemote('logport', self.nodeid, lp)

    This LogGatherer class is meant to be run as a standalone service from
    bin/flogtool, but by careful subclassing and setup it could be run as
    part of some other application.

    """

    implements(RILogGatherer)
    verbose = True
    furlFile = "log_gatherer.furl"
    TIME_FORMAT = "%Y-%m-%d-%H%M%S"

    def __init__(self, basedir, bzip=None):
        self.bzip = bzip
        GatheringBase.__init__(self, basedir)

    def format_time(self, when):
        return time.strftime(self.TIME_FORMAT, time.localtime(when))

    def start(self, res):
        now = time.time()
        self._open_savefile(now)
        if signal and hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._handle_SIGHUP)

        return GatheringBase.start(self, res)

    def _open_savefile(self, now, filename=None):
        new_filename = "from-%s--to-present.flog" % self.format_time(now)
        self._savefile_name = filename or new_filename
        self._savefile = open(self._savefile_name, "ab", 0)
        self._starting_timestamp = now
        header = {"header": {"type": "gatherer",
                             "start": self._starting_timestamp,
                             }}
        pickle.dump(header, self._savefile)

    def _handle_SIGHUP(self, *args):
        reactor.callFromThread(self.rotate)

    def rotate(self):
        self._savefile.close()
        now = time.time()
        from_time = self.format_time(self._starting_timestamp)
        to_time = self.format_time(now)
        new_name = "from-%s--to-%s.flog" % (from_time, to_time)
        os.rename(self._savefile_name, new_name)
        if self.bzip:
            # we spawn an external bzip process because it's easier than
            # using the stdlib bz2 module and spreading the work out over
            # several ticks. We're trying to resume accepting log events
            # quickly here. We don't save the events using BZ2File because
            # the gatherer might be killed at any moment, and BZ2File doesn't
            # flush its output until the file is closed.
            d = utils.getProcessOutput(self.bzip, [new_name], env=os.environ)
            def _compressed(f):
                print f
            d.addErrback(_compressed)
        self._open_savefile(now)

    def remote_logport(self, nodeid, publisher):
        # nodeid is actually a printable string
        nodeid_s = nodeid
        o = Observer(nodeid_s, self)
        d = publisher.callRemote("subscribe_to_all", o)
        d.addCallback(lambda res: None)
        return d # mostly for testing

    def msg(self, nodeid_s, d):
        e = {"from": nodeid_s,
             "rx_time": time.time(),
             "d": d,
             }
        try:
            pickle.dump(e, self._savefile)
        except Exception, ex:
            print "GATHERER: unable to pickle %s: %s" % (e, ex)


class GathererService(service.Service):
    # create this with 'flogtool create-gatherer BASEDIR'
    # run this as 'cd BASEDIR && twistd -y gatherer.tac'
    def __init__(self, rotate, use_bzip):
        self.rotate = rotate
        self.use_bzip = use_bzip
        self._rotator = None

    def startService(self):
        # confirm that we're running from our BASEDIR, otherwise we'll put
        # the logevent file in the wrong place.
        basedir = os.getcwd()
        tac = os.path.join(basedir, "gatherer.tac")
        if not os.path.exists(tac):
            raise RuntimeError("running in the wrong directory")
        service.Service.startService(self)
        bzip = None
        if self.use_bzip:
            bzip = procutils.which("bzip2")
            if bzip:
                bzip = bzip[0]
        lg = LogGatherer(basedir, bzip)
        if self.rotate:
            self._rotator = task.LoopingCall(lg.rotate)
            self._rotator.start(self.rotate, now=False)
        d = fireEventually()
        d.addCallback(lg.start)
        d.addErrback(lg._error)

    def stopService(self):
        if self._rotator:
            self._rotator.stop()
        return service.Service.stopService(self)

TACFILE = """\
# -*- python -*-

# we record the path when 'flogtool create-gatherer' is run, in case flogtool
# was run out of a source tree. This is somewhat fragile, of course.

stashed_path = [
%(path)s]

import sys
needed = [p for p in stashed_path if p not in sys.path]
sys.path = needed + sys.path
print 'NEEDED', needed

from foolscap.logging import gatherer
from twisted.application import service

rotate = %(rotate)s
use_bzip = %(use_bzip)s
gs = gatherer.GathererService(rotate, use_bzip)
application = service.Application('log_gatherer')
gs.setServiceParent(application)
"""

def create_log_gatherer(config, stdout=sys.stdout):
    basedir = config["basedir"]
    if not os.path.exists(basedir):
        os.makedirs(basedir)
    f = open(os.path.join(basedir, "gatherer.tac"), "w")
    stashed_path = ""
    for p in sys.path:
        stashed_path += "  %r,\n" % p
    if config["rotate"]:
        rotate = config["rotate"]
    else:
        rotate = "None"
    f.write(TACFILE % { 'path': stashed_path,
                        'rotate': rotate,
                        'use_bzip': bool(config["bzip"]),
                        })
    f.close()
    if not config["quiet"]:
        print >>stdout, "Gatherer created in directory %s" % basedir
        print >>stdout, "Now run '(cd %s && twistd -y gatherer.tac)' to launch the daemon" % basedir


###################
# Incident Gatherer


class CreateIncidentGatherOptions(usage.Options):
    """flogtool create-incident-gatherer BASEDIR"""

    optFlags = [
        ("quiet", "q", "Don't print instructions to stdout"),
        ]
    optParameters = [
        ]

    def parseArgs(self, basedir):
        self["basedir"] = basedir


class IncidentObserver(foolscap.Referenceable):
    implements(RILogObserver)

    def __init__(self, basedir, nodeid_s, gatherer, publisher):
        if not os.path.isdir(basedir):
            os.makedirs(basedir)
        self.basedir = filepath.FilePath(basedir)
        self.nodeid_s = nodeid_s # printable string
        self.gatherer = gatherer
        self.publisher = publisher

    def connect(self):
        # look for a local state file, to see what incidents we've already
        # got
        statefile = self.basedir.child("latest").path
        latest = ""
        try:
            latest = open(statefile, "r").read().strip()
        except EnvironmentError:
            pass
        print "connected to %s, last known incident is %s" % (self.nodeid_s,
                                                              latest)
        # now subscribe to everything since then
        d = self.publisher.callRemote("subscribe_to_incidents", self,
                                      catch_up=True, since=latest)
        return d

    def remote_new_incident(self, name, trigger):
        print "got incident", name
        # name= should look like "incident-2008-07-29-204211-aspkxoi". We
        # prevent name= from containing path metacharacters like / or : by
        # using FilePath later on.
        d = self.publisher.callRemote("get_incident", name)
        d.addCallback(self._got_incident, name, trigger)
        d.addCallback(lambda res: None)
        return d
    def _got_incident(self, incident, name, trigger):
        # We always save the incident to a .bz2 file.
        abs_fn = self.basedir.child(name).path # this prevents evil
        abs_fn += ".flog.bz2"
        # we need to record the relative pathname of the savefile, for use by
        # the classifiers (they write it into their output files)
        rel_fn = os.path.join("incidents", self.nodeid_s, name) + ".flog.bz2"
        self.save_incident(abs_fn, incident)
        self.update_latest(name)
        self.gatherer.new_incident(abs_fn, rel_fn, self.nodeid_s, incident)

    def save_incident(self, filename, incident):
        now = time.time()
        (header, events) = incident
        f = bz2.BZ2File(filename, "w")
        h = {"header": header}
        pickle.dump(h, f)
        for e in events:
            wrapper = {"from": self.nodeid_s,
                       "rx_time": now,
                       "d": e}
            pickle.dump(wrapper, f)
        f.close()

    def update_latest(self, name):
        f = open(self.basedir.child("latest").path, "w")
        f.write(name + "\n")
        f.close()

    def remote_done_with_incident_catchup(self):
        return None

class IncidentGatherer(GatheringBase):
    """Run a service that gathers Incidents from multiple applications.

    The IncidentGatherer sits in a corner and receives incidents from many
    applications at once. At startup, it runs a Tub and emits the gatherer's
    long-term FURL. You can then configure your applications to connect to
    this FURL when they start and pass it a reference to their LogPublisher.
    The gatherer will subscribe to the publisher and save all the resulting
    incidents in the incidents/ directory, organized by the publisher's
    tubid. The gatherer will also run a set of user-supplied classifier
    functions on the incidents and put the filenames (one line per incident)
    into files in the categories/ directory.

    This IncidentGatherer class is meant to be run as a standalone service
    from bin/flogtool, but by careful subclassing and setup it could be run
    as part of some other application.

    """

    implements(RILogGatherer)
    verbose = True
    furlFile = "incident_gatherer.furl"

    def __init__(self, basedir, classifiers):
        GatheringBase.__init__(self, basedir)
        self.classifiers = classifiers


    def start(self, res):
        indir = os.path.join(self.basedir, "incidents")
        if not os.path.isdir(indir):
            os.makedirs(indir)
        outputdir = os.path.join(self.basedir, "classified")
        if not os.path.isdir(outputdir):
            os.makedirs(outputdir)
            self.classify_stored_incidents(indir)
        return GatheringBase.start(self, res)

    def classify_stored_incidents(self, indir):
        print "No classified/ directory: reclassifying stored incidents"
        # now classify all stored incidents
        for nodeid_s in os.listdir(indir):
            nodedir = os.path.join(indir, nodeid_s)
            for fn in os.listdir(nodedir):
                if fn.startswith("incident-"):
                    abs_fn = os.path.join(nodedir, fn)
                    incident = self.load_incident(abs_fn)
                    rel_fn = os.path.join("incidents", nodeid_s, fn)
                    self.classify_incident(rel_fn, nodeid_s, incident)

    def load_incident(self, abs_fn):
        assert abs_fn.endswith(".bz2")
        f = bz2.BZ2File(abs_fn, "r")
        header = pickle.load(f)["header"]
        events = []
        while True:
            try:
                wrapped = pickle.load(f)
            except (EOFError, ValueError):
                break
            events.append(wrapped["d"])
        f.close()
        return (header, events)

    def remote_logport(self, nodeid, publisher):
        # nodeid is actually a printable string
        tubid_s = nodeid
        if not base32.is_base32(tubid_s):
            # we must check it to exclude .. and / and other nasties
            raise BadTubID("%s is not a valid base32-encoded Tub ID" % tubid_s)
        basedir = os.path.join(self.basedir, "incidents", tubid_s)
        o = IncidentObserver(basedir, tubid_s, self, publisher)
        d = o.connect()
        d.addCallback(lambda res: None)
        return d # mostly for testing

    def new_incident(self, abs_fn, rel_fn, nodeid_s, incident):
        print "NEW INCIDENT", rel_fn
        self.classify_incident(rel_fn, nodeid_s, incident)

    def classify_incident(self, rel_fn, nodeid_s, incident):
        categories = set()
        for f in self.classifiers:
            c = f(nodeid_s, incident)
            if c: # allow the classifier to return None, or [], or ["foo"]
                if isinstance(c, str):
                    c = [c] # or just "foo"
                categories.update(c)
        if not categories:
            categories.add("unknown")
        for c in categories:
            fn = os.path.join(self.basedir, "classified", c)
            f = open(fn, "a")
            f.write(rel_fn + "\n")
            f.close()


class IncidentGathererService(service.Service):
    # create this with 'flogtool create-incident-gatherer BASEDIR'
    # run this as 'cd BASEDIR && twistd -y gatherer.tac'

    def __init__(self):
        #service.Service.__init__(self) # Service has no __init__
        self.classifiers = []

    def addClassifier(self, f):
        self.classifiers.append(f)

    def startService(self):
        # confirm that we're running from our BASEDIR, otherwise we'll put
        # files in the wrong place.
        basedir = os.getcwd()
        tac = os.path.join(basedir, "incident-gatherer.tac")
        if not os.path.exists(tac):
            raise RuntimeError("running in the wrong directory")
        service.Service.startService(self)
        lg = IncidentGatherer(basedir, self.classifiers)
        d = fireEventually()
        d.addCallback(lg.start)
        d.addErrback(lg._error)

INCIDENT_TACFILE = """\
# -*- python -*-

# we record the path when 'flogtool create-incident-gatherer' is run, in case
# flogtool was run out of a source tree. This is somewhat fragile, of course.

stashed_path = [
%(path)s]

import sys
needed = [p for p in stashed_path if p not in sys.path]
sys.path = needed + sys.path
print 'NEEDED', needed

from foolscap.logging import gatherer
from twisted.application import service

gs = gatherer.IncidentGathererService()
application = service.Application('incident_gatherer')
gs.setServiceParent(application)
"""

def create_incident_gatherer(config, stdout=sys.stdout):
    basedir = config["basedir"]
    if not os.path.exists(basedir):
        os.makedirs(basedir)
    f = open(os.path.join(basedir, "incident-gatherer.tac"), "w")
    stashed_path = ""
    for p in sys.path:
        stashed_path += "  %r,\n" % p
    f.write(INCIDENT_TACFILE % { 'path': stashed_path,
                                 })
    f.close()
    if not config["quiet"]:
        print >>stdout, "Incident Gatherer created in directory %s" % basedir
        print >>stdout, "Now run '(cd %s && twistd -y incident-gatherer.tac)' to launch the daemon" % basedir
