
import os, sys, time, bz2
signal = None
try:
    import signal
except ImportError:
    pass
from zope.interface import implements
from twisted.internet import reactor, utils, defer
from twisted.python import usage, procutils, filepath, log as tw_log
from twisted.application import service, internet
from foolscap.api import Tub, Referenceable
from foolscap.logging.interfaces import RILogGatherer, RILogObserver
from foolscap.logging.incident import IncidentClassifierBase, TIME_FORMAT
from foolscap.logging import flogfile
from foolscap.util import move_into_place

class BadTubID(Exception):
    pass

class ObsoleteGatherer(Exception):
    pass

class GatheringBase(service.MultiService, Referenceable):
    # requires self.furlFile and self.tacFile to be set on the class, both of
    # which should be relative to the basedir.
    use_local_addresses = True

    def __init__(self, basedir):
        service.MultiService.__init__(self)
        if basedir is None:
            # This instance was created by a gatherer.tac file. Confirm that
            # we're running from the right directory (the one with the .tac
            # file), otherwise we'll put the logfiles in the wrong place.
            basedir = os.getcwd()
            tac = os.path.join(basedir, self.tacFile)
            if not os.path.exists(tac):
                raise RuntimeError("running in the wrong directory")
        self.basedir = basedir
        certFile = os.path.join(self.basedir, "gatherer.pem")
        portfile = os.path.join(self.basedir, "port")
        locationfile = os.path.join(self.basedir, "location")
        furlFile = os.path.join(self.basedir, self.furlFile)

        # Foolscap-0.11.0 was the last release that used
        # automatically-determined listening addresses and ports. New ones
        # (created with "flogtool create-gatherer" or
        # "create-incident-gathererer" now require --location and --port
        # arguments to provide these values. If you really don't want to
        # create a new one, you can write "tcp:3117" (or some other port
        # number of your choosing) to BASEDIR/port, and "tcp:$HOSTNAME:3117"
        # (with your hostname or IP address) to BASEDIR/location

        if (not os.path.exists(portfile) or
            not os.path.exists(locationfile)):
            raise ObsoleteGatherer("Please create a new gatherer, with both "
                                   "--port and --location")
        try:
            with open(portfile, "r") as f:
                port = f.read().strip()
        except EnvironmentError:
            raise ObsoleteGatherer("Please create a new gatherer, with both "
                                   "--port and --location")
        try:
            with open(locationfile, "r") as f:
                location = f.read().strip()
        except EnvironmentError:
            raise ObsoleteGatherer("Please create a new gatherer, with both "
                                   "--port and --location")

        self._tub = Tub(certFile=certFile)
        self._tub.setServiceParent(self)
        self._tub.listenOn(port)
        self._tub.setLocation(location)

        self.my_furl = self._tub.registerReference(self, furlFile=furlFile)
        if self.verbose:
            print "Gatherer waiting at:", self.my_furl

class CreateGatherOptions(usage.Options):
    """flogtool create-gatherer GATHERER_DIRECTORY"""
    stdout = sys.stdout
    stderr = sys.stderr

    optFlags = [
        ("bzip", "b", "Compress each output file with bzip2"),
        ("quiet", "q", "Don't print instructions to stdout"),
        ]
    optParameters = [
        ("port", "p", "tcp:3117", "TCP port to listen on (strports string)"),
        ("location", "l", None, "(required) Tub location hints to use in generated FURLs. e.g. 'tcp:example.org:3117'"),
        ("rotate", "r", None,
         "Rotate the output file every N seconds."),
        ]

    def opt_port(self, port):
        assert not port.startswith("ssl:")
        assert port != "tcp:0"
        self["port"] = port
    def parseArgs(self, gatherer_dir):
        self["basedir"] = gatherer_dir
    def postOptions(self):
        if not self["location"]:
            raise usage.UsageError("--location= is mandatory")


class Observer(Referenceable):
    implements(RILogObserver)

    def __init__(self, nodeid_s, gatherer):
        self.nodeid_s = nodeid_s # printable string
        self.gatherer = gatherer

    def remote_msg(self, d):
        self.gatherer.msg(self.nodeid_s, d)

class GathererService(GatheringBase):
    # create this with 'flogtool create-gatherer BASEDIR'
    # run this as 'cd BASEDIR && twistd -y gatherer.tac'

    """Run a service that gathers logs from multiple applications.

    The LogGatherer sits in a corner and receives log events from many
    applications at once. At startup, it runs a Tub and emits the gatherer's
    long-term FURL. You can then configure your applications to connect to
    this FURL when they start and pass it a reference to their LogPublisher.
    The gatherer will subscribe to the publisher and save all the resulting
    messages in a serialized flogfile.

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

    This LogGatherer class is meant to be run by twistd from a .tac file, but
    applications that want to provide the same functionality can just
    instantiate it with a distinct basedir= and call startService.

    """

    implements(RILogGatherer)
    verbose = True
    furlFile = "log_gatherer.furl"
    tacFile = "gatherer.tac"

    def __init__(self, rotate, use_bzip, basedir=None):
        GatheringBase.__init__(self, basedir)
        if rotate: # int or None
            rotator = internet.TimerService(rotate, self.do_rotate)
            rotator.setServiceParent(self)
        bzip = None
        if use_bzip:
            bzips = procutils.which("bzip2")
            if bzips:
                bzip = bzips[0]
        self.bzip = bzip
        if signal and hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._handle_SIGHUP)
        self._savefile = None

    def _handle_SIGHUP(self, *args):
        reactor.callFromThread(self.do_rotate)

    def startService(self):
        # note: the rotator (if any) will fire as soon as startService is
        # called, since TimerService uses now=True. To deal with this,
        # do_rotate() tests self._savefile before doing anything else, and
        # we're careful to upcall to startService before we do the first
        # call to _open_savefile().
        GatheringBase.startService(self)
        now = time.time()
        self._open_savefile(now)

    def format_time(self, when):
        return time.strftime(TIME_FORMAT, time.gmtime(when)) + "Z"

    def _open_savefile(self, now):
        new_filename = "from-%s---to-present.flog" % self.format_time(now)
        self._savefile_name = os.path.join(self.basedir, new_filename)
        self._savefile = open(self._savefile_name, "ab", 0)
        self._starting_timestamp = now
        flogfile.serialize_header(self._savefile, "gatherer",
                                  start=self._starting_timestamp)

    def do_rotate(self):
        if not self._savefile:
            return
        self._savefile.close()
        now = time.time()
        from_time = self.format_time(self._starting_timestamp)
        to_time = self.format_time(now)
        new_name = "from-%s---to-%s.flog" % (from_time, to_time)
        new_name = os.path.join(self.basedir, new_name)
        move_into_place(self._savefile_name, new_name)
        self._open_savefile(now)
        if self.bzip:
            # we spawn an external bzip process because it's easier than
            # using the stdlib bz2 module and spreading the work out over
            # several ticks. We're trying to resume accepting log events
            # quickly here. We don't save the events using BZ2File because
            # the gatherer might be killed at any moment, and BZ2File doesn't
            # flush its output until the file is closed.
            d = utils.getProcessOutput(self.bzip, [new_name], env=os.environ)
            new_name = new_name + ".bz2"
            def _compression_error(f):
                print f
            d.addErrback(_compression_error)
            # note that by returning this Deferred, the rotation timer won't
            # start again until the bzip process finishes
        else:
            d = defer.succeed(None)
        d.addCallback(lambda res: new_name)
        return d # for tests

    def remote_logport(self, nodeid, publisher):
        # nodeid is actually a printable string
        nodeid_s = nodeid
        o = Observer(nodeid_s, self)
        d = publisher.callRemote("subscribe_to_all", o)
        d.addCallback(lambda res: None)
        return d # mostly for testing

    def msg(self, nodeid_s, d):
        try:
            flogfile.serialize_wrapper(self._savefile, d,
                                       from_=nodeid_s,
                                       rx_time=time.time())
        except Exception, ex:
            print "GATHERER: unable to serialize %s: %s" % (d, ex)


LOG_GATHERER_TACFILE = """\
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

def create_log_gatherer(config):
    basedir = config["basedir"]
    stdout = config.stdout

    assert config["port"]
    assert config["location"]

    if not os.path.exists(basedir):
        os.makedirs(basedir)

    f = open(os.path.join(basedir, "port"), "w")
    f.write("%s\n" % config["port"])
    f.close()

    f = open(os.path.join(basedir, "location"), "w")
    f.write("%s\n" % config["location"])
    f.close()

    f = open(os.path.join(basedir, "gatherer.tac"), "w")
    stashed_path = ""
    for p in sys.path:
        stashed_path += "  %r,\n" % p
    if config["rotate"]:
        rotate = config["rotate"]
    else:
        rotate = "None"
    f.write(LOG_GATHERER_TACFILE % { 'path': stashed_path,
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
    stdout = sys.stdout
    stderr = sys.stderr

    optFlags = [
        ("quiet", "q", "Don't print instructions to stdout"),
        ]
    optParameters = [
        ("port", "p", "tcp:3118", "TCP port to listen on (strports string)"),
        ("location", "l", None, "(required) Tub location hints to use in generated FURLs. e.g. 'tcp:example.org:3118'"),
        ]

    def opt_port(self, port):
        assert not port.startswith("ssl:")
        assert port != "tcp:0"
        self["port"] = port
    def parseArgs(self, basedir):
        self["basedir"] = basedir
    def postOptions(self):
        if not self["location"]:
            raise usage.UsageError("--location= is mandatory")


class IncidentObserver(Referenceable):
    implements(RILogObserver)

    def __init__(self, basedir, tubid_s, gatherer, publisher, stdout):
        if not os.path.isdir(basedir):
            os.makedirs(basedir)
        self.basedir = filepath.FilePath(basedir)
        self.tubid_s = tubid_s # printable string
        self.gatherer = gatherer
        self.publisher = publisher
        self.stdout = stdout
        self.caught_up_d = defer.Deferred()
        self.incidents_wanted = []
        self.incident_fetch_outstanding = False

    def connect(self):
        # look for a local state file, to see what incidents we've already
        # got
        statefile = self.basedir.child("latest").path
        latest = ""
        try:
            latest = open(statefile, "r").read().strip()
        except EnvironmentError:
            pass
        print >>self.stdout, "connected to %s, last known incident is %s" \
              % (self.tubid_s, latest)
        # now subscribe to everything since then
        d = self.publisher.callRemote("subscribe_to_incidents", self,
                                      catch_up=True, since=latest)
        # for testing, we arrange for this Deferred (which governs the return
        # from remote_logport) to not fire until we've finished catching up
        # on all incidents.
        d.addCallback(lambda res: self.caught_up_d)
        return d

    def remote_new_incident(self, name, trigger):
        print >>self.stdout, "new incident", name
        # name= should look like "incident-2008-07-29-204211-aspkxoi". We
        # prevent name= from containing path metacharacters like / or : by
        # using FilePath later on.
        self.incidents_wanted.append( (name, trigger) )
        self.maybe_fetch_incident()

    def maybe_fetch_incident(self):
        # only fetch one incident at a time, to keep the sender's outbound
        # memory usage to a reasonable level
        if self.incident_fetch_outstanding:
            return
        if not self.incidents_wanted:
            return
        self.incident_fetch_outstanding = True
        (name, trigger) = self.incidents_wanted.pop(0)
        print >>self.stdout, "fetching incident", name
        d = self.publisher.callRemote("get_incident", name)
        def _clear_outstanding(res):
            self.incident_fetch_outstanding = False
            return res
        d.addBoth(_clear_outstanding)
        d.addCallback(self._got_incident, name, trigger)
        d.addErrback(tw_log.err,
                     "IncidentObserver.get_incident or _got_incident")
        d.addBoth(lambda ign: self.maybe_fetch_incident())

    def _got_incident(self, incident, name, trigger):
        # We always save the incident to a .bz2 file.
        abs_fn = self.basedir.child(name).path # this prevents evil
        abs_fn += ".flog.bz2"
        # we need to record the relative pathname of the savefile, for use by
        # the classifiers (they write it into their output files)
        rel_fn = os.path.join("incidents", self.tubid_s, name) + ".flog.bz2"
        self.save_incident(abs_fn, incident)
        self.update_latest(name)
        self.gatherer.new_incident(abs_fn, rel_fn, self.tubid_s, incident)

    def save_incident(self, filename, incident):
        now = time.time()
        (header, events) = incident
        f = bz2.BZ2File(filename, "w")
        flogfile.serialize_raw_header(f, header)
        for e in events:
            flogfile.serialize_wrapper(f, e, from_=self.tubid_s, rx_time=now)
        f.close()

    def update_latest(self, name):
        f = open(self.basedir.child("latest").path, "w")
        f.write(name + "\n")
        f.close()

    def remote_done_with_incident_catchup(self):
        self.caught_up_d.callback(None)
        return None

class IncidentGathererService(GatheringBase, IncidentClassifierBase):
    # create this with 'flogtool create-incident-gatherer BASEDIR'
    # run this as 'cd BASEDIR && twistd -y gatherer.tac'

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
    furlFile = "log_gatherer.furl"
    tacFile = "gatherer.tac"

    def __init__(self, classifiers=[], basedir=None, stdout=None):
        GatheringBase.__init__(self, basedir)
        IncidentClassifierBase.__init__(self)
        self.classifiers.extend(classifiers)
        self.stdout = stdout
        self.incidents_received = 0 # for tests


    def startService(self):
        indir = os.path.join(self.basedir, "incidents")
        if not os.path.isdir(indir):
            os.makedirs(indir)
        outputdir = os.path.join(self.basedir, "classified")
        if not os.path.isdir(outputdir):
            os.makedirs(outputdir)
        self.add_classify_files(self.basedir)
        self.classify_stored_incidents(indir)
        GatheringBase.startService(self)

    def classify_stored_incidents(self, indir):
        stdout = self.stdout or sys.stdout
        print >>stdout, "classifying stored incidents"
        # now classify all stored incidents that aren't already classified
        already = set()
        outputdir = os.path.join(self.basedir, "classified")
        for category in os.listdir(outputdir):
            for line in open(os.path.join(outputdir, category), "r"):
                fn = line.strip()
                abs_fn = os.path.join(self.basedir, fn)
                already.add(abs_fn)
        print >>stdout, "%d incidents already classified" % len(already)
        count = 0
        for tubid_s in os.listdir(indir):
            nodedir = os.path.join(indir, tubid_s)
            for fn in os.listdir(nodedir):
                if fn.startswith("incident-"):
                    abs_fn = os.path.join(nodedir, fn)
                    if abs_fn in already:
                        continue
                    incident = self.load_incident(abs_fn)
                    rel_fn = os.path.join("incidents", tubid_s, fn)
                    self.move_incident(rel_fn, tubid_s, incident)
                    count += 1
        print >>stdout, "done classifying %d stored incidents" % count

    def remote_logport(self, nodeid, publisher):
        # we ignore nodeid (which is a printable string), and get the tubid
        # from the publisher remoteReference. getRemoteTubID() protects us
        # from .. and / and other nasties.
        tubid_s = publisher.getRemoteTubID()
        basedir = os.path.join(self.basedir, "incidents", tubid_s)
        stdout = self.stdout or sys.stdout
        o = IncidentObserver(basedir, tubid_s, self, publisher, stdout)
        d = o.connect()
        d.addCallback(lambda res: None)
        return d # mostly for testing

    def new_incident(self, abs_fn, rel_fn, tubid_s, incident):
        self.move_incident(rel_fn, tubid_s, incident)
        self.incidents_received += 1

    def move_incident(self, rel_fn, tubid_s, incident):
        stdout = self.stdout or sys.stdout
        categories = self.classify_incident(incident)
        for c in categories:
            fn = os.path.join(self.basedir, "classified", c)
            f = open(fn, "a")
            f.write(rel_fn + "\n")
            f.close()
        print >>stdout, "classified %s as [%s]" % (rel_fn, ",".join(categories))
        return categories


INCIDENT_GATHERER_TACFILE = """\
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

# To add a classifier function, store it in a neighboring file named
# classify_*.py, in a function named classify_incident(). All such files will
# be loaded at startup:
#
# %% cat classify_foolscap.py
# import re
# TUBCON_RE = re.compile(r'^Tub.connectorFinished: WEIRD, <foolscap.connection.TubConnector instance at \w+> is not in \[')
# def classify_incident(trigger):
#     # match some foolscap messages
#     m = trigger.get('message', '')
#     if TUBCON_RE.search(m):
#         return 'foolscap-tubconnector'
# %%

application = service.Application('incident_gatherer')
gs.setServiceParent(application)
"""

def create_incident_gatherer(config):
    basedir = config["basedir"]
    stdout = config.stdout

    assert config["port"]
    assert config["location"]

    if not os.path.exists(basedir):
        os.makedirs(basedir)

    f = open(os.path.join(basedir, "port"), "w")
    f.write("%s\n" % config["port"])
    f.close()

    f = open(os.path.join(basedir, "location"), "w")
    f.write("%s\n" % config["location"])
    f.close()

    f = open(os.path.join(basedir, "gatherer.tac"), "w")
    stashed_path = ""
    for p in sys.path:
        stashed_path += "  %r,\n" % p
    f.write(INCIDENT_GATHERER_TACFILE % { 'path': stashed_path,
                                          })
    f.close()
    if not config["quiet"]:
        print >>stdout, "Incident Gatherer created in directory %s" % basedir
        print >>stdout, "Now run '(cd %s && twistd -y gatherer.tac)' to launch the daemon" % basedir
