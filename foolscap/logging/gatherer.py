
import os, sys, time, pickle
signal = None
try:
    import signal
except ImportError:
    pass
from zope.interface import implements
from twisted.internet import reactor, defer, task, utils
from twisted.python import usage, procutils
from twisted.application import service
import foolscap
from foolscap.eventual import fireEventually
from foolscap.logging.interfaces import RILogGatherer, RILogObserver
from foolscap.util import get_local_ip_for

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

class LogGatherer(foolscap.Referenceable):
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

    def __init__(self, bzip=None):
        self.bzip = bzip

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

    def format_time(self, when):
        return time.strftime(self.TIME_FORMAT, time.localtime(when))

    def _open_savefile(self, now, filename=None):
        new_filename = "from-%s--to-present.flog" % self.format_time(now)
        self._savefile_name = filename or new_filename
        self._savefile = open(self._savefile_name, "ab", 0)
        self._starting_timestamp = now
        header = {"header": {"type": "gatherer",
                             "start": self._starting_timestamp,
                             }}
        pickle.dump(header, self._savefile)

    def start(self, res):
        now = time.time()
        self._open_savefile(now)

        if signal and hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._handle_SIGHUP)

        d = self.setup_tub()
        d.addCallback(self._tub_ready)
        return d

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

    def remote_logport(self, nodeid, publisher):
        # nodeid is actually a printable string
        nodeid_s = nodeid
        o = Observer(nodeid_s, self)
        publisher.callRemote("subscribe_to_all", o)

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
        tac = os.path.join(os.getcwd(), "gatherer.tac")
        if not os.path.exists(tac):
            raise RuntimeError("running in the wrong directory")
        service.Service.startService(self)
        bzip = None
        if self.use_bzip:
            bzip = procutils.which("bzip2")
            if bzip:
                bzip = bzip[0]
        lg = LogGatherer(bzip)
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

def create_log_gatherer(config):
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
        print "Gatherer created in directory %s" % basedir
        print "Now run '(cd %s && twistd -y gatherer.tac)' to launch the daemon" % basedir
