
import time, pickle
import socket
from zope.interface import implements
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol
from twisted.python import usage
import foolscap
from foolscap.eventual import fireEventually
from foolscap.logging.interfaces import RILogGatherer, RILogObserver
from foolscap.logging.tail import short_tubid_b2a

class GatherOptions(usage.Options):
    pass

class LogSaver(foolscap.Referenceable):
    implements(RILogObserver)
    def __init__(self, nodeid, savefile):
        self.nodeid = nodeid
        self.f = savefile

    def remote_msg(self, d):
        e = {"from": self.nodeid,
             "rx_time": time.time(),
             "d": d,
             }
        try:
            pickle.dump(e, self.f)
        except:
            print "GATHERER: unable to pickle %s" % e

    def disconnected(self):
        del self.f


# adapted from Tahoe: finds a single publically-visible address, or None.
# Tahoe also uses code to run /bin/ifconfig (or equivalent) to find other
# addresses, but that's a bit heavy for this. Note that this runs
# synchronously.
def get_local_ip_for(target='A.ROOT-SERVERS.NET'):
    """Find out what our IP address is for use by a given target.

    @return: the IP address as a dotted-quad string which could be used by
              to connect to us. It might work for them, it might not. If
              there is no suitable address (perhaps we don't currently have an
              externally-visible interface), this will return None.
    """
    try:
        target_ipaddr = socket.gethostbyname(target)
    except socket.gaierror:
        # DNS isn't running
        return None
    udpprot = DatagramProtocol()
    port = reactor.listenUDP(0, udpprot)
    try:
        udpprot.transport.connect(target_ipaddr, 7)
        localip = udpprot.transport.getHost().host
    except socket.error:
        # no route to that host
        localip = None
    port.stopListening() # note, this returns a Deferred
    return localip

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
        self._savefile = open("logs.pickle", "ab", 0)
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

    def remote_logport(self, nodeid, publisher):
        short = short_tubid_b2a(nodeid)
        ls = LogSaver(nodeid, self._savefile)
        publisher.callRemote("subscribe_to_all", ls)
        publisher.notifyOnDisconnect(ls.disconnected)

