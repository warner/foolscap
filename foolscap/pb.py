# -*- test-case-name: foolscap.test.test_pb -*-
import os.path, weakref, binascii, re
from zope.interface import implements
from twisted.internet import defer, protocol, error
import foolscap.discovery as discovery
from twisted.application import service, internet
from twisted.python.failure import Failure

from foolscap import ipb, base32, negotiate, broker, observer, eventual, storage
from foolscap import util
from foolscap.referenceable import SturdyRef
from foolscap.tokens import PBError, BananaError, WrongTubIdError, \
     WrongNameError, NoLocationError
from foolscap.reconnector import Reconnector
from foolscap.logging import log as flog
from foolscap.logging import log
from foolscap.logging import publish as flog_publish
from foolscap.logging.log import UNUSUAL

crypto_available = False
try:
    from foolscap import crypto
    crypto_available = crypto.available
except ImportError:
    pass


def parse_strport(port):
    if port.startswith("unix:"):
        raise ValueError("UNIX sockets are not supported for Listeners")
    mo = re.search(r'^(tcp:)?(?P<port>\d+)(:interface=(?P<interface>[\d\.]+))?$', port)
    if not mo:
        raise ValueError("Unable to parse port string '%s'" % (port,))
    portnum = int(mo.group('port'))
    interface = mo.group('interface') or ""
    # TODO: IPv6
    return (portnum, interface)

Listeners = []
class Listener(protocol.ServerFactory):
    """I am responsible for a single listening port, which may connect to
    multiple Tubs. I have a strports-based Service, which I will attach as a
    child of one of my Tubs. If that Tub disconnects, I will reparent the
    Service to a remaining one.

    Unauthenticated Tubs use a TubID of 'None'. There may be at most one such
    Tub attached to any given Listener."""

    noisy = False

    # this also serves as the ServerFactory

    def __init__(self, port, options={},
                 negotiationClass=negotiate.Negotiation):
        """
        @type port: string
        @param port: a L{twisted.application.strports} -style description,
        specifying a TCP server
        """
        # parse the following 'port' strings:
        #  80
        #  tcp:80
        #  tcp:80:interface=127.0.0.1
        # we reject UNIX sockets.. I don't know if they ever worked.
        portnum, interface = parse_strport(port)
        self.port = port
        self.options = options
        self.negotiationClass = negotiationClass
        self.parentTub = None
        self.tubs = {}
        self.redirects = {}
        self.s = internet.TCPServer(portnum, self, interface=interface)
        Listeners.append(self)

    def getPortnum(self):
        """When this Listener was created with a port string of '0' or
        'tcp:0' (meaning 'please allocate me something'), and if the Listener
        is active (it is attached to a Tub which is in the 'running' state),
        this method will return the port number that was allocated. This is
        useful for the following pattern::

            t = Tub()
            l = t.listenOn('tcp:0')
            t.setLocation('localhost:%d' % l.getPortnum())
        """

        assert self.s.running
        return self.s._port.getHost().port

    def getInterface(self):
        assert self.s.running
        return self.s._port.getHost().host

    def __repr__(self):
        if self.tubs:
            return "<Listener at 0x%x on %s with tubs %s>" % (
                abs(id(self)),
                self.port,
                ",".join([str(k) for k in self.tubs.keys()]))
        return "<Listener at 0x%x on %s with no tubs>" % (abs(id(self)),
                                                          self.port)

    def addTub(self, tub):
        if tub.tubID in self.tubs:
            if tub.tubID is None:
                raise RuntimeError("This Listener (on %s) already has an "
                                   "unauthenticated Tub, you cannot add a "
                                   "second one" % self.port)
            raise RuntimeError("This Listener (on %s) is already connected "
                               "to TubID '%s'" % (self.port, tub.tubID))
        self.tubs[tub.tubID] = tub
        if self.parentTub is None:
            self.parentTub = tub
            self.s.setServiceParent(self.parentTub)

    def removeTub(self, tub):
        # this might return a Deferred, since the removal might cause the
        # Listener to shut down. It might also return None.
        del self.tubs[tub.tubID]
        if self.parentTub is tub:
            # we need to switch to a new one
            tubs = self.tubs.values()
            if tubs:
                self.parentTub = tubs[0]
                # TODO: I want to do this without first doing
                # disownServiceParent, so the port remains listening. Can we
                # do this? It looks like setServiceParent does
                # disownServiceParent first, so it may glitch.
                self.s.setServiceParent(self.parentTub)
            else:
                # no more tubs, this Listener will go away now
                d = self.s.disownServiceParent()
                Listeners.remove(self)
                return d
        return None

    def getService(self):
        return self.s

    def addRedirect(self, tubID, location):
        assert tubID is not None # unauthenticated Tubs don't get redirects
        self.redirects[tubID] = location
    def removeRedirect(self, tubID):
        del self.redirects[tubID]

    def startFactory(self):
        log.msg("Starting factory %r" % self, facility="foolscap.listener")
        return protocol.ServerFactory.startFactory(self)
    def stopFactory(self):
        log.msg("Stopping factory %r" % self, facility="foolscap.listener")
        return protocol.ServerFactory.stopFactory(self)


    def buildProtocol(self, addr):
        """Return a Broker attached to me (as the service provider).
        """
        lp = log.msg("%s accepting connection from %s" % (self, addr),
                     addr=(addr.host, addr.port),
                     facility="foolscap.listener")
        proto = self.negotiationClass(logparent=lp)
        proto.initServer(self)
        proto.factory = self
        return proto

    def lookupTubID(self, tubID):
        return self.tubs.get(tubID), self.redirects.get(tubID)

def generateSwissnumber(bits):
    bytes = os.urandom(bits/8)
    return base32.encode(bytes)

class Tub(service.MultiService):
    """I am a presence in the PB universe, also known as a Tub.

    I am a Service (in the twisted.application.service.Service sense),
    so you either need to call my startService() method before using me,
    or setServiceParent() me to a running service.

    This is the primary entry point for all PB-using applications, both
    clients and servers.

    I am known to the outside world by a base URL, which may include
    authentication information (a yURL). This is my 'TubID'.

    I contain Referenceables, and manage RemoteReferences to Referenceables
    that live in other Tubs.


    @param certData: if provided, use it as a certificate rather than
                     generating a new one. This is a PEM-encoded
                     private/public keypair, as returned by Tub.getCertData()

    @param certFile: if provided, the Tub will store its certificate in
                     this file. If the file does not exist when the Tub is
                     created, the Tub will generate a new certificate and
                     store it here. If the file does exist, the certificate
                     will be loaded from this file.

                     The simplest way to use the Tub is to choose a long-term
                     location for the certificate, use certFile= to tell the
                     Tub about it, and then let the Tub manage its own
                     certificate.

                     You may provide certData, or certFile, (or neither), but
                     not both.

    @param options: a dictionary of options that can influence connection
                    connection negotiation. Currently defined keys are:
                     - debug_slow: if True, wait half a second between
                                   each negotiation response

    @ivar brokers: maps TubIDs to L{Broker} instances

    @ivar listeners: maps strport to TCPServer service

    @ivar referenceToName: maps Referenceable to a name
    @ivar nameToReference: maps name to Referenceable

    @type tubID: string
    @ivar tubID: a global identifier for this Tub, possibly including
                 authentication information, hash of SSL certificate

    """
    implements(ipb.ITub)

    unsafeTracebacks = True # TODO: better way to enable this
    logLocalFailures = False
    logRemoteFailures = False
    debugBanana = False
    NAMEBITS = 160 # length of swissnumber for each reference
    TUBIDBITS = 16 # length of non-crypto tubID
    encrypted = True
    negotiationClass = negotiate.Negotiation
    brokerClass = broker.Broker
    keepaliveTimeout = 4*60 # ping when connection has been idle this long
    disconnectTimeout = None # disconnect after this much idle time
    tubID = None

    def __init__(self, certData=None, certFile=None, options={}):
        service.MultiService.__init__(self)
        self.setup(options)
        if certFile:
            self.setupEncryptionFile(certFile)
        else:
            self.setupEncryption(certData)

    def __repr__(self):
        return "<Tub id=%s>" % self.tubID

    def setupEncryptionFile(self, certFile):
        try:
            certData = open(certFile, "rb").read()
        except EnvironmentError:
            certData = None
        self.setupEncryption(certData)

        if certData is None:
            f = open(certFile, "wb")
            f.write(self.getCertData())
            f.close()

    def setupEncryption(self, certData):
        if not crypto_available:
            raise RuntimeError("crypto for PB is not available, "
                               "try importing foolscap.crypto and see "
                               "what happens")
        if certData:
            cert = crypto.PrivateCertificate.loadPEM(certData)
        else:
            cert = self.createCertificate()
        self.myCertificate = cert
        self.tubID = crypto.digest32(cert.digest("sha1"))

    def make_incarnation(self):
        unique = os.urandom(8)
        # TODO: it'd be nice to have a sequential component, so incarnations
        # could be ordered, but it requires disk space
        sequential = None
        self.incarnation = (unique, sequential)
        self.incarnation_string = binascii.b2a_hex(unique)

    def getIncarnationString(self):
        return self.incarnation_string

    def setup(self, options):
        self.options = options
        self.logger = flog.theLogger
        self.listeners = []
        self.locationHints = []

        # duplicate-connection management
        self.make_incarnation()

        # the master_table records the master-seqnum we used for the last
        # established connection with the given tubid. It only contains
        # entries for which we were the master.
        self.master_table = {} # k:tubid, v:seqnum
        # the slave_table records the (master-IR,master-seqnum) pair for the
        # last established connection with the given tubid. It only contains
        # entries for which we were the slave.
        self.slave_table = {} # k:tubid, v:(master-IR,seqnum)

        # local Referenceables
        self.nameToReference = weakref.WeakValueDictionary()
        self.referenceToName = weakref.WeakKeyDictionary()
        self.strongReferences = []
        self.nameLookupHandlers = []

        self.discovery_publisher = None
        for hint in options.get("discovery", []):
            self.enableDiscovery(hint)

        # remote stuff. Most of these use a TubRef (or NoAuthTubRef) as a
        # dictionary key
        self.tubConnectors = {} # maps TubRef to a TubConnector
        self.waitingForBrokers = {} # maps TubRef to list of Deferreds
        self.brokers = {} # maps TubRef to a Broker that connects to them
        self.unauthenticatedBrokers = [] # inbound Brokers without TubRefs
        self.reconnectors = []

        # all connections, used or not, go in here, so we can stall
        # stopService() until they're all gone.
        self._allConnections = set()
        self._allConnectionsAreDisconnected = observer.OneShotObserverList()

        self._activeConnectors = []
        self._allConnectorsAreFinished = observer.OneShotObserverList()

        self._pending_getReferences = [] # list of (d, furl) pairs

        self._logport = None
        self._logport_furl = None
        self._logport_furlfile = None

        self._log_gatherer_furls = []
        self._log_gatherer_furlfile = None
        self._log_gatherer_connectors = {} # maps furl to reconnector

        self._handle_old_duplicate_connections = False
        self._expose_remote_exception_types = True

    def setOption(self, name, value):
        if name == "logLocalFailures":
            # log (with log.err) any exceptions that occur during the
            # execution of a local Referenceable's method, which is invoked
            # on behalf of a remote caller. These exceptions are reported to
            # the remote caller through their callRemote's Deferred as usual:
            # this option enables logging on the callee's side (i.e. our
            # side) as well.
            #
            # TODO: This does not yet include Violations which were raised
            # because the inbound callRemote had arguments that didn't meet
            # our specifications. But it should.
            self.logLocalFailures = value
        elif name == "logRemoteFailures":
            # log (with log.err) any exceptions that occur during the
            # execution of a remote Referenceabe's method, invoked on behalf
            # of a local RemoteReference.callRemote(). These exceptions are
            # reported to our local caller through the usual Deferred.errback
            # mechanism: this enables logging on the caller's side (i.e. our
            # side) as well.
            self.logRemoteFailures = value
        elif name == "keepaliveTimeout":
            self.keepaliveTimeout = value
        elif name == "disconnectTimeout":
            self.disconnectTimeout = value
        elif name == "logport-furlfile":
            self.setLogPortFURLFile(value)
        elif name == "log-gatherer-furl":
            self.setLogGathererFURL(value)
        elif name == "log-gatherer-furlfile":
            self.setLogGathererFURLFile(value)
        elif name == "bridge-twisted-logs":
            assert value is not False, "cannot unbridge twisted logs"
            if value is True:
                return flog.bridgeLogsFromTwisted(self.tubID)
            else:
                # for tests, bridge logs from a specific twisted LogPublisher
                return flog.bridgeLogsFromTwisted(self.tubID,
                                                  twisted_logger=value)
        elif name == "handle-old-duplicate-connections":
            if value is True:
                value = 60
            self._handle_old_duplicate_connections = int(value)
        elif name == "expose-remote-exception-types":
            self._expose_remote_exception_types = bool(value)
        else:
            raise KeyError("unknown option name '%s'" % name)

    def setLogGathererFURL(self, gatherer_furl_or_furls):
        assert not self._log_gatherer_furls
        if isinstance(gatherer_furl_or_furls, basestring):
            self._log_gatherer_furls.append(gatherer_furl_or_furls)
        else:
            self._log_gatherer_furls.extend(gatherer_furl_or_furls)
        self._maybeConnectToGatherer()

    def setLogGathererFURLFile(self, gatherer_furlfile):
        assert not self._log_gatherer_furlfile
        self._log_gatherer_furlfile = gatherer_furlfile
        self._maybeConnectToGatherer()

    def _maybeConnectToGatherer(self):
        if not self.locationHints:
            return
        furls = []
        if self._log_gatherer_furls:
            furls.extend(self._log_gatherer_furls)
        if self._log_gatherer_furlfile:
            try:
                # allow multiple lines
                for line in open(self._log_gatherer_furlfile, "r").readlines():
                    furl = line.strip()
                    if furl:
                        furls.append(furl)
            except EnvironmentError:
                pass
        for f in furls:
            if f in self._log_gatherer_connectors:
                continue
            connector = self.connectTo(f, self._log_gatherer_connected)
            self._log_gatherer_connectors[f] = connector

    def _log_gatherer_connected(self, rref):
        # we want the logport's furl to be nailed down now, so we'll use the
        # right (persistent) name even if the user never calls
        # tub.getLogPortFURL() directly.
        ignored = self.getLogPortFURL()
        del ignored
        tubID = self.tubID
        if tubID is None:
            # RILogGatherer.logport requires a string for nodeid=
            tubID = '<unauth>'
        rref.callRemoteOnly('logport', tubID, self.getLogPort())


    def getLogPort(self):
        if not self.locationHints:
            raise NoLocationError
        return self._maybeCreateLogPort()

    def _maybeCreateLogPort(self):
        if not self._logport:
            self._logport = flog_publish.LogPublisher(self.logger)
        return self._logport

    def setLogPortFURLFile(self, furlfile):
        self._logport_furlfile = furlfile
        self._maybeCreateLogPortFURLFile()

    def _maybeCreateLogPortFURLFile(self):
        if not self._logport_furlfile:
            return
        if not self.locationHints:
            return
        # getLogPortFURL() creates the logport-furlfile as a side-effect
        ignored = self.getLogPortFURL()
        del ignored

    def _maybeEnableDiscovery(self):
        for hint in set(discovery.supported_hints) & set(self.locationHints):
            self.enableDiscovery(hint)

    def enableDiscovery(self, how):
        self.discovery_publisher = discovery.start_publishing_using(how, self)
        for l in self.listeners:
            self.discovery_publisher.listenOn(l)

    def getLogPortFURL(self):
        if not self.locationHints:
            raise NoLocationError
        if self._logport_furl:
            return self._logport_furl
        furlfile = self._logport_furlfile
        # the Tub must be running and configured (setLocation) by now
        self._logport_furl = self.registerReference(self.getLogPort(),
                                                    furlFile=furlfile)
        return self._logport_furl


    def log(self, *args, **kwargs):
        kwargs['tubID'] = self.tubID
        return log.msg(*args, **kwargs)

    def createCertificate(self):
        # this is copied from test_sslverify.py
        dn = crypto.DistinguishedName(commonName="newpb_thingy")
        keypair = crypto.KeyPair.generate()
        req = keypair.certificateRequest(dn)
        certData = keypair.signCertificateRequest(dn, req,
                                                  lambda dn: True,
                                                  132)
        cert = keypair.newCertificate(certData)
        #opts = cert.options()
        # 'opts' can be given to reactor.listenSSL, or to transport.startTLS

        return cert

    def getCertData(self):
        # the string returned by this method can be used as the certData=
        # argument to create a new Tub with the same identity. TODO: actually
        # test this, I don't know if dump/keypair.newCertificate is the right
        # pair of methods.
        return self.myCertificate.dumpPEM()

    def setLocation(self, *hints):
        """Tell this service what its location is: a host:port description of
        how to reach it from the outside world. You need to use this because
        the Tub can't do it without help. If you do a
        C{s.listenOn('tcp:1234')}, and the host is known as
        C{foo.example.com}, then it would be appropriate to do::

            s.setLocation('foo.example.com:1234')

        You must set the location before you can register any references.

        Encrypted Tubs can have multiple location hints, just provide
        multiple arguments. Unauthenticated Tubs can only have one location."""
        if not self.encrypted and len(hints) > 1:
            raise PBError("Unauthenticated tubs may only have one "
                          "location hint")
        if self.locationHints:
            raise PBError("Tub.setLocation() can only be called once")
        self.locationHints = hints
        self._maybeCreateLogPortFURLFile()
        self._maybeConnectToGatherer()
        self._maybeEnableDiscovery()

    def setLocationAutomatically(self, *extra_addresses):
        """Determine one of this host's publically-visible IP addresses and
        use it to set our location. This uses whatever source address would
        be used to get to a well-known public host (A.ROOT-SERVERS.NET),
        which is effectively the interface on which a default route lives.
        This is neither very pretty (IP address instead of hostname) nor
        guaranteed to work (it may very well be a 192.168 'private' address),
        but for publically-visible hosts this will probably produce a useable
        FURL.

        This method returns a Deferred that will fire once the location is
        actually established. Calls to registerReference() must be put off
        until the location has been set. And of course, you must call
        listenOn() before calling setLocationAutomatically()."""

        # first, make sure the reactor is actually running, by using the
        # eventual-send queue
        d = eventual.fireEventually()

        def _reactor_running(res):
            assert self.running
            # we can't use get_local_ip_for until the reactor is running
            return util.get_local_ip_for()
        d.addCallback(_reactor_running)

        def _got_local_ip(local_address):
            local_addresses = set(extra_addresses)
            if local_address:
                local_addresses.add(local_address)
            local_addresses.add("127.0.0.1")
            locations = set()
            for l in self.getListeners():
                portnum = l.getPortnum()
                for addr in local_addresses:
                    locations.add("%s:%d" % (addr, portnum))
            locations = list(locations)
            locations.sort()
            assert len(locations) >= 1
            location = ",".join(locations)
            self.setLocation(location)
        d.addCallback(_got_local_ip)
        return d

    def listenOn(self, what, options={}):
        """Start listening for connections.

        @type  what: string or Listener instance
        @param what: a L{twisted.application.strports} -style description,
                     or a L{Listener} instance returned by a previous call to
                     listenOn.
        @param options: a dictionary of options that can influence connection
                        negotiation before the target Tub has been determined

        @return: The Listener object that was created. This can be used to
        stop listening later on, to have another Tub listen on the same port,
        and to figure out which port was allocated when you used a strports
        specification of 'tcp:0'. """
        if type(what) is str:
            l = Listener(what, options, self.negotiationClass)
        else:
            assert not options
            l = what
        assert l not in self.listeners
        l.addTub(self)
        self.listeners.append(l)
        if self.discovery_publisher:
            self.discovery_publisher.listenOn(l)
        return l

    def stopListeningOn(self, l):
        # this returns a Deferred when the port is shut down
        if self.discovery_publisher:
            self.discovery_publisher.stopListeningOn(l)
        self.listeners.remove(l)
        d = defer.maybeDeferred(l.removeTub, self)
        return d

    def getListeners(self):
        """Return the set of Listener objects that allow the outside world to
        connect to this Tub."""
        return self.listeners[:]

    def clone(self):
        """Return a new Tub (with a different ID), listening on the same
        ports as this one."""
        if self.encrypted:
            t = Tub()
        else:
            t = UnauthenticatedTub()
        for l in self.listeners:
            t.listenOn(l)
        return t

    def getTubID(self):
        return self.tubID
    def getShortTubID(self):
        return self.tubID[:4]

    def connectorStarted(self, c):
        assert self.running
        self._activeConnectors.append(c)
    def connectorFinished(self, c):
        if c in self._activeConnectors:
            self._activeConnectors.remove(c)
            if not self.running and not self._activeConnectors:
                self._allConnectorsAreFinished.fire(self)

    def startService(self):
        service.MultiService.startService(self)
        for d,sturdy in self._pending_getReferences:
            d1 = eventual.fireEventually(sturdy)
            d1.addCallback(self.getReference)
            d1.addBoth(lambda res, d=d: d.callback(res))
        del self._pending_getReferences
        for rc in self.reconnectors:
            eventual.eventually(rc.startConnecting, self)

    def _tubsAreNotRestartable(self, *args, **kwargs):
        raise RuntimeError("Sorry, but Tubs cannot be restarted.")
    def _tubHasBeenShutDown(self, *args, **kwargs):
        raise RuntimeError("Sorry, but this Tub has been shut down.")

    def stopService(self):
        # note that once you stopService a Tub, I cannot be restarted. (at
        # least this code is not designed to make that possible.. it might be
        # doable in the future).
        assert self.running
        self.startService = self._tubsAreNotRestartable
        self.getReference = self._tubHasBeenShutDown
        self.connectTo = self._tubHasBeenShutDown
        dl = []
        for rc in self.reconnectors:
            rc.stopConnecting()
        del self.reconnectors
        for l in self.listeners:
            # TODO: rethink this, what I want is for stopService to cause all
            # Listeners to shut down, but I'm not sure this is the right way
            # to do it.
            d = l.removeTub(self)
            if isinstance(d, defer.Deferred):
                dl.append(d)
        dl.append(service.MultiService.stopService(self))

        if self._activeConnectors:
            dl.append(self._allConnectorsAreFinished.whenFired())
        for c in self._activeConnectors:
            c.shutdown()

        if self._allConnections:
            dl.append(self._allConnectionsAreDisconnected.whenFired())
        why = Failure(error.ConnectionDone("Tub.stopService was called"))
        for b in self.brokers.values():
            b.shutdown(why, fireDisconnectWatchers=False)
        for b in self.unauthenticatedBrokers:
            b.shutdown(why, fireDisconnectWatchers=False)

        return defer.DeferredList(dl)

    def generateSwissnumber(self, bits):
        return generateSwissnumber(bits)

    def buildURL(self, name):
        if self.encrypted:
            # TODO: IPv6 dotted-quad addresses have colons, but need to have
            # host:port
            hint_str = ",".join(self.locationHints)
            return "pb://" + self.tubID + "@" + hint_str + "/" + name
        return "pbu://" + self.locationHints[0] + "/" + name

    def registerReference(self, ref, name=None, furlFile=None):
        """Make a Referenceable available to the outside world. A URL is
        returned which can be used to access this object. This registration
        will remain in effect (and the Tub will retain a reference to the
        object to keep it meaningful) until explicitly unregistered, or the
        Tub is shut down.

        @type  name: string (optional)
        @param name: if provided, the object will be registered with this
                     name. If not, a random (unguessable) string will be
                     used.

        @param furlFile: if provided, get the name from this file (if
                         it exists), and write the new FURL to this file.
                         If 'name=' is also provided, it is used for the
                         name, but the FURL is still written to this file.

        @rtype: string
        @return: the URL which points to this object. This URL can be passed
        to Tub.getReference() in any Tub on any host which can reach this
        one.
        """

        if not self.locationHints:
            raise RuntimeError("you must setLocation() before "
                               "you can registerReference()")
        oldfurl = None
        if furlFile:
            try:
                oldfurl = open(furlFile, "r").read().strip()
            except EnvironmentError:
                pass
        if oldfurl:
            sr = SturdyRef(oldfurl)
            if name is None:
                name = sr.name
            if self.tubID != sr.tubID:
                raise WrongTubIdError("I cannot keep using the old FURL from %s"
                                      " because it does not have the same"
                                      " TubID as I do (%s)" %
                                      (furlFile, self.tubID))
            if name != sr.name:
                raise WrongNameError("I cannot keep using the old FURL from %s"
                                     " because you called registerReference"
                                     " with a new name (%s)" %
                                     (furlFile, name))
        name = self._assignName(ref, name)
        assert name
        if ref not in self.strongReferences:
            self.strongReferences.append(ref)
        furl = self.buildURL(name)
        if furlFile:
            need_to_chmod = not os.path.exists(furlFile)
            open(furlFile, "w").write(furl + "\n")
            if need_to_chmod:
                os.chmod(furlFile, 0600)
        return furl

    # this is called by either registerReference or by
    # getOrCreateURLForReference
    def _assignName(self, ref, preferred_name=None):
        """Make a Referenceable available to the outside world, but do not
        retain a strong reference to it. If we must create a new name, use
        preferred_name. If that is None, use a random unguessable name.
        """
        if not self.locationHints:
            # without a location, there is no point in giving it a name
            return None
        if self.referenceToName.has_key(ref):
            return self.referenceToName[ref]
        name = preferred_name
        if not name:
            name = self.generateSwissnumber(self.NAMEBITS)
        self.referenceToName[ref] = name
        self.nameToReference[name] = ref
        return name

    def getReferenceForName(self, name):
        if name in self.nameToReference:
            return self.nameToReference[name]
        for lookup in self.nameLookupHandlers:
            ref = lookup(name)
            if ref:
                if ref not in self.referenceToName:
                    self.referenceToName[ref] = name
                return ref
        # don't reveal the full swissnum
        hint = name[:2]
        raise KeyError("unable to find reference for name starting with '%s'"
                       % hint)

    def getReferenceForURL(self, url):
        # TODO: who should this be used by?
        sturdy = SturdyRef(url)
        assert sturdy.tubID == self.tubID
        return self.getReferenceForName(sturdy.name)

    def getOrCreateURLForReference(self, ref):
        """Return the global URL for the reference, if there is one, or None
        if there is not."""
        name = self._assignName(ref)
        if name:
            return self.buildURL(name)
        return None

    def revokeReference(self, ref):
        # TODO
        pass

    def unregisterURL(self, url):
        sturdy = SturdyRef(url)
        name = sturdy.name
        ref = self.nameToReference[name]
        del self.nameToReference[name]
        del self.referenceToName[ref]
        self.revokeReference(ref)

    def unregisterReference(self, ref):
        name = self.referenceToName[ref]
        url = self.buildURL(name)
        sturdy = SturdyRef(url)
        name = sturdy.name
        del self.nameToReference[name]
        del self.referenceToName[ref]
        if ref in self.strongReferences:
            self.strongReferences.remove(ref)
        self.revokeReference(ref)

    def registerNameLookupHandler(self, lookup):
        """Add a function to help convert names to Referenceables.

        When remote systems pass a FURL to their Tub.getReference(), our Tub
        will be asked to locate a Referenceable for the name inside that
        furl. The normal mechanism for this is to look at the table
        maintained by registerReference() and unregisterReference(). If the
        name does not exist in that table, other 'lookup handler' functions
        are given a chance. Each lookup handler is asked in turn, and the
        first which returns a non-None value wins.

        This may be useful for cases where the furl represents an object that
        lives on disk, or is generated on demand: rather than creating all
        possible Referenceables at startup, the lookup handler can create or
        retrieve the objects only when someone asks for them.

        Note that constructing the FURLs of these objects may be non-trivial.
        It is safe to create an object, use tub.registerReference in one
        invocation of a program to obtain (and publish) the furl, parse the
        furl to extract the name, save the contents of the object on disk,
        then in a later invocation of the program use a lookup handler to
        retrieve the object from disk. This approach means the objects that
        are created in a given invocation stick around (inside
        tub.strongReferences) for the rest of that invocation. An alternatve
        approach is to create the object but *not* use tub.registerReference,
        but in that case you have to construct the FURL yourself, and the Tub
        does not currently provide any support for doing this robustly.

        @param lookup: a callable which accepts a name (as a string) and
                       returns either a Referenceable or None. Note that
                       these strings should not contain a slash, a question
                       mark, or an ampersand, as these are reserved in the
                       FURL for later expansion (to add parameters beyond the
                       object name)
        """
        self.nameLookupHandlers.append(lookup)

    def unregisterNameLookupHandler(self, lookup):
        self.nameLookupHandlers.remove(lookup)

    def getReference(self, sturdyOrURL):
        """Acquire a RemoteReference for the given SturdyRef/URL.

        The Tub must be running (i.e. Tub.startService()) when this is
        invoked. Future releases may relax this requirement.

        @return: a Deferred that fires with the RemoteReference. Any failures
        are returned asynchronously.
        """

        return defer.maybeDeferred(self._getReference, sturdyOrURL)

    def _getReference(self, sturdyOrURL):
        if isinstance(sturdyOrURL, SturdyRef):
            sturdy = sturdyOrURL
        else:
            sturdy = SturdyRef(sturdyOrURL)
        # pb->pb: ok, requires crypto
        # pbu->pb: ok, requires crypto
        # pbu->pbu: ok
        # pb->pbu: ok, requires crypto
        if sturdy.encrypted and not crypto_available:
            e = BananaError("crypto for PB is not available, "
                            "we cannot handle encrypted PB-URLs like %s"
                            % sturdy.getURL())
            return defer.fail(e)

        if not self.running:
            # queue their request for service once the Tub actually starts
            log.msg("Tub.getReference(%s) queued until Tub.startService called"
                    % sturdy, facility="foolscap.tub")
            d = defer.Deferred()
            self._pending_getReferences.append((d, sturdy))
            return d

        name = sturdy.name
        d = self.getBrokerForTubRef(sturdy.getTubRef())
        d.addCallback(lambda b: b.getYourReferenceByName(name))
        return d

    def connectTo(self, _sturdyOrURL, _cb, *args, **kwargs):
        """Establish (and maintain) a connection to a given PBURL.

        I establish a connection to the PBURL and run a callback to inform
        the caller about the newly-available RemoteReference. If the
        connection is lost, I schedule a reconnection attempt for the near
        future. If that one fails, I keep trying at longer and longer
        intervals (exponential backoff).

        I accept a callback which will be fired each time a connection
        attempt succeeds. This callback is run with the new RemoteReference
        and any additional args/kwargs provided to me. The callback should
        then use rref.notifyOnDisconnect() to get a message when the
        connection goes away. At some point after it goes away, the
        Reconnector will reconnect.

        The Tub must be running (i.e. Tub.startService()) when this is
        invoked. Future releases may relax this requirement.

        I return a Reconnector object. When you no longer want to maintain
        this connection, call the stopConnecting() method on the Reconnector.
        I promise to not invoke your callback after you've called
        stopConnecting(), even if there was already a connection attempt in
        progress. If you had an active connection before calling
        stopConnecting(), you will still have access to it, until it breaks
        on its own. (I will not attempt to break existing connections, I will
        merely stop trying to create new ones). All my Reconnector objects
        will be shut down when the Tub is stopped.

        Usage::

         def _got_ref(rref, arg1, arg2):
             rref.callRemote('hello again')
             # etc
         rc = tub.connectTo(_got_ref, 'arg1', 'arg2')
         ...
         rc.stopConnecting() # later
        """

        rc = Reconnector(_sturdyOrURL, _cb, args, kwargs)
        if self.running:
            rc.startConnecting(self)
        else:
            self.log("Tub.connectTo(%s) queued until Tub.startService called"
                     % _sturdyOrURL, level=UNUSUAL)
        self.reconnectors.append(rc)
        return rc

    def serialize(self, obj):
        b = broker.StorageBroker(None)
        b.setTub(self)
        d = storage.serialize(obj, banana=b)
        return d

    def unserialize(self, data):
        b = broker.StorageBroker(None)
        b.setTub(self)
        d = storage.unserialize(data, banana=b)
        assert isinstance(d, defer.Deferred)
        return d

    # beyond here are internal methods, not for use by application code

    # _removeReconnector is called by the Reconnector
    def _removeReconnector(self, rc):
        self.reconnectors.remove(rc)

    def getBrokerForTubRef(self, tubref):
        if tubref in self.brokers:
            return defer.succeed(self.brokers[tubref])
        if tubref.getTubID() == self.tubID:
            b = self._createLoopbackBroker(tubref)
            # _createLoopbackBroker will call brokerAttached, which will add
            # it to self.brokers
            # TODO: stash this in self.brokers, so we don't create multiples
            return defer.succeed(b)

        d = defer.Deferred()
        if tubref not in self.waitingForBrokers:
            self.waitingForBrokers[tubref] = []
        self.waitingForBrokers[tubref].append(d)

        if tubref not in self.tubConnectors:
            # the TubConnector will call our brokerAttached when it finishes
            # negotiation, which will fire waitingForBrokers[tubref].
            c = negotiate.TubConnector(self, tubref)
            self.tubConnectors[tubref] = c
            c.connect()

        return d

    def _createLoopbackBroker(self, tubref):
        t1,t2 = broker.LoopbackTransport(), broker.LoopbackTransport()
        t1.setPeer(t2); t2.setPeer(t1)
        n = negotiate.Negotiation()
        params = n.loopbackDecision()
        b1,b2 = (self.brokerClass(tubref, params),
                 self.brokerClass(tubref, params))
        # we treat b1 as "our" broker, and b2 as "theirs", and we pretend
        # that b2 has just connected to us. We keep track of b1, and b2 keeps
        # track of us.
        b1.setTub(self)
        b2.setTub(self)
        t1.protocol = b1; t2.protocol = b2
        b1.makeConnection(t1); b2.makeConnection(t2)
        self.connectionAttached(b1)
        self.connectionAttached(b2)
        self.brokerAttached(tubref, b1, False)
        return b1

    def connectionFailed(self, tubref, why):
        # we previously initiated an outbound TubConnector to this tubref, but
        # it was unable to establish a connection. 'why' is the most useful
        # Failure that occurred (i.e. it is a NegotiationError if we made it
        # that far, otherwise it's a ConnectionFailed).

        if tubref in self.tubConnectors:
            del self.tubConnectors[tubref]
        if tubref in self.brokers:
            # oh, but fortunately an inbound connection must have succeeded.
            # Nevermind.
            return

        # inform hopeful Broker-waiters that they aren't getting one
        if tubref in self.waitingForBrokers:
            waiting = self.waitingForBrokers[tubref]
            del self.waitingForBrokers[tubref]
            for d in waiting:
                d.errback(why)

    def connectionAttached(self, broker):
        self._allConnections.add(broker)

    def brokerAttached(self, tubref, broker, isClient):
        assert self.running
        if not tubref:
            # this is an inbound connection from an unauthenticated Tub
            assert not isClient
            # we just track it so we can disconnect it later
            self.unauthenticatedBrokers.append(broker)
            return

        if tubref in self.tubConnectors:
            # we initiated an outbound connection to this tubref
            if not isClient:
                # however, the connection we got was from an inbound
                # connection. The completed (inbound) connection wins, so
                # abandon the outbound TubConnector
                self.tubConnectors[tubref].shutdown()

            # we don't need the TubConnector any more
            del self.tubConnectors[tubref]

        if tubref in self.brokers:
            # this shouldn't happen: acceptDecision is supposed to drop any
            # existing old connection first.
            self.log("ERROR: unexpected duplicate connection from %s" % tubref)
            raise BananaError("unexpected duplicate connection")
        self.brokers[tubref] = broker

        # now inform everyone who's been waiting on it
        if tubref in self.waitingForBrokers:
            for d in self.waitingForBrokers[tubref]:
                eventual.eventually(d.callback, broker)
            del self.waitingForBrokers[tubref]

    def brokerDetached(self, broker, why):
        # a loopback connection will produce two Brokers that both use the
        # same tubref. Both will shut down about the same time. Make sure
        # this doesn't confuse us.

        # the Broker will have already severed all active references
        for tubref in self.brokers.keys():
            if self.brokers[tubref] is broker:
                del self.brokers[tubref]
        if broker in self.unauthenticatedBrokers:
            self.unauthenticatedBrokers.remove(broker)

    def connectionDropped(self, broker):
        self._allConnections.discard(broker)
        # if the Tub has already shut down, we may need to notify observers
        # who are waiting for all of our connections to finish shutting down.
        if (not self.running and not self._allConnections):
            self._allConnectionsAreDisconnected.fire(self)

    def debug_listBrokers(self):
        # return a list of (tubref, inbound, outbound) tuples. The tubref
        # tells you which broker this is, 'inbound' is a list of
        # InboundDelivery objects (one per outstanding inbound message), and
        # 'outbound' is a list of PendingRequest objects (one per message
        # that's waiting on a remote broker to complete).
        output = []
        all_brokers = (self.brokers.items()
                       + [("unauth",broker)
                          for broker in self.unauthenticatedBrokers])
        for tubref,broker in all_brokers:
            inbound = broker.inboundDeliveryQueue[:]
            outbound = [pr
                        for (reqID, pr) in
                        sorted(broker.waitingForAnswers.items()) ]
            output.append( (str(tubref), inbound, outbound) )
        output.sort(lambda x,y: cmp( (len(x[1]), len(x[2])),
                                     (len(y[1]), len(y[2])) ))
        return output


class UnauthenticatedTub(Tub):
    encrypted = False

    def __init__(self, tubID=None, options={}):
        service.MultiService.__init__(self)
        self.setup(options)
        self.myCertificate = None
        assert not tubID # not yet
        self.tubID = tubID

    def getTubID(self):
        return "<unauth>"
    def getShortTubID(self):
        return "<unauth>"
