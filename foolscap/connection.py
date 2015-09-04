import re
from twisted.python.failure import Failure
from twisted.internet import protocol, reactor, endpoints, error
from foolscap.tokens import (NoLocationHintsError, NegotiationError,
                             RemoteNegotiationError)
from foolscap.logging import log
from foolscap.logging.log import CURIOUS, OPERATIONAL
from foolscap.util import isSubstring

# once twisted#8014 is fixed, use HostnameEndpoint when possible
#try:
#    # added in twisted-13.2.0, handles IPv4/IPv6
#    BEST_TCP_ENDPOINT = endpoints.HostnameEndpoint
#except NameError:
#    # added in twisted-10.1.0, but IPv4-only
#    BEST_TCP_ENDPOINT = endpoints.TCP4ClientEndpoint

# This can match IPv4 IP addresses + port numbers *or* host names +
# port numbers.
DOTTED_QUAD_RESTR=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

DNS_NAME_RESTR=r"[A-Za-z.0-9\-]+"

OLD_STYLE_HINT_RE=re.compile(r"^(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                        DNS_NAME_RESTR))

# _tokenize(), _parse() and _parseClientTCP() are copied from
# twisted.internet.endpoints

_OP, _STRING = range(2)

def _tokenize(description):
    """
    Tokenize a strports string and yield each token.

    @param description: a string as described by L{serverFromString} or
        L{clientFromString}.

    @return: an iterable of 2-tuples of (L{_OP} or L{_STRING}, string).  Tuples
        starting with L{_OP} will contain a second element of either ':' (i.e.
        'next parameter') or '=' (i.e. 'assign parameter value').  For example,
        the string 'hello:greet\=ing=world' would result in a generator
        yielding these values::

            _STRING, 'hello'
            _OP, ':'
            _STRING, 'greet=ing'
            _OP, '='
            _STRING, 'world'
    """
    current = ''
    ops = ':='
    nextOps = {':': ':=', '=': ':'}
    description = iter(description)
    for n in description:
        if n in ops:
            yield _STRING, current
            yield _OP, n
            current = ''
            ops = nextOps[n]
        elif n == '\\':
            current += description.next()
        else:
            current += n
    yield _STRING, current

def _parse(description):
    """
    Convert a description string into a list of positional and keyword
    parameters, using logic vaguely like what Python does.

    @param description: a string as described by L{serverFromString} or
        L{clientFromString}.

    @return: a 2-tuple of C{(args, kwargs)}, where 'args' is a list of all
        ':'-separated C{str}s not containing an '=' and 'kwargs' is a map of
        all C{str}s which do contain an '='.  For example, the result of
        C{_parse('a:b:d=1:c')} would be C{(['a', 'b', 'c'], {'d': '1'})}.
    """
    args, kw = [], {}
    def add(sofar):
        if len(sofar) == 1:
            args.append(sofar[0])
        else:
            kw[sofar[0]] = sofar[1]
    sofar = ()
    for (type, value) in _tokenize(description):
        if type is _STRING:
            sofar += (value,)
        elif value == ':':
            add(sofar)
            sofar = ()
    add(sofar)
    return args, kw

def _parseClientTCP(*args, **kwargs):
    """
    Perform any argument value coercion necessary for TCP client parameters.

    Valid positional arguments to this function are host and port.

    Valid keyword arguments to this function are all L{IReactorTCP.connectTCP}
    arguments.

    @return: The coerced values as a C{dict}.
    """

    if len(args) == 2:
        kwargs['port'] = int(args[1])
        kwargs['host'] = args[0]
    elif len(args) == 1:
        if 'host' in kwargs:
            kwargs['port'] = int(args[0])
        else:
            kwargs['host'] = args[0]

    try:
        kwargs['port'] = int(kwargs['port'])
    except KeyError:
        pass

    try:
        kwargs['timeout'] = int(kwargs['timeout'])
    except KeyError:
        pass

    try:
        kwargs['bindAddress'] = (kwargs['bindAddress'], 0)
    except KeyError:
        pass

    return kwargs

# Each location hint must start with "TYPE:" (where TYPE is alphanumeric) and
# then can contain any characters except "," and "/". These are expected to
# look like Twisted endpoint descriptors, or contain other ":"-separated
# fields (e.g. "TYPE:key=value:key=value" or "TYPE:stuff:morestuff"). We also
# accept old-syle implicit TCP hints (host:port). To avoid being interpreted
# as an old-style hint, the part after TYPE: may not consist of only 1-5
# digits (so "type:123" will be treated as type="tcp" and hostname="type").

# Future versions of foolscap may put hints in their FURLs which we do not
# understand. We will ignore such hints. This version understands two types
# of hints:
#
#  HOST:PORT                 (implicit tcp)
#  tcp:host=HOST:port=PORT }
#  tcp:HOST:PORT           } (endpoint syntax for TCP connections
#  tcp:host=HOST:PORT      }  in full, compact and mixed forms)
#  tcp:HOST:port=PORT      }

def hint_to_endpoint(hint, reactor):
    # Return (endpoint, hostname), where "hostname" is what we pass to the
    # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
    # Return (None,None) if the hint isn't recognized.
    mo = OLD_STYLE_HINT_RE.search(hint)
    if mo:
        host, port = mo.group(1), int(mo.group(2))
        return endpoints.TCP4ClientEndpoint(reactor, host, port), host
    args, kwargs = _parse(hint)
    aname = args.pop(0)
    if aname.upper() == "TCP":
        fields = _parseClientTCP(*args, **kwargs)
        host, port = fields["host"], fields["port"]
        return endpoints.TCP4ClientEndpoint(reactor, host, port), host
    # Ignore other things from the future.
    return (None, None)

class TubConnectorFactory(protocol.Factory, object):
    # this is for internal use only. Application code should use
    # Tub.getReference(url)

    noisy = False

    def __init__(self, tc, host, logparent):
        self.tc = tc # the TubConnector
        self.host = host
        self._logparent = logparent

    def __repr__(self):
        # make it clear which remote Tub we're trying to connect to
        base = object.__repr__(self)
        at = base.find(" at ")
        if at == -1:
            # our annotation isn't really important, so don't fail just
            # because we guessed the default __repr__ incorrectly
            return base
        assert self.tc.tub.tubID
        origin = self.tc.tub.tubID[:8]
        assert self.tc.target.getTubID()
        target = self.tc.target.getTubID()[:8]
        return base[:at] + " [from %s]" % origin + " [to %s]" % target + base[at:]

    def buildProtocol(self, addr):
        nc = self.tc.tub.negotiationClass # this is usually Negotiation
        proto = nc(self._logparent)
        proto.initClient(self.tc, self.host)
        proto.factory = self
        return proto


class TubConnector(object):
    """I am used to make an outbound connection. I am given a target TubID
    and a list of locationHints, and I try all of them until I establish a
    Broker connected to the target. I will consider redirections returned
    along the way. The first hint that yields a connected Broker will stop
    the search.

    This is a single-use object. The connection attempt begins as soon as my
    connect() method is called.

    I live until all but one of the TCP connections I initiated have finished
    closing down. This means that connection establishment attempts in
    progress are cancelled, and established connections (the ones which did
    *not* complete negotiation before the winning connection) have called
    their connectionLost() methods.
    """

    failureReason = None
    CONNECTION_TIMEOUT = 60
    timer = None

    def __init__(self, parent, tubref):
        self._logparent = log.msg(format="TubConnector created from "
                                  "%(fromtubid)s to %(totubid)s",
                                  fromtubid=parent.tubID,
                                  totubid=tubref.getTubID(),
                                  level=OPERATIONAL,
                                  facility="foolscap.connection")
        self.tub = parent
        self.target = tubref
        self.remainingLocations = list(self.target.getLocations())
        # attemptedLocations keeps track of where we've already tried to
        # connect, so we don't try them twice, even if they appear in the
        # hints multiple times. this isn't too clever: slight variations of
        # the same hint will fool it, but it should be enough to avoid
        # infinite redirection loops.
        self.attemptedLocations = []

        # pendingConnections contains a Deferred for each endpoint.connect()
        # that has started (but not yet established) a connection. We keep
        # track of these so we can shut them down (using d.cancel()) when we
        # stop connecting (either because one of the other connections
        # succeeded, or because someone told us to give up).
        self.pendingConnections = set()

        # self.pendingNegotiations maps Negotiation instances (connected but
        # not finished negotiation) to the hint that got us the connection.
        # We track these so we can abandon the negotiation.
        self.pendingNegotiations = {}

    def __repr__(self):
        s = object.__repr__(self)
        s = s[:-1]
        s += " from %s to %s>" % (self.tub.tubID, self.target.getTubID())
        return s

    def log(self, *args, **kwargs):
        kwargs['parent'] = kwargs.get('parent') or self._logparent
        kwargs['facility'] = kwargs.get('facility') or "foolscap.connection"
        return log.msg(*args, **kwargs)

    def connect(self):
        """Begin the connection process. This should only be called once.
        This will either result in the successful Negotiation object invoking
        the parent Tub's brokerAttached() method, or us calling the Tub's
        connectionFailed() method."""
        self.tub.connectorStarted(self)
        timeout = self.tub.options.get('connect_timeout',
                                       self.CONNECTION_TIMEOUT)
        self.timer = reactor.callLater(timeout, self.connectionTimedOut)
        self.active = True
        self.connectToAll()

    def stopConnectionTimer(self):
        if self.timer:
            self.timer.cancel()
            del self.timer

    def shutdown(self):
        self.active = False
        self.remainingLocations = []
        self.stopConnectionTimer()
        self.cancelRemainingConnections()

    def cancelRemainingConnections(self):
        for d in list(self.pendingConnections):
            d.cancel()
            # this will trigger self._connectionFailed(), via the errback,
            # with a ConnectingCancelledError
        for n in self.pendingNegotiations.keys():
            n.transport.loseConnection()
            # triggers n.connectionLost(), then self.negotiationFailed()

    def connectToAll(self):
        triedAnything = False
        while self.remainingLocations:
            location = self.remainingLocations.pop()
            if location in self.attemptedLocations:
                continue
            self.attemptedLocations.append(location)
            ep, host = hint_to_endpoint(location, reactor)
            if not ep:
                self.log("unrecognized hint %s, skipping")
                continue
            triedAnything = True
            lp = self.log("connectTCP to %s" % (location,))
            f = TubConnectorFactory(self, host, lp)
            d = ep.connect(f)
            self.pendingConnections.add(d)
            def _remove(res, d=d):
                self.pendingConnections.remove(d)
                return res
            d.addBoth(_remove)
            d.addCallback(self._connectionSuccess, location, lp)
            d.addErrback(self._connectionFailed, location, lp)
            if self.tub.options.get("debug_stall_second_connection"):
                # for unit tests, hold off on making the second connection
                # for a moment. This allows the first connection to get to a
                # known state.
                reactor.callLater(0.1, self.connectToAll)
                return
        if not triedAnything:
            self.failureReason = Failure(NoLocationHintsError())
        self.checkForFailure()

    def connectionTimedOut(self):
        # this timer is for the overall connection attempt, not each
        # individual endpoint/TCP connector
        self.timer = None
        why = "no connection established within client timeout"
        self.failureReason = Failure(NegotiationError(why))
        self.shutdown()
        self.failed()

    def _connectionFailed(self, reason, hint, lp):
        # this is called if some individual TCP connection cannot be
        # established
        if reason.check(error.ConnectionRefusedError):
            self.log("connection refused for %s" % hint, level=OPERATIONAL,
                     parent=lp, umid="rSrUxQ")
        elif reason.check(error.ConnectingCancelledError):
            self.log("abandoned attempt to %s" % hint, level=OPERATIONAL,
                     parent=lp, umid="CC8vwg")
        else:
            log.err(reason, "failed to connect to %s" % hint, level=CURIOUS,
                    parent=lp, facility="foolscap.connection",
                    umid="2PEowg")
        if not self.failureReason:
            self.failureReason = reason
        self.checkForFailure()
        self.checkForIdle()

    def _connectionSuccess(self, p, hint, lp):
        # fires with the Negotiation protocol instance, after
        # p.makeConnection(transport) returns, which is after
        # p.connectionMade() returns
        self.log("connected to %s, beginning negotiation" % hint,
                 level=OPERATIONAL, parent=lp, umid="VN0XGQ")
        self.pendingNegotiations[p] = hint

    def redirectReceived(self, newLocation):
        # the redirected connection will disconnect soon, which will trigger
        # negotiationFailed(), so we don't have to do a
        self.remainingLocations.append(newLocation)
        self.connectToAll()

    def negotiationFailed(self, n, reason):
        assert isinstance(n, self.tub.negotiationClass)
        # this is called if protocol negotiation cannot be established, or if
        # the connection is closed for any reason prior to switching to the
        # Banana protocol
        self.pendingNegotiations.pop(n)
        assert isinstance(reason, Failure), \
               "Hey, %s isn't a Failure" % (reason,)
        if (not self.failureReason or
            isinstance(reason, NegotiationError)):
            # don't let mundane things like ConnectionFailed override the
            # actually significant ones like NegotiationError
            self.failureReason = reason
        self.checkForFailure()
        self.checkForIdle()

    def negotiationComplete(self, n):
        assert isinstance(n, self.tub.negotiationClass)
        # 'factory' has just completed negotiation, so abandon all the other
        # connection attempts
        self.log("negotiationComplete, %s won" % n)
        self.pendingNegotiations.pop(n) # this one succeeded
        self.active = False
        if self.timer:
            self.timer.cancel()
            self.timer = None
        self.cancelRemainingConnections() # abandon the others
        self.checkForIdle()

    def checkForFailure(self):
        if not self.active:
            return
        if (self.remainingLocations or
            self.pendingConnections or self.pendingNegotiations):
            return
        # we have no more options, so the connection attempt will fail. The
        # getBrokerForTubRef may have succeeded, however, if the other side
        # tried to connect to us at exactly the same time, they were the
        # master, they established their connection first (but the final
        # decision is still in flight), and they hung up on our connection
        # because they felt it was a duplicate. So, if self.failureReason
        # indicates a duplicate connection, do not signal a failure here. We
        # leave the connection timer in place in case they lied about having
        # a duplicate connection ready to go.
        if (self.failureReason.check(RemoteNegotiationError) and
            isSubstring(self.failureReason.value.args[0],
                        "Duplicate connection")):
            self.log("TubConnector.checkForFailure: connection attempt "
                     "failed because the other end decided ours was a "
                     "duplicate connection, so we won't signal the "
                     "failure here")
            return
        self.failed()

    def failed(self):
        self.stopConnectionTimer()
        self.active = False
        self.tub.connectionFailed(self.target, self.failureReason)
        self.tub.connectorFinished(self)

    def checkForIdle(self):
        # When one connection finishes negotiation, the others are cancelled
        # to hurry them along their way towards disconnection. The last one
        # to resolve finally causes us to notify our parent Tub.
        if (self.remainingLocations or
            self.pendingConnections or self.pendingNegotiations):
            return
        # we have no more outstanding connections (either in progress or in
        # negotiation), so this connector is finished.
        self.log("connectorFinished (%s)" % self)
        self.tub.connectorFinished(self)
