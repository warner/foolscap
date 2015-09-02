
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

class TubConnectorClientFactory(protocol.ClientFactory, object):
    # this is for internal use only. Application code should use
    # Tub.getReference(url)

    noisy = False

    def __init__(self, tc, host, logparent):
        self.tc = tc # the TubConnector
        self.host = host
        self._logparent = logparent

    def log(self, *args, **kwargs):
        kwargs['parent'] = self._logparent
        kwargs['facility'] = "foolscap.negotiation"
        return log.msg(*args, **kwargs)

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

    def startFactory(self):
        self.log("Starting factory %r" % self)
        return protocol.ClientFactory.startFactory(self)
    def stopFactory(self):
        self.log("Stopping factory %r" % self)
        return protocol.ClientFactory.stopFactory(self)

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
        hints = []
        # filter out the hints that we can actually use.. there may be
        # extensions from the future sitting in this list
        for h in self.target.getLocations():
            if h[0] == "tcp":
                (host, port) = h[1:]
                hints.append( (host, port) )
        self.remainingLocations = hints
        # attemptedLocations keeps track of where we've already tried to
        # connect, so we don't try them twice.
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
        kwargs['parent'] = self._logparent
        kwargs['facility'] = "foolscap.connection"
        return log.msg(*args, **kwargs)

    def connect(self):
        """Begin the connection process. This should only be called once.
        This will either result in the successful Negotiation object invoking
        the parent Tub's brokerAttached() method, or us calling the Tub's
        connectionFailed() method."""
        self.tub.connectorStarted(self)
        if not self.remainingLocations:
            # well, that's going to make it difficult. connectToAll() will
            # pass through to checkForFailure(), which will notice our lack
            # of options and deliver this failureReason to the caller.
            self.failureReason = Failure(NoLocationHintsError())
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
        while self.remainingLocations:
            location = self.remainingLocations.pop()
            if location in self.attemptedLocations:
                continue
            self.attemptedLocations.append(location)
            host, port = location
            hint = "tcp:%s:%s" % (host, port) # TODO: stash the original hint
            lp = self.log("connectTCP to %s" % (location,))
            f = TubConnectorClientFactory(self, host, lp)
            ep = endpoints.TCP4ClientEndpoint(reactor, host, port)
            d = ep.connect(f)
            self.pendingConnections.add(d)
            def _remove(res, d=d):
                self.pendingConnections.remove(d)
                return res
            d.addBoth(_remove)
            d.addCallback(self._connectionSuccess, hint)
            d.addErrback(self._connectionFailed, hint)
            if self.tub.options.get("debug_stall_second_connection"):
                # for unit tests, hold off on making the second connection
                # for a moment. This allows the first connection to get to a
                # known state.
                reactor.callLater(0.1, self.connectToAll)
                return
        self.checkForFailure()

    def connectionTimedOut(self):
        # this timer is for the overall connection attempt, not each
        # individual endpoint/TCP connector
        self.timer = None
        why = "no connection established within client timeout"
        self.failureReason = Failure(NegotiationError(why))
        self.shutdown()
        self.failed()

    def _connectionFailed(self, reason, hint):
        # this is called if some individual TCP connection cannot be
        # established
        if reason.check(error.ConnectingCancelledError,
                        error.ConnectionRefusedError):
            self.log("failed to connect to %s" % hint, level=OPERATIONAL,
                     umid="rSrUxQ")
        else:
            log.err(reason, "failed to connect to %s" % hint, level=CURIOUS,
                    parent=self._logparent, facility="foolscap.connection",
                    umid="2PEowg")
        if not self.failureReason:
            self.failureReason = reason
        self.checkForFailure()
        self.checkForIdle()

    def _connectionSuccess(self, p, hint):
        # fires with the Negotiation protocol instance, after
        # p.makeConnection(transport) returns, which is after
        # p.connectionMade() returns
        self.log("connected to %s, beginning negotiation" % hint,
                 level=OPERATIONAL, umid="VN0XGQ")
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
