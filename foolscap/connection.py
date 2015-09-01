
from twisted.python.failure import Failure
from twisted.internet import protocol, reactor
from foolscap.tokens import (NoLocationHintsError, NegotiationError,
                             RemoteNegotiationError)
from foolscap.logging import log
from foolscap.logging.log import OPERATIONAL
from foolscap.util import isSubstring

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

    def startedConnecting(self, connector):
        self.connector = connector

    def startFactory(self):
        self.log("Starting factory %r" % self)
        return protocol.ClientFactory.startFactory(self)
    def stopFactory(self):
        self.log("Stopping factory %r" % self)
        return protocol.ClientFactory.stopFactory(self)

    def disconnect(self):
        self.log("told to disconnect")
        self.connector.disconnect()

    def buildProtocol(self, addr):
        nc = self.tc.tub.negotiationClass # this is usually Negotiation
        proto = nc(self._logparent)
        proto.initClient(self.tc, self.host)
        proto.factory = self
        return proto

    def clientConnectionFailed(self, connector, reason):
        self.tc.clientConnectionFailed(self, reason)


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

        # pendingConnections contains a (PBClientFactory -> Connector) map
        # for pairs where connectTCP has started, but negotiation has not yet
        # completed. We keep track of these so we can shut them down when we
        # stop connecting (either because one of the connections succeeded,
        # or because someone told us to give up).
        self.pendingConnections = {}

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
        the parent Tub's brokerAttached() method, our us calling the Tub's
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
        for c in self.pendingConnections.values():
            c.disconnect()
        # as each disconnect() finishes, it will either trigger our
        # clientConnectionFailed or our negotiationFailed methods, both of
        # which will trigger checkForIdle, and the last such message will
        # invoke self.tub.connectorFinished()

    def connectToAll(self):
        while self.remainingLocations:
            location = self.remainingLocations.pop()
            if location in self.attemptedLocations:
                continue
            self.attemptedLocations.append(location)
            host, port = location
            lp = self.log("connectTCP to %s" % (location,))
            f = TubConnectorClientFactory(self, host, lp)
            c = reactor.connectTCP(host, port, f)
            self.pendingConnections[f] = c
            # the tcp.Connector that we get back from reactor.connectTCP will
            # retain a reference to the transport that it creates, so we can
            # use it to disconnect the established (but not yet negotiated)
            # connection
            if self.tub.options.get("debug_stall_second_connection"):
                # for unit tests, hold off on making the second connection
                # for a moment. This allows the first connection to get to a
                # known state.
                reactor.callLater(0.1, self.connectToAll)
                return
        self.checkForFailure()

    def connectionTimedOut(self):
        self.timer = None
        why = "no connection established within client timeout"
        self.failureReason = Failure(NegotiationError(why))
        self.shutdown()
        self.failed()

    def clientConnectionFailed(self, factory, reason):
        # this is called if some individual TCP connection cannot be
        # established
        if not self.failureReason:
            self.failureReason = reason
        del self.pendingConnections[factory]
        self.checkForFailure()
        self.checkForIdle()

    def redirectReceived(self, newLocation):
        # the redirected connection will disconnect soon, which will trigger
        # negotiationFailed(), so we don't have to do a
        # del self.pendingConnections[factory]
        self.remainingLocations.append(newLocation)
        self.connectToAll()

    def negotiationFailed(self, factory, reason):
        # this is called if protocol negotiation cannot be established, or if
        # the connection is closed for any reason prior to switching to the
        # Banana protocol
        assert isinstance(reason, Failure), \
               "Hey, %s isn't a Failure" % (reason,)
        if (not self.failureReason or
            isinstance(reason, NegotiationError)):
            # don't let mundane things like ConnectionFailed override the
            # actually significant ones like NegotiationError
            self.failureReason = reason
        del self.pendingConnections[factory]
        self.checkForFailure()
        self.checkForIdle()

    def negotiationComplete(self, factory):
        # 'factory' has just completed negotiation, so abandon all the other
        # connection attempts
        self.log("negotiationComplete, %s won" % factory)
        self.active = False
        if self.timer:
            self.timer.cancel()
            self.timer = None
        del self.pendingConnections[factory] # this one succeeded
        for f in self.pendingConnections.keys(): # abandon the others
            # for connections that are not yet established, this will trigger
            # clientConnectionFailed. For connections that are established
            # (and exchanging negotiation messages), this does
            # loseConnection() and will thus trigger negotiationFailed.
            f.disconnect()
        self.checkForIdle()

    def checkForFailure(self):
        if not self.active:
            return
        if self.remainingLocations:
            return
        if self.pendingConnections:
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
        if self.remainingLocations:
            return
        if self.pendingConnections:
            return
        # we have no more outstanding connections (either in progress or in
        # negotiation), so this connector is finished.
        self.log("connectorFinished (%s)" % self)
        self.tub.connectorFinished(self)
