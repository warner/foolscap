
from twisted.trial import unittest

from twisted.internet import protocol, defer
from twisted.application import internet
from foolscap import negotiate, tokens
from foolscap.api import Referenceable, Tub, BananaError
from foolscap.util import allocate_tcp_port
from foolscap.test.common import (BaseMixin,
                                  tubid_low, certData_low,
                                  certData_high)

class Target(Referenceable):
    def __init__(self):
        self.calls = 0
    def remote_call(self):
        self.calls += 1


class OneTimeDeferred(defer.Deferred):
    def callback(self, res):
        if self.called:
            return
        return defer.Deferred.callback(self, res)

class Basic(BaseMixin, unittest.TestCase):

    def testOptions(self):
        url, portnum = self.makeServer({'opt': 12})
        self.failUnlessEqual(self.tub._test_options['opt'], 12)

    def testAuthenticated(self):
        url, portnum = self.makeServer()
        client = Tub()
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        return d
    testAuthenticated.timeout = 10

class Versus(BaseMixin, unittest.TestCase):

    def testVersusHTTPServerAuthenticated(self):
        portnum = self.makeHTTPServer()
        client = Tub()
        client.startService()
        self.services.append(client)
        url = "pb://%s@127.0.0.1:%d/target" % (tubid_low, portnum)
        d = client.getReference(url)
        d.addCallbacks(lambda res: self.fail("this is supposed to fail"),
                       lambda f: f.trap(BananaError))
        # the HTTP server needs a moment to notice that the connection has
        # gone away. Without this, trial flunks the test because of the
        # leftover HTTP server socket.
        d.addCallback(self.stall, 1)
        return d
    testVersusHTTPServerAuthenticated.timeout = 10

    def testVersusHTTPClientAuthenticated(self):
        try:
            from twisted.web import error
        except ImportError:
            raise unittest.SkipTest('this test needs twisted.web')
        url, portnum = self.makeServer()
        d = self.connectHTTPClient(portnum)
        d.addCallbacks(lambda res: self.fail("this is supposed to fail"),
                       lambda f: f.trap(error.Error))
        return d
    testVersusHTTPClientAuthenticated.timeout = 10

    def testNoConnection(self):
        url, portnum = self.makeServer()
        d = self.tub.stopService()
        d.addCallback(self._testNoConnection_1, url)
        return d
    testNoConnection.timeout = 10
    def _testNoConnection_1(self, res, url):
        self.services.remove(self.tub)
        client = Tub()
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        d.addCallbacks(lambda res: self.fail("this is supposed to fail"),
                       self._testNoConnection_fail)
        return d
    def _testNoConnection_fail(self, why):
        from twisted.internet import error
        self.failUnless(why.check(error.ConnectionRefusedError))

    def testClientTimeout(self):
        portnum = self.makeNullServer()
        # lower the connection timeout to 2 seconds
        client = Tub(_test_options={'connect_timeout': 1})
        client.startService()
        self.services.append(client)
        url = "pb://faketubid@127.0.0.1:%d/target" % portnum
        d = client.getReference(url)
        d.addCallbacks(lambda res: self.fail("hey! this is supposed to fail"),
                       lambda f: f.trap(tokens.NegotiationError))
        return d
    testClientTimeout.timeout = 10

    def testServerTimeout(self):
        # lower the connection timeout to 1 seconds

        # the debug callback gets fired each time Negotiate.negotiationFailed
        # is fired, which happens twice (once for the timeout, once for the
        # resulting connectionLost), so we have to make sure the Deferred is
        # only fired once.
        d = OneTimeDeferred()
        options = {'server_timeout': 1,
                   'debug_negotiationFailed_cb': d.callback
                   }
        url, portnum = self.makeServer(listenerOptions=options)
        f = protocol.ClientFactory()
        f.protocol = protocol.Protocol # discards everything
        s = internet.TCPClient("127.0.0.1", portnum, f)
        s.startService()
        self.services.append(s)
        d.addCallbacks(lambda res: self.fail("hey! this is supposed to fail"),
                       lambda f: self._testServerTimeout_1)
        return d
    testServerTimeout.timeout = 10
    def _testServerTimeout_1(self, f):
        self.failUnless(f.check(tokens.NegotiationError))
        self.failUnlessEqual(f.value.args[0], "negotiation timeout")


class Parallel(BaseMixin, unittest.TestCase):
    # testParallel*: listen on two separate ports, set up a URL with both
    # ports in the locationHints field, the connect. PB is supposed to
    # connect to both ports at the same time, using whichever one completes
    # negotiation first. The other connection is supposed to be dropped
    # silently.

    # the cases we need to cover are enumerated by the possible states that
    # connection[1] can be in when connection[0] (the winning connection)
    # completes negotiation. Those states are:
    #  1: connectTCP initiated and failed
    #  2: connectTCP initiated, but not yet established
    #  3: connection established, but still in the PLAINTEXT phase
    #     (sent GET, waiting for the 101 Switching Protocols)
    #  4: still in ENCRYPTED phase: sent Hello, waiting for their Hello
    #  5: in DECIDING phase (non-master), waiting for their decision
    #

    def makeServers(self, tubopts={}, lo1={}, lo2={}):
        self.tub = tub = Tub(certData=certData_high, _test_options=tubopts)
        tub.startService()
        self.services.append(tub)
        self.p1, self.p2 = allocate_tcp_port(), allocate_tcp_port()
        tub.listenOn("tcp:%d:interface=127.0.0.1" % self.p1, lo1)
        tub.listenOn("tcp:%d:interface=127.0.0.1" % self.p2, lo2)
        tub.setLocation("127.0.0.1:%d" % self.p1, "127.0.0.1:%d" % self.p2)
        self.target = Target()
        return tub.registerReference(self.target)

    def connect(self, url):
        self.clientPhases = []
        opts = {"debug_stall_second_connection": True,
                "debug_gatherPhases": self.clientPhases}
        self.client = client = Tub(certData_low, _test_options=opts)
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        return d

    def checkConnectedToFirstListener(self, rr, targetPhases):
        # verify that we connected to the first listener, and not the second
        self.failUnlessEqual(rr.tracker.broker.transport.getPeer().port,
                             self.p1)
        # then pause a moment for the other connection to finish giving up
        d = self.stall(rr, 0.5)
        # and verify that we finished during the phase that we meant to test
        d.addCallback(lambda res:
                      self.failUnlessEqual(self.clientPhases, targetPhases,
                                           "negotiation was abandoned in "
                                           "the wrong phase"))
        return d

    def test1(self):
        # in this test, we stop listening on the second port, so the second
        # connection will terminate with an ECONNREFUSED before the first one
        # completes. We also slow down the first port so we're sure to
        # recognize the failed second connection before starting negotiation
        # on the first.
        url = self.makeServers(lo1={'debug_slow_connectionMade': True})
        d = self.tub.stopListeningOn(self.tub.getListeners()[1])
        d.addCallback(self._test1_1, url)
        return d
    def _test1_1(self, res, url):
        d = self.connect(url)
        d.addCallback(self.checkConnectedToFirstListener, [])
        #d.addCallback(self.stall, 1)
        return d
    test1.timeout = 10

    def test2(self):
        # slow down the second listener so that the first one is used. The
        # second listener will be connected but it will not respond to
        # negotiation for a moment, allowing the first connection to
        # complete.
        url = self.makeServers(lo2={'debug_slow_connectionMade': True})
        d = self.connect(url)
        d.addCallback(self.checkConnectedToFirstListener,
                      [negotiate.PLAINTEXT])
        #d.addCallback(self.stall, 1)
        return d
    test2.timeout = 10

    def test3(self):
        # have the second listener stall just before it does
        # sendPlaintextServer(). This insures the second connection will be
        # waiting in the PLAINTEXT phase when the first connection completes.
        url = self.makeServers(lo2={'debug_slow_sendPlaintextServer': True})
        d = self.connect(url)
        d.addCallback(self.checkConnectedToFirstListener,
                      [negotiate.PLAINTEXT])
        return d
    test3.timeout = 10

    def test4(self):
        # stall the second listener just before it sends the Hello.
        # This insures the second connection will be waiting in the ENCRYPTED
        # phase when the first connection completes.
        url = self.makeServers(lo2={'debug_slow_sendHello': True})
        d = self.connect(url)
        d.addCallback(self.checkConnectedToFirstListener,
                      [negotiate.ENCRYPTED])
        #d.addCallback(self.stall, 1)
        return d
    test4.timeout = 10

    def test5(self):
        # stall the second listener just before it sends the decision. This
        # insures the second connection will be waiting in the DECIDING phase
        # when the first connection completes.

        # note: this requires that the listener winds up as the master. We
        # force this by ensuring that the server uses a stable certificate
        # with a pre-calculated tubid sort order.
        url = self.makeServers(lo2={'debug_slow_sendDecision': True})
        d = self.connect(url)
        d.addCallback(self.checkConnectedToFirstListener,
                      [negotiate.DECIDING])
        return d
    test5.timeout = 10

class ThreeInParallel(BaseMixin, unittest.TestCase):
    # Reentrancy bugs can appear when multiple connections are abandoned at
    # the same time. Create three hints, of which one wins, to exercise two
    # being abandoned together.

    def makeServers(self, tubopts={}):
        self.tub = tub = Tub(certData=certData_high, _test_options=tubopts)
        tub.startService()
        self.services.append(tub)
        port = allocate_tcp_port()
        tub.listenOn("tcp:%d:interface=127.0.0.1" % port)
        tub.setLocation("127.0.0.1:%d" % port,
                        "127.0.0.2:%d" % port,
                        "127.0.0.3:%d" % port)
        self.target = Target()
        return tub.registerReference(self.target)

    def connect(self, url):
        self.client = client = Tub(certData_low)
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        return d

    def test1(self):
        url = self.makeServers()
        d = self.connect(url)
        # We stall to notice any errors that might happen when the losing
        # connections get cancelled. It doesn't matter so much for
        # TCP4ClientEndpoint, but HostnameEndpoint throws them (see
        # twisted#8014), so this will improve testing when we switch.
        d.addCallback(self.stall, 0.5)
        return d
    test1.timeout = 10

class SharedConnections(BaseMixin, unittest.TestCase):
    def makeServers(self):
        self.tub = tub = Tub(certData=certData_high)
        tub.startService()
        self.services.append(tub)
        port = allocate_tcp_port()
        tub.listenOn("tcp:%d:interface=127.0.0.1" % port)
        tub.setLocation("127.0.0.1:%d" % port)
        furl1 = tub.registerReference(Target())
        furl2 = tub.registerReference(Target())
        return furl1, furl2

    def test1(self):
        # Two FURLs pointing at the same Tub should share a connection. This
        # basically exercises TubRef.__cmp__ .
        furl1, furl2 = self.makeServers()
        client = Tub(certData_low)
        client.startService()
        self.services.append(client)
        d = client.getReference(furl1)
        rrefs = []
        d.addCallback(rrefs.append)
        d.addCallback(lambda _: client.getReference(furl2))
        d.addCallback(rrefs.append)
        def _check(_):
            self.failUnlessIdentical(rrefs[0].tracker.broker,
                                     rrefs[1].tracker.broker)
        d.addCallback(_check)
        return d

class CrossfireMixin(BaseMixin):
    # testSimultaneous*: similar to Parallel, but connection[0] is initiated
    # in the opposite direction. This is the case when two Tubs initiate
    # connections to each other at the same time.
    tub1IsMaster = False

    def makeServers(self, t1opts={}, t2opts={}, lo1={}, lo2={}):
        # first we create two Tubs
        a = Tub(_test_options=t1opts)
        b = Tub(_test_options=t1opts)

        # then we figure out which one will be the master, and call it tub1
        if a.tubID > b.tubID:
            # a is the master
            tub1,tub2 = a,b
        else:
            tub1,tub2 = b,a
        if not self.tub1IsMaster:
            tub1,tub2 = tub2,tub1
        self.tub1 = tub1
        self.tub2 = tub2

        # now fix up the options and everything else
        self.tub1phases = []
        t1opts['debug_gatherPhases'] = self.tub1phases
        tub1._test_options = t1opts
        self.tub2phases = []
        t2opts['debug_gatherPhases'] = self.tub2phases
        tub2._test_options = t2opts

        # connection[0], the winning connection, will be from tub1 to tub2

        tub1.startService()
        self.services.append(tub1)
        self.portnum1 = allocate_tcp_port()
        tub1.listenOn("tcp:%d:interface=127.0.0.1" % self.portnum1, lo1)
        tub1.setLocation("127.0.0.1:%d" % self.portnum1)
        self.target1 = Target()
        self.url1 = tub1.registerReference(self.target1)

        # connection[1], the abandoned connection, will be from tub2 to tub1
        tub2.startService()
        self.services.append(tub2)
        self.portnum2 = allocate_tcp_port()
        tub2.listenOn("tcp:%d:interface=127.0.0.1" % self.portnum2, lo2)
        tub2.setLocation("127.0.0.1:%d" % self.portnum2)
        self.target2 = Target()
        self.url2 = tub2.registerReference(self.target2)

    def connect(self):
        # initiate connection[1] from tub2 to tub1, which will stall (but the
        # actual getReference will eventually succeed once the
        # reverse-direction connection is established)
        d1 = self.tub2.getReference(self.url1)
        # give it a moment to get to the point where it stalls
        d = self.stall(None, 0.1)
        d.addCallback(self._connect, d1)
        return d, d1
    def _connect(self, res, d1):
        # now initiate connection[0], from tub1 to tub2
        d2 = self.tub1.getReference(self.url2)
        return d2

    def checkConnectedViaReverse(self, rref, targetPhases):
        # assert that connection[0] (from tub1 to tub2) is actually in use.
        # This connection uses a per-client allocated port number for the
        # tub1 side, and the tub2 Listener's port for the tub2 side.
        # Therefore tub1's Broker (as used by its RemoteReference) will have
        # a far-end port number that should match tub2's Listener.
        self.failUnlessEqual(rref.tracker.broker.transport.getPeer().port,
                             self.portnum2)
        # in addition, connection[1] should have been abandoned during a
        # specific phase.
        self.failUnlessEqual(self.tub2phases, targetPhases)


class CrossfireReverse(CrossfireMixin, unittest.TestCase):
    # just like the following Crossfire except that tub2 is the master, just
    # in case it makes a difference somewhere
    tub1IsMaster = False

    def test1(self):
        # in this test, tub2 isn't listening at all. So not only will
        # connection[1] fail, the tub2.getReference that uses it will fail
        # too (whereas in all other tests, connection[1] is abandoned but
        # tub2.getReference succeeds)
        self.makeServers(lo1={'debug_slow_connectionMade': True})
        d = self.tub2.stopListeningOn(self.tub2.getListeners()[0])
        d.addCallback(self._test1_1)
        return d

    def _test1_1(self, res):
        d,d1 = self.connect()
        d.addCallback(self.insert_turns, 4)
        d.addCallbacks(lambda res: self.fail("hey! this is supposed to fail"),
                       self._test1_2, errbackArgs=(d1,))
        return d
    def _test1_2(self, why, d1):
        from twisted.internet import error
        self.failUnless(why.check(error.ConnectionRefusedError))
        # but now the other getReference should succeed
        return d1
    test1.timeout = 10

    def test2(self):
        self.makeServers(lo1={'debug_slow_connectionMade': True})
        d,d1 = self.connect()
        d.addCallback(self.insert_turns, 4)
        d.addCallback(self.checkConnectedViaReverse, [negotiate.PLAINTEXT])
        d.addCallback(lambda res: d1) # other getReference should work too
        return d
    test2.timeout = 10

    def test3(self):
        self.makeServers(lo1={'debug_slow_sendPlaintextServer': True})
        d,d1 = self.connect()
        d.addCallback(self.insert_turns, 4)
        d.addCallback(self.checkConnectedViaReverse, [negotiate.PLAINTEXT])
        d.addCallback(lambda res: d1) # other getReference should work too
        return d
    test3.timeout = 10

    def test4(self):
        self.makeServers(lo1={'debug_slow_sendHello': True})
        d,d1 = self.connect()
        d.addCallback(self.insert_turns, 4)
        d.addCallback(self.checkConnectedViaReverse, [negotiate.ENCRYPTED])
        d.addCallback(lambda res: d1) # other getReference should work too
        return d
    test4.timeout = 10

class Crossfire(CrossfireReverse):
    tub1IsMaster = True

    def test5(self):
        # this is the only test where we rely upon the fact that
        # makeServers() always puts the higher-numbered Tub (which will be
        # the master) in self.tub1

        # connection[1] (the abandoned connection) is started from tub2 to
        # tub1. It connects, begins negotiation (tub1 is the master), but
        # then is stalled because we've added the debug_slow_sendDecision
        # flag to tub1's Listener. That allows connection[0] to begin from
        # tub1 to tub2, which is *not* stalled (because we added the slowdown
        # flag to the Listener's options, not tub1.options), so it completes
        # normally. When connection[1] is unpaused and hits switchToBanana,
        # it discovers that it already has a Broker in place, and the
        # connection is abandoned.

        self.makeServers(lo1={'debug_slow_sendDecision': True})
        d,d1 = self.connect()
        d.addCallback(self.insert_turns, 4)
        d.addCallback(self.checkConnectedViaReverse, [negotiate.DECIDING])
        d.addCallback(lambda res: d1) # other getReference should work too
        return d
    test5.timeout = 10

# TODO: some of these tests cause the TLS connection to be abandoned, and it
# looks like TLS sockets don't shut down very cleanly. I connectionLost
# getting called with the following error (instead of a normal ConnectionDone
# exception):
#  2005/10/10 19:56 PDT [Negotiation,0,127.0.0.1]
#  Negotiation.negotiationFailed: [Failure instance: Traceback:
#   exceptions.AttributeError: TLSConnection instance has no attribute 'socket'
#          twisted/internet/tcp.py:402:connectionLost
#          twisted/pb/negotiate.py:366:connectionLost
#          twisted/pb/negotiate.py:205:debug_forceTimer
#          twisted/pb/negotiate.py:223:debug_fireTimer
#          --- <exception caught here> ---
#          twisted/pb/negotiate.py:324:dataReceived
#          twisted/pb/negotiate.py:432:handlePLAINTEXTServer
#          twisted/pb/negotiate.py:457:sendPlaintextServerAndStartENCRYPTED
#          twisted/pb/negotiate.py:494:startENCRYPTED
#          twisted/pb/negotiate.py:768:startTLS
#          twisted/internet/tcp.py:693:startTLS
#          twisted/internet/tcp.py:314:startTLS
#          ]
#
# specifically, I saw this happen for CrossfireReverse.test2, Parallel.test2

# other tests don't do quite what I want: closing a connection (say, due to a
# duplicate broker) should send a sensible error message to the other side,
# rather than triggering a low-level protocol error.


class Existing(CrossfireMixin, unittest.TestCase):

    def checkNumBrokers(self, res, expected, dummy):
        if type(expected) not in (tuple,list):
            expected = [expected]
        self.failUnless(len(self.tub1.brokers) in expected)
        self.failUnless(len(self.tub2.brokers) in expected)

    def testAuthenticated(self):
        # When two Tubs connect, that connection should be used in the
        # reverse connection too
        self.makeServers()
        d = self.tub1.getReference(self.url2)
        d.addCallback(self._testAuthenticated_1)
        return d
    def _testAuthenticated_1(self, r12):
        # this should use the existing connection
        d = self.tub2.getReference(self.url1)
        d.addCallback(self.checkNumBrokers, 1, (r12,))
        return d

# this test will have to change when the regular Negotiation starts using
# different decision blocks. The version numbers must be updated each time
# the negotiation version is changed.
assert negotiate.Negotiation.maxVersion == 3
MAX_HANDLED_VERSION = negotiate.Negotiation.maxVersion
UNHANDLED_VERSION = 4
class NegotiationVbig(negotiate.Negotiation):
    maxVersion = UNHANDLED_VERSION
    def __init__(self, logparent):
        negotiate.Negotiation.__init__(self, logparent)
        self.negotiationOffer["extra"] = "new value"
    def evaluateNegotiationVersion4(self, offer):
        # just like v1, but different
        return self.evaluateNegotiationVersion1(offer)
    def acceptDecisionVersion4(self, decision):
        return self.acceptDecisionVersion1(decision)

class NegotiationVbigOnly(NegotiationVbig):
    minVersion = UNHANDLED_VERSION

class Future(BaseMixin, unittest.TestCase):
    def testFuture1(self):
        # when a peer that understands version=[1] that connects to a peer
        # that understands version=[1,2], they should pick version=1

        # the listening Tub will have the higher tubID, and thus make the
        # negotiation decision
        url, portnum = self.makeSpecificServer(certData_high)
        # the client
        client = Tub(certData=certData_low)
        client.negotiationClass = NegotiationVbig
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _check_version(rref):
            ver = rref.tracker.broker._banana_decision_version
            self.failUnlessEqual(ver, MAX_HANDLED_VERSION)
        d.addCallback(_check_version)
        return d
    testFuture1.timeout = 10

    def testFuture2(self):
        # same as before, but the connecting Tub will have the higher tubID,
        # and thus make the negotiation decision
        url, portnum = self.makeSpecificServer(certData_low)
        # the client
        client = Tub(certData=certData_high)
        client.negotiationClass = NegotiationVbig
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _check_version(rref):
            ver = rref.tracker.broker._banana_decision_version
            self.failUnlessEqual(ver, MAX_HANDLED_VERSION)
        d.addCallback(_check_version)
        return d
    testFuture2.timeout = 10

    def testFuture3(self):
        # same as testFuture1, but it is the listening server that
        # understands [1,2]
        url, portnum = self.makeSpecificServer(certData_high, NegotiationVbig)
        client = Tub(certData=certData_low)
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _check_version(rref):
            ver = rref.tracker.broker._banana_decision_version
            self.failUnlessEqual(ver, MAX_HANDLED_VERSION)
        d.addCallback(_check_version)
        return d
    testFuture3.timeout = 10

    def testFuture4(self):
        # same as testFuture2, but it is the listening server that
        # understands [1,2]
        url, portnum = self.makeSpecificServer(certData_low, NegotiationVbig)
        # the client
        client = Tub(certData=certData_high)
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _check_version(rref):
            ver = rref.tracker.broker._banana_decision_version
            self.failUnlessEqual(ver, MAX_HANDLED_VERSION)
        d.addCallback(_check_version)
        return d
    testFuture4.timeout = 10

    def testTooFarInFuture1(self):
        # when a peer that understands version=[1] that connects to a peer
        # that only understands version=[2], they should fail to negotiate

        # the listening Tub will have the higher tubID, and thus make the
        # negotiation decision
        url, portnum = self.makeSpecificServer(certData_high)
        # the client
        client = Tub(certData=certData_low)
        client.negotiationClass = NegotiationVbigOnly
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _oops_succeeded(rref):
            self.fail("hey! this is supposed to fail")
        def _check_failure(f):
            f.trap(tokens.NegotiationError, tokens.RemoteNegotiationError)
        d.addCallbacks(_oops_succeeded, _check_failure)
        return d
    testTooFarInFuture1.timeout = 10

    def testTooFarInFuture2(self):
        # same as before, but the connecting Tub will have the higher tubID,
        # and thus make the negotiation decision
        url, portnum = self.makeSpecificServer(certData_low)
        client = Tub(certData=certData_high)
        client.negotiationClass = NegotiationVbigOnly
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _oops_succeeded(rref):
            self.fail("hey! this is supposed to fail")
        def _check_failure(f):
            f.trap(tokens.NegotiationError, tokens.RemoteNegotiationError)
        d.addCallbacks(_oops_succeeded, _check_failure)
        return d
    testTooFarInFuture1.timeout = 10

    def testTooFarInFuture3(self):
        # same as testTooFarInFuture1, but it is the listening server which
        # only understands [2]
        url, portnum = self.makeSpecificServer(certData_high,
                                               NegotiationVbigOnly)
        client = Tub(certData=certData_low)
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _oops_succeeded(rref):
            self.fail("hey! this is supposed to fail")
        def _check_failure(f):
            f.trap(tokens.NegotiationError, tokens.RemoteNegotiationError)
        d.addCallbacks(_oops_succeeded, _check_failure)
        return d
    testTooFarInFuture3.timeout = 10

    def testTooFarInFuture4(self):
        # same as testTooFarInFuture2, but it is the listening server which
        # only understands [2]
        url, portnum = self.makeSpecificServer(certData_low,
                                               NegotiationVbigOnly)
        client = Tub(certData=certData_high)
        client.startService()
        self.services.append(client)
        d = client.getReference(url)
        def _oops_succeeded(rref):
            self.fail("hey! this is supposed to fail")
        def _check_failure(f):
            f.trap(tokens.NegotiationError, tokens.RemoteNegotiationError)
        d.addCallbacks(_oops_succeeded, _check_failure)
        return d
    testTooFarInFuture4.timeout = 10


class Replacement(BaseMixin, unittest.TestCase):
    # in certain circumstances, a new connection is supposed to replace an
    # existing one.

    def createDuplicateServer(self, oldtub):
        tub = Tub(certData=oldtub.getCertData())
        tub.startService()
        self.services.append(tub)
        tub.incarnation = oldtub.incarnation
        tub.incarnation_string = oldtub.incarnation_string
        tub.slave_table = oldtub.slave_table.copy()
        tub.master_table = oldtub.master_table.copy()
        portnum = allocate_tcp_port()
        tub.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        tub.setLocation("127.0.0.1:%d" % portnum)
        target = Target()
        return tub, target, tub.registerReference(target), portnum

    def setUp(self):
        BaseMixin.setUp(self)
        (self.tub1, self.target1, self.furl1, l1) = \
                    self.createSpecificServer(certData_low)
        (self.tub2, self.target2, self.furl2, l2) = \
                    self.createSpecificServer(certData_high)
        # self.tub1 is the slave, self.tub2 is the master
        assert self.tub2.tubID > self.tub1.tubID

    def clone_servers(self):
        (self.tub1a, self.target1a, self.furl1a, l1a) = \
                     self.createDuplicateServer(self.tub1)
        (self.tub2a, self.target2a, self.furl2a, l2a) = \
                     self.createDuplicateServer(self.tub2)

    def testBouncedClient(self):
        # self.tub1 is the slave, self.tub2 is the master

        d = self.tub1.getReference(self.furl2)
        d2 = defer.Deferred()
        def _connected(rref):
            self.clone_servers()
            # our tub1a is not the same incarnation as tub1
            self.tub1a.make_incarnation()

            # a new incarnation of the slave should replace the old connection
            rref.notifyOnDisconnect(d2.callback, None)
            return self.tub1a.getReference(self.furl2)
        d.addCallback(_connected)
        # the old rref should be broken (eventually)
        d.addCallback(lambda res: d2)
        return d

    def testAncientClient(self):
        disconnects = []
        d = self.tub1.getReference(self.furl2)
        def _connected(rref):
            self.clone_servers()
            # old clients (foolscap-0.1.7 or earlier) don't send a
            # my-incarnation header, so we're supposed to reject their
            # connection offer
            self.tub1a.incarnation_string = ""

            # this new connection attempt will be rejected
            rref.notifyOnDisconnect(disconnects.append, 1)
            return self.shouldFail(tokens.RemoteNegotiationError,
                                   "testAncientClient",
                                   "Duplicate connection",
                                   self.tub1a.getReference, self.furl2)
        d.addCallback(_connected)
        d.addCallback(self.insert_turns, 1)
        def _check(res):
            self.failIf(disconnects)
        d.addCallback(_check)
        return d

    def testAncientClientWorkaround(self):
        self.tub2.setOption("handle-old-duplicate-connections", True)
        # the second connection will be dropped, because it shows up too
        # quickly.
        disconnects = []
        d2 = defer.Deferred()
        d = self.tub1.getReference(self.furl2)
        def _connected(rref):
            self.clone_servers()
            # old clients (foolscap-0.1.7 or earlier) don't send a
            # my-incarnation header, so we're supposed to reject their
            # connection offer
            self.tub1a.incarnation_string = ""

            # this new connection attempt will be rejected
            rref.notifyOnDisconnect(disconnects.append, 1)
            rref.notifyOnDisconnect(d2.callback, None)
            return self.shouldFail(tokens.RemoteNegotiationError,
                                   "testAncientClientWorkaround",
                                   "Duplicate connection",
                                   self.tub1a.getReference, self.furl2)
        d.addCallback(_connected)
        d.addCallback(self.insert_turns, 1)
        def _check(res):
            self.failIf(disconnects)
        d.addCallback(_check)

        # now we tweak the connection-is-old threshold to allow the third
        # connection to succeed.
        def _reconnect(rref):
            self.tub2._handle_old_duplicate_connections = -10
            return self.tub1a.getReference(self.furl2)
        d.addCallback(_reconnect)
        # the old rref should be broken (eventually)
        d.addCallback(lambda res: d2)

        return d


    def testLostDecisionMessage_NewServer(self):
        # doctor the client's memory, make it think that it had a connection
        # to a different incarnation of the server

        # this test exercises the offer_master_IR != self.tub..IR case

        d = self.tub1.getReference(self.furl2)
        d2 = defer.Deferred()
        def _connected(rref):
            # if the slave thinks it was connected to an earlier master, we
            # accept the new connection
            self.clone_servers()
            oldrecord = self.tub1.slave_table[self.tub2.tubID]
            self.tub1a.slave_table[self.tub2.tubID] = ("figment", oldrecord[1])
            rref.notifyOnDisconnect(d2.callback, None)
            return self.tub1a.getReference(self.furl2)
        d.addCallback(_connected)
        # the old rref should be broken (eventually)
        d.addCallback(lambda res: d2)
        return d

    def testTwoLostDecisionMessages(self):
        # the client connects successfully with seqnum=1. Then the client
        # thinks the connection is lost, so it tries to reconnect, the server
        # accepts (seqnum=2), but the decision message gets lost. Then the
        # client tries to connect a third time: the client says it knows
        # about seqnum=1, which is older than the current one. We should
        # reject the third attempt.

        # we represent this case by connecting once, disconnecting,
        # reconnecting, then having the second tub connect with an
        # artificially-decremented seqnum.

        # this test exercises the offer_master_seqnum < existing_seqnum case

        disconnects = []
        d = self.tub1.getReference(self.furl2)
        def _connect1(rref):
            d2 = defer.Deferred()
            rref.notifyOnDisconnect(d2.callback, None)
            rref.tracker.broker.transport.loseConnection()
            return d2
        d.addCallback(_connect1)
        def _reconnect(res):
            return self.tub1.getReference(self.furl2)
        d.addCallback(_reconnect)
        def _connect2(rref):
            self.clone_servers()
            old_record = self.tub1a.slave_table[self.tub2.tubID]
            (old_IR, old_seqnum) = old_record
            new_record = (old_IR, str(int(old_seqnum)-1))
            self.tub1a.slave_table[self.tub2.tubID] = new_record

            # this new connection attempt will be rejected
            rref.notifyOnDisconnect(disconnects.append, 1)
            return self.shouldFail(tokens.RemoteNegotiationError,
                                   "testTwoLostDecisionMessages",
                                   "Duplicate connection",
                                   self.tub1a.getReference, self.furl2)
        d.addCallback(_connect2)
        d.addCallback(self.insert_turns, 1)
        def _check(res):
            self.failIf(disconnects)
        d.addCallback(_check)
        return d

    def testWeirdSeqnum(self):
        # if the client sends a seqnum that's too far into the future,
        # something weird is going on, and we should reject the offer.

        # this test exercises the offer_master_seqnum > existing_seqnum case

        disconnects = []
        d = self.tub1.getReference(self.furl2)
        def _connected(rref):
            self.clone_servers()
            old_record = self.tub1a.slave_table[self.tub2.tubID]
            (old_IR, old_seqnum) = old_record
            new_record = (old_IR, str(int(old_seqnum)+10))
            self.tub1a.slave_table[self.tub2.tubID] = new_record
            # this new connection attempt will be rejected
            rref.notifyOnDisconnect(disconnects.append, 1)
            return self.shouldFail(tokens.RemoteNegotiationError,
                                   "testSimultaneousClient",
                                   "Duplicate connection",
                                   self.tub1a.getReference, self.furl2)
        d.addCallback(_connected)
        d.addCallback(self.insert_turns, 1)
        def _check(res):
            self.failIf(disconnects)
        d.addCallback(_check)
        return d

    def testNATEntryDropped(self):
        # a client connects successfully, and receives the decision, but then
        # the connection goes away such that the client sees it but the
        # server does not. The new connection should be accepted.

        # this test exercises the offer_master_seqnum == existing_seqnum case

        d = self.tub1.getReference(self.furl2)
        d2 = defer.Deferred()
        def _connected(rref):
            self.clone_servers()
            # leave the slave_table entry intact
            rref.notifyOnDisconnect(d2.callback, None)
            return self.tub1a.getReference(self.furl2)
        d.addCallback(_connected)
        # the old rref should be broken (eventually)
        d.addCallback(lambda res: d2)
        return d

    def testConnectionHintRace(self):
        # doctor the client to make the second connection look like it came
        # from the same batch as the existing one. This should be rejected:
        # this is the multiple-connection-hints case.

        # This is also what happens when a decision message is droped.

        # since this is the first time the slave tried to connect, this test
        # exercises the offer_master_IR == "none" case

        disconnects = []
        d = self.tub1.getReference(self.furl2)
        def _connected(rref):
            self.clone_servers()
            del self.tub1a.slave_table[self.tub2.tubID]
            # this new connection attempt will be rejected
            rref.notifyOnDisconnect(disconnects.append, 1)
            return self.shouldFail(tokens.RemoteNegotiationError,
                                   "testSimultaneousClient",
                                   "Duplicate connection",
                                   self.tub1a.getReference, self.furl2)
        d.addCallback(_connected)
        d.addCallback(self.insert_turns, 1)
        def _check(res):
            self.failIf(disconnects)
        d.addCallback(_check)
        return d

    def testBouncedClient_Reverse(self):
        # self.tub1 is the master, self.tub2 is the slave

        d = self.tub2.getReference(self.furl1)
        d2 = defer.Deferred()
        def _connected(rref):
            self.clone_servers()
            # our tub2a is not the same incarnation as tub2
            self.tub2a.make_incarnation()

            # a new incarnation of the master should replace the old connection
            rref.notifyOnDisconnect(d2.callback, None)
            return self.tub2a.getReference(self.furl1)
        d.addCallback(_connected)
        # the old rref should be broken (eventually)
        d.addCallback(lambda res: d2)
        return d
