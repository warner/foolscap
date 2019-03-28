# -*- test-case-name: foolscap.test.test_reconnector -*-

import time
from twisted.trial import unittest
from foolscap.api import Tub, eventually, flushEventualQueue
from foolscap.test.common import HelperTarget, MakeTubsMixin, PollMixin
from foolscap.util import allocate_tcp_port
from twisted.internet import defer, reactor, error
from foolscap import negotiate, referenceable

class AlwaysFailNegotiation(negotiate.Negotiation):
    def sendHello(self):
        hello = {"error": "I always fail",
                 'my-tub-id': self.myTubID,
                 }
        self.sendBlock(hello)
        self.receive_phase = negotiate.ABANDONED

class Reconnector(MakeTubsMixin, PollMixin, unittest.TestCase):
    def setUp(self):
        self.tubA, self.tubB = self.makeTubs(2)

    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d


    def test_try(self):
        self.count = 0
        self.attached = False
        self.done = defer.Deferred()
        target = HelperTarget("bob")
        self.url = self.tubB.registerReference(target)
        self._time1 = time.time()
        self.rc = self.tubA.connectTo(self.url, self._got_ref, "arg", kw="kwarg")
        ri = self.rc.getReconnectionInfo()
        self.assertEqual(ri.state, "connecting")
        # at least make sure the stopConnecting method is present, even if we
        # don't have a real test for it yet
        self.assertTrue(self.rc.stopConnecting)
        return self.done

    def _got_ref(self, rref, arg, kw):
        self.assertEqual(self.attached, False)
        self.attached = True
        self.assertEqual(arg, "arg")
        self.assertEqual(kw, "kwarg")
        ri = self.rc.getReconnectionInfo()
        self.assertEqual(ri.state, "connected")
        time2 = time.time()
        last = ri.lastAttempt
        self.assertTrue(self._time1 <= last <= time2, (self._time1, last, time2))
        ci = ri.connectionInfo
        self.assertEqual(ci.connected, True)
        hints = referenceable.SturdyRef(self.url).getTubRef().getLocations()
        expected_hint = hints[0]
        self.assertEqual(ci.winningHint, expected_hint)
        self.assertEqual(ci.listenerStatus, (None, None))
        self.assertEqual(ci.connectorStatuses, {expected_hint: "successful"})
        self.assertEqual(ci.connectionHandlers, {expected_hint: "tcp"})
        self.count += 1
        rref.notifyOnDisconnect(self._disconnected, self.count)
        if self.count < 2:
            # forcibly disconnect it
            eventually(rref.tracker.broker.transport.loseConnection)
        else:
            self.done.callback("done")

    def _disconnected(self, count):
        self.assertEqual(self.attached, True)
        self.assertEqual(count, self.count)
        self.attached = False
        ri = self.rc.getReconnectionInfo()
        self.assertEqual(ri.state, "waiting")
        # The next connection attempt will be about 1.0s after disconnect.
        # We'll assert that this is in the future, although on very slow
        # systems, this may not be true.
        now = time.time()
        next_attempt = ri.nextAttempt
        self.assertTrue(now <= next_attempt, (now, next_attempt))

    def _connected(self, ref, notifiers, accumulate):
        accumulate.append(ref)
        if notifiers:
            notifiers.pop(0).callback(ref)

    def stall(self, timeout, res=None):
        d = defer.Deferred()
        reactor.callLater(timeout, d.callback, res)
        return d

    @defer.inlineCallbacks
    def test_retry(self):
        tubC = Tub(certData=self.tubB.getCertData())
        connects = []
        target = HelperTarget("bob")
        url = self.tubB.registerReference(target, "target")
        portb = self.tub_ports[1]
        d1 = defer.Deferred()
        notifiers = [d1]
        self.services.remove(self.tubB)

        # This will fail, since tubB is not listening anymore. Wait until it's
        # moved to the "waiting" state.
        yield self.tubB.stopService()
        rc = self.tubA.connectTo(url, self._connected, notifiers, connects)
        yield self.poll(lambda: rc.getReconnectionInfo().state == "waiting")
        self.assertEqual(len(connects), 0)

        # now start tubC listening on the same port that tubB used to, which
        # should allow the connection to complete (since they both use the same
        # certData)

        self.services.append(tubC)
        tubC.startService()
        tubC.listenOn("tcp:%d:interface=127.0.0.1" % portb)
        tubC.setLocation("tcp:127.0.0.1:%d" % portb)
        url2 = tubC.registerReference(target, "target")
        assert url2 == url
        yield d1

        self.assertEqual(len(connects), 1)
        rc.stopConnecting()

    @defer.inlineCallbacks
    def test_negotiate_fails_and_retry(self):
        connects = []
        target = HelperTarget("bob")
        url = self.tubB.registerReference(target, "target")
        hint = referenceable.SturdyRef(url).getTubRef().getLocations()[0]
        l = self.tubB.getListeners()[0]
        l._negotiationClass = AlwaysFailNegotiation
        portb = self.tub_ports[1]

        d1 = defer.Deferred()
        notifiers = [d1]
        rc = self.tubA.connectTo(url, self._connected, notifiers, connects)
        yield self.poll(lambda: rc.getReconnectionInfo().state == "waiting")

        # the reconnector should have failed once or twice, since the
        # negotiation would always fail.
        self.assertEqual(len(connects), 0)
        ci = rc.getReconnectionInfo().connectionInfo
        cs = ci.connectorStatuses
        self.assertEqual(cs, {hint: "negotiation failed: I always fail"})

        # Now we fix tubB. We only touched the Listener, so re-doing the
        # listenOn should clear it.
        yield self.tubB.stopListeningOn(l)

        self.tubB.listenOn("tcp:%d:interface=127.0.0.1" % portb)

        # the next time the reconnector tries, it should succeed
        yield d1

        self.assertEqual(len(connects), 1)
        rc.stopConnecting()

    @defer.inlineCallbacks
    def test_lose_and_retry(self):
        tubC = Tub(self.tubB.getCertData())
        connects = []
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        notifiers = [d1, d2]
        target = HelperTarget("bob")
        url = self.tubB.registerReference(target, "target")
        portb = self.tub_ports[1]
        rc = self.tubA.connectTo(url, self._connected, notifiers, connects)
        yield d1
        self.assertEqual(rc.getReconnectionInfo().state, "connected")
        # we are now connected to tubB. Shut it down to force a disconnect.
        self.services.remove(self.tubB)
        yield self.tubB.stopService()

        # wait for at least one retry
        yield self.poll(lambda: rc.getReconnectionInfo().state == "waiting")

        # wait a few seconds more to give the Reconnector a chance to try and
        # fail a few times. It isn't easy to catch the "connecting" state since
        # the target is local and the kernel knows that it's not listening.
        # TODO: add an internal retry counter to the Reconnector that we can
        # poll for tests.
        yield self.stall(2)

        # now start tubC listening on the same port that tubB used to,
        # which should allow the connection to complete (since they both
        # use the same certData)
        self.services.append(tubC)
        tubC.startService()
        tubC.listenOn("tcp:%d:interface=127.0.0.1" % portb)
        tubC.setLocation("tcp:127.0.0.1:%d" % portb)
        url2 = tubC.registerReference(target, "target")
        assert url2 == url
        # this will fire when the second connection has been made
        yield d2

        self.assertEqual(len(connects), 2)
        rc.stopConnecting()

    @defer.inlineCallbacks
    def test_stop_trying(self):
        connects = []
        target = HelperTarget("bob")
        url = self.tubB.registerReference(target, "target")
        self.services.remove(self.tubB)
        # this will fail, since tubB is not listening anymore
        yield self.tubB.stopService()
        rc = self.tubA.connectTo(url, self._connected, [], connects)
        rc.verbose = True # get better code coverage

        # wait for at least one retry
        yield self.poll(lambda: rc.getReconnectionInfo().state == "waiting")

        # and a bit more, for good measure
        yield self.stall(2)

        self.assertEqual(len(connects), 0)
        f = rc.getLastFailure()
        self.assertTrue(f.check(error.ConnectionRefusedError))
        delay = rc.getDelayUntilNextAttempt()
        self.assertTrue(delay > 0, delay)
        self.assertTrue(delay < 60, delay)
        rc.reset()
        delay = rc.getDelayUntilNextAttempt()
        self.assertTrue(delay < 2)
        # this stopConnecting occurs while the reconnector's timer is
        # active
        rc.stopConnecting()
        self.assertEqual(rc.getDelayUntilNextAttempt(), None)
        # if it keeps trying, we'll see a dirty reactor


class Unstarted(MakeTubsMixin, unittest.TestCase):
    def setUp(self):
        self.tubA, self.tubB = self.makeTubs(2, start=False)
    def test_unstarted(self):
        target = HelperTarget("bob")
        url = self.tubB.registerReference(target)
        rc = self.tubA.connectTo(url, None)
        ri = rc.getReconnectionInfo()
        self.assertEqual(ri.state, "unstarted")

# TODO: look at connections that succeed because of a listener, and also
# loopback
class Failed(PollMixin, unittest.TestCase):
    def setUp(self):
        self.services = []
    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d

    @defer.inlineCallbacks
    def test_bad_hints(self):
        self.tubA = Tub()
        self.tubA.startService()
        self.services.append(self.tubA)
        self.tubB = Tub()
        self.tubB.startService()
        self.services.append(self.tubB)
        portnum = allocate_tcp_port()
        self.tubB.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        bad1 = "no-colon"
        bad2 = "unknown:foo"
        bad3 = "tcp:300.300.300.300:333"
        self.tubB.setLocation(bad1, bad2, bad3)

        target = HelperTarget("bob")
        url = self.tubB.registerReference(target)
        rc = self.tubA.connectTo(url, None)
        ri = rc.getReconnectionInfo()
        self.assertEqual(ri.state, "connecting")

        yield self.poll(lambda: rc.getReconnectionInfo().state != "connecting")

        # now look at the details
        ri = rc.getReconnectionInfo()
        self.assertEqual(ri.state, "waiting")
        ci = ri.connectionInfo
        self.assertEqual(ci.connected, False)
        self.assertEqual(ci.winningHint, None)
        s = ci.connectorStatuses
        self.assertEqual(set(s.keys()), set([bad1, bad2, bad3]))
        self.assertEqual(s[bad1], "bad hint: no colon")
        self.assertEqual(s[bad2], "bad hint: no handler registered")
        self.assertIn("DNS lookup failed", s[bad3])
        ch = ci.connectionHandlers
        self.assertEqual(ch, {bad2: None, bad3: "tcp"})

# another test: determine the target url early, but don't actually register
# the reference yet. Start the reconnector, let it fail once, then register
# the reference and make sure the retry succeeds. This will distinguish
# between connection/negotiation failures and object-lookup failures, both of
# which ought to be handled by Reconnector. I suspect the object-lookup
# failures are not yet.

# test that Tub shutdown really stops all Reconnectors
