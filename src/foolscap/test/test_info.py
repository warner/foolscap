from zope.interface import implementer
from twisted.trial import unittest
from twisted.internet import defer, reactor
from twisted.application import service
from foolscap import info, reconnector, ipb, util
from foolscap.api import Tub
from foolscap.connections import tcp
from foolscap.test.common import (certData_low, certData_high, Target)

class Info(unittest.TestCase):
    def test_stages(self):
        ci = info.ConnectionInfo()

        self.assertEqual(ci.connected, False)
        self.assertEqual(ci.connectorStatuses, {})
        self.assertEqual(ci.connectionHandlers, {})
        self.assertEqual(ci.establishedAt, None)
        self.assertEqual(ci.winningHint, None)
        self.assertEqual(ci.listenerStatus, (None, None))
        self.assertEqual(ci.lostAt, None)

        ci._describe_connection_handler("hint1", "tcp")
        ci._set_connection_status("hint1", "working")
        self.assertEqual(ci.connectorStatuses, {"hint1": "working"})
        self.assertEqual(ci.connectionHandlers, {"hint1": "tcp"})

        ci._set_connection_status("hint1", "successful")
        ci._set_winning_hint("hint1")
        ci._set_established_at(10.0)
        ci._set_connected(True)

        self.assertEqual(ci.connected, True)
        self.assertEqual(ci.connectorStatuses, {"hint1": "successful"})
        self.assertEqual(ci.connectionHandlers, {"hint1": "tcp"})
        self.assertEqual(ci.establishedAt, 10.0)
        self.assertEqual(ci.winningHint, "hint1")
        self.assertEqual(ci.listenerStatus, (None, None))
        self.assertEqual(ci.lostAt, None)

        ci._set_connected(False)
        ci._set_lost_at(15.0)

        self.assertEqual(ci.connected, False)
        self.assertEqual(ci.lostAt, 15.0)

@implementer(ipb.IConnectionHintHandler)
class Handler:
    def __init__(self):
        self.asked = 0
        self.accepted = 0
        self._d = defer.Deferred()
        self._err = None

    def hint_to_endpoint(self, hint, reactor, update_status):
        self.asked += 1
        self._update_status = update_status
        self._d = defer.Deferred()
        if self._err:
            raise self._err
        self.accepted += 1
        update_status("resolving hint")
        return self._d

def discard_status(status):
    pass

class Connect(unittest.TestCase):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        return self.s.stopService()

    def makeTub(self, hint_type, listener_test_options={},
                extra_hint=None):
        tubA = Tub(certData=certData_low)
        tubA.setServiceParent(self.s)
        tubB = Tub(certData=certData_high)
        tubB.setServiceParent(self.s)
        self._tubA, self._tubB = tubA, tubB
        portnum = util.allocate_tcp_port()
        self._portnum = portnum
        port = "tcp:%d:interface=127.0.0.1" % portnum
        hint = "%s:127.0.0.1:%d" % (hint_type, portnum)
        if extra_hint:
            hint = hint + "," + extra_hint
        tubA.listenOn(port, _test_options=listener_test_options)
        tubA.setLocation(hint)
        self._target = Target()
        furl = tubA.registerReference(self._target)
        return furl, tubB, hint

    @defer.inlineCallbacks
    def testInfo(self):
        def tubA_sendHello_pause(d2):
            ci = tubB.getConnectionInfoForFURL(furl)
            self.assertEqual(ci.connectorStatuses, {hint: "negotiating"})
            d2.callback(None)
        test_options = {
            "debug_pause_sendHello": tubA_sendHello_pause,
            }
        furl, tubB, hint = self.makeTub("tcp", test_options)
        h = Handler()
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler("tcp", h)
        d = tubB.getReference(furl)
        ci = tubB.getConnectionInfoForFURL(furl)
        self.assertEqual(ci.connectorStatuses, {hint: "resolving hint"})
        h._d.callback(tcp.DefaultTCP().hint_to_endpoint(hint, reactor,
                                                        discard_status))
        ci = tubB.getConnectionInfoForFURL(furl)
        self.assertEqual(ci.connectorStatuses, {hint: "connecting"})
        # we use debug_pause_sendHello to catch "negotiating" here, then wait
        rref = yield d
        self.failUnlessEqual(h.asked, 1)
        self.failUnlessEqual(h.accepted, 1)
        ci = tubB.getConnectionInfoForFURL(furl)
        self.assertEqual(ci.connectorStatuses, {hint: "successful"})
        del rref

    def testNoHandler(self):
        furl, tubB, hint = self.makeTub("missing", extra_hint="slow:foo")
        missing_hint, extra = hint.split(",")
        tubB.removeAllConnectionHintHandlers()
        h = Handler()
        tubB.addConnectionHintHandler("slow", h)
        d = tubB.getReference(furl)
        del d # XXX
        ci = tubB.getConnectionInfoForFURL(furl)
        cs = ci.connectorStatuses
        self.assertEqual(cs["slow:foo"], "resolving hint")
        self.assertEqual(cs[missing_hint], "bad hint: no handler registered")
        h._update_status("phase2")
        ci = tubB.getConnectionInfoForFURL(furl)
        cs = ci.connectorStatuses
        self.assertEqual(cs["slow:foo"], "phase2")

    @defer.inlineCallbacks
    def testListener(self):
        furl, tubB, hint = self.makeTub("tcp")
        rref1 = yield tubB.getReference(furl)
        yield rref1.callRemote("free", Target())
        rref2 = self._target.calls[0][0][0]
        ci = rref2.getConnectionInfo()
        self.assertEqual(ci.connectorStatuses, {})
        (listener, status) = ci.listenerStatus
        self.assertEqual(status, "successful")
        self.assertEqual(listener,
                         "Listener on IPv4Address(TCP, '127.0.0.1', %d)"
                         % self._portnum)

    @defer.inlineCallbacks
    def testLoopback(self):
        furl, tubB, hint = self.makeTub("tcp")
        rref1 = yield self._tubA.getReference(furl)
        ci = rref1.getConnectionInfo()
        self.assertEqual(ci.connectorStatuses, {"loopback": "connected"})
        self.assertEqual(ci.listenerStatus, (None, None))


class Reconnection(unittest.TestCase):
    def test_stages(self):
        ri = reconnector.ReconnectionInfo()

        self.assertEqual(ri.state, "unstarted")
        self.assertEqual(ri.connectionInfo, None)
        self.assertEqual(ri.lastAttempt, None)
        self.assertEqual(ri.nextAttempt, None)

        ci = object()
        ri._set_state("connecting")
        ri._set_connection_info(ci)
        ri._set_last_attempt(10.0)

        self.assertEqual(ri.state, "connecting")
        self.assertEqual(ri.connectionInfo, ci)
        self.assertEqual(ri.lastAttempt, 10.0)
        self.assertEqual(ri.nextAttempt, None)

        ri._set_state("connected")

        self.assertEqual(ri.state, "connected")

        ri._set_state("waiting")
        ri._set_connection_info(None)
        ri._set_next_attempt(20.0)

        self.assertEqual(ri.state, "waiting")
        self.assertEqual(ri.connectionInfo, None)
        self.assertEqual(ri.lastAttempt, 10.0)
        self.assertEqual(ri.nextAttempt, 20.0)
