# -*- test-case-name: foolscap.test.test_reconnector -*-

from twisted.trial import unittest
from foolscap import UnauthenticatedTub
from foolscap.test.common import HelperTarget
from twisted.internet.main import CONNECTION_LOST
from twisted.internet import defer
from foolscap.eventual import eventually, flushEventualQueue

class Reconnector(unittest.TestCase):

    def setUp(self):
        self.services = [UnauthenticatedTub(), UnauthenticatedTub()]
        self.tubA, self.tubB = self.services
        for s in self.services:
            s.startService()
            l = s.listenOn("tcp:0:interface=127.0.0.1")
            s.setLocation("127.0.0.1:%d" % l.getPortnum())

    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d


    def test1(self):
        self.count = 0
        self.attached = False
        self.done = defer.Deferred()
        target = HelperTarget("bob")
        url = self.tubB.registerReference(target)
        rc = self.tubA.connectTo(url, self._got_ref, "arg", kw="kwarg")
        # at least make sure the stopConnecting method is present, even if we
        # don't have a real test for it yet
        self.failUnless(rc.stopConnecting)
        return self.done

    def _got_ref(self, rref, arg, kw):
        self.failUnlessEqual(self.attached, False)
        self.attached = True
        self.failUnlessEqual(arg, "arg")
        self.failUnlessEqual(kw, "kwarg")
        self.count += 1
        rref.notifyOnDisconnect(self._disconnected, self.count)
        if self.count < 2:
            # forcibly disconnect it
            eventually(rref.tracker.broker.transport.loseConnection,
                       CONNECTION_LOST)
        else:
            self.done.callback("done")

    def _disconnected(self, count):
        self.failUnlessEqual(self.attached, True)
        self.failUnlessEqual(count, self.count)
        self.attached = False

# TODO: construct the URL somehow, but don't start the new tub yet. Start the
# reconnector, let it fail once, then start the new tub. This will
# distinguish between connection failure and negotiation failure.

# another test: determine the target url early, but don't actually register
# the reference yet. Start the reconnector, let it fail once, then register
# the reference and make sure the retry succeeds. This will distinguish
# between connection/negotiation failures and object-lookup failures, both of
# which ought to be handled by Reconnector. I suspect the object-lookup
# failures are not yet.

# test stopConnecting
