
from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service

from foolscap.api import Tub, eventually, RelayServer, RelayListener, \
     flushEventualQueue, Referenceable
from foolscap.test.common import PollMixin, StallMixin, GoodEnoughTub

class Bob(Referenceable):
    def remote_hibob(self):
        return "hi alice"

class Basic(unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

    def test_foo(self):
        tubA, tubB, tubS = GoodEnoughTub(), GoodEnoughTub(), GoodEnoughTub()
        for t in [tubA, tubB, tubS]:
            t.setServiceParent(self.parent)
        S_listener = tubS.listenOn("tcp:0")
        S_hint = "localhost:%d" % lS.getPortnum()
        tubS.setLocation(S_hint)
        relay = RelayServer(tubS)
        relay_furl = tubS.registerReference(relay)
        self.failUnlessIn(S_hint, relay_furl)

        rl = RelayListener(tubB, relay_furl)
        d = rl.getConnectionHints()
        def _got_hints(hints):
            tubB.setLocation(hints)
            bob_obj = Bob()
            b_furl = tubB.registerReference(bob_obj)
            return tubA.getReference(b_furl)
        d.addCallback(_got_hints)
        d.addCallback(lambda bob_rref: bob_rref.callRemote("hibob"))
        def _check_results(res):
            self.failUnlessEqual(res, "hi alice")
        d.addCallback(_check_results)
        return d
