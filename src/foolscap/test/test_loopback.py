
from twisted.trial import unittest
from twisted.internet import defer
from foolscap.test.common import HelperTarget, MakeTubsMixin
from foolscap.eventual import flushEventualQueue


class ConnectToSelf(MakeTubsMixin, unittest.TestCase):
    def setUp(self):
        self.makeTubs(1)

    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d

    def testConnectAuthenticated(self):
        tub = self.services[0]
        target = HelperTarget("bob")
        target.obj = "unset"
        url = tub.registerReference(target)
        # can we connect to a reference on our own Tub?
        d = tub.getReference(url)
        def _connected(ref):
            return ref.callRemote("set", 12)
        d.addCallback(_connected)
        def _check(res):
            self.failUnlessEqual(target.obj, 12)
        d.addCallback(_check)
        def _connect_again(res):
            target.obj = None
            return tub.getReference(url)
        d.addCallback(_connect_again)
        d.addCallback(_connected)
        d.addCallback(_check)
        return d
