
from zope.interface import implements
from twisted.trial import unittest
from foolscap.ipb import IRemoteReference
from foolscap.test.common import HelperTarget, Target, ShouldFailMixin
from foolscap.eventual import flushEventualQueue
from foolscap import broker, referenceable, api

class Remote:
    implements(IRemoteReference)
    pass


class LocalReference(unittest.TestCase, ShouldFailMixin):
    def tearDown(self):
        return flushEventualQueue()

    def ignored(self):
        pass

    def test_remoteReference(self):
        r = Remote()
        rref = IRemoteReference(r)
        self.failUnlessIdentical(r, rref)

    def test_callRemote(self):
        t = HelperTarget()
        t.obj = None
        rref = IRemoteReference(t)
        marker = rref.notifyOnDisconnect(self.ignored, "args", kwargs="foo")
        rref.dontNotifyOnDisconnect(marker)
        d = rref.callRemote("set", 12)
        # the callRemote should be put behind an eventual-send
        self.failUnlessEqual(t.obj, None)
        def _check(res):
            self.failUnlessEqual(t.obj, 12)
            self.failUnlessEqual(res, True)
        d.addCallback(_check)
        return d

    def test_callRemoteOnly(self):
        t = HelperTarget()
        t.obj = None
        rref = IRemoteReference(t)
        rc = rref.callRemoteOnly("set", 12)
        self.failUnlessEqual(rc, None)

    def test_fail(self):
        t = Target()
        rref = IRemoteReference(t)
        return self.shouldFail(ValueError, "test_fail",
                               "you asked me to fail",
                               rref.callRemote, "fail")

class TubID(unittest.TestCase):
    def test_tubid_must_match(self):
        good_tubid = "fu2bixsrymp34hwrnukv7hzxc2vrhqqa"
        bad_tubid = "v5mwmba42j4hu5jxuvgciasvo4aqldkq"
        good_furl = "pb://" + good_tubid + "@127.0.0.1:1234/swissnum"
        bad_furl = "pb://" + bad_tubid + "@127.0.0.1:1234/swissnum"
        ri = "remote_interface_name"
        good_broker = broker.Broker(referenceable.TubRef(good_tubid))
        good_tracker = referenceable.RemoteReferenceTracker(good_broker,
                                                            0, good_furl, ri)
        del good_tracker
        self.failUnlessRaises(api.BananaError,
                              referenceable.RemoteReferenceTracker,
                              good_broker, 0, bad_furl, ri)

