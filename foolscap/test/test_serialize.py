# -*- test-case-name: foolscap.test.test_serialize -*-

from twisted.trial import unittest
from twisted.application import service
from twisted.internet import defer
from twisted.python import failure
from cStringIO import StringIO

crypto_available = False
try:
    from foolscap import crypto
    crypto_available = crypto.available
except ImportError:
    pass

import foolscap
from foolscap import Tub, UnauthenticatedTub
from foolscap import Referenceable, Copyable, RemoteCopy
from foolscap.referenceable import RemoteReference
from foolscap.eventual import flushEventualQueue
from foolscap.tokens import Violation

# we use authenticated tubs if possible. If crypto is not available, fall
# back to unauthenticated ones
GoodEnoughTub = UnauthenticatedTub
if crypto_available:
    GoodEnoughTub = Tub

class Foo:
    # instances of non-Copyable classes are not serializable
    pass
class Bar(Copyable, RemoteCopy):
    # but if they're Copyable, they're ok
    typeToCopy = "bar"
    copytype = "bar"
    pass

class Serialize(unittest.TestCase):

    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        return d


    def NOT_test_data_synchronous(self):
        obj = ["look at the pretty graph", 3, True]
        obj.append(obj) # and look at the pretty cycle
        data = foolscap.serialize(obj)
        obj2 = foolscap.unserialize(data)
        self.failUnlessEqual(obj2[1], 3)
        self.failUnlessIdentical(obj2[3], obj2)

    def test_data(self):
        obj = ["simple graph", 3, True]
        d = foolscap.serialize(obj)
        d.addCallback(lambda data: foolscap.unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[1], 3)
        d.addCallback(_check)
        return d

    def test_cycle(self):
        obj = ["look at the pretty graph", 3, True]
        obj.append(obj) # and look at the pretty cycle
        d = foolscap.serialize(obj)
        d.addCallback(lambda data: foolscap.unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[1], 3)
            self.failUnlessIdentical(obj2[3], obj2)
        d.addCallback(_check)
        return d

    def test_copyable(self):
        obj = ["fire pretty", Bar()]
        d = foolscap.serialize(obj)
        d.addCallback(lambda data: foolscap.unserialize(data))
        def _check(obj2):
            self.failUnless(isinstance(obj2[1], Bar))
            self.failIfIdentical(obj[1], obj2[1])
        d.addCallback(_check)
        return d

    def test_data_outstream(self):
        obj = ["look at the pretty graph", 3, True]
        obj.append(obj) # and look at the pretty cycle
        b = StringIO()
        d = foolscap.serialize(obj, outstream=b)
        def _out(res):
            self.failUnlessIdentical(res, b)
            return b.getvalue()
        d.addCallback(_out)
        d.addCallback(lambda data: foolscap.unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[1], 3)
            self.failUnlessIdentical(obj2[3], obj2)
        d.addCallback(_check)
        return d

    def shouldFail(self, _ignored, expected_failure, substring,
                   call, *args, **kwargs):
        d = defer.maybeDeferred(call, *args, **kwargs)
        def _check(res):
            if isinstance(res, failure.Failure):
                if not res.check(expected_failure):
                    self.fail("Got wrong exception type: %s but we expected %s"
                              % (res, expected_failure))
                if substring:
                    self.failUnless(substring in str(res),
                                    "substring '%s' not in '%s'"
                                    % (substring, str(res)))
            else:
                self.fail("call was supposed to raise %s, not get '%s'" %
                          (expected_failure, res))
        d.addBoth(_check)
        return d

    def test_unhandled_objects(self):
        obj1 = [1, Referenceable()]
        d = defer.succeed(None)
        d.addCallback(self.shouldFail, Violation,
                      "This object can only be serialized by a broker",
                      foolscap.serialize, obj1)
        obj2 = [1, Foo()]
        d.addCallback(self.shouldFail, Violation,
                      "cannot serialize <foolscap.test.test_serialize.Foo "
                      "instance",
                      foolscap.serialize, obj2)
        return d
        

    def OFFtest_referenceable(self):
        t1 = GoodEnoughTub()
        t1.setServiceParent(self.s)
        l = t1.listenOn("tcp:0:interface=127.0.0.1")
        t1.setLocation("127.0.0.1:%d" % l.getPortnum())
        r1 = Referenceable()
        t2 = GoodEnoughTub()
        obj = ("graph tangly", r1)
        d = t1.serialize(obj)
        d.addCallback(lambda data: t2.unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[0], "graph tangly")
            self.failUnless(isinstance(obj2[1], RemoteReference))
        d.addCallback(_check)
        return d
