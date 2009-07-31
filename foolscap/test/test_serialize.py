# -*- test-case-name: foolscap.test.test_serialize -*-

from twisted.trial import unittest
from twisted.application import service
from cStringIO import StringIO
import gc

from foolscap.api import Referenceable, Copyable, RemoteCopy, \
     flushEventualQueue, serialize, unserialize
from foolscap.referenceable import RemoteReference
from foolscap.tokens import Violation
from foolscap.test.common import GoodEnoughTub, ShouldFailMixin

class Foo:
    # instances of non-Copyable classes are not serializable
    pass
class Bar(Copyable, RemoteCopy):
    # but if they're Copyable, they're ok
    typeToCopy = "bar"
    copytype = "bar"
    pass

class Serialize(unittest.TestCase, ShouldFailMixin):

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
        data = serialize(obj)
        obj2 = unserialize(data)
        self.failUnlessEqual(obj2[1], 3)
        self.failUnlessIdentical(obj2[3], obj2)

    def test_data(self):
        obj = ["simple graph", 3, True]
        d = serialize(obj)
        d.addCallback(lambda data: unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[1], 3)
        d.addCallback(_check)
        return d

    def test_cycle(self):
        obj = ["look at the pretty graph", 3, True]
        obj.append(obj) # and look at the pretty cycle
        d = serialize(obj)
        d.addCallback(lambda data: unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[1], 3)
            self.failUnlessIdentical(obj2[3], obj2)
        d.addCallback(_check)
        return d

    def test_copyable(self):
        obj = ["fire pretty", Bar()]
        d = serialize(obj)
        d.addCallback(lambda data: unserialize(data))
        def _check(obj2):
            self.failUnless(isinstance(obj2[1], Bar))
            self.failIfIdentical(obj[1], obj2[1])
        d.addCallback(_check)
        return d

    def test_data_outstream(self):
        obj = ["look at the pretty graph", 3, True]
        obj.append(obj) # and look at the pretty cycle
        b = StringIO()
        d = serialize(obj, outstream=b)
        def _out(res):
            self.failUnlessIdentical(res, b)
            return b.getvalue()
        d.addCallback(_out)
        d.addCallback(lambda data: unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[1], 3)
            self.failUnlessIdentical(obj2[3], obj2)
        d.addCallback(_check)
        return d

    def test_unhandled_objects(self):
        obj1 = [1, Referenceable()]
        d = self.shouldFail(Violation, "1",
                            "This object can only be serialized by a broker",
                            serialize, obj1)
        obj2 = [1, Foo()]
        d.addCallback(lambda ign:
                      self.shouldFail(Violation, "2",
                                      "cannot serialize <foolscap.test.test_serialize.Foo instance",
                                      serialize, obj2))
        return d


    def test_referenceable(self):
        t1 = GoodEnoughTub()
        t1.setServiceParent(self.s)
        l = t1.listenOn("tcp:0:interface=127.0.0.1")
        t1.setLocation("127.0.0.1:%d" % l.getPortnum())
        r1 = Referenceable()
        # the serialized blob can't keep the reference alive, so you must
        # arrange for that separately
        t1.registerReference(r1)
        t2 = GoodEnoughTub()
        t2.setServiceParent(self.s)
        obj = ("graph tangly", r1)
        d = t1.serialize(obj)
        del r1; del obj
        def _done(data):
            self.failUnless("their-reference" in data)
            return data
        d.addCallback(_done)
        d.addCallback(lambda data: t2.unserialize(data))
        def _check(obj2):
            self.failUnlessEqual(obj2[0], "graph tangly")
            self.failUnless(isinstance(obj2[1], RemoteReference))
        d.addCallback(_check)
        return d
    test_referenceable.timeout = 5

    def test_referenceables_die(self):
        # serialized data will not keep the referenceable alive
        t1 = GoodEnoughTub()
        t1.setServiceParent(self.s)
        l = t1.listenOn("tcp:0:interface=127.0.0.1")
        t1.setLocation("127.0.0.1:%d" % l.getPortnum())
        r1 = Referenceable()
        t2 = GoodEnoughTub()
        t2.setServiceParent(self.s)
        obj = ("graph tangly", r1)
        d = t1.serialize(obj)
        del r1; del obj
        gc.collect()
        d.addCallback(lambda data:
                      self.shouldFail(KeyError, "test_referenceables_die",
                                      "unable to find reference for name",
                                      t2.unserialize, data))
        return d
    test_referenceables_die.timeout = 5
