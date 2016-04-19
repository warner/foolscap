
import re
from twisted.trial import unittest

from zope.interface import implements
from twisted.internet import defer
from foolscap import pb
from foolscap.api import RemoteInterface, Referenceable, Tub, flushEventualQueue
from foolscap.remoteinterface import RemoteMethodSchema
from foolscap.util import allocate_tcp_port

class RIMyCryptoTarget(RemoteInterface):
    # method constraints can be declared directly:
    add1 = RemoteMethodSchema(_response=int, a=int, b=int)

    # or through their function definitions:
    def add(a=int, b=int): return int
    #add = schema.callable(add) # the metaclass makes this unnecessary
    # but it could be used for adding options or something
    def join(a=str, b=str, c=int): return str
    def getName(): return str

class Target(Referenceable):
    implements(RIMyCryptoTarget)

    def __init__(self, name=None):
        self.calls = []
        self.name = name
    def getMethodSchema(self, methodname):
        return None
    def remote_add(self, a, b):
        self.calls.append((a,b))
        return a+b
    remote_add1 = remote_add
    def remote_getName(self):
        return self.name
    def remote_disputed(self, a):
        return 24
    def remote_fail(self):
        raise ValueError("you asked me to fail")

class UsefulMixin:
    num_services = 2
    def setUp(self):
        self.services = []
        for i in range(self.num_services):
            s = Tub()
            s.startService()
            self.services.append(s)

    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(self._tearDown_1)
        return d
    def _tearDown_1(self, res):
        return flushEventualQueue()

class TestPersist(UsefulMixin, unittest.TestCase):
    num_services = 2
    def testPersist(self):
        t1 = Target()
        s1,s2 = self.services
        port = allocate_tcp_port()
        s1.listenOn("tcp:%d:interface=127.0.0.1" % port)
        s1.setLocation("127.0.0.1:%d" % port)
        public_url = s1.registerReference(t1, "name")
        self.failUnless(public_url.startswith("pb:"))
        d = defer.maybeDeferred(s1.stopService)
        d.addCallback(self._testPersist_1, s1, s2, t1, public_url, port)
        return d
    testPersist.timeout = 5
    def _testPersist_1(self, res, s1, s2, t1, public_url, port):
        self.services.remove(s1)
        s3 = Tub(certData=s1.getCertData())
        s3.startService()
        self.services.append(s3)
        t2 = Target()
        newport = allocate_tcp_port()
        s3.listenOn("tcp:%d:interface=127.0.0.1" % newport)
        s3.setLocation("127.0.0.1:%d" % newport)
        s3.registerReference(t2, "name")
        # now patch the URL to replace the port number
        newurl = re.sub(":%d/" % port, ":%d/" % newport, public_url)
        d = s2.getReference(newurl)
        d.addCallback(lambda rr: rr.callRemote("add", a=1, b=2))
        d.addCallback(self.failUnlessEqual, 3)
        d.addCallback(self._testPersist_2, t1, t2)
        return d
    def _testPersist_2(self, res, t1, t2):
        self.failUnlessEqual(t1.calls, [])
        self.failUnlessEqual(t2.calls, [(1,2)])


class TestListeners(UsefulMixin, unittest.TestCase):
    num_services = 3

    def testListenOn(self):
        s1 = self.services[0]
        l = s1.listenOn("tcp:%d:interface=127.0.0.1" % allocate_tcp_port())
        self.failUnless(isinstance(l, pb.Listener))
        self.failUnlessEqual(len(s1.getListeners()), 1)
        s1.stopListeningOn(l)
        self.failUnlessEqual(len(s1.getListeners()), 0)

    def testGetPort1(self):
        s1,s2,s3 = self.services
        s1.listenOn("tcp:%d:interface=127.0.0.1" % allocate_tcp_port())
        listeners = s1.getListeners()
        self.failUnlessEqual(len(listeners), 1)

    def testGetPort2(self):
        s1,s2,s3 = self.services
        s1.listenOn("tcp:%d:interface=127.0.0.1" % allocate_tcp_port())
        listeners = s1.getListeners()
        self.failUnlessEqual(len(listeners), 1)
        # listen on a second port too
        s1.listenOn("tcp:%d:interface=127.0.0.1" % allocate_tcp_port())
        l2 = s1.getListeners()
        self.failUnlessEqual(len(l2), 2)
