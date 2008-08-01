# -*- test-case-name: foolscap.test.test_tub -*-

import os.path
from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service

from foolscap import Tub, SturdyRef, Referenceable
from foolscap.referenceable import RemoteReference
from foolscap.eventual import eventually, flushEventualQueue
from foolscap.test.common import HelperTarget, TargetMixin, ShouldFailMixin, \
     crypto_available, GoodEnoughTub
from foolscap.tokens import WrongTubIdError, PBError

class TestCertFile(unittest.TestCase):
    def test_generate(self):
        t = Tub()
        certdata = t.getCertData()
        self.failUnless("BEGIN CERTIFICATE" in certdata)
        self.failUnless("BEGIN RSA PRIVATE KEY" in certdata)

    def test_certdata(self):
        t1 = Tub()
        data1 = t1.getCertData()
        t2 = Tub(certData=data1)
        data2 = t2.getCertData()
        self.failUnless(data1 == data2)

    def test_certfile(self):
        fn = "test_tub.TestCertFile.certfile"
        t1 = Tub(certFile=fn)
        self.failUnless(os.path.exists(fn))
        data1 = t1.getCertData()

        t2 = Tub(certFile=fn)
        data2 = t2.getCertData()
        self.failUnless(data1 == data2)

if not crypto_available:
    del TestCertFile

class SetLocation(unittest.TestCase):

    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        return d

    def test_set_location(self):
        t = GoodEnoughTub()
        l = t.listenOn("tcp:0")
        t.setServiceParent(self.s)
        t.setLocation("127.0.0.1:12345")
        # setLocation may only be called once
        self.failUnlessRaises(PBError, t.setLocation, "127.0.0.1:12345")

    def test_set_location_automatically(self):
        t = GoodEnoughTub()
        l = t.listenOn("tcp:0")
        t.setServiceParent(self.s)
        d = t.setLocationAutomatically()
        d.addCallback(lambda res: t.registerReference(Referenceable()))
        def _check(furl):
            sr = SturdyRef(furl)
            portnum = l.getPortnum()
            if sr.encrypted:
                for lh in sr.locationHints:
                    self.failUnlessEqual(lh[2], portnum, lh)
                self.failUnless( ("ipv4", "127.0.0.1", portnum)
                                 in sr.locationHints)
            else:
                # TODO: unauthenticated tubs need review, I think they
                # deserve to have tubids and multiple connection hints
                pass
        d.addCallback(_check)
        return d



class FurlFile(unittest.TestCase):

    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        return d

    def test_furlfile(self):
        cfn = "test_tub.FurlFile.test_furlfile.certfile"
        t1 = Tub(certFile=cfn)
        t1.setServiceParent(self.s)
        l = t1.listenOn("tcp:0:interface=127.0.0.1")
        t1.setLocation("127.0.0.1:%d" % l.getPortnum())
        port1 = "tcp:%d:interface=127.0.0.1" % l.getPortnum()
        r1 = Referenceable()
        ffn = "test_tub.FurlFile.test_furlfile.furlfile"
        furl1 = t1.registerReference(r1, furlFile=ffn)
        d = defer.maybeDeferred(t1.disownServiceParent)

        self.failUnless(os.path.exists(ffn))
        self.failUnlessEqual(furl1, open(ffn,"r").read().strip())

        def _take2(res):
            t2 = Tub(certFile=cfn)
            t2.setServiceParent(self.s)
            l = t2.listenOn(port1)
            t2.setLocation("127.0.0.1:%d" % l.getPortnum())
            r2 = Referenceable()
            furl2 = t2.registerReference(r2, furlFile=ffn)
            self.failUnlessEqual(furl1, furl2)
            return t2.disownServiceParent()
        d.addCallback(_take2)
        return d

    def test_tubid_check(self):
        t1 = Tub() # gets a new key
        t1.setServiceParent(self.s)
        l = t1.listenOn("tcp:0:interface=127.0.0.1")
        t1.setLocation("127.0.0.1:%d" % l.getPortnum())
        port1 = "tcp:%d:interface=127.0.0.1" % l.getPortnum()
        r1 = Referenceable()
        ffn = "test_tub.FurlFile.test_tubid_check.furlfile"
        furl1 = t1.registerReference(r1, furlFile=ffn)
        d = defer.maybeDeferred(t1.disownServiceParent)

        self.failUnless(os.path.exists(ffn))
        self.failUnlessEqual(furl1, open(ffn,"r").read().strip())

        def _take2(res):
            t2 = Tub() # gets a different key
            t2.setServiceParent(self.s)
            l = t2.listenOn(port1)
            t2.setLocation("127.0.0.1:%d" % l.getPortnum())
            r2 = Referenceable()
            self.failUnlessRaises(WrongTubIdError,
                                  t2.registerReference, r2, furlFile=ffn)
            return t2.disownServiceParent()
        d.addCallback(_take2)
        return d

if not crypto_available:
    del FurlFile

class QueuedStartup(TargetMixin, unittest.TestCase):
    # calling getReference and connectTo before the Tub has started should
    # put off network activity until the Tub is started.

    def setUp(self):
        TargetMixin.setUp(self)
        self.tubB = GoodEnoughTub()
        self.services = [self.tubB]
        for s in self.services:
            s.startService()
            l = s.listenOn("tcp:0:interface=127.0.0.1")
            s.setLocation("127.0.0.1:%d" % l.getPortnum())

        self.barry = HelperTarget("barry")
        self.barry_url = self.tubB.registerReference(self.barry)

        self.bill = HelperTarget("bill")
        self.bill_url = self.tubB.registerReference(self.bill)

        self.bob = HelperTarget("bob")
        self.bob_url = self.tubB.registerReference(self.bob)

    def tearDown(self):
        d = TargetMixin.tearDown(self)
        def _more(res):
            return defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(_more)
        d.addCallback(flushEventualQueue)
        return d

    def test_queued_getref(self):
        t1 = GoodEnoughTub()
        d1 = t1.getReference(self.barry_url)
        d2 = t1.getReference(self.bill_url)
        def _check(res):
            ((barry_success, barry_rref),
             (bill_success, bill_rref)) = res
            self.failUnless(barry_success)
            self.failUnless(bill_success)
            self.failUnless(isinstance(barry_rref, RemoteReference))
            self.failUnless(isinstance(bill_rref, RemoteReference))
            self.failIf(barry_rref == bill_success)
        dl = defer.DeferredList([d1, d2])
        dl.addCallback(_check)
        self.services.append(t1)
        eventually(t1.startService)
        return dl

    def test_queued_reconnector(self):
        t1 = GoodEnoughTub()
        bill_connections = []
        barry_connections = []
        t1.connectTo(self.bill_url, bill_connections.append)
        t1.connectTo(self.barry_url, barry_connections.append)
        def _check():
            if len(bill_connections) >= 1 and len(barry_connections) >= 1:
                return True
            return False
        d = self.poll(_check)
        def _validate(res):
            self.failUnless(isinstance(bill_connections[0], RemoteReference))
            self.failUnless(isinstance(barry_connections[0], RemoteReference))
            self.failIf(bill_connections[0] == barry_connections[0])
        d.addCallback(_validate)
        self.services.append(t1)
        eventually(t1.startService)
        return d


class NameLookup(TargetMixin, unittest.TestCase):

    # test registerNameLookupHandler

    def setUp(self):
        TargetMixin.setUp(self)
        self.tubA, self.tubB = [GoodEnoughTub(), GoodEnoughTub()]
        self.services = [self.tubA, self.tubB]
        self.tubA.startService()
        self.tubB.startService()
        l = self.tubB.listenOn("tcp:0:interface=127.0.0.1")
        self.tubB.setLocation("127.0.0.1:%d" % l.getPortnum())
        self.url_on_b = self.tubB.registerReference(Referenceable())
        self.lookups = []
        self.lookups2 = []
        self.names = {}
        self.names2 = {}

    def tearDown(self):
        d = TargetMixin.tearDown(self)
        def _more(res):
            return defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(_more)
        d.addCallback(flushEventualQueue)
        return d

    def lookup(self, name):
        self.lookups.append(name)
        return self.names.get(name, None)

    def lookup2(self, name):
        self.lookups2.append(name)
        return self.names2.get(name, None)

    def testNameLookup(self):
        t1 = HelperTarget()
        t2 = HelperTarget()
        self.names["foo"] = t1
        self.names2["bar"] = t2
        self.names2["baz"] = t2
        self.tubB.registerNameLookupHandler(self.lookup)
        self.tubB.registerNameLookupHandler(self.lookup2)
        # hack up a new furl pointing at the same tub but with a name that
        # hasn't been registered.
        s = SturdyRef(self.url_on_b)
        s.name = "foo"

        d = self.tubA.getReference(s)

        def _check(res):
            self.failUnless(isinstance(res, RemoteReference))
            self.failUnlessEqual(self.lookups, ["foo"])
            # the first lookup should short-circuit the process
            self.failUnlessEqual(self.lookups2, [])
            self.lookups = []; self.lookups2 = []
            s.name = "bar"
            return self.tubA.getReference(s)
        d.addCallback(_check)

        def _check2(res):
            self.failUnless(isinstance(res, RemoteReference))
            # if the first lookup fails, the second handler should be asked
            self.failUnlessEqual(self.lookups, ["bar"])
            self.failUnlessEqual(self.lookups2, ["bar"])
            self.lookups = []; self.lookups2 = []
            # make sure that loopbacks use this too
            return self.tubB.getReference(s)
        d.addCallback(_check2)

        def _check3(res):
            self.failUnless(isinstance(res, RemoteReference))
            self.failUnlessEqual(self.lookups, ["bar"])
            self.failUnlessEqual(self.lookups2, ["bar"])
            self.lookups = []; self.lookups2 = []
            # and make sure we can de-register handlers
            self.tubB.unregisterNameLookupHandler(self.lookup)
            s.name = "baz"
            return self.tubA.getReference(s)
        d.addCallback(_check3)

        def _check4(res):
            self.failUnless(isinstance(res, RemoteReference))
            self.failUnlessEqual(self.lookups, [])
            self.failUnlessEqual(self.lookups2, ["baz"])
            self.lookups = []; self.lookups2 = []
        d.addCallback(_check4)

        return d

class Shutdown(unittest.TestCase, ShouldFailMixin):
    def test_doublestop(self):
        tub = GoodEnoughTub()
        tub.startService()
        d = tub.stopService()
        d.addCallback(lambda res:
                      self.shouldFail(RuntimeError,
                                      "test_doublestop_startService",
                                      "Sorry, but Tubs cannot be restarted",
                                      tub.startService))
        d.addCallback(lambda res:
                      self.shouldFail(RuntimeError,
                                      "test_doublestop_getReference",
                                      "Sorry, but this Tub has been shut down",
                                      tub.getReference, "furl"))
        d.addCallback(lambda res:
                      self.shouldFail(RuntimeError,
                                      "test_doublestop_connectTo",
                                      "Sorry, but this Tub has been shut down",
                                      tub.connectTo, "furl", None))
        return d

