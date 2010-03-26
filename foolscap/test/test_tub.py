# -*- test-case-name: foolscap.test.test_tub -*-

import os.path
from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service
from twisted.python import log, failure

from foolscap.api import Tub, SturdyRef, Referenceable
from foolscap.referenceable import RemoteReference
from foolscap.eventual import eventually, fireEventually, flushEventualQueue
from foolscap.test.common import HelperTarget, TargetMixin, ShouldFailMixin, \
     crypto_available, GoodEnoughTub, StallMixin
from foolscap.tokens import WrongTubIdError, PBError, NoLocationHintsError

# create this data with:
#  t = Tub()
#  print t.getCertData()
CERT_TUBID = "kyc7sslzzyl4evmk7imxrdfcdzvq7qjk"
CERT_DATA = """\
-----BEGIN CERTIFICATE-----
MIIBnjCCAQcCAgCEMA0GCSqGSIb3DQEBBAUAMBcxFTATBgNVBAMUDG5ld3BiX3Ro
aW5neTAeFw0wOTA1MTkwMTEyMDNaFw0xMDA1MTkwMTEyMDNaMBcxFTATBgNVBAMU
DG5ld3BiX3RoaW5neTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0xVspHI+
YPkkBAposW5G3CBA8fa8kqBeBoqIiGfJq7uDrT4MYqe96DOs6ehd/1MTtbvK0mhd
4BDOurMS/+rBdMDAcfZlM4PMq+aqNRLBobFHrVH+H6h7v3V7grEOeZkSSvJbJdXT
xTKRu7AQrKXXAMHpOfMWfyZYDzYxKm4TY00CAwEAATANBgkqhkiG9w0BAQQFAAOB
gQA2HfwiApHoIc50eq/KO8tQqXC1PLTnb3Q8wy5OK5PZuBPlafloBRjRw8I14tfq
2puvr61rQt6AEjXGrhhndg5d8KIvY6LzZT4AHFQ0L4iL8zJ/GAHSBVY88Q1r2PyD
Dy8XFzPuxEo3WRzL2ncaFcPbYzsLFQBmwJaav725VFbTbg==
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDTFWykcj5g+SQECmixbkbcIEDx9rySoF4GioiIZ8mru4OtPgxi
p73oM6zp6F3/UxO1u8rSaF3gEM66sxL/6sF0wMBx9mUzg8yr5qo1EsGhsUetUf4f
qHu/dXuCsQ55mRJK8lsl1dPFMpG7sBCspdcAwek58xZ/JlgPNjEqbhNjTQIDAQAB
AoGAah63Q+V7nt0iUjW5dJpwXXKJtBvLqhudqcQz5//lz8Sx6oLrTx3tx7NTFzWP
LDHkEtWanjWCHIfWpt4oiyjGoLWwon32wfgahEiDBKpmY61by/xo4RSDAzm5Oogu
E4WGIPtpduc+GZf5C0m7zwhP0fC57MGfAX/xyctx6z7qzzECQQD2tJwvfkdSk+5f
qvg7iUnP5mLcjKGjHFL8s9sIQysyjpwXloBgIWztuJdp5vFt0ojV+8NKUFxtmBmf
yYpWPHe3AkEA2wlBCtzafGYNCSGiHfa/94M4Duf0dAua3hBQ9+Ld3ZD3KgBU5ZMC
qRbm5ul8CKFmuwKGE//TWnX6JYbur6VVGwJAesCZKiR6FoOWyzFFvFHuUSzAKh8r
Wf6A6E4RgQXy24AL+Myg6bQYAByl8kLABDYKcfaIUFS1+K4CqffdBlWl9wJAX3Ii
46blljuqBoafbEsvz51gei5deYvtCkM15S742ynmamkGlZuAF0qhh5HKuMAMUgWB
g4mBAfRS8rNfoy56bQJBAMShPEINsuumVaUnrEQg6g/misPPycO4MIEm5G1hHvli
uXVWwCwZgjHHsG5+jhGheZjvKXl+RS71Z6dQjwOYkng=
-----END RSA PRIVATE KEY-----
"""

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

    def test_tubid(self):
        t = Tub(certData=CERT_DATA)
        self.failUnlessEqual(t.getTubID(), CERT_TUBID)

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
        t.listenOn("tcp:0")
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

class Receiver(Referenceable):
    def __init__(self, tub):
        self.tub = tub
        self.done_d = defer.Deferred()
    def remote_one(self):
        d = self.tub.stopService()
        d.addBoth(lambda r: fireEventually(r))
        d.addBoth(self.done_d.callback)
    def remote_two(self):
        msg = "Receiver.remote_two: I shouldn't be called"
        print msg
        f = failure.Failure(ValueError(msg))
        log.err(f)

class CancelPendingDeliveries(unittest.TestCase, StallMixin):
    def tearDown(self):
        dl = [defer.succeed(None)]
        if self.tubA.running:
            dl.append(defer.maybeDeferred(self.tubA.stopService))
        if self.tubB.running:
            dl.append(defer.maybeDeferred(self.tubB.stopService))
        d = defer.DeferredList(dl)
        d.addCallback(flushEventualQueue)
        return d

    def test_cancel_pending_deliveries(self):
        # when a Tub is stopped, any deliveries that were pending should be
        # discarded. TubA sends remote_one+remote_two (and we hope they
        # arrive in the same chunk). TubB responds to remote_one by shutting
        # down. remote_two should be discarded. The bug was that remote_two
        # would cause an unhandled error on the TubB side.
        self.tubA = GoodEnoughTub()
        self.tubB = GoodEnoughTub()
        self.tubA.startService()
        self.tubB.startService()

        self.tubB.listenOn("tcp:0")
        d = self.tubB.setLocationAutomatically()
        r = Receiver(self.tubB)
        d.addCallback(lambda res: self.tubB.registerReference(r))
        d.addCallback(lambda furl: self.tubA.getReference(furl))
        def _go(rref):
            # we want these two to get sent and received in the same hunk
            rref.callRemoteOnly("one")
            rref.callRemoteOnly("two")
            return r.done_d
        d.addCallback(_go)
        # let remote_two do its log.err before we move on to the next test
        d.addCallback(self.stall, 1.0)
        return d

class BadLocationFURL(unittest.TestCase):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        return d

    def test_empty_location(self):
        # bug #129: a FURL with no location hints causes a synchronous
        # exception in Tub.getReference(), instead of an errback'ed Deferred.

        tubA = GoodEnoughTub()
        tubA.setServiceParent(self.s)
        tubB = GoodEnoughTub()
        tubB.setServiceParent(self.s)

        tubB.setLocation("")
        r = Receiver(tubB)
        furl = tubB.registerReference(r)
        # the buggy behavior is that the following call raises an exception
        d = tubA.getReference(furl)
        # whereas it ought to return a Deferred
        self.failUnless(isinstance(d, defer.Deferred))
        def _check(f):
            self.failUnless(isinstance(f, failure.Failure), f)
            self.failUnless(f.check(ValueError), f) # unparseable FURL
        d.addBoth(_check)
        return d

    def test_empty_location2(self):
        tubA = GoodEnoughTub()
        tubA.setServiceParent(self.s)
        tubB = GoodEnoughTub()
        tubB.setServiceParent(self.s)

        # "," is two empty locations. This passes the regexp, unlike "".
        tubB.setLocation(",")
        r = Receiver(tubB)
        furl = tubB.registerReference(r)
        # the buggy behavior is that the following call raises an exception
        d = tubA.getReference(furl)
        # whereas it ought to return a Deferred
        self.failUnless(isinstance(d, defer.Deferred))
        def _check(f):
            self.failUnless(isinstance(f, failure.Failure), f)
            self.failUnless(f.check(NoLocationHintsError), f) # unparseable FURL
        d.addBoth(_check)
        return d

    def test_unrouteable(self):
        # bug #129: a FURL with no location hints causes a synchronous
        # exception in Tub.getReference(), instead of an errback'ed Deferred.

        tubA = GoodEnoughTub()
        tubA.setServiceParent(self.s)
        tubB = GoodEnoughTub()
        tubB.setServiceParent(self.s)

        # "-unrouteable-" is interpreted as a "location hint format from the
        # future", which we're supposed to ignore, and are thus left with no
        # hints
        tubB.setLocation("-unrouteable-")
        r = Receiver(tubB)
        furl = tubB.registerReference(r)
        # the buggy behavior is that the following call raises an exception
        d = tubA.getReference(furl)
        # whereas it ought to return a Deferred
        self.failUnless(isinstance(d, defer.Deferred))
        def _check(f):
            self.failUnless(isinstance(f, failure.Failure), f)
            self.failUnless(f.check(NoLocationHintsError), f) # unparseable FURL
        d.addBoth(_check)
        return d
    
