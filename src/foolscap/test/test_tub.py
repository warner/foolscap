# -*- test-case-name: foolscap.test.test_tub -*-

from __future__ import print_function
import os.path
import os
from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service
from twisted.python import log, failure
from twisted.test.proto_helpers import StringTransport

from foolscap.api import Tub, SturdyRef, Referenceable
from foolscap.furl import encode_furl
from foolscap.referenceable import RemoteReference
from foolscap.eventual import eventually, fireEventually, flushEventualQueue
from foolscap.util import allocate_tcp_port
from foolscap.test.common import HelperTarget, TargetMixin, ShouldFailMixin, \
     StallMixin, MakeTubsMixin
from foolscap.tokens import WrongTubIdError, PBError, NoLocationHintsError, \
    NoLocationError

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
        self.assertTrue(b"BEGIN CERTIFICATE" in certdata)
        self.assertTrue(b"PRIVATE KEY" in certdata)

    def test_certdata(self):
        t1 = Tub()
        data1 = t1.getCertData()
        t2 = Tub(certData=data1)
        data2 = t2.getCertData()
        self.assertTrue(data1 == data2)

    def test_certfile(self):
        fn = "test_tub.TestCertFile.certfile"
        t1 = Tub(certFile=fn)
        self.assertTrue(os.path.exists(fn))
        data1 = t1.getCertData()

        t2 = Tub(certFile=fn)
        data2 = t2.getCertData()
        self.assertTrue(data1 == data2)

        if os.path.exists(fn):
            os.remove(fn)

    def test_tubid(self):
        t = Tub(certData=CERT_DATA)
        self.assertEqual(t.getTubID(), CERT_TUBID)

class SetLocation(unittest.TestCase):

    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        return d

    def test_set_location(self):
        t = Tub()
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setServiceParent(self.s)
        t.setLocation("127.0.0.1:12345")
        # setLocation may only be called once
        self.assertRaises(PBError, t.setLocation, "127.0.0.1:12345")

    def test_unreachable(self):
        t = Tub()
        t.setServiceParent(self.s)
        # we call neither .listenOn nor .setLocation
        self.assertEqual(t.locationHints, [])
        self.assertRaises(NoLocationError,
                              t.registerReference, Referenceable())



class FurlFile(unittest.TestCase):

    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()
        self.cfn = "test_tub.FurlFile.test_furlfile.certfile"
        self.ffn_furl = "test_tub.FurlFile.test_furlfile.furlfile"
        self.ffn_tubid = "test_tub.FurlFile.test_tubid_check.furlfile"

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        if os.path.exists(self.cfn):
            os.remove(self.cfn)
        if os.path.exists(self.ffn_furl):
            os.remove(self.ffn_furl)
        if os.path.exists(self.ffn_tubid):
            os.remove(self.ffn_tubid)
        return d

    def test_furlfile(self):
        t1 = Tub(certFile=self.cfn)
        t1.setServiceParent(self.s)
        portnum = allocate_tcp_port()
        port1 = "tcp:%d:interface=127.0.0.1" % portnum
        t1.listenOn(port1)
        t1.setLocation("127.0.0.1:%d" % portnum)
        r1 = Referenceable()
        furl1 = t1.registerReference(r1, furlFile=self.ffn_furl)
        d = defer.maybeDeferred(t1.disownServiceParent)

        self.assertTrue(os.path.exists(self.ffn_furl))
        self.assertEqual(furl1, open(self.ffn_furl,"r").read().strip())

        def _take2(res):
            t2 = Tub(certFile=self.cfn)
            t2.setServiceParent(self.s)
            t2.listenOn(port1)
            t2.setLocation("127.0.0.1:%d" % portnum)
            r2 = Referenceable()
            furl2 = t2.registerReference(r2, furlFile=self.ffn_furl)
            self.assertEqual(furl1, furl2)
            return t2.disownServiceParent()
        d.addCallback(_take2)
        return d

    def test_tubid_check(self):
        t1 = Tub() # gets a new key
        t1.setServiceParent(self.s)
        portnum = allocate_tcp_port()
        port1 = "tcp:%d:interface=127.0.0.1" % portnum
        t1.listenOn(port1)
        t1.setLocation("127.0.0.1:%d" % portnum)
        r1 = Referenceable()
        furl1 = t1.registerReference(r1, furlFile=self.ffn_tubid)
        d = defer.maybeDeferred(t1.disownServiceParent)

        self.assertTrue(os.path.exists(self.ffn_tubid))
        self.assertEqual(furl1, open(self.ffn_tubid,"r").read().strip())

        def _take2(res):
            t2 = Tub() # gets a different key
            t2.setServiceParent(self.s)
            t2.listenOn(port1)
            t2.setLocation("127.0.0.1:%d" % portnum)
            r2 = Referenceable()
            self.assertRaises(WrongTubIdError,
                                  t2.registerReference, r2, furlFile=self.ffn_tubid)
            return t2.disownServiceParent()
        d.addCallback(_take2)
        return d

class QueuedStartup(TargetMixin, MakeTubsMixin, unittest.TestCase):
    # calling getReference and connectTo before the Tub has started should
    # put off network activity until the Tub is started.

    def setUp(self):
        TargetMixin.setUp(self)
        (self.tubB,) = self.makeTubs(1)

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
        t1 = Tub()
        d1 = t1.getReference(self.barry_url)
        d2 = t1.getReference(self.bill_url)
        def _check(res):
            ((barry_success, barry_rref),
             (bill_success, bill_rref)) = res
            self.assertTrue(barry_success)
            self.assertTrue(bill_success)
            self.assertTrue(isinstance(barry_rref, RemoteReference))
            self.assertTrue(isinstance(bill_rref, RemoteReference))
            self.assertFalse(barry_rref == bill_success)
        dl = defer.DeferredList([d1, d2])
        dl.addCallback(_check)
        self.services.append(t1)
        eventually(t1.startService)
        return dl

    def test_queued_reconnector(self):
        t1 = Tub()
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
            self.assertTrue(isinstance(bill_connections[0], RemoteReference))
            self.assertTrue(isinstance(barry_connections[0], RemoteReference))
            self.assertFalse(bill_connections[0] == barry_connections[0])
        d.addCallback(_validate)
        self.services.append(t1)
        eventually(t1.startService)
        return d


class NameLookup(TargetMixin, MakeTubsMixin, unittest.TestCase):

    # test registerNameLookupHandler

    def setUp(self):
        TargetMixin.setUp(self)
        self.tubA, self.tubB = self.makeTubs(2)
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
            self.assertTrue(isinstance(res, RemoteReference))
            self.assertEqual(self.lookups, ["foo"])
            # the first lookup should short-circuit the process
            self.assertEqual(self.lookups2, [])
            self.lookups = []; self.lookups2 = []
            s.name = "bar"
            return self.tubA.getReference(s)
        d.addCallback(_check)

        def _check2(res):
            self.assertTrue(isinstance(res, RemoteReference))
            # if the first lookup fails, the second handler should be asked
            self.assertEqual(self.lookups, ["bar"])
            self.assertEqual(self.lookups2, ["bar"])
            self.lookups = []; self.lookups2 = []
            # make sure that loopbacks use this too
            return self.tubB.getReference(s)
        d.addCallback(_check2)

        def _check3(res):
            self.assertTrue(isinstance(res, RemoteReference))
            self.assertEqual(self.lookups, ["bar"])
            self.assertEqual(self.lookups2, ["bar"])
            self.lookups = []; self.lookups2 = []
            # and make sure we can de-register handlers
            self.tubB.unregisterNameLookupHandler(self.lookup)
            s.name = "baz"
            return self.tubA.getReference(s)
        d.addCallback(_check3)

        def _check4(res):
            self.assertTrue(isinstance(res, RemoteReference))
            self.assertEqual(self.lookups, [])
            self.assertEqual(self.lookups2, ["baz"])
            self.lookups = []; self.lookups2 = []
        d.addCallback(_check4)

        return d

class Shutdown(unittest.TestCase, ShouldFailMixin):
    def test_doublestop(self):
        tub = Tub()
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


    def test_wait_for_brokers(self):
        """
        The L{Deferred} returned by L{Tub.stopService} fires only after the
        L{Broker} connections belonging to the L{Tub} have disconnected.
        """
        tub = Tub()
        tub.startService()

        another_tub = Tub()
        another_tub.startService()

        brokers = list(tub.brokerClass(None) for i in range(3))
        for n, b in enumerate(brokers):
            b.makeConnection(StringTransport())
            ref = SturdyRef(encode_furl(another_tub.tubID, [], str(n)))
            tub.brokerAttached(ref, b, isClient=(n % 2)==1)

        stopping = tub.stopService()
        d = flushEventualQueue()

        def event(ignored):
            self.assertNoResult(stopping)
            for b in brokers:
                b.connectionLost(failure.Failure(Exception("Connection lost")))
            return flushEventualQueue()
        d.addCallback(event)

        def connectionsLost(ignored):
            self.successResultOf(stopping)
        d.addCallback(connectionsLost)

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
        print(msg)
        f = failure.Failure(ValueError(msg))
        log.err(f)

class CancelPendingDeliveries(StallMixin, MakeTubsMixin, unittest.TestCase):
    def setUp(self):
        self.tubA, self.tubB = self.makeTubs(2)

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

        r = Receiver(self.tubB)
        furl = self.tubB.registerReference(r)
        d = self.tubA.getReference(furl)
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

        tubA = Tub()
        tubA.setServiceParent(self.s)
        tubB = Tub()
        tubB.setServiceParent(self.s)

        # This is a hack to get a FURL with empty location hints. The correct
        # way to make a Tub unreachable is to not call .setLocation() at all.
        tubB.setLocation("")
        r = Receiver(tubB)
        furl = tubB.registerReference(r)
        # the buggy behavior is that the following call raises an exception
        d = tubA.getReference(furl)
        # whereas it ought to return a Deferred
        self.assertTrue(isinstance(d, defer.Deferred))
        def _check(f):
            self.assertTrue(isinstance(f, failure.Failure), f)
            self.assertTrue(f.check(NoLocationHintsError), f)
        d.addBoth(_check)
        return d

    def test_future(self):
        tubA = Tub()
        tubA.setServiceParent(self.s)
        tubB = Tub()
        tubB.setServiceParent(self.s)

        # "future:stuff" is interpreted as a "location hint format from the
        # future", which we're supposed to ignore, and are thus left with no
        # hints
        tubB.setLocation("future:stuff")
        r = Receiver(tubB)
        furl = tubB.registerReference(r)
        # the buggy behavior is that the following call raises an exception
        d = tubA.getReference(furl)
        # whereas it ought to return a Deferred
        self.assertTrue(isinstance(d, defer.Deferred))
        def _check(f):
            self.assertTrue(isinstance(f, failure.Failure), f)
            self.assertTrue(f.check(NoLocationHintsError), f)
        d.addBoth(_check)
        return d
