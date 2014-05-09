# -*- test-case-name: foolscap.test.test_pb -*-

import re

if False:
    import sys
    from twisted.python import log
    log.startLogging(sys.stderr)

from twisted.python import failure, reflect
from twisted.internet import defer
from twisted.internet.interfaces import IAddress
from twisted.trial import unittest

from foolscap import referenceable
from foolscap.tokens import BananaError, Violation, INT, STRING, OPEN
from foolscap.tokens import BananaFailure
from foolscap import broker, call
from foolscap.constraint import IConstraint
from foolscap.logging import log

from foolscap.test.common import HelperTarget, TargetMixin, \
     Target, TargetWithoutInterfaces, crypto_available, GoodEnoughTub
from foolscap.eventual import fireEventually, flushEventualQueue



class TestRequest(call.PendingRequest):
    def __init__(self, reqID, rref=None):
        self.answers = []
        call.PendingRequest.__init__(self, reqID, rref, None, None)
    def complete(self, res):
        self.answers.append((True, res))
    def fail(self, why):
        self.answers.append((False, why))

class NullTransport:
    def write(self, data):
        pass
    def loseConnection(self, why=None):
        pass

class TestReferenceUnslicer(unittest.TestCase):
    # OPEN(reference), INT(refid), [STR(interfacename), INT(version)]... CLOSE
    def setUp(self):
        self.broker = broker.Broker(None)
        self.broker.transport = NullTransport()
        self.broker.connectionMade()

    def tearDown(self):
        return flushEventualQueue()

    def newUnslicer(self):
        unslicer = referenceable.ReferenceUnslicer()
        unslicer.broker = self.broker
        unslicer.opener = self.broker.rootUnslicer
        return unslicer

    def testReject(self):
        u = self.newUnslicer()
        self.failUnlessRaises(BananaError, u.checkToken, STRING, 10)
        u = self.newUnslicer()
        self.failUnlessRaises(BananaError, u.checkToken, OPEN, 0)

    def testNoInterfaces(self):
        u = self.newUnslicer()
        u.checkToken(INT, 0)
        u.receiveChild(12)
        rr1,rr1d = u.receiveClose()
        self.failUnless(rr1d is None)
        rr2 = self.broker.getTrackerForYourReference(12).getRef()
        self.failUnless(rr2)
        self.failUnless(isinstance(rr2, referenceable.RemoteReference))
        self.failUnlessEqual(rr2.tracker.broker, self.broker)
        self.failUnlessEqual(rr2.tracker.clid, 12)
        self.failUnlessEqual(rr2.tracker.interfaceName, None)

    def testInterfaces(self):
        u = self.newUnslicer()
        u.checkToken(INT, 0)
        u.receiveChild(12)
        u.receiveChild("IBar")
        rr1,rr1d = u.receiveClose()
        self.failUnless(rr1d is None)
        rr2 = self.broker.getTrackerForYourReference(12).getRef()
        self.failUnless(rr2)
        self.failUnlessIdentical(rr1, rr2)
        self.failUnless(isinstance(rr2, referenceable.RemoteReference))
        self.failUnlessEqual(rr2.tracker.broker, self.broker)
        self.failUnlessEqual(rr2.tracker.clid, 12)
        self.failUnlessEqual(rr2.tracker.interfaceName, "IBar")

class TestAnswer(unittest.TestCase):
    # OPEN(answer), INT(reqID), [answer], CLOSE
    def setUp(self):
        self.broker = broker.Broker(None)
        self.broker.transport = NullTransport()
        self.broker.connectionMade()

    def tearDown(self):
        return flushEventualQueue()

    def newUnslicer(self):
        unslicer = call.AnswerUnslicer()
        unslicer.broker = self.broker
        unslicer.opener = self.broker.rootUnslicer
        unslicer.protocol = self.broker
        return unslicer

    def testAccept1(self):
        req = TestRequest(12)
        self.broker.addRequest(req)
        u = self.newUnslicer()
        u.start(0)
        u.checkToken(INT, 0)
        u.receiveChild(12) # causes broker.getRequest
        u.checkToken(STRING, 8)
        u.receiveChild("results")
        self.failIf(req.answers)
        u.receiveClose() # causes broker.gotAnswer
        self.failUnlessEqual(req.answers, [(True, "results")])

    def testAccept2(self):
        req = TestRequest(12)
        req.setConstraint(IConstraint(str))
        self.broker.addRequest(req)
        u = self.newUnslicer()
        u.start(0)
        u.checkToken(INT, 0)
        u.receiveChild(12) # causes broker.getRequest
        u.checkToken(STRING, 15)
        u.receiveChild("results")
        self.failIf(req.answers)
        u.receiveClose() # causes broker.gotAnswer
        self.failUnlessEqual(req.answers, [(True, "results")])


    def testReject1(self):
        # answer a non-existent request
        req = TestRequest(12)
        self.broker.addRequest(req)
        u = self.newUnslicer()
        u.checkToken(INT, 0)
        self.failUnlessRaises(Violation, u.receiveChild, 13)

    def testReject2(self):
        # answer a request with a result that violates the constraint
        req = TestRequest(12)
        req.setConstraint(IConstraint(int))
        self.broker.addRequest(req)
        u = self.newUnslicer()
        u.checkToken(INT, 0)
        u.receiveChild(12)
        self.failUnlessRaises(Violation, u.checkToken, STRING, 42)
        # this does not yet errback the request
        self.failIf(req.answers)
        # it gets errbacked when banana reports the violation
        v = Violation("icky")
        v.setLocation("here")
        u.reportViolation(BananaFailure(v))
        self.failUnlessEqual(len(req.answers), 1)
        err = req.answers[0]
        self.failIf(err[0])
        f = err[1]
        self.failUnless(f.check(Violation))



class TestReferenceable(TargetMixin, unittest.TestCase):
    # test how a Referenceable gets transformed into a RemoteReference as it
    # crosses the wire, then verify that it gets transformed back into the
    # original Referenceable when it comes back. Also test how shared
    # references to the same object are handled.

    def setUp(self):
        TargetMixin.setUp(self)
        self.setupBrokers()
        if 0:
            print
            self.callingBroker.doLog = "TX"
            self.targetBroker.doLog = " rx"

    def send(self, arg):
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("set", obj=arg)
        d.addCallback(self.failUnless)
        d.addCallback(lambda res: target.obj)
        return d

    def send2(self, arg1, arg2):
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("set2", obj1=arg1, obj2=arg2)
        d.addCallback(self.failUnless)
        d.addCallback(lambda res: (target.obj1, target.obj2))
        return d

    def echo(self, arg):
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("echo", obj=arg)
        return d

    def testRef1(self):
        # Referenceables turn into RemoteReferences
        r = Target()
        d = self.send(r)
        d.addCallback(self._testRef1_1, r)
        return d
    def _testRef1_1(self, res, r):
        self.failUnless(isinstance(res, referenceable.RemoteReference))
        rref = res
        self.failUnless(isinstance(rref.getPeer(), broker.LoopbackAddress))
        self.failUnlessEqual(rref.isConnected(), True)
        self.failUnlessEqual(rref.getLocationHints(), []) # loopback
        self.failUnlessEqual(rref.getSturdyRef().getURL(), None)
        # keepalives are disabled
        self.failUnlessEqual(rref.getDataLastReceivedAt(), None)
        t = rref.tracker
        self.failUnlessEqual(t.broker, self.targetBroker)
        self.failUnless(type(t.clid) is int)
        self.failUnless(self.callingBroker.getMyReferenceByCLID(t.clid) is r)
        self.failUnlessEqual(t.interfaceName, 'RIMyTarget')

    def testRef2(self):
        # sending a Referenceable over the wire multiple times should result
        # in equivalent RemoteReferences
        r = Target()
        d = self.send(r)
        d.addCallback(self._testRef2_1, r)
        return d
    def _testRef2_1(self, res1, r):
        d = self.send(r)
        d.addCallback(self._testRef2_2, res1)
        return d
    def _testRef2_2(self, res2, res1):
        self.failUnless(res1 == res2)
        self.failUnless(res1 is res2) # newpb does this, oldpb didn't

    def testRef3(self):
        # sending the same Referenceable in multiple arguments should result
        # in equivalent RRs
        r = Target()
        d = self.send2(r, r)
        d.addCallback(self._testRef3_1)
        return d
    def _testRef3_1(self, (res1, res2)):
        self.failUnless(res1 == res2)
        self.failUnless(res1 is res2)

    def testRef4(self):
        # sending the same Referenceable in multiple calls will result in
        # equivalent RRs
        r = Target()
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("set", obj=r)
        d.addCallback(self._testRef4_1, rr, r, target)
        return d
    def _testRef4_1(self, res, rr, r, target):
        res1 = target.obj
        d = rr.callRemote("set", obj=r)
        d.addCallback(self._testRef4_2, target, res1)
        return d
    def _testRef4_2(self, res, target, res1):
        res2 = target.obj
        self.failUnless(res1 == res2)
        self.failUnless(res1 is res2)

    def testRef5(self):
        # those RemoteReferences can be used to invoke methods on the sender.
        # 'r' lives on side A. The anonymous target lives on side B. From
        # side A we invoke B.set(r), and we get the matching RemoteReference
        # 'rr' which lives on side B. Then we use 'rr' to invoke r.getName
        # from side A.
        r = Target()
        r.name = "ernie"
        d = self.send(r)
        d.addCallback(lambda rr: rr.callRemote("getName"))
        d.addCallback(self.failUnlessEqual, "ernie")
        return d

    def testRef6(self):
        # Referenceables survive round-trips
        r = Target()
        d = self.echo(r)
        d.addCallback(self.failUnlessIdentical, r)
        return d

##     def NOTtestRemoteRef1(self):
##         # known URLRemoteReferences turn into Referenceables
##         root = Target()
##         rr, target = self.setupTarget(HelperTarget())
##         self.targetBroker.factory = pb.PBServerFactory(root)
##         urlRRef = self.callingBroker.remoteReferenceForName("", [])
##         # urlRRef points at root
##         d = rr.callRemote("set", obj=urlRRef)
##         self.failUnless(dr(d))

##         self.failUnlessIdentical(target.obj, root)

##     def NOTtestRemoteRef2(self):
##         # unknown URLRemoteReferences are errors
##         root = Target()
##         rr, target = self.setupTarget(HelperTarget())
##         self.targetBroker.factory = pb.PBServerFactory(root)
##         urlRRef = self.callingBroker.remoteReferenceForName("bogus", [])
##         # urlRRef points at nothing
##         d = rr.callRemote("set", obj=urlRRef)
##         f = de(d)
##         #print f
##         #self.failUnlessEqual(f.type, tokens.Violation)
##         self.failUnlessEqual(type(f.value), str)
##         self.failUnless(f.value.find("unknown clid 'bogus'") != -1)

    def testArgs1(self):
        # sending the same non-Referenceable object in multiple calls results
        # in distinct objects, because the serialization scope is bounded by
        # each method call
        r = [1,2]
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("set", obj=r)
        d.addCallback(self._testArgs1_1, rr, r, target)
        # TODO: also make sure the original list goes out of scope once the
        # method call has finished, to guard against a leaky
        # reference-tracking implementation.
        return d
    def _testArgs1_1(self, res, rr, r, target):
        res1 = target.obj
        d = rr.callRemote("set", obj=r)
        d.addCallback(self._testArgs1_2, target, res1)
        return d
    def _testArgs1_2(self, res, target, res1):
        res2 = target.obj
        self.failUnless(res1 == res2)
        self.failIf(res1 is res2)

    def testArgs2(self):
        # but sending them as multiple arguments of the *same* method call
        # results in identical objects
        r = [1,2]
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("set2", obj1=r, obj2=r)
        d.addCallback(self._testArgs2_1, rr, target)
        return d
    def _testArgs2_1(self, res, rr, target):
        self.failUnlessIdentical(target.obj1, target.obj2)

    def testAnswer1(self):
        # also, shared objects in a return value should be shared
        r = [1,2]
        rr, target = self.setupTarget(HelperTarget())
        target.obj = (r,r)
        d = rr.callRemote("get")
        d.addCallback(lambda res: self.failUnlessIdentical(res[0], res[1]))
        return d

    def testAnswer2(self):
        # but objects returned by separate method calls should be distinct
        rr, target = self.setupTarget(HelperTarget())
        r = [1,2]
        target.obj = r
        d = rr.callRemote("get")
        d.addCallback(self._testAnswer2_1, rr, target)
        return d
    def _testAnswer2_1(self, res1, rr, target):
        d = rr.callRemote("get")
        d.addCallback(self._testAnswer2_2, res1)
        return d
    def _testAnswer2_2(self, res2, res1):
        self.failUnless(res1 == res2)
        self.failIf(res1 is res2)


class TestFactory(unittest.TestCase):
    def setUp(self):
        self.client = None
        self.server = None

    def gotReference(self, ref):
        self.client = ref

    def tearDown(self):
        if self.client:
            self.client.broker.transport.loseConnection()
        if self.server:
            d = self.server.stopListening()
        else:
            d = defer.succeed(None)
        d.addCallback(flushEventualQueue)
        return d

class TestCallable(unittest.TestCase):
    def setUp(self):
        self.services = [GoodEnoughTub(), GoodEnoughTub()]
        self.tubA, self.tubB = self.services
        self.tub_ports = []
        for s in self.services:
            s.startService()
            l = s.listenOn("tcp:0:interface=127.0.0.1")
            s.setLocation("127.0.0.1:%d" % l.getPortnum())
            self.tub_ports.append(l.getPortnum())
        self._log_observers_to_remove = []

    def addLogObserver(self, observer):
        log.theLogger.addObserver(observer)
        self._log_observers_to_remove.append(observer)

    def tearDown(self):
        for lo in self._log_observers_to_remove:
            log.theLogger.removeObserver(lo)
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d

    def testWrongSwiss(self):
        target = Target()
        url = self.tubB.registerReference(target)
        badurl = url + "_wrong"
        swiss = url[url.rindex("/")+1:]
        d = self.tubA.getReference(badurl)
        def _check(f):
            self.failIf(swiss in str(f), "swissnum revealed")
            self.failUnless(swiss[:2] in str(f), "swissnum hint not given")
        d.addErrback(_check)
        return d

    def testGetSturdyRef(self):
        target = Target()
        url = self.tubB.registerReference(target)
        d = self.tubA.getReference(url)
        def _check(rref):
            sr = rref.getSturdyRef()
            self.failUnlessEqual(sr.getURL(), url)
            peer = rref.getPeer()
            self.failUnless(IAddress.providedBy(peer))
            self.failUnlessEqual(peer.type, "TCP")
            self.failUnlessEqual(peer.host, "127.0.0.1")
            self.failUnlessEqual(rref.getRemoteTubID(), self.tubB.getTubID())
            self.failUnlessEqual(rref.isConnected(), True)
            self.failUnlessEqual(rref.getLocationHints(),
                                 ["tcp:host=127.0.0.1:port=%d" % self.tub_ports[1]])
        d.addCallback(_check)
        return d

    def testLogLocalFailure(self):
        self.tubB.setOption("logLocalFailures", True)
        target = Target()
        logs = []
        self.addLogObserver(logs.append)
        url = self.tubB.registerReference(target)
        d = self.tubA.getReference(url)
        d.addCallback(lambda rref: rref.callRemote("fail"))
        # this will cause some text to be logged with log.msg. TODO: capture
        # this text and look at it more closely.
        def _check(res):
            self.failUnless(isinstance(res, failure.Failure))
            res.trap(ValueError)
            messages = [log.format_message(e) for e in logs]
            failures = [e['failure'] for e in logs if "failure" in e]
            text = "\n".join(messages)
            msg = ("an inbound callRemote that we [%s] executed (on behalf of "
                   "someone else, TubID %s) failed\n"
                   % (self.tubB.getShortTubID(), self.tubA.getShortTubID()))
            self.failUnless(msg in text,
                            "msg '%s' not in text '%s'" % (msg, text))
            self.failUnless("\n reqID=2, rref=<foolscap.test.common.Target object at "
                            in text)
            self.failUnless(", methname=RIMyTarget.fail\n" in text)
            self.failUnless("\n args=[]\n" in text)
            self.failUnless("\n kwargs={}\n" in text)
            self.failUnless("\n the LOCAL failure was:" in text)
            self.failUnlessEqual(len(failures), 1)
            f = failures[0]
            self.failUnless(isinstance(f, failure.Failure))
            self.failUnless(isinstance(f, call.CopiedFailure))
            self.failUnless("Traceback (most recent call last):\n"
                            in str(f))
            self.failUnless("\nexceptions.ValueError: you asked me to fail\n"
                            in str(f))
        d.addBoth(_check)
        return d
    testLogLocalFailure.timeout = 2

    def testLogRemoteFailure(self):
        self.tubA.setOption("logRemoteFailures", True)
        target = Target()
        logs = []
        self.addLogObserver(logs.append)
        url = self.tubB.registerReference(target)
        d = self.tubA.getReference(url)
        d.addCallback(lambda rref: rref.callRemote("fail"))
        # this will cause some text to be logged with log.msg. Capture this
        # text and look at it more closely. Log events are sent through an
        # eventual-send, so we need the fireEventually() call to give the
        # event a chance to be put into the list.
        d.addBoth(fireEventually)
        def _check(res):
            self.failUnless(isinstance(res, failure.Failure))
            res.trap(ValueError)
            messages = [log.format_message(e) for e in logs]
            failures = [e['failure'] for e in logs if "failure" in e]
            text = "\n".join(messages)
            msg = ("an outbound callRemote (that we [%s] sent to someone "
                   "else [%s]) failed on the far end\n"
                   % (self.tubA.getShortTubID(), self.tubB.getShortTubID()))
            self.failUnless(msg in text)
            self.failUnless("\n reqID=2, rref=<RemoteReference at "
                            in text)
            self.failUnless((" [%s]>, methname=RIMyTarget.fail\n" % url)
                            in text)
            #self.failUnless("\n args=[]\n" in text) # TODO: log these too
            #self.failUnless("\n kwargs={}\n" in text)
            self.failUnlessEqual(len(failures), 1)
            f = failures[0]
            self.failUnless("Traceback (most recent call last):\n"
                            in str(f))
            self.failUnless("\nexceptions.ValueError: you asked me to fail\n"
                            in str(f))
        d.addBoth(_check)
        return d
    testLogRemoteFailure.timeout = 2

    def testBoundMethod(self):
        target = Target()
        meth_url = self.tubB.registerReference(target.remote_add)
        d = self.tubA.getReference(meth_url)
        d.addCallback(self._testBoundMethod_1)
        return d
    testBoundMethod.timeout = 5
    def _testBoundMethod_1(self, ref):
        self.failUnless(isinstance(ref, referenceable.RemoteMethodReference))
        #self.failUnlessEqual(ref.getSchemaName(),
        #                     RIMyTarget.__remote_name__ + "/remote_add")
        d = ref.callRemote(a=1, b=2)
        d.addCallback(lambda res: self.failUnlessEqual(res, 3))
        return d

    def testFunction(self):
        l = []
        # we need a keyword arg here
        def append(what):
            l.append(what)
        func_url = self.tubB.registerReference(append)
        d = self.tubA.getReference(func_url)
        d.addCallback(self._testFunction_1, l)
        return d
    testFunction.timeout = 5
    def _testFunction_1(self, ref, l):
        self.failUnless(isinstance(ref, referenceable.RemoteMethodReference))
        d = ref.callRemote(what=12)
        d.addCallback(lambda res: self.failUnlessEqual(l, [12]))
        return d


class TestService(unittest.TestCase):
    def setUp(self):
        self.services = [GoodEnoughTub()]
        self.services[0].startService()

    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d

    def testRegister(self):
        s = self.services[0]
        l = s.listenOn("tcp:0:interface=127.0.0.1")
        s.setLocation("127.0.0.1:%d" % l.getPortnum())
        t1 = Target()
        public_url = s.registerReference(t1, "target")
        if crypto_available:
            self.failUnless(public_url.startswith("pb://"))
            self.failUnless(public_url.endswith("@127.0.0.1:%d/target"
                                                % l.getPortnum()))
        else:
            self.failUnlessEqual(public_url,
                                 "pbu://127.0.0.1:%d/target"
                                 % l.getPortnum())
        self.failUnlessEqual(s.registerReference(t1, "target"), public_url)
        self.failUnlessIdentical(s.getReferenceForURL(public_url), t1)
        t2 = Target()
        private_url = s.registerReference(t2)
        self.failUnlessEqual(s.registerReference(t2), private_url)
        self.failUnlessIdentical(s.getReferenceForURL(private_url), t2)

        s.unregisterURL(public_url)
        self.failUnlessRaises(KeyError, s.getReferenceForURL, public_url)

        s.unregisterReference(t2)
        self.failUnlessRaises(KeyError, s.getReferenceForURL, private_url)

        # TODO: check what happens when you register the same referenceable
        # under multiple URLs

    def getRef(self, target):
        self.services.append(GoodEnoughTub())
        s1 = self.services[0]
        s2 = self.services[1]
        s2.startService()
        l = s1.listenOn("tcp:0:interface=127.0.0.1")
        s1.setLocation("127.0.0.1:%d" % l.getPortnum())
        public_url = s1.registerReference(target, "target")
        self.public_url = public_url
        d = s2.getReference(public_url)
        return d

    def testConnect1(self):
        t1 = TargetWithoutInterfaces()
        d = self.getRef(t1)
        d.addCallback(lambda ref: ref.callRemote('add', a=2, b=3))
        d.addCallback(self._testConnect1, t1)
        return d
    testConnect1.timeout = 5
    def _testConnect1(self, res, t1):
        self.failUnlessEqual(t1.calls, [(2,3)])
        self.failUnlessEqual(res, 5)

    def testConnect2(self):
        t1 = Target()
        d = self.getRef(t1)
        d.addCallback(lambda ref: ref.callRemote('add', a=2, b=3))
        d.addCallback(self._testConnect2, t1)
        return d
    testConnect2.timeout = 5
    def _testConnect2(self, res, t1):
        self.failUnlessEqual(t1.calls, [(2,3)])
        self.failUnlessEqual(res, 5)


    def testConnect3(self):
        # test that we can get the reference multiple times
        t1 = Target()
        d = self.getRef(t1)
        d.addCallback(lambda ref: ref.callRemote('add', a=2, b=3))
        def _check(res):
            self.failUnlessEqual(t1.calls, [(2,3)])
            self.failUnlessEqual(res, 5)
            t1.calls = []
        d.addCallback(_check)
        d.addCallback(lambda res:
                      self.services[1].getReference(self.public_url))
        d.addCallback(lambda ref: ref.callRemote('add', a=5, b=6))
        def _check2(res):
            self.failUnlessEqual(t1.calls, [(5,6)])
            self.failUnlessEqual(res, 11)
        d.addCallback(_check2)
        return d
    testConnect3.timeout = 5

    def TODO_testStatic(self):
        # make sure we can register static data too, at least hashable ones
        t1 = (1,2,3)
        d = self.getRef(t1)
        d.addCallback(lambda ref: self.failUnlessEqual(ref, (1,2,3)))
        return d
    #testStatic.timeout = 2

    def testBadMethod(self):
        t1 = Target()
        d = self.getRef(t1)
        d.addCallback(lambda ref: ref.callRemote('missing', a=2, b=3))
        d.addCallbacks(self._testBadMethod_cb, self._testBadMethod_eb)
        return d
    testBadMethod.timeout = 5
    def _testBadMethod_cb(self, res):
        self.fail("method wasn't supposed to work")
    def _testBadMethod_eb(self, f):
        #self.failUnlessEqual(f.type, 'foolscap.tokens.Violation')
        self.failUnlessEqual(f.type, Violation)
        self.failUnless(re.search(r'RIMyTarget\(.*\) does not offer missing',
                                  str(f)))

    def testBadMethod2(self):
        t1 = TargetWithoutInterfaces()
        d = self.getRef(t1)
        d.addCallback(lambda ref: ref.callRemote('missing', a=2, b=3))
        d.addCallbacks(self._testBadMethod_cb, self._testBadMethod2_eb)
        return d
    testBadMethod2.timeout = 5
    def _testBadMethod2_eb(self, f):
        self.failUnlessEqual(reflect.qual(f.type), 'exceptions.AttributeError')
        self.failUnlessSubstring("TargetWithoutInterfaces", f.value)
        self.failUnlessSubstring(" has no attribute 'remote_missing'", f.value)



# TODO:
#  when the Violation is remote, it is reported in a CopiedFailure, which
#  means f.type is a string. When it is local, it is reported in a Failure,
#  and f.type is the tokens.Violation class. I'm not sure how I feel about
#  these being different.

# TODO: tests to port from oldpb suite
# testTooManyRefs: sending pb.MAX_BROKER_REFS across the wire should die
# testFactoryCopy?

# tests which aren't relevant right now but which might be once we port the
# corresponding functionality:
#
# testObserve, testCache (pb.Cacheable)
# testViewPoint
# testPublishable (spread.publish??)
# SpreadUtilTestCase (spread.util)
# NewCredTestCase

# tests which aren't relevant and aren't like to ever be
#
# PagingTestCase
# ConnectionTestCase (oldcred)
# NSPTestCase
