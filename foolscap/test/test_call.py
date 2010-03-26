
import gc
import re
import sets
import sys

if False:
    from twisted.python import log
    log.startLogging(sys.stderr)

from twisted.python import log
from twisted.trial import unittest
from twisted.internet.main import CONNECTION_LOST, CONNECTION_DONE
from twisted.python.failure import Failure
from twisted.application import service

from foolscap.tokens import Violation
from foolscap.eventual import flushEventualQueue
from foolscap.test.common import HelperTarget, TargetMixin, ShouldFailMixin
from foolscap.test.common import RIMyTarget, Target, TargetWithoutInterfaces, \
     BrokenTarget
from foolscap.api import RemoteException, UnauthenticatedTub, DeadReferenceError
from foolscap.call import CopiedFailure
from foolscap.logging import log as flog

class Unsendable:
    pass


class TestCall(TargetMixin, ShouldFailMixin, unittest.TestCase):
    def setUp(self):
        TargetMixin.setUp(self)
        self.setupBrokers()

    def testCall1(self):
        # this is done without interfaces
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("add", a=1, b=2)
        d.addCallback(lambda res: self.failUnlessEqual(res, 3))
        d.addCallback(lambda res: self.failUnlessEqual(target.calls, [(1,2)]))
        d.addCallback(self._testCall1_1, rr)
        return d
    def _testCall1_1(self, res, rr):
        # the caller still holds the RemoteReference
        self.failUnless(self.callingBroker.yourReferenceByCLID.has_key(1))

        # release the RemoteReference. This does two things: 1) the
        # callingBroker will forget about it. 2) they will send a decref to
        # the targetBroker so *they* can forget about it.
        del rr # this fires a DecRef
        gc.collect() # make sure

        # we need to give it a moment to deliver the DecRef message and act
        # on it. Poll until the caller has received it.
        def _check():
            if self.callingBroker.yourReferenceByCLID.has_key(1):
                return False
            return True
        d = self.poll(_check)
        d.addCallback(self._testCall1_2)
        return d
    def _testCall1_2(self, res):
        self.failIf(self.callingBroker.yourReferenceByCLID.has_key(1))
        self.failIf(self.targetBroker.myReferenceByCLID.has_key(1))

    def testCall1a(self):
        # no interfaces, but use positional args
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("add", 1, 2)
        d.addCallback(lambda res: self.failUnlessEqual(res, 3))
        d.addCallback(lambda res: self.failUnlessEqual(target.calls, [(1,2)]))
        return d
    testCall1a.timeout = 2

    def testCall1b(self):
        # no interfaces, use both positional and keyword args
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("add", 1, b=2)
        d.addCallback(lambda res: self.failUnlessEqual(res, 3))
        d.addCallback(lambda res: self.failUnlessEqual(target.calls, [(1,2)]))
        return d
    testCall1b.timeout = 2

    def testFail1(self):
        # this is done without interfaces
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("fail")
        self.failIf(target.calls)
        d.addBoth(self._testFail1_1)
        return d
    testFail1.timeout = 2
    def _testFail1_1(self, f):
        # f should be a CopiedFailure
        self.failUnless(isinstance(f, Failure),
                        "Hey, we didn't fail: %s" % f)
        self.failUnless(isinstance(f, CopiedFailure),
                        "not CopiedFailure: %s" % f)
        self.failUnless(f.check(ValueError),
                        "wrong exception type: %s" % f)
        self.failUnlessSubstring("you asked me to fail", f.value)

    def testFail2(self):
        # this is done without interfaces
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("add", a=1, b=2, c=3)
        # add() does not take a 'c' argument, so we get a TypeError here
        self.failIf(target.calls)
        d.addBoth(self._testFail2_1)
        return d
    testFail2.timeout = 2
    def _testFail2_1(self, f):
        self.failUnless(isinstance(f, Failure),
                        "Hey, we didn't fail: %s" % f)
        self.failUnless(f.check(TypeError),
                        "wrong exception type: %s" % f.type)
        self.failUnlessSubstring("remote_add() got an unexpected keyword "
                                 "argument 'c'", f.value)

    def testFail3(self):
        # this is done without interfaces
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("bogus", a=1, b=2)
        # the target does not have .bogus method, so we get an AttributeError
        self.failIf(target.calls)
        d.addBoth(self._testFail3_1)
        return d
    testFail3.timeout = 2
    def _testFail3_1(self, f):
        self.failUnless(isinstance(f, Failure),
                        "Hey, we didn't fail: %s" % f)
        self.failUnless(f.check(AttributeError),
                        "wrong exception type: %s" % f.type)
        self.failUnlessSubstring("TargetWithoutInterfaces", str(f))
        self.failUnlessSubstring(" has no attribute 'remote_bogus'", str(f))

    def testFailStringException(self):
        # make sure we handle string exceptions correctly
        if sys.version_info >= (2,5):
            log.msg("skipping test: string exceptions are deprecated in 2.5")
            return
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("failstring")
        self.failIf(target.calls)
        d.addBoth(self._testFailStringException_1)
        return d
    testFailStringException.timeout = 2
    def _testFailStringException_1(self, f):
        # f should be a CopiedFailure
        self.failUnless(isinstance(f, Failure),
                        "Hey, we didn't fail: %s" % f)
        self.failUnless(f.check("string exceptions are annoying"),
                        "wrong exception type: %s" % f)

    def testCopiedFailure(self):
        # A calls B, who calls C. C fails. B gets a CopiedFailure and reports
        # it back to A. What does A get?
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = rr.callRemote("fail_remotely", target)
        def _check(f):
            # f should be a CopiedFailure
            self.failUnless(isinstance(f, Failure),
                            "Hey, we didn't fail: %s" % f)
            self.failUnless(f.check(ValueError),
                            "wrong exception type: %s" % f)
            self.failUnlessSubstring("you asked me to fail", f.value)
        d.addBoth(_check)
        return d
    testCopiedFailure.timeout = 2

    def testCall2(self):
        # server end uses an interface this time, but not the client end
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("add", a=3, b=4, _useSchema=False)
        # the schema is enforced upon receipt
        d.addCallback(lambda res: self.failUnlessEqual(res, 7))
        return d
    testCall2.timeout = 2

    def testCall3(self):
        # use interface on both sides
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote('add', 3, 4) # enforces schemas
        d.addCallback(lambda res: self.failUnlessEqual(res, 7))
        return d
    testCall3.timeout = 2

    def testCall4(self):
        # call through a manually-defined RemoteMethodSchema
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("add", 3, 4, _methodConstraint=RIMyTarget['add1'])
        d.addCallback(lambda res: self.failUnlessEqual(res, 7))
        return d
    testCall4.timeout = 2

    def testChoiceOf(self):
        # this is a really small test case to check specific bugs. We
        # definitely need more here.

        # in bug (#13), the ChoiceOf constraint did not override the
        # checkToken() call to its children, which had the consequence of not
        # propagating the maxLength= attribute of the StringConstraint to the
        # children (using the default of 1000 bytes instead).
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("choice1", 4)
        d.addCallback(lambda res: self.failUnlessEqual(res, None))
        d.addCallback(lambda res: rr.callRemote("choice1", "a"*2000))
        d.addCallback(lambda res: self.failUnlessEqual(res, None))
        # False does not conform
        d.addCallback(lambda res:
                      self.shouldFail(Violation, "testChoiceOf", None,
                                      rr.callRemote, "choice1", False))
        return d

    def testMegaSchema(self):
        # try to exercise all our constraints at once
        rr, target = self.setupTarget(HelperTarget())
        t = (sets.Set([1, 2, 3]),
             "str", True, 12, 12L, 19.3, None,
             u"unicode",
             "bytestring",
             "any", 14.3,
             15,
             "a"*95,
             "1234567890",
              )
        obj1 = {"key": [t]}
        obj2 = (sets.Set([1,2,3]), [1,2,3], {1:"two"})
        d = rr.callRemote("megaschema", obj1, obj2)
        d.addCallback(lambda res: self.failUnlessEqual(res, None))
        return d

    def testMega3(self):
        # exercise a specific bug: shared references don't pass schemas
        t = (0,1)
        obj = [t, t]
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("mega3", obj)
        d.addCallback(lambda res: self.failUnlessEqual(res, None))
        return d

    def testUnconstrainedMethod(self):
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote('free', 3, 4, x="boo")
        def _check(res):
            self.failUnlessEqual(res, "bird")
            self.failUnlessEqual(target.calls, [((3,4), {"x": "boo"})])
        d.addCallback(_check)
        return d

    def testFailWrongMethodLocal(self):
        # the caller knows that this method does not really exist
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("bogus") # RIMyTarget doesn't implement .bogus()
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongMethodLocal_1)
        return d
    testFailWrongMethodLocal.timeout = 2
    def _testFailWrongMethodLocal_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnless(re.search(r'RIMyTarget\(.*\) does not offer bogus',
                                  str(f)))

    def testFailWrongMethodRemote(self):
        # if the target doesn't specify any remote interfaces, then the
        # calling side shouldn't try to do any checking. The problem is
        # caught on the target side.
        rr, target = self.setupTarget(Target(), False)
        d = rr.callRemote("bogus") # RIMyTarget doesn't implement .bogus()
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongMethodRemote_1)
        return d
    testFailWrongMethodRemote.timeout = 2
    def _testFailWrongMethodRemote_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnlessSubstring("method 'bogus' not defined in RIMyTarget",
                                 str(f))

    def testFailWrongMethodRemote2(self):
        # call a method which doesn't actually exist. The sender thinks
        # they're ok but the recipient catches the violation
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("bogus", _useSchema=False)
        # RIMyTarget2 has a 'sub' method, but RIMyTarget (the real interface)
        # does not
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongMethodRemote2_1)
        d.addCallback(lambda res: self.failIf(target.calls))
        return d
    testFailWrongMethodRemote2.timeout = 2
    def _testFailWrongMethodRemote2_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnless(re.search(r'RIMyTarget\(.*\) does not offer bogus',
                                  str(f)))

    def testFailWrongArgsLocal1(self):
        # we violate the interface (extra arg), and the sender should catch it
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("add", a=1, b=2, c=3)
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongArgsLocal1_1)
        d.addCallback(lambda res: self.failIf(target.calls))
        return d
    testFailWrongArgsLocal1.timeout = 2
    def _testFailWrongArgsLocal1_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnlessSubstring("unknown argument 'c'", str(f.value))

    def testFailWrongArgsLocal2(self):
        # we violate the interface (bad arg), and the sender should catch it
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("add", a=1, b="two")
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongArgsLocal2_1)
        d.addCallback(lambda res: self.failIf(target.calls))
        return d
    testFailWrongArgsLocal2.timeout = 2
    def _testFailWrongArgsLocal2_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnlessSubstring("not a number", str(f.value))

    def testFailWrongArgsRemote1(self):
        # the sender thinks they're ok but the recipient catches the
        # violation
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("add", a=1, b="foo", _useSchema=False)
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongArgsRemote1_1)
        d.addCallbacks(lambda res: self.failIf(target.calls))
        return d
    testFailWrongArgsRemote1.timeout = 2
    def _testFailWrongArgsRemote1_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnlessSubstring("STRING token rejected by IntegerConstraint",
                                 f.value)
        self.failUnlessSubstring("<RootUnslicer>.<methodcall", f.value)
        self.failUnlessSubstring(" methodname=add", f.value)
        self.failUnlessSubstring("<arguments arg[b]>", f.value)

    def testFailWrongReturnRemote(self):
        rr, target = self.setupTarget(BrokenTarget(), True)
        d = rr.callRemote("add", 3, 4) # violates return constraint
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongReturnRemote_1)
        return d
    testFailWrongReturnRemote.timeout = 2
    def _testFailWrongReturnRemote_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnlessSubstring("in return value of <foolscap.test.common.BrokenTarget object at ", f.value)
        self.failUnlessSubstring(">.add", f.value)
        self.failUnlessSubstring("not a number", f.value)

    def testFailWrongReturnLocal(self):
        # the target returns a value which violates our _resultConstraint
        rr, target = self.setupTarget(Target(), True)
        d = rr.callRemote("add", a=1, b=2, _resultConstraint=str)
        # The target returns an int, which matches the schema they're using,
        # so they think they're ok. We've overridden our expectations to
        # require a string.
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testFailWrongReturnLocal_1)
        # the method should have been run
        d.addCallback(lambda res: self.failUnless(target.calls))
        return d
    testFailWrongReturnLocal.timeout = 2
    def _testFailWrongReturnLocal_1(self, f):
        self.failUnless(f.check(Violation))
        self.failUnlessSubstring("INT token rejected by ByteStringConstraint",
                                 str(f))
        self.failUnlessSubstring("in inbound method results", str(f))
        self.failUnlessSubstring("<RootUnslicer>.Answer(req=1)", str(f))



    def testDefer(self):
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("defer", obj=12)
        d.addCallback(lambda res: self.failUnlessEqual(res, 12))
        return d
    testDefer.timeout = 2

    def testStallOrdering(self):
        # if the first message hangs (it returns a Deferred that doesn't fire
        # for a while), that shouldn't stall the second message.
        rr, target = self.setupTarget(HelperTarget())
        d0 = rr.callRemote("hang")
        d = rr.callRemote("echo", 1)
        d.addCallback(lambda res: self.failUnlessEqual(res, 1))
        def _done(res):
            target.d.callback(2)
            return d0
        d.addCallback(_done)
        return d
    testStallOrdering.timeout = 5

    def testDisconnect_during_call(self):
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("hang")
        e = RuntimeError("lost connection")
        rr.tracker.broker.transport.loseConnection(Failure(e))
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       lambda why: why.trap(RuntimeError) and None)
        return d

    def test_connection_lost_is_deadref(self):
        rr, target = self.setupTarget(HelperTarget())
        d1 = rr.callRemote("hang")
        def get_d(): return d1
        rr.tracker.broker.transport.loseConnection(Failure(CONNECTION_LOST))
        d = self.shouldFail(DeadReferenceError, "lost_is_deadref.1",
                            "Connection was lost",
                            get_d)
        def _examine_error((f,)):
            # the (to tubid=XXX) part will see "tub=call", which is an
            # abbreviation of "callingBroker" as created in
            # TargetMixin.setupBrokers
            self.failUnlessIn("(to tubid=call)", str(f.value))
            self.failUnlessIn("(during method=None:hang)", str(f.value))
        d.addCallback(_examine_error)
        # and once the connection is down, we should get a DeadReferenceError
        # for new messages
        d.addCallback(lambda res:
                      self.shouldFail(DeadReferenceError, "lost_is_deadref.2",
                                      "Calling Stale Broker",
                                      rr.callRemote, "hang"))
        return d

    def test_connection_done_is_deadref(self):
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("hang")
        rr.tracker.broker.transport.loseConnection(Failure(CONNECTION_DONE))
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       lambda why: why.trap(DeadReferenceError) and None)
        return d

    def disconnected(self, *args, **kwargs):
        self.lost = 1
        self.lost_args = (args, kwargs)

    def testNotifyOnDisconnect(self):
        rr, target = self.setupTarget(HelperTarget())
        self.lost = 0
        self.failUnlessEqual(rr.isConnected(), True)
        rr.notifyOnDisconnect(self.disconnected)
        rr.tracker.broker.transport.loseConnection(Failure(CONNECTION_LOST))
        d = flushEventualQueue()
        def _check(res):
            self.failUnlessEqual(rr.isConnected(), False)
            self.failUnless(self.lost)
            self.failUnlessEqual(self.lost_args, ((),{}))
            # it should be safe to unregister now, even though the callback
            # has already fired, since dontNotifyOnDisconnect is tolerant
            rr.dontNotifyOnDisconnect(self.disconnected)
        d.addCallback(_check)
        return d

    def testNotifyOnDisconnect_unregister(self):
        rr, target = self.setupTarget(HelperTarget())
        self.lost = 0
        m = rr.notifyOnDisconnect(self.disconnected)
        rr.dontNotifyOnDisconnect(m)
        # dontNotifyOnDisconnect is supposed to be tolerant of duplicate
        # unregisters, because otherwise it is hard to avoid race conditions.
        # Validate that we can unregister something multiple times.
        rr.dontNotifyOnDisconnect(m)
        rr.tracker.broker.transport.loseConnection(Failure(CONNECTION_LOST))
        d = flushEventualQueue()
        d.addCallback(lambda res: self.failIf(self.lost))
        return d

    def testNotifyOnDisconnect_args(self):
        rr, target = self.setupTarget(HelperTarget())
        self.lost = 0
        rr.notifyOnDisconnect(self.disconnected, "arg", foo="kwarg")
        rr.tracker.broker.transport.loseConnection(Failure(CONNECTION_LOST))
        d = flushEventualQueue()
        def _check(res):
            self.failUnless(self.lost)
            self.failUnlessEqual(self.lost_args, (("arg",),
                                                  {"foo": "kwarg"}))
        d.addCallback(_check)
        return d

    def testNotifyOnDisconnect_already(self):
        # make sure notifyOnDisconnect works even if the reference was already
        # broken
        rr, target = self.setupTarget(HelperTarget())
        self.lost = 0
        rr.tracker.broker.transport.loseConnection(Failure(CONNECTION_LOST))
        d = flushEventualQueue()
        d.addCallback(lambda res: rr.notifyOnDisconnect(self.disconnected))
        d.addCallback(lambda res: flushEventualQueue())
        def _check(res):
            self.failUnless(self.lost, "disconnect handler not run")
            self.failUnlessEqual(self.lost_args, ((),{}))
        d.addCallback(_check)
        return d

    def testUnsendable(self):
        rr, target = self.setupTarget(HelperTarget())
        d = rr.callRemote("set", obj=Unsendable())
        d.addCallbacks(lambda res: self.fail("should have failed"),
                       self._testUnsendable_1)
        return d
    testUnsendable.timeout = 2
    def _testUnsendable_1(self, why):
        self.failUnless(why.check(Violation))
        self.failUnlessSubstring("cannot serialize", why.value.args[0])


class TestCallOnly(TargetMixin, unittest.TestCase):
    def setUp(self):
        TargetMixin.setUp(self)
        self.setupBrokers()

    def testCallOnly(self):
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        ret = rr.callRemoteOnly("add", a=1, b=2)
        self.failUnlessIdentical(ret, None)
        # since we don't have a Deferred to wait upon, we just have to poll
        # for the call to take place. It should happen pretty quickly.
        def _check():
            if target.calls:
                self.failUnlessEqual(target.calls, [(1,2)])
                return True
            return False
        d = self.poll(_check)
        return d
    testCallOnly.timeout = 2

class ExamineFailuresMixin:
    def _examine_raise(self, r, should_be_remote):
        f = r[0]
        if should_be_remote:
            self.failUnless(f.check(RemoteException))
            self.failIf(f.check(ValueError))
            f2 = f.value.failure
        else:
            self.failUnless(f.check(ValueError))
            self.failIf(f.check(RemoteException))
            f2 = f
        self.failUnless(f2.check(ValueError))
        self.failUnless(isinstance(f2, CopiedFailure))
        self.failUnlessSubstring("you asked me to fail", f2.value)
        self.failIf(f2.check(RemoteException))
        l = flog.FoolscapLogger()
        l.msg("f1", failure=f)
        l.msg("f2", failure=f2)

    def _examine_local_violation(self, r):
        f = r[0]
        self.failUnless(f.check(Violation))
        self.failUnless(re.search(r'RIMyTarget\(.*\) does not offer bogus',
                                  str(f)))
        self.failIf(f.check(RemoteException))

    def _examine_remote_violation(self, r, should_be_remote):
        f = r[0]
        if should_be_remote:
            self.failUnless(f.check(RemoteException))
            self.failIf(f.check(Violation))
            f2 = f.value.failure
        else:
            self.failIf(f.check(RemoteException))
            self.failUnless(f.check(Violation))
            f2 = f
        self.failUnless(isinstance(f2, CopiedFailure))
        self.failUnless(f2.check(Violation))
        self.failUnlessSubstring("STRING token rejected by IntegerConstraint",
                                 f2.value)
        self.failUnlessSubstring("<RootUnslicer>.<methodcall", f2.value)
        self.failUnlessSubstring(" methodname=add", f2.value)
        self.failUnlessSubstring("<arguments arg[b]>", f2.value)
        self.failIf(f2.check(RemoteException))

    def _examine_remote_attribute_error(self, r, should_be_remote):
        f = r[0]
        if should_be_remote:
            self.failUnless(f.check(RemoteException))
            self.failIf(f.check(AttributeError))
            f2 = f.value.failure
        else:
            self.failUnless(f.check(AttributeError))
            self.failIf(f.check(RemoteException))
            f2 = f
        self.failUnless(isinstance(f2, CopiedFailure))
        self.failUnless(f2.check(AttributeError))
        self.failUnlessSubstring(" has no attribute 'remote_bogus'", str(f2))
        self.failIf(f2.check(RemoteException))

    def _examine_local_return_violation(self, r):
        f = r[0]
        self.failUnless(f.check(Violation))
        self.failUnlessSubstring("INT token rejected by ByteStringConstraint",
                                 str(f))
        self.failUnlessSubstring("in inbound method results", str(f))
        self.failUnlessSubstring("<RootUnslicer>.Answer(req=1)", str(f))
        self.failIf(f.check(RemoteException))

class Failures(ExamineFailuresMixin, TargetMixin, ShouldFailMixin,
               unittest.TestCase):
    def setUp(self):
        TargetMixin.setUp(self)
        self.setupBrokers()

    def _set_expose(self, value):
        self.callingBroker._expose_remote_exception_types = value

    def test_raise_not_exposed(self):
        self._set_expose(False)
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = self.shouldFail(RemoteException, "one", None, rr.callRemote, "fail")
        d.addCallback(self._examine_raise, True)
        return d

    def test_raise_yes_exposed(self):
        self._set_expose(True)
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = self.shouldFail(ValueError, "one", None, rr.callRemote, "fail")
        d.addCallback(self._examine_raise, False)
        return d

    def test_raise_default(self):
        # current default is to expose exceptions. This may change in the
        # future.
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = self.shouldFail(ValueError, "one", None, rr.callRemote, "fail")
        d.addCallback(self._examine_raise, False)
        return d


    def test_local_violation_not_exposed(self):
        self._set_expose(False)
        # the caller knows that this method does not really exist, so we
        # should get a local Violation. Local exceptions are never reported
        # as RemoteExceptions, so the expose option doesn't affect behavior.
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None, rr.callRemote, "bogus")
        d.addCallback(self._examine_local_violation)
        return d

    def test_local_violation_yes_exposed(self):
        self._set_expose(True)
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None, rr.callRemote, "bogus")
        d.addCallback(self._examine_local_violation)
        return d

    def test_local_violation_default(self):
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None, rr.callRemote, "bogus")
        d.addCallback(self._examine_local_violation)
        return d


    def test_remote_violation_not_exposed(self):
        self._set_expose(False)
        # the sender thinks they're ok, but the recipient catches the
        # violation.
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(RemoteException, "one", None,
                            rr.callRemote, "add", a=1,b="foo", _useSchema=False)
        d.addCallback(self._examine_remote_violation, True)
        return d

    def test_remote_violation_yes_exposed(self):
        self._set_expose(True)
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None,
                            rr.callRemote, "add", a=1,b="foo", _useSchema=False)
        d.addCallback(self._examine_remote_violation, False)
        return d

    def test_remote_violation_default(self):
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None,
                            rr.callRemote, "add", a=1,b="foo", _useSchema=False)
        d.addCallback(self._examine_remote_violation, False)
        return d


    def test_remote_attribute_error_not_exposed(self):
        self._set_expose(False)
        # the target doesn't specify an interface, so the sender can't know
        # that the method is missing
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = self.shouldFail(RemoteException, "one", None,
                            rr.callRemote, "bogus")
        d.addCallback(self._examine_remote_attribute_error, True)
        return d

    def test_remote_attribute_error_yes_exposed(self):
        self._set_expose(True)
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = self.shouldFail(AttributeError, "one", None,
                            rr.callRemote, "bogus")
        d.addCallback(self._examine_remote_attribute_error, False)
        return d

    def test_remote_attribute_error_default(self):
        rr, target = self.setupTarget(TargetWithoutInterfaces())
        d = self.shouldFail(AttributeError, "one", None,
                            rr.callRemote, "bogus")
        d.addCallback(self._examine_remote_attribute_error, False)
        return d


    def test_local_return_violation_not_exposed(self):
        self._set_expose(False)
        # the target returns a value which violations our _resultConstraint
        # Local exceptions are never reported as RemoteExceptions, so the
        # expose option doesn't affect behavior.
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None,
                            rr.callRemote,
                            "add", a=1, b=2, _resultConstraint=str)
        d.addCallback(self._examine_local_return_violation)
        return d

    def test_local_return_violation_yes_exposed(self):
        self._set_expose(True)
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None,
                            rr.callRemote,
                            "add", a=1, b=2, _resultConstraint=str)
        d.addCallback(self._examine_local_return_violation)
        return d

    def test_local_return_violation_default(self):
        rr, target = self.setupTarget(Target(), True)
        d = self.shouldFail(Violation, "one", None,
                            rr.callRemote,
                            "add", a=1, b=2, _resultConstraint=str)
        d.addCallback(self._examine_local_return_violation)
        return d

    # TODO: test Tub.setOption("expose-remote-exception-types")
    # TODO: A calls B. B calls C. C raises an exception. What does A get?

class TubFailures(ExamineFailuresMixin, ShouldFailMixin, unittest.TestCase):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()
        self.target_tub = UnauthenticatedTub()
        self.target_tub.setServiceParent(self.s)
        l = self.target_tub.listenOn("tcp:0:interface=127.0.0.1")
        self.target_tub.setLocation("127.0.0.1:%d" % l.getPortnum())
        self.source_tub = UnauthenticatedTub()
        self.source_tub.setServiceParent(self.s)

    def tearDown(self):
        return self.s.stopService()

    def setupTarget(self, target):
        furl = self.target_tub.registerReference(target)
        d = self.source_tub.getReference(furl)
        return d


    def test_raise_not_exposed(self):
        self.source_tub.setOption("expose-remote-exception-types", False)
        d = self.setupTarget(TargetWithoutInterfaces())
        d.addCallback(lambda rr:
                      self.shouldFail(RemoteException, "one", None,
                                      rr.callRemote, "fail"))
        d.addCallback(self._examine_raise, True)
        return d

    def test_raise_yes_exposed(self):
        self.source_tub.setOption("expose-remote-exception-types", True)
        d = self.setupTarget(TargetWithoutInterfaces())
        d.addCallback(lambda rr:
                      self.shouldFail(ValueError, "one", None,
                                      rr.callRemote, "fail"))
        d.addCallback(self._examine_raise, False)
        return d

    def test_raise_default(self):
        # current default is to expose exceptions. This may change in the
        # future.
        d = self.setupTarget(TargetWithoutInterfaces())
        d.addCallback(lambda rr:
                      self.shouldFail(ValueError, "one", None,
                                      rr.callRemote, "fail"))
        d.addCallback(self._examine_raise, False)
        return d

class ReferenceCounting(ShouldFailMixin, unittest.TestCase):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()
        self.target_tub = UnauthenticatedTub()
        self.target_tub.setServiceParent(self.s)
        l = self.target_tub.listenOn("tcp:0:interface=127.0.0.1")
        self.target_tub.setLocation("127.0.0.1:%d" % l.getPortnum())
        self.source_tub = UnauthenticatedTub()
        self.source_tub.setServiceParent(self.s)

    def tearDown(self):
        return self.s.stopService()

    def setupTarget(self, target):
        furl = self.target_tub.registerReference(target)
        d = self.source_tub.getReference(furl)
        return d

    def test_reference_counting(self):
        self.source_tub.setOption("expose-remote-exception-types", True)
        target = HelperTarget()
        d = self.setupTarget(target)
        def _stash(rref):
            # to exercise bug #104, we need to trigger remote Violations, so
            # we tell the sending side to not use a RemoteInterface. We do
            # this by reaching inside the RemoteReference and making it
            # forget
            rref.tracker.interfaceName = None
            rref.tracker.interface = None
            self.rref = rref
        d.addCallback(_stash)

        # the first call causes an error, which discards all remaining
        # tokens, including the OPEN tokens for the arguments. The #104 bug
        # is that this causes the open-count to get out of sync, by -2 (one
        # for the arguments sequence, one for the list inside it).
        d.addCallback(lambda ign:
                      self.shouldFail(Violation, "one", None,
                                      self.rref.callRemote, "bogus",
                                      ["one list"]))

        #d.addCallback(lambda ign:
        #              self.rref.callRemote("set", ["one list"]))

        # a method call that has no arguments (specifically no REFERENCE
        # sequences) won't notice the loss of sync
        d.addCallback(lambda ign: self.rref.callRemote("set", 42))
        def _check_42(ign):
            self.failUnlessEqual(target.obj, 42)
        d.addCallback(_check_42)
        # but when the call takes shared arguments, sync matters
        l = ["list", 1, 2]
        s = set([3,4])
        t = ("tuple", 5, 6)
        d.addCallback(lambda ign: self.rref.callRemote("set", [t, l, s, t]))
        def _check_shared(ign):
            # the off-by-two bug would cause the second tuple shared-ref to
            # point at the set instead of the first tuple
            self.failUnlessEqual(type(target.obj), list)
            one, two, three, four = target.obj
            self.failUnlessEqual(type(one), tuple)
            self.failUnlessEqual(one, t)
            self.failUnlessEqual(type(two), list)
            self.failUnlessEqual(two, l)
            self.failUnlessEqual(type(three), set)
            self.failUnlessEqual(three, s)
            self.failUnlessEqual(type(four), tuple) # this is where it fails
            self.failUnlessEqual(four, t)
            self.failUnlessIdentical(one, four)
        d.addCallback(_check_shared)
        return d

