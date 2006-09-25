
from twisted.trial import unittest

from twisted.python.failure import Failure
from foolscap.promise import makePromise, send, sendOnly, when, UsageError
from foolscap.eventual import flushEventualQueue, fireEventually

class KaboomError(Exception):
    pass

class Target:
    def __init__(self):
        self.calls = []
    def one(self, a):
        self.calls.append(("one", a))
        return a+1
    def two(self, a, b=2, **kwargs):
        self.calls.append(("two", a, b, kwargs))
    def three(self, c, *args):
        self.calls.append(("three", c, args))
        return self.d
    def four(self, newtarget, arg):
        return newtarget.one(arg)
    def fail(self, arg):
        raise KaboomError("kaboom!")

class Send(unittest.TestCase):

    def tearDown(self):
        return flushEventualQueue()

    def testNear(self):
        t = Target()
        p = send(t).one(1)
        self.failIf(t.calls)
        def _check(res):
            self.failUnlessEqual(res, 2)
            self.failUnlessEqual(t.calls, [("one", 1)])
        when(p).addCallback(_check)

    def testOrdering(self):
        t = Target()
        p1 = send(t).one(1)
        p2 = send(t).two(3, k="extra")
        self.failIf(t.calls)
        def _check1(res):
            # we can't check t.calls here: the when() clause is not
            # guaranteed to fire before the second send.
            self.failUnlessEqual(res, 2)
        when(p1).addCallback(_check1)
        def _check2(res):
            self.failUnlessEqual(res, None)
        when(p2).addCallback(_check2)
        def _check3(res):
            self.failUnlessEqual(t.calls, [("one", 1),
                                           ("two", 3, 2, {"k": "extra"}),
                                           ])
        fireEventually().addCallback(_check3)

    def testFailure(self):
        t = Target()
        p1 = send(t).fail(0)
        def _check(res):
            self.failUnless(isinstance(res, Failure))
            self.failUnless(res.check(KaboomError))
        when(p1).addBoth(_check)

    def testBadName(self):
        t = Target()
        p1 = send(t).missing(0)
        def _check(res):
            self.failUnless(isinstance(res, Failure))
            self.failUnless(res.check(AttributeError))
        when(p1).addBoth(_check)

    def testNoImmediateCall(self):
        p,r = makePromise()
        def wrong(p):
            p.one(12)
        self.failUnlessRaises(AttributeError, wrong, p)

    def testNoMultipleResolution(self):
        p,r = makePromise()
        r(3)
        self.failUnlessRaises(UsageError, r, 4)

    def testResolveBefore(self):
        t = Target()
        p,r = makePromise()
        r(t)
        p = send(p).one(2)
        def _check(res):
            self.failUnlessEqual(res, 3)
        when(p).addCallback(_check)

    def testResolveAfter(self):
        t = Target()
        p,r = makePromise()
        p = send(p).one(2)
        def _check(res):
            self.failUnlessEqual(res, 3)
        when(p).addCallback(_check)
        r(t)

    def testResolveFailure(self):
        t = Target()
        p,r = makePromise()
        p = send(p).one(2)
        def _check(res):
            self.failUnless(isinstance(res, Failure))
            self.failUnless(res.check(KaboomError))
        when(p).addBoth(_check)
        f = Failure(KaboomError("oops"))
        r(f)


class SendOnly(unittest.TestCase):
    def testNear(self):
        t = Target()
        sendOnly(t).one(1)
        self.failIf(t.calls)
        def _check(res):
            self.failUnlessEqual(t.calls, [("one", 1)])
        d = flushEventualQueue()
        d.addCallback(_check)
        return d

    def testResolveBefore(self):
        t = Target()
        p,r = makePromise()
        r(t)
        sendOnly(p).one(1)
        d = flushEventualQueue()
        def _check(res):
            self.failUnlessEqual(t.calls, [("one", 1)])
        d.addCallback(_check)
        return d

    def testResolveAfter(self):
        t = Target()
        p,r = makePromise()
        sendOnly(p).one(1)
        r(t)
        d = flushEventualQueue()
        def _check(res):
            self.failUnlessEqual(t.calls, [("one", 1)])
        d.addCallback(_check)
        return d

class Chained(unittest.TestCase):
    def tearDown(self):
        return flushEventualQueue()

    def testChain(self):
        p1,r1 = makePromise()
        p2,r2 = makePromise()
        def _check(res):
            self.failUnlessEqual(res, 1)
        when(p1).addCallback(_check)
        r1(p2)
        def _continue(res):
            r2(1)
        flushEventualQueue().addCallback(_continue)
        return when(p1)

    def testFailure(self):
        p1,r1 = makePromise()
        p2,r2 = makePromise()
        r1(p2)
        def _continue(res):
            r2(Failure(KaboomError("foom")))
        flushEventualQueue().addCallback(_continue)
        def _check2(res):
            self.failUnless(isinstance(res, Failure))
            self.failUnless(res.check(KaboomError))
        d = when(p1)
        d.addBoth(_check2)
        return d
