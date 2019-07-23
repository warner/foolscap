
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
    def fail(self, arg):
        raise KaboomError("kaboom!")

class Counter:
    def __init__(self, count=0):
        self.count = count
    def add(self, value):
        self.count += value
        return self

class Send(unittest.TestCase):

    def tearDown(self):
        return flushEventualQueue()

    def testBasic(self):
        p,r = makePromise()
        def _check(res, *args, **kwargs):
            self.assertEqual(res, 1)
            self.assertEqual(args, ("one",))
            self.assertEqual(kwargs, {"two": 2})
        p2 = p._then(_check, "one", two=2)
        self.failUnlessIdentical(p2, p)
        r(1)

    def testBasicFailure(self):
        p,r = makePromise()
        def _check(res, *args, **kwargs):
            self.assertTrue(isinstance(res, Failure))
            self.assertTrue(res.check(KaboomError))
            self.assertEqual(args, ("one",))
            self.assertEqual(kwargs, {"two": 2})
        p2 = p._except(_check, "one", two=2)
        self.failUnlessIdentical(p2, p)
        r(Failure(KaboomError("oops")))

    def testSend(self):
        t = Target()
        p = send(t).one(1)
        self.assertFalse(t.calls)
        def _check(res):
            self.assertEqual(res, 2)
            self.assertEqual(t.calls, [("one", 1)])
        p._then(_check)
        when(p).addCallback(_check) # check it twice to test both syntaxes

    def testOrdering(self):
        t = Target()
        p1 = send(t).one(1)
        p2 = send(t).two(3, k="extra")
        self.assertFalse(t.calls)
        def _check1(res):
            # we can't check t.calls here: the when() clause is not
            # guaranteed to fire before the second send.
            self.assertEqual(res, 2)
        when(p1).addCallback(_check1)
        def _check2(res):
            self.assertEqual(res, None)
        when(p2).addCallback(_check2)
        def _check3(res):
            self.assertEqual(t.calls, [("one", 1),
                                           ("two", 3, 2, {"k": "extra"}),
                                           ])
        fireEventually().addCallback(_check3)

    def testFailure(self):
        t = Target()
        p1 = send(t).fail(0)
        def _check(res):
            self.assertTrue(isinstance(res, Failure))
            self.assertTrue(res.check(KaboomError))
        p1._then(lambda res: self.fail("we were supposed to fail"))
        p1._except(_check)
        when(p1).addBoth(_check)

    def testBadName(self):
        t = Target()
        p1 = send(t).missing(0)
        def _check(res):
            self.assertTrue(isinstance(res, Failure))
            self.assertTrue(res.check(AttributeError))
        when(p1).addBoth(_check)

    def testDisableDataflowStyle(self):
        p,r = makePromise()
        p._useDataflowStyle = False
        def wrong(p):
            p.one(12)
        self.assertRaises(AttributeError, wrong, p)

    def testNoMultipleResolution(self):
        p,r = makePromise()
        r(3)
        self.assertRaises(UsageError, r, 4)

    def testResolveBefore(self):
        t = Target()
        p,r = makePromise()
        r(t)
        p = send(p).one(2)
        def _check(res):
            self.assertEqual(res, 3)
        when(p).addCallback(_check)

    def testResolveAfter(self):
        t = Target()
        p,r = makePromise()
        p = send(p).one(2)
        def _check(res):
            self.assertEqual(res, 3)
        when(p).addCallback(_check)
        r(t)

    def testResolveFailure(self):
        p,r = makePromise()
        p = send(p).one(2)
        def _check(res):
            self.assertTrue(isinstance(res, Failure))
            self.assertTrue(res.check(KaboomError))
        when(p).addBoth(_check)
        f = Failure(KaboomError("oops"))
        r(f)

class Call(unittest.TestCase):
    def tearDown(self):
        return flushEventualQueue()

    def testResolveBefore(self):
        t = Target()
        p1,r = makePromise()
        r(t)
        p2 = p1.one(2)
        def _check(res):
            self.assertEqual(res, 3)
        p2._then(_check)

    def testResolveAfter(self):
        t = Target()
        p1,r = makePromise()
        p2 = p1.one(2)
        def _check(res):
            self.assertEqual(res, 3)
        p2._then(_check)
        r(t)

    def testResolveFailure(self):
        p1,r = makePromise()
        p2 = p1.one(2)
        def _check(res):
            self.assertTrue(isinstance(res, Failure))
            self.assertTrue(res.check(KaboomError))
        p2._then(lambda res: self.fail("this was supposed to fail"))
        p2._except(_check)
        f = Failure(KaboomError("oops"))
        r(f)

class SendOnly(unittest.TestCase):
    def testNear(self):
        t = Target()
        sendOnly(t).one(1)
        self.assertFalse(t.calls)
        def _check(res):
            self.assertEqual(t.calls, [("one", 1)])
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
            self.assertEqual(t.calls, [("one", 1)])
        d.addCallback(_check)
        return d

    def testResolveAfter(self):
        t = Target()
        p,r = makePromise()
        sendOnly(p).one(1)
        r(t)
        d = flushEventualQueue()
        def _check(res):
            self.assertEqual(t.calls, [("one", 1)])
        d.addCallback(_check)
        return d

class Chained(unittest.TestCase):
    def tearDown(self):
        return flushEventualQueue()

    def testResolveToAPromise(self):
        p1,r1 = makePromise()
        p2,r2 = makePromise()
        def _check(res):
            self.assertEqual(res, 1)
        p1._then(_check)
        r1(p2)
        def _continue(res):
            r2(1)
        flushEventualQueue().addCallback(_continue)
        return when(p1)

    def testResolveToABrokenPromise(self):
        p1,r1 = makePromise()
        p2,r2 = makePromise()
        r1(p2)
        def _continue(res):
            r2(Failure(KaboomError("foom")))
        flushEventualQueue().addCallback(_continue)
        def _check2(res):
            self.assertTrue(isinstance(res, Failure))
            self.assertTrue(res.check(KaboomError))
        d = when(p1)
        d.addBoth(_check2)
        return d

    def testChained1(self):
        p1,r = makePromise()
        p2 = p1.add(2)
        p3 = p2.add(3)
        def _check(c):
            self.assertEqual(c.count, 5)
        p3._then(_check)
        r(Counter(0))

    def testChained2(self):
        p1,r = makePromise()
        def _check(c, expected):
            self.assertEqual(c.count, expected)
        p1.add(2).add(3)._then(_check, 6)
        r(Counter(1))
