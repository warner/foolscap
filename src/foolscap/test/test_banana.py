import six
import os
import os.path
from twisted.trial import unittest
from twisted.python.failure import Failure
from twisted.python.components import registerAdapter
from twisted.internet import defer

from foolscap.tokens import ISlicer, Violation, BananaError
from foolscap.tokens import BananaFailure, tokenNames, \
     OPEN, CLOSE, ABORT, INT, LONGINT, NEG, LONGNEG, FLOAT, STRING
from foolscap import slicer, schema, storage, banana, vocab
from foolscap.eventual import fireEventually, flushEventualQueue
from foolscap.slicers.allslicers import RootSlicer, DictUnslicer, TupleUnslicer
from foolscap.constraint import IConstraint
from foolscap.banana import int2b128, long_to_bytes

import io
import struct
from decimal import Decimal

#log.startLogging(sys.stderr)

# some utility functions to manually assemble bytestreams

def bOPEN(opentype, count):
    opentype = six.ensure_binary(opentype)
    assert count < 128
    return six.int2byte(count) + b"\x88" + six.int2byte(len(opentype)) + b"\x82" + opentype
def bCLOSE(count):
    assert count < 128
    return six.int2byte(count) + b"\x89"
def bINT(num):
    if num >=0:
        assert num < 128
        return six.int2byte(num) + b"\x81"
    num = -num
    assert num < 128
    return six.int2byte(num) + b"\x83"
def bSTR(b):
    b = six.ensure_binary(b)
    assert len(b) < 128
    return six.int2byte(len(b)) + b"\x82" + b
def bERROR(b):
    assert isinstance(b, bytes)
    assert len(b) < 128
    return six.int2byte(len(b)) + b"\x8d" + b
def bABORT(count):
    assert count < 128
    return six.int2byte(count) + b"\x8A"
# DecodeTest (24): turns tokens into objects, tests objects and UFs
# EncodeTest (13): turns objects/instance into tokens, tests tokens
# FailedInstanceTests (2): 1:turn instances into tokens and fail, 2:reverse

# ByteStream (3): turn object into bytestream, test bytestream
# InboundByteStream (14): turn bytestream into object, check object
#                         with or without constraints
# ThereAndBackAgain (20): encode then decode object, check object

# VocabTest1 (2): test setOutgoingVocabulary and an inbound Vocab sequence
# VocabTest2 (1): send object, test bytestream w/vocab-encoding
# Sliceable (2): turn instance into tokens (with ISliceable, test tokens

def tOPEN(count):
    return ("OPEN", count)
def tCLOSE(count):
    return ("CLOSE", count)
tABORT = ("ABORT",)

class TokenBanana(banana.Banana):
    """this Banana formats tokens as strings, numbers, and ('OPEN',) tuples
    instead of bytes. Used for testing purposes."""

    def sendOpen(self):
        openID = self.openCount
        self.openCount += 1
        self.sendToken(("OPEN", openID))
        return openID

    def sendToken(self, token):
        #print token
        self.tokens.append(token)

    def sendClose(self, openID):
        self.sendToken(("CLOSE", openID))

    def sendAbort(self, count=0):
        self.sendToken(("ABORT",))

    def sendError(self, msg):
        #print "TokenBanana.sendError(%s)" % msg
        pass

    def testSlice(self, obj):
        assert len(self.slicerStack) == 1
        assert isinstance(self.slicerStack[0][0], RootSlicer)
        self.tokens = []
        d = self.send(obj)
        d.addCallback(self._testSlice_1)
        return d
    def _testSlice_1(self, res):
        assert len(self.slicerStack) == 1
        assert not self.rootSlicer.sendQueue
        assert isinstance(self.slicerStack[0][0], RootSlicer)
        return self.tokens

    def __del__(self):
        assert not self.rootSlicer.sendQueue

def untokenize(tokens):
    data = []
    for t in tokens:
        if isinstance(t, tuple):
            if t[0] == "OPEN":
                int2b128(t[1], data.append)
                data.append(OPEN)
            elif t[0] == "CLOSE":
                int2b128(t[1], data.append)
                data.append(CLOSE)
            elif t[0] == "ABORT":
                data.append(ABORT)
            else:
                raise RuntimeError("bad token")
        else:
            if isinstance(t, int):
                if t >= 2**31:
                    s = long_to_bytes(t)
                    int2b128(len(s), data.append)
                    data.append(LONGINT)
                    data.append(s)
                elif t >= 0:
                    int2b128(t, data.append)
                    data.append(INT)
                elif -t > 2**31: # NEG is [-2**31, 0)
                    s = long_to_bytes(-t)
                    int2b128(len(s), data.append)
                    data.append(LONGNEG)
                    data.append(s)
                else:
                    int2b128(-t, data.append)
                    data.append(NEG)
            elif isinstance(t, float):
                data.append(FLOAT)
                data.append(struct.pack("!d", t))
            elif isinstance(t, (str, bytes)):
                t = six.ensure_binary(t)
                int2b128(len(t), data.append)
                data.append(STRING)
                data.append(t)
            else:
                raise BananaError("could not send object: %s" % repr(t))
    return b"".join(data)

class UnbananaTestMixin:
    def setUp(self):
        self.hangup = False
        self.banana = storage.StorageBanana()
        self.banana.slicerClass = storage.StorageRootSlicer
        self.banana.unslicerClass = storage.StorageRootUnslicer
        self.banana.connectionMade()
    def tearDown(self):
        if not self.hangup:
            self.assertTrue(len(self.banana.receiveStack) == 1)
            self.assertTrue(isinstance(self.banana.receiveStack[0],
                                       storage.StorageRootUnslicer))

    def do(self, tokens):
        self.banana.violation = None
        self.banana.disconnectReason = None
        self.assertTrue(len(self.banana.receiveStack) == 1)
        self.assertTrue(isinstance(self.banana.receiveStack[0],
                                   storage.StorageRootUnslicer))
        data = untokenize(tokens)
        results = []
        d = self.banana.prepare()
        d.addCallback(results.append)
        self.banana.dataReceived(data)
        # we expect everything here to be synchronous
        if len(results) == 1:
            return results[0]
        self.assertTrue(self.banana.violation or self.banana.disconnectReason)
        return None

    def shouldFail(self, tokens):
        obj = self.do(tokens)
        self.assertTrue(obj is None, "object was produced: %s" % obj)
        self.assertTrue(self.banana.violation, "didn't fail, ret=%s" % obj)
        self.assertFalse(self.banana.disconnectReason,
                    "connection was dropped: %s" % \
                    self.banana.disconnectReason)
        return self.banana.violation

    def shouldDropConnection(self, tokens):
        self.banana.logReceiveErrors = False
        try:
            obj = self.do(tokens)
            self.fail("connection was supposed to be dropped, got obj=%s"
                      % (obj,))
        except BananaError:
            f = self.banana.disconnectReason
            if not isinstance(f, Failure):
                self.fail("disconnectReason wasn't a Failure: %s" % f)
            if not f.check(BananaError):
                self.fail("wrong exception type: %s" % f)
            self.hangup = True # to stop the tearDown check
            self.assertFalse(self.banana.violation)
            return f


    def failIfBananaFailure(self, res):
        if isinstance(res, BananaFailure):
            # something went wrong
            print("There was a failure while Unbananaing '%s':" % res.where)
            print(res.getTraceback())
            self.fail("BananaFailure")

    def checkBananaFailure(self, res, where, failtype=None):
        print(res)
        self.assertTrue(isinstance(res, BananaFailure))
        if failtype:
            self.assertTrue(res.failure,
                            "No Failure object in BananaFailure")
            if not res.check(failtype):
                print("Wrong exception (wanted '%s'):" % failtype)
                print(res.getTraceback())
                self.fail("Wrong exception (wanted '%s'):" % failtype)
        self.assertEqual(res.where, where)
        self.banana.object = None # to stop the tearDown check TODO ??

class TestTransport(io.BytesIO):
    disconnectReason = None
    def loseConnection(self):
        pass

class _None: pass

class TestBananaMixin:
    def setUp(self):
        self.makeBanana()

    def makeBanana(self):
        self.banana = storage.StorageBanana()
        self.banana.slicerClass = storage.StorageRootSlicer
        self.banana.unslicerClass = storage.StorageRootUnslicer
        self.banana.transport = TestTransport()
        self.banana.connectionMade()

    def encode(self, obj):
        d = self.banana.send(obj)
        d.addCallback(lambda res: self.banana.transport.getvalue())
        return d

    def clearOutput(self):
        self.banana.transport = TestTransport()

    def decode(self, stream):
        self.banana.violation = None
        results = []
        d = self.banana.prepare()
        d.addCallback(results.append)
        self.banana.dataReceived(stream)
        # we expect everything here to be synchronous
        if len(results) == 1:
            return results[0]
        self.assertTrue(self.banana.violation or self.banana.disconnectReason)
        return None

    def shouldDecode(self, stream):
        obj = self.decode(stream)
        self.assertFalse(self.banana.violation)
        self.assertFalse(self.banana.disconnectReason)
        self.assertEqual(len(self.banana.receiveStack), 1)
        return obj

    def shouldFail(self, stream):
        obj = self.decode(stream)
        # Violations on a StorageBanana will continue to decode objects, but
        # will set b.violation, which we can examine afterwards
        self.assertEqual(obj, None)
        self.assertFalse(self.banana.disconnectReason,
                    "connection was dropped: %s" % \
                    self.banana.disconnectReason)
        self.assertEqual(len(self.banana.receiveStack), 1)
        f = self.banana.violation
        if not f:
            self.fail("didn't fail")
        if not isinstance(f, BananaFailure):
            self.fail("violation wasn't a BananaFailure: %s" % f)
        if not f.check(Violation):
            self.fail("wrong exception type: %s" % f)
        return f

    def shouldDropConnection(self, stream):
        self.banana.logReceiveErrors = False # trial hooks log.err
        try:
            obj = self.decode(stream)
            self.fail("decode worked! got '%s', expected dropConnection" \
                      % (obj,))
        except BananaError:
            # the receiveStack is allowed to be non-empty here, since we've
            # dropped the connection anyway
            f = self.banana.disconnectReason
            if not f:
                self.fail("didn't fail")
            if not isinstance(f, Failure):
                self.fail("disconnectReason wasn't a Failure: %s" % f)
            if not f.check(BananaError):
                self.fail("wrong exception type: %s" % f)
            self.makeBanana() # need a new one, we squished the last one
            return f

    def wantEqual(self, got, wanted):
        if got != wanted:
            print()
            print("wanted: '%s'" % wanted, repr(wanted))
            print("got   : '%s'" % got, repr(got))
            self.fail("did not get expected string")

    def loop(self, obj):
        self.clearOutput()
        d = self.encode(obj)
        d.addCallback(self.shouldDecode)
        return d

    def looptest(self, obj, newvalue=_None):
        if newvalue is _None:
            newvalue = obj
        d = self.loop(obj)
        d.addCallback(self._looptest_1, newvalue)
        return d
    def _looptest_1(self, obj2, newvalue):
        self.assertEqual(obj2, newvalue)
        self.assertEqual(type(obj2), type(newvalue))

def join(*args):
    return b"".join(args)



class BrokenDictUnslicer(DictUnslicer):
    dieInFinish = 0

    def receiveKey(self, key):
        if key == b"die":
            raise Violation("aaagh")
        if key == b"please_die_in_finish":
            self.dieInFinish = 1
        DictUnslicer.receiveKey(self, key)

    def receiveValue(self, value):
        if value == b"die":
            raise Violation("aaaaaaaaargh")
        DictUnslicer.receiveValue(self, value)

    def receiveClose(self):
        if self.dieInFinish:
            raise Violation("dead in receiveClose()")
        DictUnslicer.receiveClose(self)
        return None, None

class ReallyBrokenDictUnslicer(DictUnslicer):
    def start(self, count):
        raise Violation("dead in start")


class DecodeTest(UnbananaTestMixin, unittest.TestCase):
    def setUp(self):
        UnbananaTestMixin.setUp(self)
        self.banana.logReceiveErrors = False
        d ={ ('dict1',): BrokenDictUnslicer,
             ('dict2',): ReallyBrokenDictUnslicer,
             }
        self.banana.rootUnslicer.topRegistries.insert(0, d)
        self.banana.rootUnslicer.openRegistries.insert(0, d)

    def test_simple_list(self):
        "simple list"
        res = self.do([tOPEN(0),'list',1,2,3,"a","b",tCLOSE(0)])
        self.assertEqual(res, [1,2,3,b'a',b'b'])

    def test_aborted_list(self):
        "aborted list"
        f = self.shouldFail([tOPEN(0),'list', 1, tABORT, tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1]")
        self.assertEqual(f.value.args[0], "ABORT received")

    def test_aborted_list2(self):
        "aborted list2"
        f = self.shouldFail([tOPEN(0),'list', 1, tABORT,
                             tOPEN(1),'list', 2, 3, tCLOSE(1),
                             tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1]")
        self.assertEqual(f.value.args[0], "ABORT received")

    def test_aborted_list3(self):
        "aborted list3"
        f = self.shouldFail([tOPEN(0),'list', 1,
                              tOPEN(1),'list', 2, 3, 4,
                               tOPEN(2),'list', 5, 6, tABORT, tCLOSE(2),
                              tCLOSE(1),
                             tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1].[3].[2]")
        self.assertEqual(f.value.args[0], "ABORT received")

    def test_nested_list(self):
        "nested list"
        res = self.do([tOPEN(0),'list',1,2,
                        tOPEN(1),'list',3,4,tCLOSE(1),
                       tCLOSE(0)])
        self.assertEqual(res, [1,2,[3,4]])

    def test_list_with_tuple(self):
        "list with tuple"
        res = self.do([tOPEN(0),'list',1,2,
                        tOPEN(1),'tuple',3,4,tCLOSE(1),
                       tCLOSE(0)])
        self.assertEqual(res, [1,2,(3,4)])

    def test_dict(self):
        "dict"
        res = self.do([tOPEN(0),'dict',"a",1,"b",2,tCLOSE(0)])
        self.assertEqual(res, {b'a':1, b'b':2})

    def test_dict_with_duplicate_keys(self):
        "dict with duplicate keys"
        f = self.shouldDropConnection([tOPEN(0),'dict',
                                       1,"a",1,"b",
                                       tCLOSE(0)])
        self.assertEqual(f.value.where, "<RootUnslicer>.{}")
        self.assertEqual(f.value.args[0], "duplicate key '1'")

    def test_dict_with_list(self):
        "dict with list"
        res = self.do([tOPEN(0),'dict',
                        "a",1,
                        "b", tOPEN(1),'list', 2, 3, tCLOSE(1),
                       tCLOSE(0)])
        self.assertEqual(res, {b'a':1, b'b':[2,3]})

    def test_dict_with_tuple_as_key(self):
        "dict with tuple as key"
        res = self.do([tOPEN(0),'dict',
                        tOPEN(1),'tuple', 1, 2, tCLOSE(1), "a",
                       tCLOSE(0)])
        self.assertEqual(res, {(1,2):b'a'})

    def test_dict_with_mutable_key(self):
        "dict with mutable key"
        f = self.shouldDropConnection([tOPEN(0),'dict',
                                        tOPEN(1),'list', 1, 2, tCLOSE(1), "a",
                                       tCLOSE(0)])
        self.assertEqual(f.value.where, "<RootUnslicer>.{}")
        self.assertEqual(f.value.args[0], "unhashable key '[1, 2]'")

    def test_ref1(self):
        res = self.do([tOPEN(0),'list',
                        tOPEN(1),'list', 1, 2, tCLOSE(1),
                        tOPEN(2),'reference', 1, tCLOSE(2),
                       tCLOSE(0)])
        self.failIfBananaFailure(res)
        self.assertEqual(res, [[1,2], [1,2]])
        self.failUnlessIdentical(res[0], res[1])

    def test_ref2(self):
        res = self.do([tOPEN(0),'list',
                       tOPEN(1),'list', 1, 2, tCLOSE(1),
                       tOPEN(2),'reference', 0, tCLOSE(2),
                       tCLOSE(0)])
        self.failIfBananaFailure(res)
        wanted = [[1,2]]
        wanted.append(wanted)
        # python2.3 is clever and can do
        #  self.failUnlessEqual(res, wanted)
        # python2.4 is not, so we do it by hand
        self.assertEqual(len(res), len(wanted))
        self.assertEqual(res[0], wanted[0])
        self.failUnlessIdentical(res, res[1])

    def test_ref3(self):
        res = self.do([tOPEN(0),'list',
                        tOPEN(1),'tuple', 1, 2, tCLOSE(1),
                        tOPEN(2),'reference', 1, tCLOSE(2),
                       tCLOSE(0)])
        self.failIfBananaFailure(res)
        wanted = [(1,2)]
        wanted.append(wanted[0])
        self.assertEqual(res, wanted)
        self.failUnlessIdentical(res[0], res[1])

    def test_ref4(self):
        res = self.do([tOPEN(0),'list',
                        tOPEN(1),'dict', "a", 1, tCLOSE(1),
                        tOPEN(2),'reference', 1, tCLOSE(2),
                       tCLOSE(0)])
        self.failIfBananaFailure(res)
        wanted = [{b"a":1}]
        wanted.append(wanted[0])
        self.assertEqual(res, wanted)
        self.failUnlessIdentical(res[0], res[1])

    def test_ref5(self):
        # The Droste Effect: a list that contains itself
        res = self.do([tOPEN(0),'list',
                        5,
                        6,
                        tOPEN(1),'reference', 0, tCLOSE(1),
                        7,
                       tCLOSE(0)])
        self.failIfBananaFailure(res)
        wanted = [5,6]
        wanted.append(wanted)
        wanted.append(7)
        #self.failUnlessEqual(res, wanted)
        self.assertEqual(len(res), len(wanted))
        self.assertEqual(res[0:2], wanted[0:2])
        self.failUnlessIdentical(res[2], res)
        self.assertEqual(res[3], wanted[3])

    def test_ref6(self):
        # everybody's favorite "([(ref0" test case. A tuple of a list of a
        # tuple of the original tuple. Such cycles must always have a
        # mutable container in them somewhere, or they couldn't be
        # constructed, but the resulting object involves a lot of deferred
        # results because the mutable list is the *only* object that can
        # be created without dependencies
        res = self.do([tOPEN(0),'tuple',
                        tOPEN(1),'list',
                         tOPEN(2),'tuple',
                          tOPEN(3),'reference', 0, tCLOSE(3),
                         tCLOSE(2),
                        tCLOSE(1),
                       tCLOSE(0)])
        self.failIfBananaFailure(res)
        wanted = ([],)
        wanted[0].append((wanted,))
        #self.failUnlessEqual(res, wanted)
        self.assertTrue(type(res) is tuple)
        self.assertTrue(len(res) == 1)
        self.assertTrue(type(res[0]) is list)
        self.assertTrue(len(res[0]) == 1)
        self.assertTrue(type(res[0][0]) is tuple)
        self.assertTrue(len(res[0][0]) == 1)
        self.failUnlessIdentical(res[0][0][0], res)

        # TODO: need a test where tuple[0] and [1] are deferred, but
        # tuple[0] becomes available before tuple[2] is inserted. Not sure
        # this is possible, but it would improve test coverage in
        # TupleUnslicer

    def test_failed_dict1(self):
        # dies during open because of bad opentype
        f = self.shouldFail([tOPEN(0),'list', 1,
                              tOPEN(1),"bad",
                               "a", 2,
                               "b", 3,
                              tCLOSE(1),
                             tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1]")
        self.assertEqual(f.value.args[0], "unknown OPEN type ('bad',)")

    def test_failed_dict2(self):
        # dies during start
        f = self.shouldFail([tOPEN(0),'list', 1,
                             tOPEN(1),'dict2', "a", 2, "b", 3, tCLOSE(1),
                             tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1].{}")
        self.assertEqual(f.value.args[0], "dead in start")

    def test_failed_dict3(self):
        # dies during key
        f = self.shouldFail([tOPEN(0),'list', 1,
                             tOPEN(1),'dict1', "a", 2, "die", tCLOSE(1),
                             tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1].{}")
        self.assertEqual(f.value.args[0], "aaagh")

        res = self.do([tOPEN(2),'list', 3, 4, tCLOSE(2)])
        self.assertEqual(res, [3,4])

    def test_failed_dict4(self):
        # dies during value
        f = self.shouldFail([tOPEN(0),'list', 1,
                              tOPEN(1),'dict1',
                               "a", 2,
                               3, "die",
                              tCLOSE(1),
                             tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1].{}[3]")
        self.assertEqual(f.value.args[0], "aaaaaaaaargh")

    def test_failed_dict5(self):
        # dies during finish
        f = self.shouldFail([tOPEN(0),'list', 1,
                              tOPEN(1),'dict1',
                               "a", 2,
                               "please_die_in_finish", 3,
                              tCLOSE(1),
                             tCLOSE(0)])
        self.assertTrue(isinstance(f, BananaFailure))
        self.assertTrue(f.check(Violation))
        self.assertEqual(f.value.where, "<RootUnslicer>.[1].{}")
        self.assertEqual(f.value.args[0], "dead in receiveClose()")

class EncodeTest(unittest.TestCase):
    def setUp(self):
        self.banana = TokenBanana()
        self.banana.slicerClass = storage.StorageRootSlicer
        self.banana.unslicerClass = storage.StorageRootUnslicer
        self.banana.connectionMade()
    def do(self, obj):
        return self.banana.testSlice(obj)
    def tearDown(self):
        self.assertTrue(len(self.banana.slicerStack) == 1)
        self.assertTrue(isinstance(self.banana.slicerStack[0][0], RootSlicer))

    def testList(self):
        d = self.do([1,2])
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'list', 1, 2, tCLOSE(0)])
        return d

    def testTuple(self):
        d = self.do((1,2))
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'tuple', 1, 2, tCLOSE(0)])
        return d

    def testNestedList(self):
        d = self.do([1,2,[3,4]])
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'list', 1, 2,
                        tOPEN(1),b'list', 3, 4, tCLOSE(1),
                       tCLOSE(0)])
        return d

    def testNestedList2(self):
        d = self.do([1,2,(3,4,[5, b"hi"])])
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'list', 1, 2,
                        tOPEN(1),b'tuple', 3, 4,
                         tOPEN(2),b'list', 5, b"hi", tCLOSE(2),
                        tCLOSE(1),
                       tCLOSE(0)])
        return d

    def testDict(self):
        d = self.do({b'a': 1, b'b': 2})
        d.addCallback(lambda res:
                      self.assertTrue(
            res == [tOPEN(0),b'dict', b'a', 1, b'b', 2, tCLOSE(0)] or
            res == [tOPEN(0),b'dict', b'b', 2, b'a', 1, tCLOSE(0)]))
        return d

    def test_ref1(self):
        l = [1,2]
        obj = [l,l]
        d = self.do(obj)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'list',
                        tOPEN(1),b'list', 1, 2, tCLOSE(1),
                        tOPEN(2),b'reference', 1, tCLOSE(2),
                       tCLOSE(0)])
        return d

    def test_ref2(self):
        obj = [[1,2]]
        obj.append(obj)
        d = self.do(obj)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'list',
                        tOPEN(1),b'list', 1, 2, tCLOSE(1),
                        tOPEN(2),b'reference', 0, tCLOSE(2),
                       tCLOSE(0)])
        return d

    def test_ref3(self):
        obj = [(1,2)]
        obj.append(obj[0])
        d = self.do(obj)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'list',
                        tOPEN(1),b'tuple', 1, 2, tCLOSE(1),
                        tOPEN(2),b'reference', 1, tCLOSE(2),
                       tCLOSE(0)])
        return d

    def test_ref4(self):
        obj = [{b"a":1}]
        obj.append(obj[0])
        d = self.do(obj)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'list',
                        tOPEN(1),b'dict', b"a", 1, tCLOSE(1),
                        tOPEN(2),b'reference', 1, tCLOSE(2),
                       tCLOSE(0)])
        return d

    def test_ref6(self):
        # everybody's favorite "([(ref0" test case.
        obj = ([],)
        obj[0].append((obj,))
        d = self.do(obj)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'tuple',
                        tOPEN(1),b'list',
                         tOPEN(2),b'tuple',
                          tOPEN(3),b'reference', 0, tCLOSE(3),
                         tCLOSE(2),
                        tCLOSE(1),
                       tCLOSE(0)])
        return d

    def test_refdict1(self):
        # a dictionary with a value that isn't available right away
        d0 = {1: b"a"}
        t = (d0,)
        d0[2] = t
        d = self.do(d0)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),b'dict',
                        1, b"a",
                        2, tOPEN(1),b'tuple',
                            tOPEN(2),b'reference', 0, tCLOSE(2),
                           tCLOSE(1),
                       tCLOSE(0)])
        return d


class ErrorfulSlicer(slicer.BaseSlicer):
    def __init__(self, mode, shouldSucceed, ignoreChildDeath=False):
        self.mode = mode
        self.items = [1]
        self.items.append(mode)
        self.items.append(3)
        #if mode not in ('success', 'deferred-good'):
        if not shouldSucceed:
            self.items.append("unreached")
        self.counter = -1
        self.childDied = False
        self.ignoreChildDeath = ignoreChildDeath

    def slice(self, streamable, banana):
        self.streamable = streamable
        if self.mode == "slice":
            raise Violation("slice failed")
        return iter(self)

    def __iter__(self):
        return self

    def __next__(self):
        self.counter += 1
        if not self.items:
            raise StopIteration
        obj = self.items.pop(0)
        if obj == "next":
            raise Violation("next failed")
        if obj == "deferred-good":
            return fireEventually(None)
        if obj == "deferred-bad":
            d = defer.Deferred()
            # the Banana should bail, so don't bother with the timer
            return d
        if obj == "newSlicerFor":
            unserializable = open("unserializable.txt", "w")
            # Hah! Serialize that!
            return unserializable
        if obj == "unreached":
            print("error: slicer.next called after it should have stopped")
        return obj
    next = __next__

    def childAborted(self, v):
        self.childDied = True
        if self.ignoreChildDeath:
            return None
        return v

    def describe(self):
        return "ErrorfulSlicer[%d]" % self.counter

# Slicer creation (schema pre-validation?)
# .slice (called in pushSlicer) ?
# .slice.next raising Violation
# .slice.next returning Deferred when streaming isn't allowed
# .sendToken (non-primitive token, can't happen)
# .newSlicerFor (no ISlicer adapter)
# top.childAborted

class EncodeFailureTest(unittest.TestCase):
    def setUp(self):
        self.banana = TokenBanana()
        self.banana.slicerClass = storage.StorageRootSlicer
        self.banana.unslicerClass = storage.StorageRootUnslicer
        self.banana.connectionMade()

    def tearDown(self):
        if os.path.exists("unserializable.txt"):
            os.remove("unserializable.txt")
        return flushEventualQueue()

    def send(self, obj):
        self.banana.tokens = []
        d = self.banana.send(obj)
        d.addCallback(lambda res: self.banana.tokens)
        return d

    def testSuccess1(self):
        # make sure the test slicer works correctly
        s = ErrorfulSlicer(b"success", True)
        d = self.send(s)
        d.addCallback(self.assertEqual,
                      [('OPEN', 0), 1, b'success', 3, ('CLOSE', 0)])
        return d

    def testSuccessStreaming(self):
        # success
        s = ErrorfulSlicer("deferred-good", True)
        d = self.send(s)
        d.addCallback(self.assertEqual,
                      [('OPEN', 0), 1, 3, ('CLOSE', 0)])
        return d

    def test1(self):
        # failure during .slice (called from pushSlicer)
        s = ErrorfulSlicer("slice", False)
        d = self.send(s)
        d.addCallbacks(lambda res: self.fail("this was supposed to fail"),
                       self._test1_1)
        return d
    def _test1_1(self, e):
        e.trap(Violation)
        self.assertEqual(e.value.where, "<RootSlicer>")
        self.assertEqual(e.value.args, ("slice failed",))
        self.assertEqual(self.banana.tokens, [])

    def test2(self):
        # .slice.next raising Violation
        s = ErrorfulSlicer("next", False)
        d = self.send(s)
        d.addCallbacks(lambda res: self.fail("this was supposed to fail"),
                       self._test2_1)
        return d
    def _test2_1(self, e):
        e.trap(Violation)
        self.assertEqual(e.value.where, "<RootSlicer>.ErrorfulSlicer[1]")
        self.assertEqual(e.value.args, ("next failed",))
        self.assertEqual(self.banana.tokens,
                             [('OPEN', 0), 1, ('ABORT',), ('CLOSE', 0)])

    def test3(self):
        # .slice.next returning Deferred when streaming isn't allowed
        self.banana.rootSlicer.allowStreaming(False)
        s = ErrorfulSlicer("deferred-bad", False)
        d = self.send(s)
        d.addCallbacks(lambda res: self.fail("this was supposed to fail"),
                       self._test3_1)
        return d
    def _test3_1(self, e):
        e.trap(Violation)
        self.assertEqual(e.value.where, "<RootSlicer>.ErrorfulSlicer[1]")
        self.assertEqual(e.value.args, ("parent not streamable",))
        self.assertEqual(self.banana.tokens,
                             [('OPEN', 0), 1, ('ABORT',), ('CLOSE', 0)])

    def test4(self):
        # .newSlicerFor (no ISlicer adapter), parent propagates upwards
        s = ErrorfulSlicer("newSlicerFor", False)
        d = self.send(s)
        d.addCallbacks(lambda res: self.fail("this was supposed to fail"),
                       self._test4_1, errbackArgs=(s,))
        return d
    def _test4_1(self, e, s):
        e.trap(Violation)
        self.assertEqual(e.value.where, "<RootSlicer>.ErrorfulSlicer[1]")
        # this used to assert that the error included a description of the
        # object that could not be serialized. The open filehandle we use was
        # presented as "<open file..>" on py2, and "<_io.TextIOWrapper..>" on
        # py3, and it was too difficult to unify these representations, so I
        # just removed the detailed check.
        self.failUnlessSubstring("cannot serialize", e.value.args[0])
        self.assertTrue(s.childDied)
        self.assertEqual(self.banana.tokens,
                             [('OPEN', 0), 1, ('ABORT',), ('CLOSE', 0)])

    def test5(self):
        # .newSlicerFor (no ISlicer adapter), parent ignores
        s = ErrorfulSlicer("newSlicerFor", True, True)
        d = self.send(s)
        d.addCallback(lambda res:
                      self.assertTrue(s.childDied)) # noticed but ignored
        d.addCallback(lambda res:
                      self.assertEqual(self.banana.tokens,
                                           [('OPEN', 0), 1, 3, ('CLOSE', 0)]))
        return d

# receiving side:
#  long header (>64 bytes)
#  checkToken (top.openerCheckToken)
#  checkToken (top.checkToken)
#  typebyte == LIST (oldbanana)
#  bad VOCAB key # TODO
#  too-long vocab key
#  bad FLOAT encoding  # I don't there is such a thing
#  top.receiveClose
#  top.finish
#  top.reportViolation
#  oldtop.finish (in from handleViolation)
#  top.doOpen
#  top.start
# plus all of these when discardCount != 0

class ErrorfulUnslicer(slicer.BaseUnslicer):
    debug = False

    def doOpen(self, opentype):
        if self.mode == "doOpen":
            raise Violation("boom")
        return slicer.BaseUnslicer.doOpen(self, opentype)

    def start(self, count):
        self.mode = self.protocol.mode
        self.ignoreChildDeath = self.protocol.ignoreChildDeath
        if self.debug:
            print("ErrorfulUnslicer.start, mode=%s" % self.mode)
        self.list = []
        if self.mode == "start":
            raise Violation("boom")

    def openerCheckToken(self, typebyte, size, opentype):
        if self.debug:
            print("ErrorfulUnslicer.openerCheckToken(%s)" % tokenNames[typebyte])
        if self.mode == "openerCheckToken":
            raise Violation("boom")
        return slicer.BaseUnslicer.openerCheckToken(self, typebyte,
                                                    size, opentype)
    def checkToken(self, typebyte, size):
        if self.debug:
            print("ErrorfulUnslicer.checkToken(%s)" % tokenNames[typebyte])
        if self.mode == "checkToken":
            raise Violation("boom")
        if self.mode == "checkToken-OPEN" and typebyte == OPEN:
            raise Violation("boom")
        return slicer.BaseUnslicer.checkToken(self, typebyte, size)

    def receiveChild(self, obj, ready_deferred=None):
        if self.debug: print("ErrorfulUnslicer.receiveChild", obj)
        if self.mode == "receiveChild":
            raise Violation("boom")
        self.list.append(obj)

    def reportViolation(self, why):
        if self.ignoreChildDeath:
            return None
        return why

    def receiveClose(self):
        if self.debug: print("ErrorfulUnslicer.receiveClose")
        if self.protocol.mode == "receiveClose":
            raise Violation("boom")
        return self.list, None

    def finish(self):
        if self.debug: print("ErrorfulUnslicer.receiveClose")
        if self.protocol.mode == "finish":
            raise Violation("boom")

    def describe(self):
        return "errorful"

class FailingUnslicer(TupleUnslicer):
    def receiveChild(self, obj, ready_deferred=None):
        if self.protocol.mode != "success":
            raise Violation("foom")
        return TupleUnslicer.receiveChild(self, obj, ready_deferred)
    def describe(self):
        return "failing"

class DecodeFailureTest(TestBananaMixin, unittest.TestCase):
    listStream = join(bOPEN(b"errorful", 0), bINT(1), bINT(2), bCLOSE(0))
    nestedStream = join(bOPEN(b"errorful", 0), bINT(1),
                        bOPEN(b"list", 1), bINT(2), bINT(3), bCLOSE(1),
                        bCLOSE(0))
    nestedStream2 = join(bOPEN(b"failing", 0), bSTR(b"a"),
                          bOPEN(b"errorful", 1), bINT(1),
                           bOPEN(b"list", 2), bINT(2), bINT(3), bCLOSE(2),
                          bCLOSE(1),
                          bSTR(b"b"),
                          bCLOSE(0),
                         )
    abortStream = join(bOPEN(b"errorful", 0), bINT(1),
                        bOPEN(b"list", 1),
                         bINT(2), bABORT(1), bINT(3),
                        bCLOSE(1),
                       bCLOSE(0))

    def setUp(self):
        TestBananaMixin.setUp(self)
        d = {('errorful',): ErrorfulUnslicer,
             ('failing',): FailingUnslicer,
             }
        self.banana.rootUnslicer.topRegistries.insert(0, d)
        self.banana.rootUnslicer.openRegistries.insert(0, d)
        self.banana.ignoreChildDeath = False

    def testSuccess1(self):
        self.banana.mode = "success"
        o = self.shouldDecode(self.listStream)
        self.assertEqual(o, [1,2])
        o = self.shouldDecode(self.nestedStream)
        self.assertEqual(o, [1,[2,3]])
        o = self.shouldDecode(self.nestedStream2)
        self.assertEqual(o, (b"a",[1,[2,3]],b"b"))

    def testLongHeader(self):
        # would be a string but the header is too long
        s = b"\x01" * 66 + b"\x82" + b"stupidly long string"
        f = self.shouldDropConnection(s)
        self.assertTrue(f.value.args[0].startswith("token prefix is limited to 64 bytes"))

    def testLongHeader2(self):
        # bad string while discarding
        s = b"\x01" * 66 + b"\x82" + b"stupidly long string"
        s = bOPEN("errorful",0) + bINT(1) + s + bINT(2) + bCLOSE(0)
        self.banana.mode = "start"
        f = self.shouldDropConnection(s)
        self.assertTrue(f.value.args[0].startswith("token prefix is limited to 64 bytes"))

    def testCheckToken1(self):
        # violation raised in top.openerCheckToken
        self.banana.mode = "openerCheckToken"
        f = self.shouldFail(self.nestedStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        self.testSuccess1()

    def testCheckToken2(self):
        # violation raised in top.openerCheckToken, but the error is
        # absorbed
        self.banana.mode = "openerCheckToken"
        self.banana.ignoreChildDeath = True
        o = self.shouldDecode(self.nestedStream)
        self.assertEqual(o, [1])
        self.testSuccess1()

    def testCheckToken3(self):
        # violation raised in top.checkToken
        self.banana.mode = "checkToken"
        f = self.shouldFail(self.listStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        self.testSuccess1()

    def testCheckToken4(self):
        # violation raised in top.checkToken, but only for the OPEN that
        # starts the nested list. The error is absorbed.
        self.banana.mode = "checkToken-OPEN"
        self.banana.ignoreChildDeath = True
        o = self.shouldDecode(self.nestedStream)
        self.assertEqual(o, [1])
        self.testSuccess1()

    def testCheckToken5(self):
        # violation raised in top.checkToken, while discarding
        self.banana.mode = "checkToken"
        #self.banana.debugReceive=True
        f = self.shouldFail(self.nestedStream2)
        self.assertEqual(f.value.where, "<RootUnslicer>.failing")
        self.assertEqual(f.value.args[0], "foom")
        self.testSuccess1()

    def testReceiveChild1(self):
        self.banana.mode = "receiveChild"
        f = self.shouldFail(self.listStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        self.testSuccess1()

    def testReceiveChild2(self):
        self.banana.mode = "receiveChild"
        f = self.shouldFail(self.nestedStream2)
        self.assertEqual(f.value.where, "<RootUnslicer>.failing")
        self.assertEqual(f.value.args[0], "foom")
        self.testSuccess1()

    def testReceiveChild3(self):
        self.banana.mode = "receiveChild"
        # the ABORT should be ignored, since it is in the middle of a
        # sequence which is being ignored. One possible bug is that the
        # ABORT delivers a second Violation. In this test, we only record
        # the last Violation, so we'll catch that case.
        f = self.shouldFail(self.abortStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        # (the other Violation would be at 'root', of type 'ABORT received'
        self.testSuccess1()

    def testReceiveClose1(self):
        self.banana.mode = "receiveClose"
        f = self.shouldFail(self.listStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        self.testSuccess1()

    def testReceiveClose2(self):
        self.banana.mode = "receiveClose"
        f = self.shouldFail(self.nestedStream2)
        self.assertEqual(f.value.where, "<RootUnslicer>.failing")
        self.assertEqual(f.value.args[0], "foom")
        self.testSuccess1()

    def testFinish1(self):
        self.banana.mode = "finish"
        f = self.shouldFail(self.listStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        self.testSuccess1()

    def testFinish2(self):
        self.banana.mode = "finish"
        f = self.shouldFail(self.nestedStream2)
        self.assertEqual(f.value.where, "<RootUnslicer>.failing")
        self.assertEqual(f.value.args[0], "foom")
        self.testSuccess1()

    def testStart1(self):
        self.banana.mode = "start"
        f = self.shouldFail(self.listStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        self.testSuccess1()

    def testStart2(self):
        self.banana.mode = "start"
        f = self.shouldFail(self.nestedStream2)
        self.assertEqual(f.value.where, "<RootUnslicer>.failing")
        self.assertEqual(f.value.args[0], "foom")
        self.testSuccess1()

    def testDoOpen1(self):
        self.banana.mode = "doOpen"
        f = self.shouldFail(self.nestedStream)
        self.assertEqual(f.value.where, "<RootUnslicer>.errorful")
        self.assertEqual(f.value.args[0], "boom")
        self.testSuccess1()

    def testDoOpen2(self):
        self.banana.mode = "doOpen"
        f = self.shouldFail(self.nestedStream2)
        self.assertEqual(f.value.where, "<RootUnslicer>.failing")
        self.assertEqual(f.value.args[0], "foom")
        self.testSuccess1()

class ByteStream(TestBananaMixin, unittest.TestCase):

    def test_list(self):
        obj = [1,2]
        expected = join(bOPEN("list", 0),
                         bINT(1), bINT(2),
                        bCLOSE(0),
                        )
        d = self.encode(obj)
        d.addCallback(self.wantEqual, expected)
        return d

    def test_ref6(self):
        # everybody's favorite "([(ref0" test case.
        obj = ([],)
        obj[0].append((obj,))

        expected = join(bOPEN("tuple",0),
                         bOPEN("list",1),
                          bOPEN("tuple",2),
                           bOPEN("reference",3),
                            bINT(0),
                           bCLOSE(3),
                          bCLOSE(2),
                         bCLOSE(1),
                        bCLOSE(0))
        d = self.encode(obj)
        d.addCallback(self.wantEqual, expected)
        return d

class InboundByteStream(TestBananaMixin, unittest.TestCase):

    def check(self, obj, stream):
        # use a new Banana for each check
        self.makeBanana()
        obj2 = self.shouldDecode(stream)
        self.assertEqual(obj, obj2)

    def testInt(self):
        self.check(1, b"\x01\x81")
        self.check(130, b"\x02\x01\x81")
        self.check(-1, b"\x01\x83")
        self.check(-130, b"\x02\x01\x83")
        self.check(0, bINT(0))
        self.check(1, bINT(1))
        self.check(127, bINT(127))
        self.check(-1, bINT(-1))
        self.check(-127, bINT(-127))

    def testString(self):
        self.check(b"", b"\x82")
        self.check(b"", b"\x00\x82")
        self.check(b"", b"\x00\x00\x82")
        self.check(b"", b"\x00" * 64 + b"\x82")

        f = self.shouldDropConnection(b"\x00" * 65)
        self.assertEqual(f.value.where, "<RootUnslicer>")
        self.assertTrue(f.value.args[0].startswith("token prefix is limited to 64 bytes"))
        f = self.shouldDropConnection(b"\x00" * 65 + b"\x82")
        self.assertEqual(f.value.where, "<RootUnslicer>")
        self.assertTrue(f.value.args[0].startswith("token prefix is limited to 64 bytes"))

        self.check(b"a", b"\x01\x82a")
        self.check(b"b"*130, b"\x02\x01\x82" + b"b"*130 + b"extra")
        self.check(b"c"*1025, b"\x01\x08\x82" + b"c" * 1025 + b"extra")
        self.check(b"fluuber", bSTR("fluuber"))


    def testList(self):
        self.check([1,2],
                   join(bOPEN('list',1),
                        bINT(1), bINT(2),
                        bCLOSE(1)))
        self.check([1,b"b"],
                   join(bOPEN('list',1), bINT(1),
                        b"\x01\x82b",
                        bCLOSE(1)))
        self.check([1,2,[3,4]],
                   join(bOPEN('list',1), bINT(1), bINT(2),
                         bOPEN('list',2), bINT(3), bINT(4),
                         bCLOSE(2),
                        bCLOSE(1)))

    def testTuple(self):
        self.check((1,2),
                   join(bOPEN('tuple',1), bINT(1), bINT(2),
                        bCLOSE(1)))

    def testDict(self):
        self.check({1:b"a", 2:[b"b",b"c"]},
                   join(bOPEN('dict',1),
                        bINT(1), bSTR("a"),
                        bINT(2), bOPEN('list',2),
                         bSTR("b"), bSTR("c"),
                        bCLOSE(2),
                        bCLOSE(1)))

    def TRUE(self):
        return join(bOPEN("boolean",2), bINT(1), bCLOSE(2))
    def FALSE(self):
        return join(bOPEN("boolean",2), bINT(0), bCLOSE(2))

    def testBool(self):
        self.check(True, self.TRUE())
        self.check(False, self.FALSE())

class InboundByteStream2(TestBananaMixin, unittest.TestCase):

    def setConstraints(self, constraint, childConstraint):
        if constraint:
            constraint = IConstraint(constraint)
        self.banana.receiveStack[-1].constraint = constraint

        if childConstraint:
            childConstraint = IConstraint(childConstraint)
        self.banana.receiveStack[-1].childConstraint = childConstraint

    def conform2(self, stream, obj, constraint=None, childConstraint=None):
        self.setConstraints(constraint, childConstraint)
        obj2 = self.shouldDecode(stream)
        self.assertEqual(obj, obj2)

    def violate2(self, stream, where, constraint=None, childConstraint=None):
        self.setConstraints(constraint, childConstraint)
        f = self.shouldFail(stream)
        self.assertEqual(f.value.where, where)
        self.assertEqual(len(self.banana.receiveStack), 1)

    def testConstrainedInt(self):
        pass # TODO: after implementing new LONGINT token

    def testConstrainedString(self):
        self.conform2(b"\x82", b"",
                      schema.StringConstraint(10))
        self.conform2(b"\x0a\x82" + b"a"*10 + b"extra", b"a"*10,
                      schema.StringConstraint(10))
        self.violate2(b"\x0b\x82" + b"a"*11 + b"extra",
                      "<RootUnslicer>",
                      schema.StringConstraint(10))

    def NOTtestFoo(self):
        if 0:
            a100 = six.int2byte(100) + "\x82" + "a"*100
            b100 = six.int2byte(100) + "\x82" + "b"*100
            self.violate2(join(bOPEN('list',1),
                               bOPEN('list',2), a100, b100, bCLOSE(2),
                               bCLOSE(1)),
                          "<RootUnslicer>.[0].[0]",
                          schema.ListOf(
                schema.ListOf(schema.StringConstraint(99), 2), 2))

        def OPENweird(count, weird):
            return six.int2byte(count) + "\x88" + weird

        self.violate2(join(bOPEN('list',1),
                           bOPEN('list',2),
                           OPENweird(3, bINT(64)),
                           bINT(1), bINT(2), bCLOSE(3),
                           bCLOSE(2),
                           bCLOSE(1)),
                      "<RootUnslicer>.[0].[0]", None)



    def testConstrainedList(self):
        self.conform2(join(bOPEN('list',1), bINT(1), bINT(2),
                           bCLOSE(1)),
                      [1,2],
                      schema.ListOf(int))
        self.violate2(join(bOPEN('list',1), bINT(1), b"\x01\x82b",
                           bCLOSE(1)),
                      "<RootUnslicer>.[1]",
                      schema.ListOf(int))
        self.conform2(join(bOPEN('list',1),
                            bINT(1), bINT(2), bINT(3),
                           bCLOSE(1)),
                      [1,2,3],
                      schema.ListOf(int, maxLength=3))
        self.violate2(join(bOPEN('list',1),
                            bINT(1), bINT(2), bINT(3), bINT(4),
                           bCLOSE(1)),
                      "<RootUnslicer>.[3]",
                      schema.ListOf(int, maxLength=3))
        a100 = six.int2byte(100) + b"\x82" + b"a"*100
        b100 = six.int2byte(100) + b"\x82" + b"b"*100
        self.conform2(join(bOPEN('list',1), a100, b100, bCLOSE(1)),
                      [b"a"*100, b"b"*100],
                      schema.ListOf(schema.StringConstraint(100), 2))
        self.violate2(join(bOPEN('list',1), a100, b100, bCLOSE(1)),
                      "<RootUnslicer>.[0]",
                      schema.ListOf(schema.StringConstraint(99), 2))
        self.violate2(join(bOPEN('list',1), a100, b100, a100, bCLOSE(1)),
                      "<RootUnslicer>.[2]",
                      schema.ListOf(schema.StringConstraint(100), 2))

        self.conform2(join(bOPEN('list',1),
                            bOPEN('list',2),
                             bINT(11), bINT(12),
                            bCLOSE(2),
                            bOPEN('list',3),
                             bINT(21), bINT(22), bINT(23),
                            bCLOSE(3),
                           bCLOSE(1)),
                      [[11,12], [21, 22, 23]],
                      schema.ListOf(schema.ListOf(int, maxLength=3)))

        self.violate2(join(bOPEN('list',1),
                            bOPEN('list',2),
                             bINT(11), bINT(12),
                            bCLOSE(2),
                            bOPEN('list',3),
                             bINT(21), bINT(22), bINT(23),
                            bCLOSE(3),
                           bCLOSE(1)),
                      "<RootUnslicer>.[1].[2]",
                      schema.ListOf(schema.ListOf(int, maxLength=2)))

    def testConstrainedTuple(self):
        self.conform2(join(bOPEN('tuple',1), bINT(1), bINT(2),
                           bCLOSE(1)),
                      (1,2),
                      schema.TupleOf(int, int))
        self.violate2(join(bOPEN('tuple',1),
                           bINT(1), bINT(2), bINT(3),
                           bCLOSE(1)),
                      "<RootUnslicer>.[2]",
                      schema.TupleOf(int, int))
        self.violate2(join(bOPEN('tuple',1),
                           bINT(1), bSTR("not a number"),
                           bCLOSE(1)),
                      "<RootUnslicer>.[1]",
                      schema.TupleOf(int, int))
        self.conform2(join(bOPEN('tuple',1),
                           bINT(1), bSTR("twine"),
                           bCLOSE(1)),
                      (1, b"twine"),
                      schema.TupleOf(int, bytes))
        self.conform2(join(bOPEN('tuple',1),
                           bINT(1),
                            bOPEN('list',2),
                             bINT(1), bINT(2), bINT(3),
                            bCLOSE(2),
                           bCLOSE(1)),
                      (1, [1,2,3]),
                      schema.TupleOf(int, schema.ListOf(int)))
        self.conform2(join(bOPEN('tuple',1),
                           bINT(1),
                            bOPEN('list',2),
                             bOPEN('list',3), bINT(2), bCLOSE(3),
                             bOPEN('list',4), bINT(3), bCLOSE(4),
                            bCLOSE(2),
                           bCLOSE(1)),
                      (1, [[2], [3]]),
                      schema.TupleOf(int, schema.ListOf(schema.ListOf(int))))
        self.violate2(join(bOPEN('tuple',1),
                           bINT(1),
                            bOPEN('list',2),
                             bOPEN('list',3),
                              bSTR("nan"),
                             bCLOSE(3),
                             bOPEN('list',4), bINT(3), bCLOSE(4),
                            bCLOSE(2),
                           bCLOSE(1)),
                      "<RootUnslicer>.[1].[0].[0]",
                      schema.TupleOf(int, schema.ListOf(schema.ListOf(int))))

    def testConstrainedDict(self):
        self.conform2(join(bOPEN('dict',1),
                           bINT(1), bSTR("a"),
                           bINT(2), bSTR("b"),
                           bINT(3), bSTR("c"),
                           bCLOSE(1)),
                      {1:b"a", 2:b"b", 3:b"c"},
                      schema.DictOf(int, bytes))
        self.conform2(join(bOPEN('dict',1),
                           bINT(1), bSTR("a"),
                           bINT(2), bSTR("b"),
                           bINT(3), bSTR("c"),
                           bCLOSE(1)),
                      {1:b"a", 2:b"b", 3:b"c"},
                      schema.DictOf(int, bytes, maxKeys=3))
        self.violate2(join(bOPEN('dict',1),
                           bINT(1), bSTR("a"),
                           bINT(2), bINT(10),
                           bINT(3), bSTR("c"),
                           bCLOSE(1)),
                      "<RootUnslicer>.{}[2]",
                      schema.DictOf(int, bytes))
        self.violate2(join(bOPEN('dict',1),
                           bINT(1), bSTR("a"),
                           bINT(2), bSTR("b"),
                           bINT(3), bSTR("c"),
                           bCLOSE(1)),
                      "<RootUnslicer>.{}",
                      schema.DictOf(int, bytes, maxKeys=2))

    def TRUE(self):
        return join(bOPEN("boolean",2), bINT(1), bCLOSE(2))
    def FALSE(self):
        return join(bOPEN("boolean",2), bINT(0), bCLOSE(2))

    def testConstrainedBool(self):
        self.conform2(self.TRUE(),
                      True,
                      bool)
        self.conform2(self.TRUE(),
                      True,
                      schema.BooleanConstraint())
        self.conform2(self.FALSE(),
                      False,
                      schema.BooleanConstraint())

        # booleans have ints, not strings. To do otherwise is a protocol
        # error, not a schema Violation.
        f = self.shouldDropConnection(join(bOPEN("boolean",1),
                                            bSTR("vrai"),
                                           bCLOSE(1)))
        self.assertEqual(f.value.args[0],
                             "BooleanUnslicer only accepts an INT token")

        # but true/false is a constraint, and is reported with Violation
        self.violate2(self.TRUE(),
                      "<RootUnslicer>.<bool>",
                      schema.BooleanConstraint(False))
        self.violate2(self.FALSE(),
                      "<RootUnslicer>.<bool>",
                      schema.BooleanConstraint(True))


class ThereAndBackAgain(TestBananaMixin, unittest.TestCase):

    def test_int(self):
        d = self.looptest(42)
        d.addCallback(lambda res: self.looptest(-47))
        return d

    def test_bigint(self):
        # some of these are small enough to fit in an INT
        d = self.looptest(int(2**31-1)) # most positive representable INT
        d.addCallback(lambda res: self.looptest(2**31+0))
        d.addCallback(lambda res: self.looptest(2**31+1))

        d.addCallback(lambda res: self.looptest(-2**31-1))
        # the following is the most negative representable INT
        d.addCallback(lambda res: self.looptest(-2**31+0))
        d.addCallback(lambda res: self.looptest(-2**31+1))

        d.addCallback(lambda res: self.looptest(2**100))
        d.addCallback(lambda res: self.looptest(-2**100))
        d.addCallback(lambda res: self.looptest(2**1000))
        d.addCallback(lambda res: self.looptest(-2**1000))
        return d

    def test_decimal(self):
        d = self.looptest(Decimal(0))
        d.addCallback(lambda res: self.looptest(Decimal(123)))
        d.addCallback(lambda res: self.looptest(Decimal(-123)))
        d.addCallback(lambda res: self.looptest(Decimal("123")))
        d.addCallback(lambda res: self.looptest(Decimal("-123")))
        d.addCallback(lambda res: self.looptest(Decimal("123.456")))
        d.addCallback(lambda res: self.looptest(Decimal("-123.456")))
        d.addCallback(lambda res: self.looptest(Decimal("0.000003")))
        d.addCallback(lambda res: self.looptest(Decimal("-0.000003")))
        d.addCallback(lambda res: self.looptest(Decimal('Inf')))
        d.addCallback(lambda res: self.looptest(Decimal('-Inf')))
        # NaN is a bit weird: by definition, NaN != NaN. So we need to make
        # sure it serializes, and that str(new) == str(old), but we don't
        # check that new == old.
        d.addCallback(lambda res: self.loop(Decimal('NaN')))
        def _check_NaN(new_NaN):
            self.assertEqual(str(new_NaN), str(Decimal('NaN')))
        d.addCallback(_check_NaN)
        return d

    def test_string(self):
        return self.looptest("biggles")
    def test_unicode(self):
        return self.looptest(u"biggles\u1234")
    def test_list(self):
        return self.looptest([1,2])
    def test_tuple(self):
        return self.looptest((1,2))
    def test_set(self):
        d = self.looptest(set([1,2]))
        d.addCallback(lambda res: self.looptest(frozenset([1,2])))
        return d

    def test_bool(self):
        d = self.looptest(True)
        d.addCallback(lambda res: self.looptest(False))
        return d
    def test_float(self):
        return self.looptest(20.3)
    def test_none(self):
        d = self.loop(None)
        d.addCallback(lambda n2: self.assertTrue(n2 is None))
        return d
    def test_dict(self):
        return self.looptest({'a':1})

    # some stuff from test_newjelly
    def testIdentity(self):
        # test to make sure that objects retain identity properly
        x = []
        y = (x,)
        x.append(y)
        x.append(y)
        self.assertIdentical(x[0], x[1])
        self.assertIdentical(x[0][0], x)
        d = self.encode(x)
        d.addCallback(self.shouldDecode)
        d.addCallback(self._testIdentity_1)
        return d
    def _testIdentity_1(self, z):
        self.assertIdentical(z[0], z[1])
        self.assertIdentical(z[0][0], z)

    def testUnicode(self):
        x = ['blah']
        d = self.loop(x)
        d.addCallback(self._testUnicode_1, x)
        return d
    def _testUnicode_1(self, y, x):
        self.assertEquals(x, y)
        self.assertEquals(type(x[0]), type(y[0]))

    def testStressReferences(self):
        reref = []
        toplevelTuple = ({'list': reref}, reref)
        reref.append(toplevelTuple)
        d = self.loop(toplevelTuple)
        d.addCallback(self._testStressReferences_1)
        return d
    def _testStressReferences_1(self, z):
        self.assertIdentical(z[0]['list'], z[1])
        self.assertIdentical(z[0]['list'][0], z)

    def test_cycles_1(self):
        # a list that contains a tuple that can't be referenced yet
        a = []
        t1 = (a,)
        t2 = (t1,)
        a.append(t2)
        d = self.loop(t1)
        d.addCallback(lambda z: self.assertIdentical(z[0][0][0], z))
        return d

    def test_cycles_2(self):
        # a dict that contains a tuple that can't be referenced yet.
        a = {}
        t1 = (a,)
        t2 = (t1,)
        a['foo'] = t2
        d = self.loop(t1)
        d.addCallback(lambda z: self.assertIdentical(z[0]['foo'][0], z))
        return d

    def test_cycles_3(self):
        # sets seem to be transitively immutable: any mutable contents would
        # be unhashable, and sets can only contain hashable objects.
        # Therefore sets cannot participate in cycles the way that tuples
        # can.

        # a set that contains a tuple that can't be referenced yet. You can't
        # actually create this in python, because you can only create a set
        # out of hashable objects, and sets aren't hashable, and a tuple that
        # contains a set is not hashable.
        a = set()
        t1 = (a,)
        t2 = (t1,)
        a.add(t2)
        d = self.loop(t1)
        d.addCallback(lambda z: self.assertIdentical(list(z[0])[0][0], z))

        # a list that contains a frozenset that can't be referenced yet
        a = []
        t1 = frozenset([a])
        t2 = frozenset([t1])
        a.append(t2)
        d = self.loop(t1)
        d.addCallback(lambda z:
                      self.assertIdentical(list(list(z)[0][0])[0], z))

        # a dict that contains a frozenset that can't be referenced yet.
        a = {}
        t1 = frozenset([a])
        t2 = frozenset([t1])
        a['foo'] = t2
        d = self.loop(t1)
        d.addCallback(lambda z:
                      self.assertIdentical(list(list(z)[0]['foo'])[0], z))

        # a set that contains a frozenset that can't be referenced yet.
        a = set()
        t1 = frozenset([a])
        t2 = frozenset([t1])
        a.add(t2)
        d = self.loop(t1)
        d.addCallback(lambda z: self.assertIdentical(list(list(list(z)[0])[0])[0], z))
        return d
    del test_cycles_3



class VocabTest1(unittest.TestCase):
    def test_incoming1(self):
        b = TokenBanana()
        b.connectionMade()
        vdict = {1: b'list', 2: b'tuple', 3: b'dict'}
        keys = list(vdict.keys())
        keys.sort()
        setVdict = [tOPEN(0),'set-vocab']
        for k in keys:
            setVdict.append(k)
            setVdict.append(vdict[k])
        setVdict.append(tCLOSE(0))
        b.dataReceived(untokenize(setVdict))
        # banana should now know this vocabulary
        self.assertEqual(b.incomingVocabulary, vdict)

    def test_outgoing(self):
        b = TokenBanana()
        b.connectionMade()
        b.tokens = []
        strings = ["list", "tuple", "dict"]
        vdict = {0: b'list', 1: b'tuple', 2: b'dict'}
        keys = list(vdict.keys())
        keys.sort()
        setVdict = [tOPEN(0),b'set-vocab']
        for k in keys:
            setVdict.append(k)
            setVdict.append(vdict[k])
        setVdict.append(tCLOSE(0))
        b.setOutgoingVocabulary(strings)
        vocabTokens = b.tokens
        self.assertEqual(vocabTokens, setVdict)

    def test_table_hashes(self):
        # make sure that we don't change any published vocab tables, and that
        # we don't change the hash algorithm that they use
        hash_v0 = vocab.hashVocabTable(0)
        self.assertEqual(hash_v0, "da39")
        hash_v1 = vocab.hashVocabTable(1)
        self.assertEqual(hash_v1, "bb33")


class VocabTest2(TestBananaMixin, unittest.TestCase):
    def vbOPEN(self, count, opentype):
        opentype = six.ensure_binary(opentype)
        num = self.invdict[opentype]
        return six.int2byte(count) + b"\x88" + six.int2byte(num) + b"\x87"

    def test_loop(self):
        strings = ["list", "tuple", "dict"]
        vdict = {0: b'list', 1: b'tuple', 2: b'dict'}
        self.invdict = dict(list(zip(list(vdict.values()), list(vdict.keys()))))

        self.banana.setOutgoingVocabulary(strings)
        # this next check only happens to work because there is nothing to
        # keep serialization from completing synchronously. If Banana
        # acquires some eventual-sends, this test might need to be rewritten.
        self.assertEqual(self.banana.outgoingVocabulary, self.invdict)
        self.shouldDecode(self.banana.transport.getvalue())
        self.assertEqual(self.banana.incomingVocabulary, vdict)
        self.clearOutput()

        vbOPEN = self.vbOPEN
        expected = b"".join([vbOPEN(1,"list"),
                             vbOPEN(2,"tuple"),
                              vbOPEN(3,"dict"),
                               bSTR('a'), bINT(1),
                              bCLOSE(3),
                             bCLOSE(2),
                            bCLOSE(1)])
        d = self.encode([({b'a':1},)])
        d.addCallback(self.wantEqual, expected)
        return d


class SliceableByItself(slicer.BaseSlicer):
    def __init__(self, value):
        self.value = value
    def slice(self, streamable, banana):
        self.streamable = streamable
        # this is our "instance state"
        yield {b"value": self.value}

class CouldBeSliceable:
    def __init__(self, value):
        self.value = value

class _AndICanHelp(slicer.BaseSlicer):
    def slice(self, streamable, banana):
        self.streamable = streamable
        yield {b"value": self.obj.value}
registerAdapter(_AndICanHelp, CouldBeSliceable, ISlicer)

class Sliceable(unittest.TestCase):
    def setUp(self):
        self.banana = TokenBanana()
        self.banana.connectionMade()
    def do(self, obj):
        return self.banana.testSlice(obj)
    def tearDown(self):
        self.assertTrue(len(self.banana.slicerStack) == 1)
        self.assertTrue(isinstance(self.banana.slicerStack[0][0], RootSlicer))

    def testDirect(self):
        # the object is its own Slicer
        i = SliceableByItself(42)
        d = self.do(i)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),
                       tOPEN(1), b"dict", b"value", 42, tCLOSE(1),
                       tCLOSE(0)])
        return d

    def testAdapter(self):
        # the adapter is the Slicer
        i = CouldBeSliceable(43)
        d = self.do(i)
        d.addCallback(self.assertEqual,
                      [tOPEN(0),
                       tOPEN(1), b"dict", b"value", 43, tCLOSE(1),
                       tCLOSE(0)])
        return d



# TODO: vocab test:
#  send a bunch of strings
#  send an object that stalls
#  send some more strings
#  set the Vocab table to tokenize some of those strings
#  send yet more strings
#  unstall serialization, let everything flow through, verify
