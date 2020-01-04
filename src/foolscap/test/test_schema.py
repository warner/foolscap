import six
import re
from twisted.trial import unittest
from foolscap import schema, copyable, broker
from foolscap.tokens import Violation, InvalidRemoteInterface
from foolscap.constraint import IConstraint
from foolscap.remoteinterface import RemoteMethodSchema, \
     RemoteInterfaceConstraint, LocalInterfaceConstraint
from foolscap.referenceable import RemoteReferenceTracker, \
     RemoteReference, Referenceable, TubRef
from foolscap.test import common

class Dummy:
    pass

HEADER = 64
INTSIZE = HEADER+1
STR10 = HEADER+1+10

class ConformTest(unittest.TestCase):
    """This tests how Constraints are asserted on outbound objects (where the
    object already exists). Inbound constraints are checked in
    test_banana.InboundByteStream in the various testConstrainedFoo methods.
    """
    def conforms(self, c, obj):
        c.checkObject(obj, False)
    def violates(self, c, obj):
        self.assertRaises(schema.Violation, c.checkObject, obj, False)

    def testInteger(self):
        # s_int32_t
        c = schema.IntegerConstraint()
        self.conforms(c, 123)
        self.violates(c, 2**64)
        self.conforms(c, 0)
        self.conforms(c, 2**31-1)
        self.violates(c, 2**31)
        self.conforms(c, -2**31)
        self.violates(c, -2**31-1)
        self.violates(c, "123")
        self.violates(c, Dummy())
        self.violates(c, None)

    def testLargeInteger(self):
        c = schema.IntegerConstraint(64)
        self.conforms(c, 123)
        self.violates(c, "123")
        self.violates(c, None)
        self.conforms(c, 2**512-1)
        self.violates(c, 2**512)
        self.conforms(c, -2**512+1)
        self.violates(c, -2**512)

    def testByteString(self):
        c = schema.ByteStringConstraint(10)
        self.conforms(c, b"I'm short")
        self.violates(c, b"I am too long")
        self.conforms(c, b"a" * 10)
        self.violates(c, b"a" * 11)
        self.violates(c, 123)
        self.violates(c, Dummy())
        self.violates(c, None)

        c2 = schema.ByteStringConstraint(15, 10)
        self.violates(c2, b"too short")
        self.conforms(c2, b"long enough")
        self.violates(c2, b"this is too long")
        self.violates(c2, u"I am unicode")

    def testString(self):
        # this test will change once the definition of "StringConstraint"
        # changes. For now, we assert that StringConstraint is the same as
        # ByteStringConstraint.

        c = schema.StringConstraint(20)
        self.conforms(c, b"I'm short")
        self.violates(c, u"I am unicode")

    def testUnicode(self):
        c = schema.UnicodeConstraint(10)
        self.violates(c, b"I'm a bytestring")
        self.conforms(c, u"I'm short")
        self.violates(c, u"I am too long")
        self.conforms(c, u"a" * 10)
        self.violates(c, u"a" * 11)
        self.violates(c, 123)
        self.violates(c, Dummy())
        self.violates(c, None)

        c2 = schema.UnicodeConstraint(15, 10)
        self.violates(c2, b"I'm a bytestring")
        self.violates(c2, u"too short")
        self.conforms(c2, u"long enough")
        self.violates(c2, u"this is too long")

        c3 = schema.UnicodeConstraint(regexp="needle")
        self.violates(c3, b"I'm a bytestring")
        self.violates(c3, u"no present")
        self.conforms(c3, u"needle in a haystack")
        c4 = schema.UnicodeConstraint(regexp="[abc]+")
        self.violates(c4, b"I'm a bytestring")
        self.violates(c4, u"spelled entirely without those letters")
        self.conforms(c4, u"add better cases")
        c5 = schema.UnicodeConstraint(regexp=re.compile("\d+\s\w+"))
        self.violates(c5, b"I'm a bytestring")
        self.conforms(c5, u": 123 boo")
        self.violates(c5, u"more than 1  spaces")
        self.violates(c5, u"letters first 123")

    def testBool(self):
        c = schema.BooleanConstraint()
        self.conforms(c, False)
        self.conforms(c, True)
        self.violates(c, 0)
        self.violates(c, 1)
        self.violates(c, "vrai")
        self.violates(c, Dummy())
        self.violates(c, None)

    def testPoly(self):
        c = schema.PolyConstraint(schema.ByteStringConstraint(100),
                                  schema.IntegerConstraint())
        self.conforms(c, b"bytes")
        self.conforms(c, 123)
        self.violates(c, u"unicode")
        self.violates(c, 123.4)
        self.violates(c, ["not", "a", "list"])

    def testTuple(self):
        c = schema.TupleConstraint(schema.ByteStringConstraint(10),
                                   schema.ByteStringConstraint(100),
                                   schema.IntegerConstraint() )
        self.conforms(c, (b"hi", b"there buddy, you're number", 1))
        self.violates(c, b"nope")
        self.violates(c, (b"string", b"string", "NaN"))
        self.violates(c, (b"string that is too long", b"string", 1))
        self.violates(c, [b"Are tuples", b"and lists the same?", 0])

    def testNestedTuple(self):
        inner = schema.TupleConstraint(schema.ByteStringConstraint(10),
                                       schema.IntegerConstraint())
        outer = schema.TupleConstraint(schema.ByteStringConstraint(100),
                                       inner)

        self.conforms(inner, (b"hi", 2))
        self.conforms(outer, (b"long string here", (b"short", 3)))
        self.violates(outer, ((b"long string here", (b"short", 3, b"extra"))))
        self.violates(outer, ((b"long string here", (b"too long string", 3))))

        outer2 = schema.TupleConstraint(inner, inner)
        self.conforms(outer2, ((b"hi", 1), (b"there", 2)) )
        self.violates(outer2, (b"hi", 1, b"flat", 2) )

    def testRecursion(self):
        # we have to fiddle with PolyConstraint's innards
        value = schema.ChoiceOf(schema.ByteStringConstraint(),
                                schema.IntegerConstraint(),
                                # will add 'value' here
                                )
        self.conforms(value, b"key")
        self.conforms(value, 123)
        self.violates(value, [])

        mapping = schema.TupleConstraint(schema.ByteStringConstraint(10),
                                         value)
        self.conforms(mapping, (b"name", b"key"))
        self.conforms(mapping, (b"name", 123))
        value.alternatives = value.alternatives + (mapping,)

        # but note that the constraint can still be applied
        self.conforms(mapping, (b"name", 123))
        self.conforms(mapping, (b"name", b"key"))
        self.conforms(mapping, (b"name", (b"key", b"value")))
        self.conforms(mapping, (b"name", (b"key", 123)))
        self.violates(mapping, (b"name", (b"key", [])))
        l = []
        l.append(l)
        self.violates(mapping, (b"name", l))

    def testList(self):
        l = schema.ListOf(schema.ByteStringConstraint(10))
        self.conforms(l, [b"one", b"two", b"three"])
        self.violates(l, (b"can't", b"fool", b"me"))
        self.violates(l, [b"but", b"perspicacity", b"is too long"])
        self.violates(l, [0, b"numbers", b"allowed"])
        self.conforms(l, [b"short", b"sweet"])

        l2 = schema.ListOf(schema.ByteStringConstraint(10), 3)
        self.conforms(l2, [b"the number", b"shall be", b"three"])
        self.violates(l2, [b"five", b"is", b"...", b"right", b"out"])

        l3 = schema.ListOf(schema.ByteStringConstraint(10), None)
        self.conforms(l3, [b"long"] * 35)
        self.violates(l3, [b"number", 1, b"rule", b"is", 0, b"numbers"])

        l4 = schema.ListOf(schema.ByteStringConstraint(10), 3, 3)
        self.conforms(l4, [b"three", b"is", b"good"])
        self.violates(l4, [b"but", b"four", b"is", b"bad"])
        self.violates(l4, [b"two", b"too"])

    def testSet(self):
        l = schema.SetOf(schema.IntegerConstraint(), 3)
        self.conforms(l, set([]))
        self.conforms(l, set([1]))
        self.conforms(l, set([1,2,3]))
        self.violates(l, set([1,2,3,4]))
        self.violates(l, set(["not a number"]))
        self.conforms(l, frozenset([]))
        self.conforms(l, frozenset([1]))
        self.conforms(l, frozenset([1,2,3]))
        self.violates(l, frozenset([1,2,3,4]))
        self.violates(l, frozenset(["not a number"]))

        l = schema.SetOf(schema.IntegerConstraint(), 3, True)
        self.conforms(l, set([]))
        self.conforms(l, set([1]))
        self.conforms(l, set([1,2,3]))
        self.violates(l, set([1,2,3,4]))
        self.violates(l, set(["not a number"]))
        self.violates(l, frozenset([]))
        self.violates(l, frozenset([1]))
        self.violates(l, frozenset([1,2,3]))
        self.violates(l, frozenset([1,2,3,4]))
        self.violates(l, frozenset(["not a number"]))

        l = schema.SetOf(schema.IntegerConstraint(), 3, False)
        self.violates(l, set([]))
        self.violates(l, set([1]))
        self.violates(l, set([1,2,3]))
        self.violates(l, set([1,2,3,4]))
        self.violates(l, set(["not a number"]))
        self.conforms(l, frozenset([]))
        self.conforms(l, frozenset([1]))
        self.conforms(l, frozenset([1,2,3]))
        self.violates(l, frozenset([1,2,3,4]))
        self.violates(l, frozenset(["not a number"]))


    def testDict(self):
        d = schema.DictOf(schema.ByteStringConstraint(10),
                          schema.IntegerConstraint(),
                          maxKeys=4)

        self.conforms(d, {b"a": 1, b"b": 2})
        self.conforms(d, {b"foo": 123, b"bar": 345, b"blah": 456, b"yar": 789})
        self.violates(d, None)
        self.violates(d, 12)
        self.violates(d, [b"nope"])
        self.violates(d, (b"nice", b"try"))
        self.violates(d, {1:2, 3:4})
        self.violates(d, {b"a": b"b"})
        self.violates(d, {b"a": 1, b"b": 2, b"c": 3, b"d": 4, b"toomuch": 5})

    def testAttrDict(self):
        d = copyable.AttributeDictConstraint(('a', int), ('b', str))
        self.conforms(d, {"a": 1, "b": "string"})
        self.violates(d, {"a": 1, "b": 2})
        self.violates(d, {"a": 1, "b": "string", "c": "is a crowd"})

        d = copyable.AttributeDictConstraint(('a', int), ('b', str),
                                             ignoreUnknown=True)
        self.conforms(d, {"a": 1, "b": "string"})
        self.violates(d, {"a": 1, "b": 2})
        self.conforms(d, {"a": 1, "b": "string", "c": "is a crowd"})

        d = copyable.AttributeDictConstraint(attributes={"a": int, "b": str})
        self.conforms(d, {"a": 1, "b": "string"})
        self.violates(d, {"a": 1, "b": 2})
        self.violates(d, {"a": 1, "b": "string", "c": "is a crowd"})


class CreateTest(unittest.TestCase):
    def check(self, obj, expected):
        self.failUnless(isinstance(obj, expected))

    def testMakeConstraint(self):
        make = IConstraint
        c = make(int)
        self.check(c, schema.IntegerConstraint)
        self.failUnlessEqual(c.maxBytes, 1024)

        c = make(six.binary_type)
        self.check(c, schema.ByteStringConstraint)
        self.failUnlessEqual(c.maxLength, None)

        c = make(schema.ByteStringConstraint(2000))
        self.check(c, schema.ByteStringConstraint)
        self.failUnlessEqual(c.maxLength, 2000)

        c = make(six.text_type)
        self.check(c, schema.UnicodeConstraint)
        self.failUnlessEqual(c.maxLength, None)

        self.check(make(bool), schema.BooleanConstraint)
        self.check(make(float), schema.NumberConstraint)

        self.check(make(schema.NumberConstraint()), schema.NumberConstraint)
        c = make((int, bytes))
        self.check(c, schema.TupleConstraint)
        self.check(c.constraints[0], schema.IntegerConstraint)
        self.check(c.constraints[1], schema.ByteStringConstraint)

        c = make(common.RIHelper)
        self.check(c, RemoteInterfaceConstraint)
        self.assertEqual(c.interface, common.RIHelper)

        c = make(common.IFoo)
        self.check(c, LocalInterfaceConstraint)
        self.assertEqual(c.interface, common.IFoo)

        c = make(Referenceable)
        self.check(c, RemoteInterfaceConstraint)
        self.assertEqual(c.interface, None)


class Arguments(unittest.TestCase):
    def test_arguments(self):
        def foo(a=int, b=bool, c=int): return bytes
        r = RemoteMethodSchema(method=foo)
        getpos = r.getPositionalArgConstraint
        getkw = r.getKeywordArgConstraint
        self.assertTrue(isinstance(getpos(0)[1], schema.IntegerConstraint))
        self.assertTrue(isinstance(getpos(1)[1], schema.BooleanConstraint))
        self.assertTrue(isinstance(getpos(2)[1], schema.IntegerConstraint))

        self.assertTrue(isinstance(getkw("a")[1], schema.IntegerConstraint))
        self.assertTrue(isinstance(getkw("b")[1], schema.BooleanConstraint))
        self.assertTrue(isinstance(getkw("c")[1], schema.IntegerConstraint))

        self.assertTrue(isinstance(r.getResponseConstraint(),
                                   schema.ByteStringConstraint))

        self.assertTrue(isinstance(getkw("c", 1, [])[1],
                                   schema.IntegerConstraint))
        self.assertRaises(schema.Violation, getkw, "a", 1, [])
        self.assertRaises(schema.Violation, getkw, "b", 1, ["b"])
        self.assertRaises(schema.Violation, getkw, "a", 2, [])
        self.assertTrue(isinstance(getkw("c", 2, [])[1],
                                   schema.IntegerConstraint))
        self.assertTrue(isinstance(getkw("c", 0, ["a", "b"])[1],
                                   schema.IntegerConstraint))

        try:
            r.checkAllArgs((1,True,2), {}, False)
            r.checkAllArgs((), {"a":1, "b":False, "c":2}, False)
            r.checkAllArgs((1,), {"b":False, "c":2}, False)
            r.checkAllArgs((1,True), {"c":3}, False)
            r.checkResults(b"good", False)
        except schema.Violation:
            self.fail("that shouldn't have raised a Violation")
        self.assertRaises(schema.Violation, # 2 is not bool
                              r.checkAllArgs, (1,2,3), {}, False)
        self.assertRaises(schema.Violation, # too many
                              r.checkAllArgs, (1,True,3,4), {}, False)
        self.assertRaises(schema.Violation, # double "a"
                              r.checkAllArgs, (1,), {"a":1, "b":True, "c": 3},
                              False)
        self.assertRaises(schema.Violation, # missing required "b"
                              r.checkAllArgs, (1,), {"c": 3}, False)
        self.assertRaises(schema.Violation, # missing required "a"
                              r.checkAllArgs, (), {"b":True, "c": 3}, False)
        self.assertRaises(schema.Violation,
                              r.checkResults, 12, False)

    def test_bad_arguments(self):
        def foo(nodefault): return str
        self.assertRaises(InvalidRemoteInterface,
                              RemoteMethodSchema, method=foo)
        def bar(nodefault, a=int): return str
        self.assertRaises(InvalidRemoteInterface,
                              RemoteMethodSchema, method=bar)


class Interfaces(unittest.TestCase):
    def check_inbound(self, obj, constraint):
        try:
            constraint.checkObject(obj, True)
        except Violation as f:
            self.fail("constraint was violated: %s" % f)

    def check_outbound(self, obj, constraint):
        try:
            constraint.checkObject(obj, False)
        except Violation as f:
            self.fail("constraint was violated: %s" % f)

    def violates_inbound(self, obj, constraint):
        try:
            constraint.checkObject(obj, True)
        except Violation:
            return
        self.fail("constraint wasn't violated")

    def violates_outbound(self, obj, constraint):
        try:
            constraint.checkObject(obj, False)
        except Violation:
            return
        self.fail("constraint wasn't violated")

    def test_referenceable(self):
        h = common.HelperTarget()
        c1 = RemoteInterfaceConstraint(common.RIHelper)
        c2 = RemoteInterfaceConstraint(common.RIMyTarget)
        self.violates_inbound("bogus", c1)
        self.violates_outbound("bogus", c1)
        self.check_outbound(h, c1)
        self.violates_inbound(h, c1)
        self.violates_inbound(h, c2)
        self.violates_outbound(h, c2)

    def test_remotereference(self):
        # we need to create a fake RemoteReference here
        tracker = RemoteReferenceTracker(broker.Broker(TubRef("fake-tubid")),
                                         0, None,
                                         common.RIHelper.__remote_name__)
        rr = RemoteReference(tracker)

        c1 = RemoteInterfaceConstraint(common.RIHelper)
        self.check_inbound(rr, c1)
        self.check_outbound(rr, c1) # gift

        c2 = RemoteInterfaceConstraint(common.RIMyTarget)
        self.violates_inbound(rr, c2)
        self.violates_outbound(rr, c2)
