# -*- test-case-name: foolscap.test.test_banana -*-

from twisted.python.components import registerAdapter
from twisted.internet.defer import Deferred
from foolscap import schema, tokens
from foolscap.tokens import Violation, BananaError
from foolscap.slicer import BaseSlicer, LeafUnslicer


class BooleanSlicer(BaseSlicer):
    opentype = ('boolean',)
    trackReferences = False
    def sliceBody(self, streamable, banana):
        if self.obj:
            yield 1
        else:
            yield 0
registerAdapter(BooleanSlicer, bool, tokens.ISlicer)

class BooleanUnslicer(LeafUnslicer):
    opentype = ('boolean',)

    value = None
    constraint = None

    def setConstraint(self, constraint):
        if isinstance(constraint, schema.Any):
            return
        assert isinstance(constraint, schema.BooleanConstraint)
        self.constraint = constraint

    def checkToken(self, typebyte, size):
        if typebyte != tokens.INT:
            raise BananaError("BooleanUnslicer only accepts an INT token")
        if self.value != None:
            raise BananaError("BooleanUnslicer only accepts one token")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        assert type(obj) == int
        if self.constraint:
            if self.constraint.value != None:
                if bool(obj) != self.constraint.value:
                    raise Violation("This boolean can only be %s" % \
                                    self.constraint.value)
        self.value = bool(obj)

    def receiveClose(self):
        return self.value, None

    def describe(self):
        return "<bool>"
