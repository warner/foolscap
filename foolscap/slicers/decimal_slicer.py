# -*- test-case-name: foolscap.test.test_banana -*-

import decimal
from twisted.internet.defer import Deferred
from foolscap.tokens import BananaError, STRING, VOCAB
from foolscap.slicer import BaseSlicer, LeafUnslicer
from foolscap.constraint import Any

class DecimalSlicer(BaseSlicer):
    opentype = ("decimal",)
    slices = decimal.Decimal
    def sliceBody(self, streamable, banana):
        yield str(self.obj)

class DecimalUnslicer(LeafUnslicer):
    opentype = ("decimal",)
    value = None
    constraint = None

    def setConstraint(self, constraint):
        if isinstance(constraint, Any):
            return
        assert False, "DecimalUnslicer does not currently accept a constraint"

    def checkToken(self, typebyte, size):
        if typebyte not in (STRING, VOCAB):
            raise BananaError("DecimalUnslicer only accepts strings")
        #if self.constraint:
        #    self.constraint.checkToken(typebyte, size)

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.value != None:
            raise BananaError("already received a string")
        self.value = decimal.Decimal(obj)

    def receiveClose(self):
        return self.value, None
    def describe(self):
        return "<unicode>"
