# -*- test-case-name: foolscap.test.test_banana -*-

from twisted.python import log
from twisted.internet.defer import Deferred
from foolscap import schema
from foolscap.tokens import Violation, BananaError
from foolscap.slicer import BaseSlicer, BaseUnslicer

class DictSlicer(BaseSlicer):
    opentype = ('dict',)
    trackReferences = True
    slices = None
    def sliceBody(self, streamable, banana):
        for key,value in self.obj.items():
            yield key
            yield value

class DictUnslicer(BaseUnslicer):
    opentype = ('dict',)

    gettingKey = True
    keyConstraint = None
    valueConstraint = None
    maxKeys = None

    def setConstraint(self, constraint):
        if isinstance(constraint, schema.Any):
            return
        assert isinstance(constraint, schema.DictConstraint)
        self.keyConstraint = constraint.keyConstraint
        self.valueConstraint = constraint.valueConstraint
        self.maxKeys = constraint.maxKeys

    def start(self, count):
        self.d = {}
        self.protocol.setObject(count, self.d)
        self.key = None

    def checkToken(self, typebyte, size):
        if self.maxKeys != None:
            if len(self.d) >= self.maxKeys:
                raise Violation("the dict is full")
        if self.gettingKey:
            if self.keyConstraint:
                self.keyConstraint.checkToken(typebyte, size)
        else:
            if self.valueConstraint:
                self.valueConstraint.checkToken(typebyte, size)

    def doOpen(self, opentype):
        if self.maxKeys != None:
            if len(self.d) >= self.maxKeys:
                raise Violation("the dict is full")
        if self.gettingKey:
            if self.keyConstraint:
                self.keyConstraint.checkOpentype(opentype)
        else:
            if self.valueConstraint:
                self.valueConstraint.checkOpentype(opentype)
        unslicer = self.open(opentype)
        if unslicer:
            if self.gettingKey:
                if self.keyConstraint:
                    unslicer.setConstraint(self.keyConstraint)
            else:
                if self.valueConstraint:
                    unslicer.setConstraint(self.valueConstraint)
        return unslicer

    def update(self, value, key):
        # this is run as a Deferred callback, hence the backwards arguments
        self.d[key] = value

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.gettingKey:
            self.receiveKey(obj)
        else:
            self.receiveValue(obj)
        self.gettingKey = not self.gettingKey

    def receiveKey(self, key):
        # I don't think it is legal (in python) to use an incomplete object
        # as a dictionary key, because you must have all the contents to
        # hash it. Someone could fake up a token stream to hit this case,
        # however: OPEN(dict), OPEN(tuple), OPEN(reference), 0, CLOSE, CLOSE,
        # "value", CLOSE
        if isinstance(key, Deferred):
            raise BananaError("incomplete object as dictionary key")
        try:
            if self.d.has_key(key):
                raise BananaError("duplicate key '%s'" % key)
        except TypeError:
            raise BananaError("unhashable key '%s'" % key)
        self.key = key

    def receiveValue(self, value):
        if isinstance(value, Deferred):
            value.addCallback(self.update, self.key)
            value.addErrback(log.err)
        self.d[self.key] = value # placeholder

    def receiveClose(self):
        return self.d, None

    def describe(self):
        if self.gettingKey:
            return "{}"
        else:
            return "{}[%s]" % self.key


class OrderedDictSlicer(DictSlicer):
    slices = dict
    def sliceBody(self, streamable, banana):
        keys = self.obj.keys()
        keys.sort()
        for key in keys:
            value = self.obj[key]
            yield key
            yield value
