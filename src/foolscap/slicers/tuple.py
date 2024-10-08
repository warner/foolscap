# -*- test-case-name: foolscap.test.test_banana -*-

from twisted.internet.defer import Deferred
from foolscap.tokens import Violation
from foolscap.slicer import BaseUnslicer
from foolscap.slicers.list import ListSlicer
from foolscap.constraint import OpenerConstraint, Any, IConstraint
from foolscap.util import AsyncAND


class TupleSlicer(ListSlicer):
    opentype = ("tuple",)
    slices = tuple

class TupleUnslicer(BaseUnslicer):
    opentype = ("tuple",)

    debug = False
    constraints = None

    def setConstraint(self, constraint):
        if isinstance(constraint, Any):
            return
        assert isinstance(constraint, TupleConstraint)
        self.constraints = constraint.constraints

    def start(self, count):
        self.list = []
        # indices of .list which are unfilled because of children that could
        # not yet be referenced
        self.num_unreferenceable_children = 0
        self.count = count
        if self.debug:
            print("%s[%d].start with %s" % (self, self.count, self.list))
        self.finished = False
        self.deferred = Deferred()
        self.protocol.setObject(count, self.deferred)
        self._ready_deferreds = []

    def checkToken(self, typebyte, size):
        if self.constraints == None:
            return
        if len(self.list) >= len(self.constraints):
            raise Violation("the tuple is full")
        self.constraints[len(self.list)].checkToken(typebyte, size)

    def doOpen(self, opentype):
        where = len(self.list)
        if self.constraints != None:
            if where >= len(self.constraints):
                raise Violation("the tuple is full")
            self.constraints[where].checkOpentype(opentype)
        unslicer = self.open(opentype)
        if unslicer:
            if self.constraints != None:
                unslicer.setConstraint(self.constraints[where])
        return unslicer

    def update(self, obj, index):
        if self.debug:
            print("%s[%d].update: [%d]=%s" % (self, self.count, index, obj))
        self.list[index] = obj
        self.num_unreferenceable_children -= 1
        if self.finished:
            self.checkComplete()
        return obj

    def receiveChild(self, obj, ready_deferred=None):
        if ready_deferred:
            self._ready_deferreds.append(ready_deferred)
        if isinstance(obj, Deferred):
            obj.addCallback(self.update, len(self.list))
            obj.addErrback(self.explode)
            self.num_unreferenceable_children += 1
            self.list.append("placeholder")
        else:
            self.list.append(obj)

    def checkComplete(self):
        if self.debug:
            print("%s[%d].checkComplete: %d pending" % \
                  (self, self.count, self.num_unreferenceable_children))
        if self.num_unreferenceable_children:
            # not finished yet, we'll fire our Deferred when we are
            if self.debug:
                print(" not finished yet")
            return

        # list is now complete. We can finish.
        return self.complete()

    def complete(self):
        ready_deferred = None
        if self._ready_deferreds:
            ready_deferred = AsyncAND(self._ready_deferreds)

        t = tuple(self.list)
        if self.debug:
            print(" finished! tuple:%s{%s}" % (t, id(t)))
        self.protocol.setObject(self.count, t)
        self.deferred.callback(t)
        return t, ready_deferred

    def receiveClose(self):
        if self.debug:
            print("%s[%d].receiveClose" % (self, self.count))
        self.finished = 1

        if self.num_unreferenceable_children:
            # not finished yet, we'll fire our Deferred when we are
            if self.debug:
                print(" not finished yet")
            ready_deferred = None
            if self._ready_deferreds:
                ready_deferred = AsyncAND(self._ready_deferreds)
            return self.deferred, ready_deferred

        # the list is already complete
        return self.complete()

    def describe(self):
        return "[%d]" % len(self.list)


class TupleConstraint(OpenerConstraint):
    opentypes = [("tuple",)]
    name = "TupleConstraint"

    def __init__(self, *elemConstraints):
        self.constraints = [IConstraint(e) for e in elemConstraints]
    def checkObject(self, obj, inbound):
        if not isinstance(obj, tuple):
            raise Violation("not a tuple")
        if len(obj) != len(self.constraints):
            raise Violation("wrong size tuple")
        for i in range(len(self.constraints)):
            self.constraints[i].checkObject(obj[i], inbound)
