# -*- test-case-name: foolscap.test.test_banana -*-

from twisted.internet import defer
from twisted.python import log
from foolscap.slicers.list import ListSlicer
from foolscap.slicers.tuple import TupleUnslicer
from foolscap.slicer import BaseUnslicer
from foolscap.tokens import Violation
from foolscap.constraint import OpenerConstraint, Any, IConstraint
from foolscap.util import AsyncAND

class SetSlicer(ListSlicer):
    opentype = ("set",)
    trackReferences = True
    slices = set

    def sliceBody(self, streamable, banana):
        for i in self.obj:
            yield i

class FrozenSetSlicer(SetSlicer):
    opentype = ("immutable-set",)
    trackReferences = False
    slices = frozenset


class _Placeholder:
    pass

class SetUnslicer(BaseUnslicer):
    # this is a lot like a list, but sufficiently different to make it not
    # worth subclassing
    opentype = ("set",)

    debug = False
    maxLength = None
    itemConstraint = None

    def setConstraint(self, constraint):
        if isinstance(constraint, Any):
            return
        assert isinstance(constraint, SetConstraint)
        self.maxLength = constraint.maxLength
        self.itemConstraint = constraint.constraint

    def start(self, count):
        #self.opener = foo # could replace it if we wanted to
        self.set = set()
        self.count = count
        if self.debug:
            log.msg("%s[%d].start with %s" % (self, self.count, self.set))
        self.protocol.setObject(count, self.set)
        self._ready_deferreds = []

    def checkToken(self, typebyte, size):
        if self.maxLength != None and len(self.set) >= self.maxLength:
            # list is full, no more tokens accepted
            # this is hit if the max+1 item is a primitive type
            raise Violation("the set is full")
        if self.itemConstraint:
            self.itemConstraint.checkToken(typebyte, size)

    def doOpen(self, opentype):
        # decide whether the given object type is acceptable here. Raise a
        # Violation exception if not, otherwise give it to our opener (which
        # will normally be the RootUnslicer). Apply a constraint to the new
        # unslicer.
        if self.maxLength != None and len(self.set) >= self.maxLength:
            # this is hit if the max+1 item is a non-primitive type
            raise Violation("the set is full")
        if self.itemConstraint:
            self.itemConstraint.checkOpentype(opentype)
        unslicer = self.open(opentype)
        if unslicer:
            if self.itemConstraint:
                unslicer.setConstraint(self.itemConstraint)
        return unslicer

    def update(self, obj, placeholder):
        # obj has already passed typechecking
        if self.debug:
            log.msg("%s[%d].update: [%s]=%s" % (self, self.count,
                                                placeholder, obj))
        self.set.remove(placeholder)
        self.set.add(obj)
        return obj

    def receiveChild(self, obj, ready_deferred=None):
        if ready_deferred:
            self._ready_deferreds.append(ready_deferred)
        if self.debug:
            log.msg("%s[%d].receiveChild(%s)" % (self, self.count, obj))
        # obj could be a primitive type, a Deferred, or a complex type like
        # those returned from an InstanceUnslicer. However, the individual
        # object has already been through the schema validation process. The
        # only remaining question is whether the larger schema will accept
        # it.
        if self.maxLength != None and len(self.set) >= self.maxLength:
            # this is redundant
            # (if it were a non-primitive one, it would be caught in doOpen)
            # (if it were a primitive one, it would be caught in checkToken)
            raise Violation("the set is full")
        if isinstance(obj, defer.Deferred):
            if self.debug:
                log.msg(" adding my update[%d] to %s" % (len(self.set), obj))
            # note: the placeholder isn't strictly necessary, but it will
            # help debugging to see a _Placeholder sitting in the set when it
            # shouldn't rather than seeing a set that is smaller than it
            # ought to be. If a remote method ever sees a _Placeholder, then
            # something inside Foolscap has broken.
            placeholder = _Placeholder()
            obj.addCallback(self.update, placeholder)
            obj.addErrback(self.printErr)
            self.set.add(placeholder)
        else:
            self.set.add(obj)

    def printErr(self, why):
        print("ERR!")
        print(why.getBriefTraceback())
        log.err(why)

    def receiveClose(self):
        ready_deferred = None
        if self._ready_deferreds:
            ready_deferred = AsyncAND(self._ready_deferreds)
        return self.set, ready_deferred

class FrozenSetUnslicer(TupleUnslicer):
    opentype = ("immutable-set",)

    def receiveClose(self):
        obj_or_deferred, ready_deferred = TupleUnslicer.receiveClose(self)
        if isinstance(obj_or_deferred, defer.Deferred):
            def _convert(the_tuple):
                return frozenset(the_tuple)
            obj_or_deferred.addCallback(_convert)
        else:
            obj_or_deferred = frozenset(obj_or_deferred)
        return obj_or_deferred, ready_deferred


class SetConstraint(OpenerConstraint):
    """The object must be a Set of some sort, with a given maximum size. To
    accept sets of any size, use maxLength=None. All member objects must obey
    the given constraint. By default this will accept both mutable and
    immutable sets, if you want to require a particular type, set mutable= to
    either True or False.
    """

    # TODO: if mutable!=None, we won't throw out the wrong set type soon
    # enough. We need to override checkOpenType to accomplish this.
    opentypes = [("set",), ("immutable-set",)]
    name = "SetConstraint"

    def __init__(self, constraint, maxLength=None, mutable=None):
        self.constraint = IConstraint(constraint)
        self.maxLength = maxLength
        self.mutable = mutable

    def checkObject(self, obj, inbound):
        if not isinstance(obj, (set, frozenset)):
            raise Violation("not a set")
        if (self.mutable == True and
            not isinstance(obj, set)):
            raise Violation("obj is a set, but not a mutable one")
        if (self.mutable == False and
            not isinstance(obj, frozenset)):
            raise Violation("obj is a set, but not an immutable one")
        if self.maxLength is not None and len(obj) > self.maxLength:
            raise Violation("set is too large")
        if self.constraint:
            for o in obj:
                self.constraint.checkObject(o, inbound)
