
"""
storage.py: support for using Banana as if it were pickle

This includes functions for serializing to and from strings, instead of a
network socket. It also has support for serializing 'unsafe' objects,
specifically classes, modules, functions, and instances of arbitrary classes.
These are 'unsafe' because to recreate the object on the deserializing end,
we must be willing to execute code of the sender's choosing (i.e. the
constructor of whatever package.module.class names they send us). It is
unwise to do this unless you are willing to allow your internal state to be
compromised by the author of the serialized data you're unpacking.

This functionality is isolated here because it is never used for data coming
over network connections.
"""

import types
import six
from six import StringIO
import inspect
from pickle import whichmodule  # used by FunctionSlicer

from foolscap import slicer, banana, tokens
from foolscap.tokens import BananaError
from twisted.internet.defer import Deferred
from twisted.python import reflect
from foolscap.slicers.dict import OrderedDictSlicer
from foolscap.slicers.root import ScopedRootSlicer, ScopedRootUnslicer

# PY3KPORT
try:
  from types import InstanceType
except ImportError:
  InstanceType = object

try:
  from types import ClassType
except ImportError:
  ClassType = type

# PY3KPORT
def get_class_that_defined_method(meth):
  """ Function that return the class that defined a given method """

  # Fix for Python3 to get classes for unbound methods
  # for the MethodSlicer class
  # Ref: https://stackoverflow.com/questions/3589311/get-defining-class-of-unbound-method-object-in-python-3
  # with some fixes and simplifications
  
  if inspect.ismethod(meth):
    # If its a method, we can rely on __self__
    return meth.__self__.__class__

  if inspect.isfunction(meth):
    cls = getattr(inspect.getmodule(meth),
                  meth.__qualname__.split('.<locals>', 1)[0].rsplit('.', 1)[0])
    if isinstance(cls, type):
      return cls
  
################## Slicers for "unsafe" things

# Extended types, not generally safe. The UnsafeRootSlicer checks for these
# with a separate table.

def getInstanceState(inst):
    """Utility function to default to 'normal' state rules in serialization.
    """
    if hasattr(inst, "__getstate__"):
        state = inst.__getstate__()
    else:
        state = inst.__dict__
    return state

class InstanceSlicer(OrderedDictSlicer):
    opentype = ('instance',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        yield reflect.qual(self.obj.__class__) # really a second index token
        self.obj = getInstanceState(self.obj)
        for t in OrderedDictSlicer.sliceBody(self, streamable, banana):
            yield t

class ModuleSlicer(slicer.BaseSlicer):
    opentype = ('module',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        yield self.obj.__name__

class ClassSlicer(slicer.BaseSlicer):
    opentype = ('class',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        yield reflect.qual(self.obj)

class MethodSlicer(slicer.BaseSlicer):
    opentype = ('method',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        # PY3KPORT
        if six.PY2:
            yield self.obj.im_func.__name__
            yield self.obj.im_self
            yield self.obj.im_class
        elif six.PY3:
          # Name is ok
          yield self.obj.__name__
          # For bound methods this is easy as the function has
          # a __self__ defined
          if hasattr(self.obj, '__self__'):
              # Now these are tricky!
              yield self.obj.__self__ 
              yield self.obj.__self__.__class__ 
          else:
              # This is an unbound method!
              # These are very tricky in Python3 as they
              # are nothing but functions attached to
              # a namespace (of the class)
              yield None
              klass = get_class_that_defined_method(self.obj)
              # Hack
              self.obj.im_class = klass
              yield klass

class FunctionSlicer(slicer.BaseSlicer):
    opentype = ('function',)
    trackReferences = True

    def sliceBody(self, streamable, banana):
        name = self.obj.__name__
        fullname = str(whichmodule(self.obj, self.obj.__name__)) + '.' + name
        yield fullname

UnsafeSlicerTable = {}
if six.PY2:
  UnsafeSlicerTable.update({
    types.InstanceType: InstanceSlicer,
    types.ModuleType: ModuleSlicer,
    types.ClassType: ClassSlicer,
    types.MethodType: MethodSlicer,
    types.FunctionType: FunctionSlicer
    })  
else:
  UnsafeSlicerTable.update({
    InstanceType: InstanceSlicer,
    types.ModuleType: ModuleSlicer,
    type: ClassSlicer,
    types.MethodType: MethodSlicer,
    types.FunctionType: FunctionSlicer
    })


# the root slicer for storage is exactly like the regular root slicer
class StorageRootSlicer(ScopedRootSlicer):
    pass

# but the "unsafe" one (which handles instances and stuff) uses its own table
class UnsafeStorageRootSlicer(StorageRootSlicer):
    slicerTable = UnsafeSlicerTable


################## Unslicers for "unsafe" things

def setInstanceState(inst, state):
    """Utility function to default to 'normal' state rules in unserialization.
    """
    if hasattr(inst, "__setstate__"):
        inst.__setstate__(state)
    else:
        inst.__dict__ = state
    return inst


UnsafeUnslicerRegistry = {}

class InstanceUnslicer(slicer.BaseUnslicer):
    # this is an unsafe unslicer: an attacker could induce you to create
    # instances of arbitrary classes with arbitrary attributes: VERY
    # DANGEROUS!
    opentype = ('instance',)
    unslicerRegistry = UnsafeUnslicerRegistry

    # danger: instances are mutable containers. If an attribute value is not
    # yet available, __dict__ will hold a Deferred until it is. Other
    # objects might be created and use our object before this is fixed.
    # TODO: address this. Note that InstanceUnslicers aren't used in PB
    # (where we have pb.Referenceable and pb.Copyable which have schema
    # constraints and could have different restrictions like not being
    # allowed to participate in reference loops).

    def start(self, count):
        self.d = {}
        self.count = count
        self.classname = None
        self.attrname = None
        self.deferred = Deferred()
        self.protocol.setObject(count, self.deferred)

    def checkToken(self, typebyte, size):
        if self.classname is None:
            if typebyte not in (tokens.STRING, tokens.VOCAB):
                raise BananaError("InstanceUnslicer classname must be string")
        elif self.attrname is None:
            if typebyte not in (tokens.STRING, tokens.VOCAB):
                raise BananaError("InstanceUnslicer keys must be STRINGs")

    def receiveChild(self, obj, ready_deferred=None):
        assert ready_deferred is None
        if self.classname is None:
            self.classname = obj
            self.attrname = None
        elif self.attrname is None:
            self.attrname = obj
        else:
            if isinstance(obj, Deferred):
                # TODO: this is an artificial restriction, and it might
                # be possible to remove it, but I need to think through
                # it carefully first
                raise BananaError("unreferenceable object in attribute")
            if self.attrname in self.d:
                raise BananaError("duplicate attribute name '%s'" %
                                  self.attrname)
            self.setAttribute(self.attrname, obj)
            self.attrname = None

    def setAttribute(self, name, value):
        self.d[name] = value

    def receiveClose(self):
        # you could attempt to do some value-checking here, but there would
        # probably still be holes

        # PY3KPORT
        klass = reflect.namedObject(six.ensure_str(self.classname))
        assert type(klass) == ClassType # TODO: new-style classes
        obj = klass()

        setInstanceState(obj, self.d)

        self.protocol.setObject(self.count, obj)
        self.deferred.callback(obj)
        return obj, None

    def describe(self):
        if self.classname is None:
            return "<??>"
        me = "<%s>" % self.classname
        if self.attrname is None:
            return "%s.attrname??" % me
        else:
            return "%s.%s" % (me, self.attrname)

class ModuleUnslicer(slicer.LeafUnslicer):
    opentype = ('module',)
    unslicerRegistry = UnsafeUnslicerRegistry

    finished = False

    def checkToken(self, typebyte, size):
        if typebyte not in (tokens.STRING, tokens.VOCAB):
            raise BananaError("ModuleUnslicer only accepts strings")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.finished:
            raise BananaError("ModuleUnslicer only accepts one string")
        self.finished = True
        # TODO: taste here!
        # PY3KPORT
        obj_s = six.ensure_str(obj)     
        mod = __import__(obj_s, {}, {}, "x")
        self.mod = mod

    def receiveClose(self):
        if not self.finished:
            raise BananaError("ModuleUnslicer requires a string")
        return self.mod, None

class ClassUnslicer(slicer.LeafUnslicer):
    opentype = ('class',)
    unslicerRegistry = UnsafeUnslicerRegistry

    finished = False

    def checkToken(self, typebyte, size):
        if typebyte not in (tokens.STRING, tokens.VOCAB):
            raise BananaError("ClassUnslicer only accepts strings")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.finished:
            raise BananaError("ClassUnslicer only accepts one string")
        self.finished = True
        # TODO: taste here!
        # PY3KPORT
        self.klass = reflect.namedObject(six.ensure_str(obj))

    def receiveClose(self):
        if not self.finished:
            raise BananaError("ClassUnslicer requires a string")
        return self.klass, None

class MethodUnslicer(slicer.BaseUnslicer):
    opentype = ('method',)
    unslicerRegistry = UnsafeUnslicerRegistry

    state = 0
    im_func = None
    im_self = None
    im_class = None

    # self.state:
    # 0: expecting a string with the method name
    # 1: expecting an instance (or None for unbound methods)
    # 2: expecting a class

    def checkToken(self, typebyte, size):
        if self.state == 0:
            if typebyte not in (tokens.STRING, tokens.VOCAB):
                raise BananaError("MethodUnslicer methodname must be a string")
        elif self.state == 1:
            if typebyte != tokens.OPEN:
                raise BananaError("MethodUnslicer instance must be OPEN")
        elif self.state == 2:
            if typebyte != tokens.OPEN:
                raise BananaError("MethodUnslicer class must be an OPEN")

    def doOpen(self, opentype):

        if opentype[0] != None:
            open_type = six.ensure_str(opentype[0])
        else:
            open_type = None
        
        # check the opentype
        if self.state == 1:
            if open_type not in ("instance", "none"):
                raise BananaError("MethodUnslicer instance must be " +
                                  "instance or None")
        elif self.state == 2:
            if open_type != "class":
                raise BananaError("MethodUnslicer class must be a class")
        unslicer = self.open(opentype)
        # TODO: apply constraint
        return unslicer

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.state == 0:
            self.im_func = six.ensure_str(obj)
            self.state = 1
        elif self.state == 1:
            if six.PY2:
              assert type(obj) in (InstanceType, type(None))
            elif six.PY3:
              # No more instance types in PY3
              if hasattr(obj, '__class__'):
                assert(isinstance(obj.__class__, type))
              else:
                assert(type(obj) == type(None))
                
            self.im_self = obj
            self.state = 2
        elif self.state == 2:
            assert type(obj) ==ClassType # TODO: new-style classes?
            self.im_class = obj
            self.state = 3
        else:
            raise BananaError("MethodUnslicer only accepts three objects")

    def receiveClose(self):
        if self.state != 3:
            raise BananaError("MethodUnslicer requires three objects")
        if self.im_self is None:
            meth = getattr(self.im_class, self.im_func)
            # getattr gives us an unbound method
            return meth, None
        # TODO: late-available instances
        #if isinstance(self.im_self, NotKnown):
        #    im = _InstanceMethod(self.im_name, self.im_self, self.im_class)
        #    return im
        meth = self.im_class.__dict__[self.im_func]
        # whereas __dict__ gives us a function
        if six.PY2:
            im = types.MethodType(meth, self.im_self, self.im_class)
        else:
            # Takes only 2 arguments in Python3
            im = types.MethodType(meth, self.im_self)         
        
        return im, None


class FunctionUnslicer(slicer.LeafUnslicer):
    opentype = ('function',)
    unslicerRegistry = UnsafeUnslicerRegistry

    finished = False

    def checkToken(self, typebyte, size):
        if typebyte not in (tokens.STRING, tokens.VOCAB):
            raise BananaError("FunctionUnslicer only accepts strings")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, Deferred)
        assert ready_deferred is None
        if self.finished:
            raise BananaError("FunctionUnslicer only accepts one string")
        self.finished = True
        # TODO: taste here!
        # PY3KPORT
        self.func = reflect.namedObject(six.ensure_str(obj))

    def receiveClose(self):
        if not self.finished:
            raise BananaError("FunctionUnslicer requires a string")
        return self.func, None

# the root unslicer for storage is just like the regular one, but hands
# received objects to the StorageBanana
class StorageRootUnslicer(ScopedRootUnslicer):
    def receiveChild(self, obj, ready_deferred):
        self.protocol.receiveChild(obj, ready_deferred)


# but the "unsafe" one has its own tables
class UnsafeStorageRootUnslicer(StorageRootUnslicer):
    # This version tracks references for the entire lifetime of the
    # protocol. It is most appropriate for single-use purposes, such as a
    # replacement for Pickle.
    topRegistries = [slicer.UnslicerRegistry,
                     slicer.BananaUnslicerRegistry,
                     UnsafeUnslicerRegistry]
    openRegistries = [slicer.UnslicerRegistry,
                      UnsafeUnslicerRegistry]

class StorageBanana(banana.Banana):
    object = None
    violation = None
    disconnectReason = None
    slicerClass = StorageRootSlicer
    unslicerClass = StorageRootUnslicer

    def prepare(self):
        self.d = Deferred()
        return self.d

    def receiveChild(self, obj, ready_deferred):
        if ready_deferred:
            ready_deferred.addBoth(self.d.callback)
            self.d.addCallback(lambda res: obj)
        else:
            self.d.callback(obj)
        del self.d

    def receivedObject(self, obj):
        self.object = obj

    def sendError(self, msg):
        pass

    def reportViolation(self, why):
        self.violation = why

    def reportReceiveError(self, f):
        self.disconnectReason = f
        f.raiseException()

class SerializerTransport:
    def __init__(self, sio):
        self.sio = sio
    def write(self, data):
        self.sio.write(data)
            
    def loseConnection(self, why="ignored"):
        pass

def serialize(obj, outstream=None, root_class=StorageRootSlicer, banana=None):
    """Serialize an object graph into a sequence of bytes. Returns a Deferred
    that fires with the sequence of bytes."""
    if banana:
        b = banana
    else:
        b = StorageBanana()
        b.slicerClass = root_class
    if outstream is None:
        sio = StringIO()
    else:
        sio = outstream
    b.transport = SerializerTransport(sio)
    b.connectionMade()
    d = b.send(obj)
    def _report_error(res):
        if b.disconnectReason:
            return b.disconnectReason
        if b.violation:
            return b.violation
        return res
    d.addCallback(_report_error)
    if outstream is None:
        d.addCallback(lambda res: sio.getvalue())
    else:
        d.addCallback(lambda res: outstream)
    return d

def unserialize(str_or_instream, banana=None, root_class=StorageRootUnslicer):
    """Unserialize a sequence of bytes back into an object graph."""
    if banana:
        b = banana
    else:
        b = StorageBanana()
        b.unslicerClass = root_class
    b.connectionMade()
    d = b.prepare() # this will fire with the unserialized object
    if isinstance(str_or_instream, str):
        b.dataReceived(str_or_instream)
    else:
        raise RuntimeError("input streams not implemented yet")
    def _report_error(res):
        if b.disconnectReason:
            return b.disconnectReason
        if b.violation:
            return b.violation
        return res # return the unserialized object
    d.addCallback(_report_error)
    return d

