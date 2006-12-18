

"""
primitive constraints:
   - types.StringType: string with maxLength=1k
   - String(maxLength=1000): string with arbitrary maxLength
   - types.BooleanType: boolean
   - types.IntType: integer that fits in s_int32_t
   - types.LongType: integer with abs(num) < 2**8192 (fits in 1024 bytes)
   - Int(maxBytes=1024): integer with arbitrary maxValue=2**(8*maxBytes)
   - types.FloatType: number
   - Number(maxBytes=1024): float or integer with maxBytes
   - interface: instance which implements (or adapts to) the Interface
   - class: instance of the class or a subclass
   - # unicode? types? none?

container constraints:
   - TupleOf(constraint1, constraint2..): fixed size, per-element constraint
   - ListOf(constraint, maxLength=30): all elements obey constraint
   - DictOf(keyconstraint, valueconstraint): keys and values obey constraints
   - AttributeDict(*attrTuples, ignoreUnknown=False):
      - attrTuples are (name, constraint)
      - ignoreUnknown=True means that received attribute names which aren't
        listed in attrTuples should be ignored instead of raising an
        UnknownAttrName exception

composite constraints:
   - tuple: alternatives: must obey one of the different constraints

modifiers:
   - Shared(constraint, refLimit=None): object may be referenced multiple times
     within the serialization domain (question: which domain?). All
     constraints default to refLimit=1, and a MultiplyReferenced exception
     is raised as soon as the reference count goes above the limit.
     refLimit=None means no limit is enforced.
   - Optional(name, constraint, default=None): key is not required. If not
            provided and default is None, key/attribute will not be created
            Only valid inside DictOf and AttributeDict.
   

"""

import types, inspect
from zope.interface import implements, Interface
from zope.interface.interface import InterfaceClass
from twisted.python import failure

from foolscap.tokens import Violation, BananaError, SIZE_LIMIT, \
     STRING, LIST, INT, NEG, LONGINT, LONGNEG, VOCAB, FLOAT, OPEN, \
     tokenNames, UnknownSchemaType, InvalidRemoteInterface

everythingTaster = {
    # he likes everything
    STRING: SIZE_LIMIT,
    LIST: None,
    INT: None,
    NEG: None,
    LONGINT: SIZE_LIMIT,
    LONGNEG: SIZE_LIMIT,
    VOCAB: None,
    FLOAT: None,
    OPEN: None,
    }
openTaster = {
    OPEN: None,
    }
nothingTaster = {}

class UnboundedSchema(Exception):
    pass

class IConstraint(Interface):
    pass
class IRemoteMethodConstraint(IConstraint):
    pass

class Constraint:
    """
    Each __schema__ attribute is turned into an instance of this class, and
    is eventually given to the unserializer (the 'Unslicer') to enforce as
    the tokens are arriving off the wire.
    """

    implements(IConstraint)

    taster = everythingTaster
    """the Taster is a dict that specifies which basic token types are
    accepted. The keys are typebytes like INT and STRING, while the
    values are size limits: the body portion of the token must not be
    longer than LIMIT bytes.
    """

    strictTaster = False
    """If strictTaster is True, taste violations are raised as BananaErrors
    (indicating a protocol error) rather than a mere Violation.
    """

    opentypes = None
    """opentypes is a list of currently acceptable OPEN token types. None
    indicates that all types are accepted. An empty list indicates that no
    OPEN tokens are accepted.
    """

    name = None
    """Used to describe the Constraint in a Violation error message"""

    def checkToken(self, typebyte, size):
        """Check the token type. Raise an exception if it is not accepted
        right now, or if the body-length limit is exceeded."""

        limit = self.taster.get(typebyte, "not in list")
        if limit == "not in list":
            if self.strictTaster:
                raise BananaError("invalid token type")
            else:
                raise Violation("%s token rejected by %s" % \
                                (tokenNames[typebyte], self.name))
        if limit and size > limit:
            raise Violation("token too large: %d>%d" % (size, limit))

    def setNumberTaster(self, maxValue):
        self.taster = {INT: None,
                       NEG: None,
                       LONGINT: None, # TODO
                       LONGNEG: None,
                       FLOAT: None,
                       }
    def checkOpentype(self, opentype):
        """Check the OPEN type (the tuple of Index Tokens). Raise an
        exception if it is not accepted.
        """

        if self.opentypes == None:
            return

        for o in self.opentypes:
            if len(o) == len(opentype):
                if o == opentype:
                    return
            if len(o) > len(opentype):
                # we might have a partial match: they haven't flunked yet
                if opentype == o[:len(opentype)]:
                    return # still in the running
        print "opentype %s, self.opentypes %s" % (opentype, self.opentypes)
        raise Violation, "unacceptable OPEN type '%s'" % (opentype,)

    def checkObject(self, obj, inbound):
        """Validate an existing object. Usually objects are validated as
        their tokens come off the wire, but pre-existing objects may be
        added to containers if a REFERENCE token arrives which points to
        them. The older objects were were validated as they arrived (by a
        different schema), but now they must be re-validated by the new
        schema.

        A more naive form of validation would just accept the entire object
        tree into memory and then run checkObject() on the result. This
        validation is too late: it is vulnerable to both DoS and
        made-you-run-code attacks.

        If inbound=True, this object is arriving over the wire. If
        inbound=False, this is being called to validate an existing object
        before it is sent over the wire. This is done as a courtesy to the
        remote end, and to improve debuggability.

        Most constraints can use the same checker for both inbound and
        outbound objects.
        """
        # this default form passes everything
        return

    def maxSize(self, seen=None):
        """
        I help a caller determine how much memory could be consumed by the
        input stream while my constraint is in effect.

        My constraint will be enforced against the bytes that arrive over
        the wire. Eventually I will either accept the incoming bytes and my
        Unslicer will provide an object to its parent (including any
        subobjects), or I will raise a Violation exception which will kick
        my Unslicer into 'discard' mode.

        I define maxSizeAccept as the maximum number of bytes that will be
        received before the stream is accepted as valid. maxSizeReject is
        the maximum that will be received before a Violation is raised. The
        max of the two provides an upper bound on single objects. For
        container objects, the upper bound is probably (n-1)*accept +
        reject, because there can only be one outstanding
        about-to-be-rejected object at any time.

        I return (maxSizeAccept, maxSizeReject).

        I raise an UnboundedSchema exception if there is no bound.
        """
        raise UnboundedSchema

    def maxDepth(self):
        """I return the greatest number Slicer objects that might exist on
        the SlicerStack (or Unslicers on the UnslicerStack) while processing
        an object which conforms to this constraint. This is effectively the
        maximum depth of the object tree. I raise UnboundedSchema if there is
        no bound.
        """
        raise UnboundedSchema

class Nothing(Constraint):
    """Accept only 'None'."""
    taster = openTaster
    strictTaster = True
    opentypes = [("none",)]
    name = "Nothing"

    def checkObject(self, obj, inbound):
        if obj is not None:
            raise Violation("'%s' is not None" % (obj,))
    def maxSize(self, seen=None):
        if not seen: seen = []
        return OPENBYTES("none")
    def maxDepth(self, seen=None):
        if not seen: seen = []
        return 1

class Any(Constraint):
    pass # accept everything


# constraints which describe individual banana tokens

class StringConstraint(Constraint):
    opentypes = [] # redundant, as taster doesn't accept OPEN
    name = "StringConstraint"

    def __init__(self, maxLength=1000):
        self.maxLength = maxLength
        self.taster = {STRING: self.maxLength,
                       VOCAB: None}
    def checkObject(self, obj, inbound):
        if not isinstance(obj, types.StringTypes):
            raise Violation("not a String")
        if self.maxLength != None and len(obj) > self.maxLength:
            raise Violation("string too long (%d > %d)" %
                            (len(obj), self.maxLength))
    def maxSize(self, seen=None):
        if self.maxLength == None:
            raise UnboundedSchema
        return 64+1+self.maxLength
    def maxDepth(self, seen=None):
        return 1

class IntegerConstraint(Constraint):
    opentypes = [] # redundant
    # taster set in __init__
    name = "IntegerConstraint"

    def __init__(self, maxBytes=-1):
        # -1 means s_int32_t: INT/NEG instead of INT/NEG/LONGINT/LONGNEG
        # None means unlimited
        assert maxBytes == -1 or maxBytes == None or maxBytes >= 4
        self.maxBytes = maxBytes
        self.taster = {INT: None, NEG: None}
        if maxBytes != -1:
            self.taster[LONGINT] = maxBytes
            self.taster[LONGNEG] = maxBytes

    def checkObject(self, obj, inbound):
        if not isinstance(obj, (types.IntType, types.LongType)):
            raise Violation("not a number")
        if self.maxBytes == -1:
            if obj >= 2**31 or obj < -2**31:
                raise Violation("number too large")
        elif self.maxBytes != None:
            if abs(obj) >= 2**(8*self.maxBytes):
                raise Violation("number too large")

    def maxSize(self, seen=None):
        if self.maxBytes == None:
            raise UnboundedSchema
        if self.maxBytes == -1:
            return 64+1
        return 64+1+self.maxBytes
    def maxDepth(self, seen=None):
        return 1

class NumberConstraint(IntegerConstraint):
    name = "NumberConstraint"

    def __init__(self, maxBytes=1024):
        assert maxBytes != -1  # not valid here
        IntegerConstraint.__init__(self, maxBytes)
        self.taster[FLOAT] = None

    def checkObject(self, obj, inbound):
        if isinstance(obj, types.FloatType):
            return
        IntegerConstraint.checkObject(self, obj, inbound)

    def maxSize(self, seen=None):
        # floats are packed into 8 bytes, so the shortest FLOAT token is
        # 64+1+8
        intsize = IntegerConstraint.maxSize(self, seen)
        return max(64+1+8, intsize)
    def maxDepth(self, seen=None):
        return 1

# constraints which describe OPEN sequences

COUNTERBYTES = 64 # max size of opencount

def OPENBYTES(dummy):
    # an OPEN,type,CLOSE sequence could consume:
    #  64 (header)
    #  1 (OPEN)
    #   64 (header)
    #   1 (STRING)
    #   1000 (value)
    #    or
    #   64 (header)
    #   1 (VOCAB)
    #  64 (header)
    #  1 (CLOSE)
    # for a total of 65+1065+65 = 1195
    return COUNTERBYTES+1 + 64+1+1000 + COUNTERBYTES+1


class BooleanConstraint(Constraint):
    taster = openTaster
    strictTaster = True
    opentypes = [("boolean",)]
    _myint = IntegerConstraint()
    name = "BooleanConstraint"

    def __init__(self, value=None):
        # self.value is a joke. This allows you to use a schema of
        # BooleanConstraint(True) which only accepts 'True'. I cannot
        # imagine a possible use for this, but it made me laugh.
        self.value = value

    def checkObject(self, obj, inbound):
        if type(obj) != types.BooleanType:
            raise Violation("not a bool")
        if self.value != None:
            if obj != self.value:
                raise Violation("not %s" % self.value)

    def maxSize(self, seen=None):
        if not seen: seen = []
        return OPENBYTES("boolean") + self._myint.maxSize(seen)
    def maxDepth(self, seen=None):
        if not seen: seen = []
        return 1+self._myint.maxDepth(seen)

class LocalInterfaceConstraint(Constraint):
    """This constraint accepts any (local) instance which implements the
    given local Interface.
    """

    # TODO: maybe accept RemoteCopy instances
    # TODO: accept inbound your-references, if the local object they map to
    #       implements the interface

    # TODO: do we need an string-to-Interface map just like we have a
    # classname-to-class/factory map?
    taster = nothingTaster
    opentypes = []
    name = "LocalInterfaceConstraint"

    def __init__(self, interface):
        self.interface = interface
    def checkObject(self, obj, inbound):
        # TODO: maybe try to get an adapter instead?
        if not self.interface.providedBy(obj):
            raise Violation("'%s' does not provide interface %s"
                            % (obj, self.interface))

class RemoteInterfaceConstraint(Constraint):
    """This constraint accepts any RemoteReference that claims to be
    associated with a remote Referenceable that implements the given
    RemoteInterface.
    """
    taster = openTaster
    opentypes = [("my-reference",)]
    # TODO: accept their-references too
    name = "RemoteInterfaceConstraint"

    def __init__(self, interface):
        self.interface = interface
    def checkObject(self, obj, inbound):
        if inbound:
            # TODO: the late import is to deal with an import cycle.. find a
            # better way to fix this.
            from foolscap.referenceable import RemoteReference
            if not isinstance(obj, RemoteReference):
                raise Violation("'%s' does not provide RemoteInterface %s, "
                                " and isn't even a RemoteReference"
                                % (obj, self.interface))
            iface = obj.tracker.interface
            # TODO: this test probably doesn't handle subclasses of
            # RemoteInterface, which might be useful (if it even works)
            if not iface or iface != self.interface:
                raise Violation("'%s' does not provide RemoteInterface %s"
                                % (obj, self.interface))
        else:
            if not self.interface.providedBy(obj):
                raise Violation("'%s' does not provide RemoteInterface %s"
                                % (obj, self.interface))

class ClassConstraint(Constraint):
    taster = openTaster
    opentypes = [("instance",)]
    name = "ClassConstraint"

    def __init__(self, klass):
        self.klass = klass
    def checkObject(self, obj, inbound):
        if not isinstance(obj, self.klass):
            # TODO: is this a security leak to show a remote object's repr?
            raise Violation("%s is not an instance of %s" %
                            (obj, self.klass))

class PolyConstraint(Constraint):
    name = "PolyConstraint"

    def __init__(self, *alternatives):
        self.alternatives = [makeConstraint(a) for a in alternatives]
        self.alternatives = tuple(self.alternatives)
        # TODO: taster/opentypes should be a union of the alternatives'

    def checkObject(self, obj, inbound):
        ok = False
        for c in self.alternatives:
            try:
                c.checkObject(obj, inbound)
                ok = True
            except Violation:
                pass
        if not ok:
            raise Violation("does not satisfy any of %s" \
                            % (self.alternatives,))

    def maxSize(self, seen=None):
        if not seen: seen = []
        if self in seen:
            # TODO: if the PolyConstraint contains itself directly, the effect
            # is a nop. If a descendent contains the ancestor PolyConstraint,
            # then I think it's unbounded.. must draw this out
            raise UnboundedSchema # recursion
        seen.append(self)
        return reduce(max, [c.maxSize(seen[:])
                            for c in self.alternatives])

    def maxDepth(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        return reduce(max, [c.maxDepth(seen[:]) for c in self.alternatives])

ChoiceOf = PolyConstraint

class TupleConstraint(Constraint):
    taster = openTaster
    opentypes = [("tuple",)]
    name = "TupleConstraint"

    def __init__(self, *elemConstraints):
        self.constraints = [makeConstraint(e) for e in elemConstraints]
    def checkObject(self, obj, inbound):
        if type(obj) != types.TupleType:
            raise Violation("not a tuple")
        if len(obj) != len(self.constraints):
            raise Violation("wrong size tuple")
        for i in range(len(self.constraints)):
            self.constraints[i].checkObject(obj[i], inbound)
    def maxSize(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        total = OPENBYTES("tuple")
        for c in self.constraints:
            total += c.maxSize(seen[:])
        return total

    def maxDepth(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        return 1 + reduce(max, [c.maxDepth(seen[:])
                                for c in self.constraints])

TupleOf = TupleConstraint

class ListConstraint(Constraint):
    """The object must be a list of objects, with a given maximum length. To
    accept lists of any length, use maxLength=None (but you will get a
    UnboundedSchema warning). All member objects must obey the given
    constraint."""

    taster = openTaster
    opentypes = [("list",)]
    name = "ListConstraint"

    def __init__(self, constraint, maxLength=30):
        self.constraint = makeConstraint(constraint)
        self.maxLength = maxLength
    def checkObject(self, obj, inbound):
        if type(obj) != types.ListType:
            raise Violation("not a list")
        if len(obj) > self.maxLength:
            raise Violation("list too long")
        for o in obj:
            self.constraint.checkObject(o, inbound)
    def maxSize(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        if self.maxLength == None:
            raise UnboundedSchema
        return (OPENBYTES("list") +
                self.maxLength * self.constraint.maxSize(seen))
    def maxDepth(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        return 1 + self.constraint.maxDepth(seen)

ListOf = ListConstraint

class DictConstraint(Constraint):
    taster = openTaster
    opentypes = [("dict",)]
    name = "DictConstraint"

    def __init__(self, keyConstraint, valueConstraint, maxKeys=30):
        self.keyConstraint = makeConstraint(keyConstraint)
        self.valueConstraint = makeConstraint(valueConstraint)
        self.maxKeys = maxKeys
    def checkObject(self, obj, inbound):
        if type(obj) != types.DictType:
            raise Violation, "'%s' (%s) is not a Dictionary" % (obj,
                                                                type(obj))
        if self.maxKeys != None and len(obj) > self.maxKeys:
            raise Violation, "Dict keys=%d > maxKeys=%d" % (len(obj),
                                                            self.maxKeys)
        for key, value in obj.iteritems():
            self.keyConstraint.checkObject(key, inbound)
            self.valueConstraint.checkObject(value, inbound)
    def maxSize(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        if self.maxKeys == None:
            raise UnboundedSchema
        keySize = self.keyConstraint.maxSize(seen[:])
        valueSize = self.valueConstraint.maxSize(seen[:])
        return OPENBYTES("dict") + self.maxKeys * (keySize + valueSize)
    def maxDepth(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        keyDepth = self.keyConstraint.maxDepth(seen[:])
        valueDepth = self.valueConstraint.maxDepth(seen[:])
        return 1 + max(keyDepth, valueDepth)

DictOf = DictConstraint


class AttributeDictConstraint(Constraint):
    """This is a constraint for dictionaries that are used for attributes.
    All keys are short strings, and each value has a separate constraint.
    It could be used to describe instance state, but could also be used
    to constraint arbitrary dictionaries with string keys.

    Some special constraints are legal here: Optional.
    """
    taster = openTaster
    opentypes = [("attrdict",)]
    name = "AttributeDictConstraint"

    def __init__(self, *attrTuples, **kwargs):
        self.ignoreUnknown = kwargs.get('ignoreUnknown', False)
        self.acceptUnknown = kwargs.get('acceptUnknown', False)
        self.keys = {}
        for name, constraint in (list(attrTuples) +
                                 kwargs.get('attributes', {}).items()):
            assert name not in self.keys.keys()
            self.keys[name] = makeConstraint(constraint)

    def maxSize(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        total = OPENBYTES("attributedict")
        for name, constraint in self.keys.iteritems():
            total += StringConstraint(len(name)).maxSize(seen)
            total += constraint.maxSize(seen[:])
        return total

    def maxDepth(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        # all the attribute names are 1-deep, so the min depth of the dict
        # items is 1. The other "1" is for the AttributeDict container itself
        return 1 + reduce(max, [c.maxDepth(seen[:])
                                for c in self.itervalues()], 1)

    def getAttrConstraint(self, attrname):
        c = self.keys.get(attrname)
        if c:
            if isinstance(c, Optional):
                c = c.constraint
            return (True, c)
        # unknown attribute
        if self.ignoreUnknown:
            return (False, None)
        if self.acceptUnknown:
            return (True, None)
        raise Violation("unknown attribute '%s'" % attrname)

    def checkObject(self, obj, inbound):
        if type(obj) != type({}):
            raise Violation, "'%s' (%s) is not a Dictionary" % (obj,
                                                                type(obj))
        allkeys = self.keys.keys()
        for k in obj.keys():
            try:
                constraint = self.keys[k]
                allkeys.remove(k)
            except KeyError:
                if not self.ignoreUnknown:
                    raise Violation, "key '%s' not in schema" % k
                else:
                    # hmm. kind of a soft violation. allow it for now.
                    pass
            else:
                constraint.checkObject(obj[k], inbound)

        for k in allkeys[:]:
            if isinstance(self.keys[k], Optional):
                allkeys.remove(k)
        if allkeys:
            raise Violation("object is missing required keys: %s" % \
                            ",".join(allkeys))


class RemoteMethodSchema:
    """
    This is a constraint for a single remotely-invokable method. It gets to
    require, deny, or impose further constraints upon a set of named
    arguments.

    This constraint is created by using keyword arguments with the same
    names as the target method's arguments. Two special names are used:

    __ignoreUnknown__: if True, unexpected argument names are silently
    dropped. (note that this makes the schema unbounded)

    __acceptUnknown__: if True, unexpected argument names are always
    accepted without a constraint (which also makes this schema unbounded)

    The remotely-accesible object's .getMethodSchema() method may return one
    of these objects.
    """

    implements(IRemoteMethodConstraint)

    taster = {} # this should not be used as a top-level constraint
    opentypes = [] # overkill
    ignoreUnknown = False
    acceptUnknown = False

    name = None # method name, set when the RemoteInterface is parsed
    interface = None # points to the RemoteInterface which defines the method

    # under development
    def __init__(self, method=None, _response=None, __options=[], **kwargs):
        if method:
            self.initFromMethod(method)
            return
        self.argumentNames = []
        self.argConstraints = {}
        self.required = []
        self.responseConstraint = None
        # __response in the argslist gets treated specially, I think it is
        # mangled into _RemoteMethodSchema__response or something. When I
        # change it to use _response instead, it works.
        if _response:
            self.responseConstraint = makeConstraint(_response)
        self.options = {} # return, wait, reliable, etc

        if kwargs.has_key("__ignoreUnknown__"):
            self.ignoreUnknown = kwargs["__ignoreUnknown__"]
            del kwargs["__ignoreUnknown__"]
        if kwargs.has_key("__acceptUnknown__"):
            self.acceptUnknown = kwargs["__acceptUnknown__"]
            del kwargs["__acceptUnknown__"]

        for argname, constraint in kwargs.items():
            self.argumentNames.append(argname)
            constraint = makeConstraint(constraint)
            self.argConstraints[argname] = constraint
            if not isinstance(constraint, Optional):
                self.required.append(argname)

    def initFromMethod(self, method):
        # call this with the Interface's prototype method: the one that has
        # argument constraints expressed as default arguments, and which
        # does nothing but returns the appropriate return type

        names, _, _, typeList = inspect.getargspec(method)
        if names and names[0] == 'self':
            why = "RemoteInterface methods should not have 'self' in their argument list"
            raise InvalidRemoteInterface(why)
        if not names:
            typeList = []
        if len(names) != len(typeList):
            # TODO: relax this, use schema=Any for the args that don't have
            # default values. This would make:
            #  def foo(a, b=int): return None
            # equivalent to:
            #  def foo(a=Any, b=int): return None
            why = "RemoteInterface methods must have default values for all their arguments"
            raise InvalidRemoteInterface(why)
        self.argumentNames = names
        self.argConstraints = {}
        self.required = []
        for i in range(len(names)):
            argname = names[i]
            constraint = typeList[i]
            if not isinstance(constraint, Optional):
                self.required.append(argname)
            self.argConstraints[argname] = makeConstraint(constraint)

        # call the method, its 'return' value is the return constraint
        self.responseConstraint = makeConstraint(method())
        self.options = {} # return, wait, reliable, etc


    def getPositionalArgConstraint(self, argnum):
        if argnum >= len(self.argumentNames):
            raise Violation("too many positional arguments: %d >= %d" %
                            (argnum, len(self.argumentNames)))
        argname = self.argumentNames[argnum]
        c = self.argConstraints.get(argname)
        assert c
        if isinstance(c, Optional):
            c = c.constraint
        return (True, c)

    def getKeywordArgConstraint(self, argname,
                                num_posargs=0, previous_kwargs=[]):
        previous_args = self.argumentNames[:num_posargs]
        for pkw in previous_kwargs:
            assert pkw not in previous_args
            previous_args.append(pkw)
        if argname in previous_args:
            raise Violation("got multiple values for keyword argument '%s'"
                            % (argname,))
        c = self.argConstraints.get(argname)
        if c:
            if isinstance(c, Optional):
                c = c.constraint
            return (True, c)
        # what do we do with unknown arguments?
        if self.ignoreUnknown:
            return (False, None)
        if self.acceptUnknown:
            return (True, None)
        raise Violation("unknown argument '%s'" % argname)

    def getResponseConstraint(self):
        return self.responseConstraint

    def checkAllArgs(self, args, kwargs, inbound):
        # first we map the positional arguments
        allargs = {}
        if len(args) > len(self.argumentNames):
            raise Violation("method takes %d positional arguments (%d given)"
                            % (len(self.argumentNames), len(args)))
        for i,argvalue in enumerate(args):
            allargs[self.argumentNames[i]] = argvalue
        for argname,argvalue in kwargs.items():
            if argname in allargs:
                raise Violation("got multiple values for keyword argument '%s'"
                                % (argname,))
            allargs[argname] = argvalue

        for argname, argvalue in allargs.items():
            accept, constraint = self.getKeywordArgConstraint(argname)
            if not accept:
                # this argument will be ignored by the far end. TODO: emit a
                # warning
                pass
            try:
                constraint.checkObject(argvalue, inbound)
            except Violation, v:
                v.setLocation("%s=" % argname)
                raise

        for argname in self.required:
            if argname not in allargs:
                raise Violation("missing required argument '%s'" % argname)

    def checkResults(self, results, inbound):
        if self.responseConstraint:
            # this might raise a Violation. The caller will annotate its
            # location appropriately: they have more information than we do.
            self.responseConstraint.checkObject(results, inbound)

    def maxSize(self, seen=None):
        if self.acceptUnknown:
            raise UnboundedSchema # there is no limit on that thing
        if self.ignoreUnknown:
            # for now, we ignore unknown arguments by accepting the object
            # and then throwing it away. This makes us vulnerable to the
            # memory consumed by that object. TODO: in the CallUnslicer,
            # arrange to discard the ignored object instead of receiving it.
            # When this is done, ignoreUnknown will not cause the schema to
            # be unbounded and this clause should be removed.
            raise UnboundedSchema
        # TODO: implement the rest of maxSize, just like a dictionary
        raise NotImplementedError



#TODO
class Shared(Constraint):
    name = "Shared"

    def __init__(self, constraint, refLimit=None):
        self.constraint = makeConstraint(constraint)
        self.refLimit = refLimit
    def maxSize(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        return self.constraint.maxSize(seen)
    def maxDepth(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        return self.constraint.maxDepth(seen)

#TODO: might be better implemented with a .optional flag
class Optional(Constraint):
    name = "Optional"

    def __init__(self, constraint, default):
        self.constraint = makeConstraint(constraint)
        self.default = default
    def maxSize(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        return self.constraint.maxSize(seen)
    def maxDepth(self, seen=None):
        if not seen: seen = []
        if self in seen:
            raise UnboundedSchema # recursion
        seen.append(self)
        return self.constraint.maxDepth(seen)

class FailureConstraint(AttributeDictConstraint):
    taster = openTaster
    opentypes = [("copyable", "twisted.python.failure.Failure")]
    name = "FailureConstraint"
    klass = failure.Failure

    def __init__(self):
        attrs = [('type', StringConstraint(200)),
                 ('value', StringConstraint(1000)),
                 ('traceback', StringConstraint(2000)),
                 ('parents', ListOf(StringConstraint(200))),
                 ]
        AttributeDictConstraint.__init__(self, *attrs)

    def checkObject(self, obj, inbound):
        if not isinstance(obj, self.klass):
            raise Violation("is not an instance of %s" % self.klass)


def makeConstraint(t):
    #if isinstance(t, Constraint):
    if IConstraint.providedBy(t):
        return t
    map = {
        types.StringType: StringConstraint(),
        types.BooleanType: BooleanConstraint(),
        types.IntType: IntegerConstraint(),
        types.LongType: IntegerConstraint(maxBytes=1024),
        types.FloatType: NumberConstraint(),
        None: Nothing(),
        }
    c = map.get(t, None)
    if c:
        return c

    if isinstance(t, InterfaceClass):
        # this matches both local interfaces (IFoo) and remote interfaces
        # (RIFoo), so we have to distinguish between them. The late import is
        # to deal with a circular reference between this module and
        # remoteinterface.py
        from foolscap.remoteinterface import RemoteInterfaceClass
        if isinstance(t, RemoteInterfaceClass):
            return RemoteInterfaceConstraint(t)
        return LocalInterfaceConstraint(t)

    if isinstance(t, types.ClassType):
        # TODO: this can be confusing, I had a schema of foo=Any (when I
        # should have said foo=Any() ) and got weird error messages because
        # my object was not an instance of the Any class. Maybe replace this
        # case with ClassOf(Thing) instead?
        return ClassConstraint(t)

    # alternatives
    if type(t) == types.TupleType:
        return PolyConstraint(*t)

    raise UnknownSchemaType("can't make constraint from '%s' (%s)" % (t, type(t)))





# how to accept "([(ref0" ?
# X = "TupleOf(ListOf(TupleOf(" * infinity
# ok, so you can't write a constraint that accepts it. I'm ok with that.
