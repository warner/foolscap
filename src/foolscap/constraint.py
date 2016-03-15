
# This provides a base for the various Constraint subclasses to use. Those
# Constraint subclasses live next to the slicers. It also contains
# Constraints for primitive types (int, str).

# This imports foolscap.tokens, but no other Foolscap modules.

import re
from zope.interface import implements, Interface

from foolscap.tokens import Violation, BananaError, SIZE_LIMIT, \
     STRING, LIST, INT, NEG, LONGINT, LONGNEG, VOCAB, FLOAT, OPEN, \
     tokenNames

everythingTaster = {
    # he likes everything
    STRING: None,
    LIST: None,
    INT: None,
    NEG: None,
    LONGINT: SIZE_LIMIT, # this limits numbers to about 2**8000, probably ok
    LONGNEG: SIZE_LIMIT,
    VOCAB: None,
    FLOAT: None,
    OPEN: None,
    }
openTaster = {
    OPEN: None,
    }
nothingTaster = {}

class IConstraint(Interface):
    pass
class IRemoteMethodConstraint(IConstraint):
    def getPositionalArgConstraint(argnum):
        """Return the constraint for posargs[argnum]. This is called on
        inbound methods when receiving positional arguments. This returns a
        tuple of (accept, constraint), where accept=False means the argument
        should be rejected immediately, regardless of what type it might be."""
    def getKeywordArgConstraint(argname, num_posargs=0, previous_kwargs=[]):
        """Return the constraint for kwargs[argname]. The other arguments are
        used to handle mixed positional and keyword arguments. Returns a
        tuple of (accept, constraint)."""

    def checkAllArgs(args, kwargs, inbound):
        """Submit all argument values for checking. When inbound=True, this
        is called after the arguments have been deserialized, but before the
        method is invoked. When inbound=False, this is called just inside
        callRemote(), as soon as the target object (and hence the remote
        method constraint) is located.

        This should either raise Violation or return None."""
        pass
    def getResponseConstraint():
        """Return an IConstraint-providing object to enforce the response
        constraint. This is called on outbound method calls so that when the
        response starts to come back, we can start enforcing the appropriate
        constraint right away."""
    def checkResults(results, inbound):
        """Inspect the results of invoking a method call. inbound=False is
        used on the side that hosts the Referenceable, just after the target
        method has provided a value. inbound=True is used on the
        RemoteReference side, just after it has finished deserializing the
        response.

        This should either raise Violation or return None."""

class Constraint(object):
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
                raise BananaError("invalid token type: %s" %
                                  tokenNames[typebyte])
            else:
                raise Violation("%s token rejected by %s" %
                                (tokenNames[typebyte], self.name))
        if limit and size > limit:
            raise Violation("%s token too large: %d>%d" %
                            (tokenNames[typebyte], size, limit))

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

        # shared references are always accepted. checkOpentype() is a defense
        # against resource-exhaustion attacks, and references don't consume
        # any more resources than any other token. For inbound method
        # arguments, the CallUnslicer will perform a final check on all
        # arguments (after these shared references have been resolved), and
        # that will get to verify that they have resolved to the correct
        # type.

        #if opentype == ReferenceSlicer.opentype:
        if opentype == ('reference',):
            return

        for o in self.opentypes:
            if len(o) == len(opentype):
                if o == opentype:
                    return
            if len(o) > len(opentype):
                # we might have a partial match: they haven't flunked yet
                if opentype == o[:len(opentype)]:
                    return # still in the running

        raise Violation("unacceptable OPEN type: %s not in my list %s" %
                        (opentype, self.opentypes))

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

    COUNTERBYTES = 64 # max size of opencount

    def OPENBYTES(self, dummy):
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
        return self.COUNTERBYTES+1 + 64+1+1000 + self.COUNTERBYTES+1

class OpenerConstraint(Constraint):
    taster = openTaster

class Any(Constraint):
    pass # accept everything

# constraints which describe individual banana tokens

class ByteStringConstraint(Constraint):
    opentypes = [] # redundant, as taster doesn't accept OPEN
    name = "ByteStringConstraint"

    def __init__(self, maxLength=None, minLength=0, regexp=None):
        self.maxLength = maxLength
        self.minLength = minLength
        # regexp can either be a string or a compiled SRE_Match object..
        # re.compile appears to notice SRE_Match objects and pass them
        # through unchanged.
        self.regexp = None
        if regexp:
            self.regexp = re.compile(regexp)
        self.taster = {STRING: self.maxLength,
                       VOCAB: None}

    def checkObject(self, obj, inbound):
        if not isinstance(obj, str):
            raise Violation("'%r' is not a bytestring" % (obj,))
        if self.maxLength != None and len(obj) > self.maxLength:
            raise Violation("string too long (%d > %d)" %
                            (len(obj), self.maxLength))
        if len(obj) < self.minLength:
            raise Violation("string too short (%d < %d)" %
                            (len(obj), self.minLength))
        if self.regexp:
            if not self.regexp.search(obj):
                raise Violation("regexp failed to match")

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
        if not isinstance(obj, (int, long)):
            raise Violation("'%r' is not a number" % (obj,))
        if self.maxBytes == -1:
            if obj >= 2**31 or obj < -2**31:
                raise Violation("number too large")
        elif self.maxBytes != None:
            if abs(obj) >= 2**(8*self.maxBytes):
                raise Violation("number too large")

class NumberConstraint(IntegerConstraint):
    """I accept floats, ints, and longs."""
    name = "NumberConstraint"

    def __init__(self, maxBytes=1024):
        assert maxBytes != -1  # not valid here
        IntegerConstraint.__init__(self, maxBytes)
        self.taster[FLOAT] = None

    def checkObject(self, obj, inbound):
        if isinstance(obj, float):
            return
        IntegerConstraint.checkObject(self, obj, inbound)



#TODO
class Shared(Constraint):
    name = "Shared"

    def __init__(self, constraint, refLimit=None):
        self.constraint = IConstraint(constraint)
        self.refLimit = refLimit

#TODO: might be better implemented with a .optional flag
class Optional(Constraint):
    name = "Optional"

    def __init__(self, constraint, default):
        self.constraint = IConstraint(constraint)
        self.default = default
