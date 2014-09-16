Foolscap Schemas
================

*NOTE! This is all preliminary and is more an exercise in semiconscious
protocol design than anything else. Do not believe this document. This
sentence is lying. So there.*




Existing ``Constraint``  classes
--------------------------------



+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| class name                                                                  | shortcut     | \                                                                             |
+=============================================================================+==============+===============================================================================+
| ``Any()``                                                                   | \            | accept anything                                                               |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``StringConstraint(maxLength=1000)``                                        | ``str``      | string of up to maxLength characters (maxLength=None means                    |
|                                                                             |              | unlimited), or a VOCAB sequence of any length                                 |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``IntegerConstraint(maxBytes=-1)``                                          | ``int``      | integer. maxBytes=-1 means s_int32_t, =N means LONGINT which can be           |
|                                                                             |              | expressed in N or fewer bytes (i.e. abs(num) < 2**(8*maxBytes)),              |
|                                                                             |              | =None means unlimited. NOTE: shortcut 'long' is like shortcut 'int' but       |
|                                                                             |              | maxBytes=1024.                                                                |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``NumberConstraint(maxBytes=1024)``                                         | ``float``    | integer or float. Integers are limited by maxBytes as in                      |
|                                                                             |              | ``IntegerConstraint`` , floats are fixed size.                                |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``BooleanConstraint(value=None)``                                           | ``bool``     | True or False. If value=True, only accepts True. If value=False,              |
|                                                                             |              | only accepts False. NOTE: value= is a very silly parameter.                   |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``InterfaceConstraint(iface)``                                              | Interface    | TODO. UNSAFE. Accepts an instance which claims to implement the given         |
|                                                                             |              | Interface. The shortcut is simply any Interface subclass.                     |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``ClassConstraint``                                                         | Class        | TODO. UNSAFE. Accepts an instance which claims to be of the given             |
|                                                                             |              | class name. The shortcut is simply any (old-style) class object.              |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``PolyConstraint(*alternatives)``                                           | (alt1, alt2) | Accepts any object which obeys at least one of the alternative                |
|                                                                             |              | constraints provided. Implements a logical OR function of the given           |
|                                                                             |              | constraints. Also known as ``ChoiceOf`` .                                     |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``TupleConstraint(*elemConstraints)``                                       | \            | Accepts a tuple of fixed length with elements that obey the given             |
|                                                                             |              | constraints. Also known as ``TupleOf`` .                                      |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``ListConstraint(elemConstraint, maxLength=30)``                            | \            | Accepts a list of up to maxLength items, each of which obeys the              |
|                                                                             |              | element constraint provided. Also known as ``ListOf`` .                       |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``DictConstraint(keyConstraint, valueConstraint, maxKeys=30)``              | \            | Accepts a dictionary of up to maxKeys items. Each key must obey               |
|                                                                             |              | keyConstraint and each value must obey valueConstraint. Also known            |
|                                                                             |              | as ``DictOf`` .                                                               |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``AttributeDictConstraint(*attrTuples, **kwargs)``                          | \            | Constrains dictionaries used to describe instance attributes, as used         |
|                                                                             |              | by RemoteCopy. Each attrTuple is a pair of (attrname, constraint), used       |
|                                                                             |              | to constraint individual named attributes. kwargs['attributes']               |
|                                                                             |              | provides the same control. kwargs['ignoreUnknown'] is a boolean flag          |
|                                                                             |              | which indicates that unknown attributes in inbound state should simply        |
|                                                                             |              | be dropped. kwargs['acceptUnknown'] indicates that unknown attributes         |
|                                                                             |              | should be accepted into the instance state dictionary.                        |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``RemoteMethodSchema(method=None, _response=None, __options=[], **kwargs)`` | \            | Constrains arguments and return value of a single remotely-invokable          |
|                                                                             |              | method. If method= is provided, the ``inspect``  module is used               |
|                                                                             |              |     to extract constraints from the method itself (positional arguments are   |
|                                                                             |              |     not allowed, default values of keyword arguments provide constraints for  |
|                                                                             |              |     each argument, the results of running the method provide the return value |
|                                                                             |              |     constraint). If not, most kwargs items provide constraints for method     |
|                                                                             |              |     arguments, _response provides a constraint for the return value.          |
|                                                                             |              |     __options and additional kwargs keys provide neato whiz-bang future       |
|                                                                             |              |     expansion possibilities.                                                  |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``Shared(constraint, refLimit=None)``                                       | \            | TODO. Allows objects with refcounts no greater than refLimit (=None           |
|                                                                             |              | means unlimited). Wraps another constraint, which the object must obey.       |
|                                                                             |              | refLimit=1 rejects shared objects.                                            |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``Optional(constraint, default)``                                           | \            | TODO. Can be used to tag Copyable attributes or (maybe) method                |
|                                                                             |              | arguments. Wraps another constraint. If an object is provided, it must        |
|                                                                             |              | obey the constraint. If not provided, the default value will be given in      |
|                                                                             |              | its place.                                                                    |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+
| ``FailureConstraint()``                                                     | \            | Constrains the contents of a CopiedFailure.                                   |
+-----------------------------------------------------------------------------+--------------+-------------------------------------------------------------------------------+



::

    
    
    """
    
    RemoteReference objects should all be tagged with interfaces that they
    implement, which point to representations of the method schemas. When a
    remote method is called, Foolscap should look up the appropriate method and
    serialize the argument list accordingly.
    
    We plan to eliminate positional arguments, so local RemoteReferences use
    their schema to convert callRemote calls with positional arguments to
    all-keyword arguments before serialization.
    
    Conversion to the appropriate version interface should be handled at the
    application level.  Eventually, with careful use of twisted.python.context,
    we might be able to provide automated tools for helping application authors
    automatically convert interface calls and isolate version-conversion code,
    but that is probably pretty hard.
    
    """
    
    
    class Attributes:
        def __init__(self,*a,**k):
            pass
    
    X = Attributes(
        ('hello', str),
        ('goodbye', int),
    
        # Allow the possibility of multiple or circular references.  The default
        # is to make multiple copies to avoid making the serializer do extra
        # work.
        ('next', Shared(Narf)),
    
        ('asdf', ListOf(Narf, maxLength=30)),
        ('fdsa', (Narf, String(maxLength=5), int)),
        ('qqqq', DictOf(str, Narf, maxKeys=30)),
        ('larg', AttributeDict(('A', int),
                               ('X', Number),
                               ('Z', float))),
        Optional("foo", str),
        Optional("bar", str, default=None),
        ignoreUnknown=True,
        )
    
    X = Attributes(
        attributes={ 'hello': str,     # this form doesn't allow Optional()
                     'goodbye': int,
                   },
        Optional("foo", str),  # but both can be used at once
        ignoreUnknown=True)
    
    class Narf(Remoteable):
        # step 1
        __schema__ = X
        # step 2 (possibly - this loses information)
        class schema:
            hello = str
            goodbye = int
            class add:
                x = Number
                y = Number
                __return__ = Copy(Number)
    
            class getRemoteThingy:
                fooID = Arg(WhateverID, default=None)
                barID = Arg(WhateverID, default=None)
                __return__ = Reference(Narf)
    
        # step 3 - this is the only example that shows argument order, which we
        # _do_ need in order to translate positional arguments to callRemote, so
        # don't take the nested-classes example too seriously.
    
        schema = """
        int add (int a, int b)
        """
    
        # Since the above schema could also be used for Formless, or possibly for
        # World (for state) we can also do:
    
        class remote_schema:
            """blah blah
            """
    
        # You could even subclass that from the other one...
    
        class remote_schema(schema):
            dontUse = 'hello', 'goodbye'
    
    
        def remote_add(self, x, y):
            return x + y
    
        def rejuvinate(self, deadPlayer):
            return Reference(deadPlayer.bringToLife())
    
        # "Remoteable" is a new concept - objects which may be method-published
        # remotely _or_ copied remotely.  The schema objects support both method
        # / interface definitions and state definitions, so which one gets used
        # can be defined by the sending side as to whether it sends a
        # Copy(theRemoteable) or Reference(theRemoteable)
    
        # (also, with methods that are explicitly published by a schema there is
        # no longer technically any security need for the remote_ prefix, which,
        # based on past experience can be kind of annoying if you want to
        # provide the same methods locally and remotely)
    
        # outstanding design choice - Referenceable and Copyable are subclasses
        # of Remoteable, but should they restrict the possibility of sending it
        # the other way or
    
        def getPlayerInfo(self, playerID):
            return CopyOf(self.players[playerID])
    
        def getRemoteThingy(self, fooID, barID):
            return ReferenceTo(self.players[selfPlayerID])
    
    
    class RemoteNarf(Remoted):
        __schema__ = X
        # or, example of a difference between local and remote
        class schema:
            class getRemoteThingy:
                __return__ = Reference(RemoteNarf)
            class movementUpdate:
                posX = int
                posY = int
    
                # No return value
                __return__ = None
    
                # Don't wait for the answer
                __wait__ = False
    
                # Feel free to send this over UDP
                __reliable__ = False
    
                # but send in order!
                __ordered__ = True
    
                # use priority queue / stream 3
                __priority__ = 3
    
                # allow full serialization of failures
                __failure__ = FullFailure
    
                # default: trivial failures, or str or int
                __failure__ = ErrorMessage
    
                # These options may imply different method names - e.g. '__wait__ =
                # False' might imply that you can't use callRemote, you have to
                # call 'sendRemote' instead... __reliable__ = False might be
                # 'callRemoteUnreliable' (longer method name to make it less
                # convenient to call by accident...)
    
    
    ## (and yes, donovan, we know that TypedInterface exists and we are going to
    ## use it.  we're just screwing around with other syntaxes to see what about PB
    ## might be different.)
    
    Common banana sequences:
    
    A reference to a remote object.
       (On the sending side: Referenceable or ReferenceTo(aRemoteable)
        On the receiving side: RemoteReference)
    ('remote', reference-id, interface, version, interface, version, ...)
    
    
    A call to a remote method:
    ('fastcall', request-id, reference-id,
     method-name, 'arg-name', arg1, 'arg-name', arg2)
    
    A call to a remote method with extra spicy metadata:
    ('call', request-id, reference-id, interface,
     version, method-name, 'arg-name', arg1, 'arg-name', arg2)
    
    Special hack: request-id of 0 means 'do not answer this call, do not
    acknowledge', etc.
    
    Answer to a method call:
    ('answer', request-id, response)
    ('error', request-id, response)
    
    Decrement a reference incremented by 'remote' command:
    ('decref', reference-id)
    
    Broker currently has 9 proto_ methods:
    
    _version(vnum): accept a version number, compare to ours, reject if different
    
    _didNotUnderstand(command): log command, maybe drop connection
    
    _message(reqID, objID, message, answerRequired, netArgs, netKw):
    _cachemessage (like _message but finds objID with self.cachedLocallyAs instead
                   of self.localObjectForID, used by RemoteCacheMethod and
                   RemoteCacheObserver)
     look up objID, invoke it with .remoteMessageReceived(message, args),
     send "answer"(reqID, results)
    
    _answer(reqID, results): look up self.waitingForAnswers[reqID] and fire
                             callback with results
    
    _error(reqID, failure): lookup waitingForAnswers, fire errback
    
    _decref(objID): dec refcount of self.localObjects[objID]. Sent in
                    RemoteReference.__del__
    
    _decache(objID): dec refcount of self.remotelyCachedObjects[objID]
    
    _uncache(objID): remove obj from self.locallyCachedObjects[objID]

stuff
-----

A RemoteReference/RemoteCopy (called a Remote for now) has a schema
attached to it. remote.callRemote(methodname, *args) does
schema.getMethodSchema(methodname) to obtain a MethodConstraint that
describes the individual method. This MethodConstraint (or MethodSchema) has
other attributes which are used by either end: what arguments are allowed
and/or expected, calling conventions (synchronous, in-order, priority, etc),
and how the return value should be constrained.

To use the Remote like a RemoteCopy ...

::

    
    
    Remote:
     .methods
     .attributes
     .getMethodSchema(methodname) -> MethodConstraint
     .getAttributeSchema(attrname) -> a Constraint
    
    XPCOM idl specifies methods and attributes (readonly, readwrite). A Remote
    object which represented a distant XPCOM object would have a Schema that is
    created by parsing the IDL. Its callRemote would do the appropriate
    marshalling. Issue1: XPCOM lets methods have in/out/inout parameters.. these
    must be detected and a wrapper generated. Issue2: what about attribute
    set/get operations? Could add setRemote and getRemote for these.
    
    ---
    
    Some of the schema questions come down to how PBRootSlicer should deal with
    instances. The question is whether to treat the instance as a Referenceable
    (copy-by-reference: create and transmit a reference number, which will be
    turned into a RemoteReference on the other end), or as a Copyable
    (copy-by-value: collect some instance state and send it as an instance).
    This decision could be made by looking at what the instance inherits from:
    
      if isinstance(obj, pb.Referenceable):
          sendByReference(obj)
      elif isinstance(obj, pb.Copyable):
          sendByValue(obj)
      else:
          raise InsecureJellyError
    
    or by what it can be adapted to:
    
      r = IReferenceable(obj, None)
      if r:
          sendByReference(r)
      else:
          r = ICopyable(obj, None)
          if r:
              sendByValue(r)
          else:
              raise InsecureJellyError
    
    The decision could also be influenced by the sending schema currently in
    effect. Side A invokes a method on side B. A knows of a schema which states
    that the 'foo' argument of this method should be a CopyableSpam, so it
    requires the object be adaptable to ICopyableSpam (which is then copied by
    value) tries to comply when that argument is serialized. B will enforce its
    own schema. When B returns a result to A, the method-result schema on B's
    side can influence how the return value is handled.
    
    For bonus points, it may be possible to send the object as a combination of
    these two. That may get pretty hard to follow, though.

adapters and Referenceable/Copyable
-----------------------------------

One possibility: rather than using a SlicerRegistry, use Adapters. The
ISliceable interface has one method: getSlicer(). Slicer.py would register
adapters for basic types (list, dict, etc) that would just return an
appropriate ListSlicer, etc. Instances which would have been pb.Copyable
subclasses in oldpb can still inherit from pb.Copyable, which now implements
ISliceable and produces a Slicer (opentype='instance') that calls
getStateToCopy() (although the subclass-__implements__ handling is now more
important than before). pb.Referenceable implements ISlicer and produces a
Slicer (opentype='reference'?) which (possibly) registers itself in the
broker and then sends the reference number (along with a schema if necessary
(and the other end wants them)).

Classes are also welcome to implement ISlicer themselves and produce whatever
clever (streaming?) Slicer objects they like.

On the receiving side, we still need a registry to provide reasonable
security. There are two registries. The first is the
RootUnslicer.openRegistry, and maps OPEN types to Unslicer factories. It is
used in doOpen().

The second registry should map opentype=instance class names to something
which can handle the instance contents. Should this be a replacement
Unslicer?
