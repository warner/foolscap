Using Pass-By-Copy in Foolscap
==============================

Certain objects (including subclasses of ``foolscap.Copyable`` and things for
which an ``ICopyable`` adapter has been registered) are serialized using
copy-by-value semantics. Each such object is serialized as a (copytype,
state) pair of values. On the receiving end, the "copytype" is looked up in a
table to find a suitable deserializer. The "state" information is passed to
this deserializer to create a new instance that corresponds to the original.
Note that the sending and receiving ends are under no obligation to use the
same class on each side: it is fairly common for the remote form of an object
to have different methods than the original instance.

Copy-by-value (as opposed to copy-by-reference) means that the remote
representation of an object leads an independent existence, unconnected to
the original. Sending the same object multiple times will result in separate
independent copies. Sending the result of a pass-by-copy operation back to
the original sender will, at best, result in the sender holding two separate
objects containing similar state (and at worst will not work at all: not all
RemoteCopies are themselves Copyable).

More complex copy semantics can be accomplished by writing custom Slicer
code. For example, to get an object that is copied by value the first time it
traverses the wire, and then copied by reference all later times, you will
need to write a Slicer/Unslicer pair to implement this functionality.
Likewise the oldpb ``Cacheable`` class would need to be implemented with a
custom Slicer/Unslicer pair.

Copyable
--------

The easiest way to send your own classes over the wire is to use ``Copyable``
. On the sending side, this requires two things: your class must inherit from
``foolscap.Copyable`` , and it must define an attribute named ``typeToCopy``
with a unique string. This copytype string is shared between both sides, so
it is a good idea to use a stable and globally unique value: perhaps a URL
rooted in a namespace that you control, or a UUID, or perhaps the
fully-qualified package+module+class name of the class being serialized. Any
string will do, as long as it matches the one used on the receiving side.

The object being sent is asked to provide a state dictionary by calling its
``ICopyable.getStateToCopy`` method. The default implementation of
``getStateToCopy`` will simply return ``self.__dict__`` . You can override
``getStateToCopy`` to control what pieces of the source object get copied to
the target. In particular, you may want to override ``getStateToCopy`` if
there is any portion of the object's state that should **not** be sent over
the wire: references to objects that can not or should not be serialized, or
things that are private to the application. It is common practice to create
an empty dictionary in this method and then copy items into it.

On the receiving side, you must register the copytype and provide a function
to deserialize the state dictionary back into an instance. For each
``Copyable`` subclass you will create a corresponding ``RemoteCopy``
subclass. There are three requirements which must be fulfilled by this
subclass:

#. ``copytype`` : Each ``RemoteCopy`` needs a ``copytype`` attribute which
   contains the same string as the corresponding ``Copyable`` 's
   ``typeToCopy`` attribute. (metaclass magic is used to auto-register the
   ``RemoteCopy`` class in the global copytype-to-RemoteCopy table when the
   class is defined. You can also use ``registerRemoteCopy`` to manually
   register a class).
#. ``__init__`` : The ``RemoteCopy`` subclass must have an __init__ method
   that takes no arguments. When the receiving side is creating the incoming
   object, it starts by creating a new instance of the correct ``RemoteCopy``
   subclass, and at this point it has no arguments to work with. Later, once
   the instance is created, it will call ``setCopyableState`` to populate it.
#. ``setCopyableState`` : Your ``RemoteCopy`` subclass must define a method
   named ``setCopyableState`` . This method will be called with the state
   dictionary that came out of ``getStateToCopy`` on the sending side, and is
   expected to set any necessary internal state.

Note that ``RemoteCopy`` is a new-style class: if you want your copies to be
old-style classes, inherit from ``RemoteCopyOldStyle`` and manually register
the copytype-to-subclass mapping with ``registerRemoteCopy`` .

(doc/listings/copyable-send.py)

.. code-block:: python

    #! /usr/bin/python
    
    from twisted.internet import reactor
    from foolscap.api import Copyable, Referenceable, Tub
    
    # the sending side defines the Copyable
    
    class UserRecord(Copyable):
        # this class uses the default Copyable behavior
        typeToCopy = "unique-string-UserRecord"
    
        def __init__(self, name, age, shoe_size):
            self.name = name
            self.age = age
            self.shoe_size = shoe_size # this is a secret
    
        def getStateToCopy(self):
            d = {}
            d['name'] = self.name
            d['age'] = self.age
            # don't tell anyone our shoe size
            return d
    
    class Database(Referenceable):
        def __init__(self):
            self.users = {}
        def addUser(self, name, age, shoe_size):
            self.users[name] = UserRecord(name, age, shoe_size)
        def remote_getuser(self, name):
            return self.users[name]
    
    db = Database()
    db.addUser("alice", 34, 8)
    db.addUser("bob", 25, 9)
    
    tub = Tub()
    tub.listenOn("tcp:12345")
    tub.setLocation("localhost:12345")
    url = tub.registerReference(db, "database")
    print "the database is at:", url
    tub.startService()
    reactor.run()

(doc/listings/copyable-receive.py)

.. code-block:: python

    #! /usr/bin/python
    
    import sys
    from twisted.internet import reactor
    from foolscap.api import RemoteCopy, Tub
    
    # the receiving side defines the RemoteCopy
    class RemoteUserRecord(RemoteCopy):
        copytype = "unique-string-UserRecord" # this matches the sender
    
        def __init__(self):
            # note: our __init__ must take no arguments
            pass
    
        def setCopyableState(self, d):
            self.name = d['name']
            self.age = d['age']
            self.shoe_size = "they wouldn't tell us"
    
        def display(self):
            print "Name:", self.name
            print "Age:", self.age
            print "Shoe Size:", self.shoe_size
    
    def getRecord(rref, name):
        d = rref.callRemote("getuser", name=name)
        def _gotRecord(r):
            # r is an instance of RemoteUserRecord
            r.display()
            reactor.stop()
        d.addCallback(_gotRecord)
    
    
    from foolscap.api import Tub
    tub = Tub()
    tub.startService()
    
    d = tub.getReference(sys.argv[1])
    d.addCallback(getRecord, "alice")
    
    reactor.run()


Registering Copiers to serialize third-party classes
----------------------------------------------------

If you wish to serialize instances of third-party classes that are out of
your control (or you simply want to avoid subclassing), you can register a
Copier to provide serialization mechanisms for those instances.

There are plenty of cases where it is difficult to arrange for all of the
data you send over the wire to be in the form of ``Copyable`` subclasses. For
example, you might have a codebase that produces a deeply-nested data
structure that contains instances of pre-existing classes. Those classes are
written by other people, and do not happen to inherit from ``Copyable`` .
Without Copiers, you would have to traverse the whole structure, locate all
instances of these non-``Copyable`` classes, and wrap them in some new
``Copyable`` subclass. Registering a Copier for the third-party class is much
easier.

The ``foolscap.copyable.registerCopier`` function is used to provide a
"copier" for any given class. This copier is a function that accepts an
instance of the given class, and returns a (copytype, state) tuple. For
example [#]_ , the xmlrpclib module provides a ``DateTime`` class, and you
might have a data structure that includes some instances of them:

.. code-block:: python

    
    import xmlrpclib
    from foolscap import registerCopier
    
    def copy_DateTime(xd):
        return ("_xmlrpclib_DateTime", {"value": xd.value})
    
    registerCopier(xmlrpclib.DateTime, copy_DateTime)

This insures that any ``xmlrpclib.DateTime`` that is encountered while
serializing arguments or return values will be serialized with a copytype of
"_xmlrpclib_DateTime" and a state dictionary containing the single "value"
key. Even ``DateTime`` instances that appear arbitrarily deep inside nested
data structures will be serialized this way. For example, one a method
argument might be dictionary, and one of its keys was a list, and that list
could containe a ``DateTime`` instance.

To deserialize this object, the receiving side needs to register a
corresponding deserializer. ``foolscap.copyable.registerRemoteCopyFactory``
is the receiving-side parallel to ``registerCopier`` . It associates a
copytype with a function that will receive a state dictionary and is expected
to return a fully-formed instance. For example:

.. code-block:: python

    
    import xmlrpclib
    from foolscap import registerRemoteCopyFactory
    
    def make_DateTime(state):
        return xmlrpclib.DateTime(state["value"])
    
    registerRemoteCopyFactory("_xmlrpclib_DateTime", make_DateTime)

Note that the "_xmlrpclib_DateTime" copytype **must** be the same for both
the copier and the RemoteCopyFactory, otherwise the receiving side will be
unable to locate the correct deserializer.

It is perfectly reasonable to include both of these function/registration
pairs in the same module, and import it in the code on both sides of the
wire. The examples describe the sending and receiving sides separately to
emphasize the fact that the recipient may be running completely different
code than the sender.

Registering ICopyable adapters
------------------------------

A slightly more generalized way to teach Foolscap about third-party classes
is to register an ``ICopyable`` adapter for them, using the usual (i.e.
zope.interface) adapter-registration mechanism. The object that provides
``ICopyable`` needs to implement two methods: ``getTypeToCopy`` (which
returns the copytype), and ``getStateToCopy`` , which returns the state
dictionary. Any object which can be adapted to ``ICopyable`` can be
serialized this way.

On the receiving side, the copytype is looked up in the ``CopyableRegistry``
to find a corresponding UnslicerFactory. The
``registerRemoteCopyUnslicerFactory`` function accepts two arguments: the
copytype, and the unslicer factory to use. This unslicer factory is simply a
function that takes no arguments and returns a new Unslicer. Each time an
inbound message with the matching copytype is received, ths unslicer factory
is invoked to create an Unslicer that will be responsible for the single
instance described in the message. This Unslicer must implement an interface
described in the Unslicer specifications, in "doc/specifications/pb".

Registering ISlicer adapters
----------------------------

The most generalized way to serialize classes is to register a whole
``ISlicer`` adapter for them. The ``ISlicer`` gets complete control over
serialization: it can stall the production of tokens by implementing a
``slice`` method that yields Deferreds instead of basic objects. It can also
interact with other objects while the target is being serialized. As an
extreme example, if you had a service that wanted to migrate an open HTTP
connection from one process to another, the ``ISlicer`` could communication
with a front-end load-balancing box to redirect the connection to the new
host. In this case, the slicer could theoretically tell the load-balancer to
pause the connection and assign it a rendezvous number, then serialize this
rendezvous number as a form of "claim check" to the target process. The
``IUnslicer`` on the receiving end could open a new listening port, then use
the claim check to tell the load-balancer to direct the connection to this
new port. Likewise two services running on the same host could conspire to
pass open file descriptors over a Foolscap connection (via an auxilliary
unix-domain socket) through suitable magic in the ``ISlicer`` and
``IUnslicer`` on each end.

The Slicers and Unslicers are described in more detail in the specifications:
"doc/specifications/pb".

Note that a ``Copyable`` with a copytype of "foo" is serialized as the
following token stream: ``OPEN, "copyable", "foo", [state dictionary..],
CLOSE``. Any ``ISlicer`` adapter which wishes to match what ``Copyable`` does
needs to include the extra "copyable" opentype string first.

Also note that using a custom Slicer introduces an opportunity to violate
serialization coherency. ``Copyable`` and Copiers transform the original
object into a state dictionary in one swell foop, not allowing any other code
to get control (and possibly mutate the object's state). If your custom
Slicer allows other code to get control during serialization, then the
object's state might be changed, and thus the serialized state dictionary
could wind up looking pretty weird.



.. rubric:: Footnotes

.. [#] many thanks to Ricky Iacovou for the xmlrpclib.DateTime example
