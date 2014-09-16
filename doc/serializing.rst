Using Foolscap for Serialization
================================

The same code that Foolscap uses to transport object graphs from one process
to another (over a wire) can be used to transport those graphs from one
process to another (over time). This code serializes an object (and the other
objects it references) into a series of bytes: these bytes can then either be
written to a network socket, or written to a file.

The main difference between the two cases is the way that certain special
objects are represented (and whether they can be represented at all). Inert
data like strings, lists, and numbers are equally serializable.
``foolscap.Copyable`` objects are also serializable. But
``foolscap.Referenceable`` objects only make sense to serialize in the
context of a connection through which ``callRemote`` messages can eventually
be sent. So trying to serialize a ``Referenceable`` when the results are
going to be written to disk should cause an error.

The way that Foolscap enables the re-use of its serialization code is to
allow it to be called with a different "Root Slicer". This root gets to
decide how all objects are serialized. The Root Slicer for a live Foolscap
connection knows that Referenceables can be serialized with a special marker
that tells the other end of the connection how to construct a corresponding
``RemoteReference`` (one which will be able to send ``callRemote`` s over the
connection).

Serializing to Bytes
--------------------

To use Foolscap to serialize an object graph to a big string, use
``foolscap.serialize`` . Note that this returns a Deferred.:

.. code-block:: python

    import foolscap
    
    obj = ["look at the pretty graph", 3, True]
    obj.append(obj) # and look at the pretty cycle
    
    d = foolscap.serialize(obj)
    d.addCallback(lambda data: foolscap.unserialize(data))
    def _check(obj2):
        assert obj2[1] == "3"
        assert obj2[3] is obj2
    d.addCallback(_check)

This form of serialization has the following restrictions:

- it can serialize any inert Python type
- it can serialize ``foolscap.Copyable`` instances, and any other instance
  that has an ISlicer or ICopyable adapter registered for it
- it cannot serialize Referenceables
- it cannot serialize non-Copyable instances

These restrictions mean that ``foolscap.serialize`` cannot serialize
everything that Python's stdlib ``pickle`` module can handle. However, it is
safer (since ``foolscap.unserialize`` will never import or execute arbitrary
code like ``pickle.load`` will do), and more extensible (since
ISlicer/ICopyable adapters can be registered for third-party classes).

Including Referenceables
------------------------

To include Referenceables in the serialized data, you must use a Tub to do
the serialization, and the process returns a Deferred rather than running
synchronously:

.. code-block:: python

    r = Referenceable()
    obj = ["look at the pretty graph", 3, r]
    
    d = tub1.serialize(obj)
    def _done(data):
        return tub2.unserialize(data)
    d.addCallback(_done)
    def _check(obj2):
        assert obj2[1] == "3"
        assert isinstance(obj2[2], RemoteReference)
    d.addCallback(_check)

For this to work, the first Tub must have a location set on it, so that you
could do ``registerReference`` . The first Tub will serialize the
Referenceable with a special marker that the second Tub will be able to use
to establish a connection to the original object. This will only succeed if
the original Tub is still running and still knows about the Referenceable:
think of the embedded marker as a weakref.
