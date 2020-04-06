Porting Applications from Python 2 to Python 3
==============================================

Foolscap was first written back when Python 2 was the only version in
existence. At that time, "Unicode" was a special type, and everything
defaulted to bytes instead. As a result, Foolscap did not make a very clean
separation between bytes and text, and many assumptions got baked into the
protocol.

Foolscap now supports Python 3. For a while, it will support Python 2 as
well, although Python 2 was officially end-of-lifed in January 2020 so new
applications should not use it.

Networking protocols are generally pretty tricky to manage in the face of
version upgrades, because we want to maintain interoperability between old
clients (running old code, under Python 2), new clients (running new code,
under Python 3), and occasionally something in the middle (new code running
under Python 2).

If you have an application that uses Foolscap and was written before the
transition to Python 3, you must keep some details in mind to maintain
compatibility between the various flavors.

Basics
------

The Foolscap API attempts to be liberal in what it accepts. If a
Foolscap-provided method is defined to take some sort of string, it will
probably accept both bytes and unicode.

The API attempts to be local in what it emits to local callers. Methods that
return some kind of string will probably return bytes under py2 and unicode
under py3.

The implementation attempts to be backwards-compatible in what it emits over
the network.

For example, method names (the ``foo`` in ``rref.callRemote("foo", arg1,
arg2)``) are basically strings. The ``callRemote`` API will accept either
bytes or unicode on both py2 and py3. The encoded network message will always
by bytes, to support communication with old clients that can't accept
anything else. The receiving side will prepend ``remote_`` to the string and
look for a method of that name on the target object. ``Callable`` classes do
not need to do anything special.

As another example, "FURLs" are the secret unguessable identifiers that point
to objects. They contain a type prefix (``pb://``), a "Tub ID" (the hash of
the hosting program's public key), a series of "connection hints" (type
prefix, hostname, and port number), and a "Swissnum" (a randomly-generated
string). All of these components are string-like. The API will accept both
bytes and strings on both py2 and py3, but the functions that return FURLs
will return bytes on py2 and unicode on py3.

New applications should not bother trying to work under py2. They should use
py3 exclusively. From the application's point of view, the Foolscap API
should accept and return normal py3 types.

However applications that have participating nodes still using py2 will need
to do more work. There are two aspects to consider. First, assuming the same
application code is in use by all nodes, that code must be written to work
under both py2 and py3. This frequently involves the excellent ``six``
library. Second, the network-traversing messages created by the py2 nodes
must be correctly interpreted by the py3 nodes, and vice versa. This is a
question of application protocol design, which is beyond the reach of what
Foolscap's compatibility code can help with.

Porting
-------

To maintain wire-level compatibility between foolscap-based programs across
heterogeneous peers, you must keep careful track of the types sent as
arguments inside `callRemote` messages. Programs which casually sent native
strings (bytes) on py2 will continue to send those bytes over the wire, so a
py3 port of the same program will receive bytes, even though the same
(unmodified) code will send unicode instances to the py2 program. When
porting, I recommend first making all string types explicit (`b"for bytes"`
and `u"for text"`), and make sure a py2 version with these changes can
interoperate with the original py2 version. Then a py3 version has a stronger
chance of working. You may be stuck with these awkward `bytes` markers for a
long time.


The next section examines some of these second issues.

Method Signatures
-----------------

Foolscap enables a program to define a "Remotely Invocable Object" by marking
a class with ``Callable`` (i.e. have your class definition inherit from
``foolscap.api.Callable``) and defining methods like ``remote_foo()`` and
``remote_bar()``. Other programs can then obtain a "Remote Reference" to
instances of these Callable classes and invoke those methods (i.e. send
messages) with calls like ``rref.callRemote("foo", arg1, arg2)``.

Foolscap treats bytes and text/unicode as distinct types. If the message
sender uses bytes in an argument, the receiving side will also receive bytes.
This is straightforward when all clients use the same conventions, but can
cause surprises when they do not. Unmarked string literals (``"foo"`` and
``'foo'``) are treated as unicode in py3, as bytes in plain py2, and as
unicode in py2 when ``from __future__ import unicode_literals`` is in effect.
A simple method invocation with literal string arguments can thus deliver
different types depending upon the version used by the sender.

If you have legacy py2-based Foolscap-using applications, which exchange
bytes where a more modern program would exchange unicode, you will probably
be stuck using bytes.

Schema
------

``Callable`` classes can also define a "schema": a list of method names, each
with typed arguments and return values. The types include String, Unicode,
Boolean, Int, other atoms, and variety of collections: tuples, arrays,
dictionaries, etc. All values can be length-limited.

Schemas serve two purposes. The first is to provide a form of type-safety at
the boundaries between remote computers: Python is dynamically-typed and
allows any function to be called with any value, even if the recipient might
get confused if they get a string when they were expecting a number or an
array. Schemas allow the programmer to enforce typechecking before the
unaware code receives the arguments. The types are checked on the sending
side too, to expose programming errors as early as possible. The second
purpose is prevent resource-exhaustion attacks: the receiving side can reject
incoming tokens as soon as it knows the deserialized form would violate the
target schema.

These schema definitions can be built in two ways. The first is from objects
provided by the Foolscap API:

.. code-block:: python

    from foolscap.schema import ByteStringConstraint, UnicodeConstraint
    class RIFoo(RemoteInterface):
        def bar(a=ByteStringConstraint(200), b=UnicodeConstraint()):
            return

The second is to use native Python types (like ``str`` or ``bytes`` or
``unicode``). These shortcuts do not provide a way to limit the length of the
strings, but yield more compact schema definitions:

.. code-block:: python

    class RIFoo(RemoteInterface):
        def bar(a=bytes, b=unicode):
            # TupleOf(ByteStringConstraint, ByteStringConstraint)
            return (bytes, bytes)

However, the meaning of these native types depends upon which version of
Python you are using. A schema defined by ``bytes`` will behave the same on
both versions, but one defined by ``str`` will yield bytes on py2 and unicode
on py3 (and there is no compact way to name ``unicode`` on both versions,
since ``unicode`` is no longer a type name in py3). This may cause a schema
incompatibility between the same source code running on different versions of
python. Updating the code to use specific types can provide clarity, however
if you wish to maintain backwards compatibility with deployed py2-based
applications, you may need to stick with ``bytes`` in remote APIs that would
really prefer to use text/unicode.

Flogfiles
---------

Foolscap has extensive logging facilities, which include remote log ports (so
one applications can retrieve or live-stream log events from another), saving
individual log entries to disk, transferring and saving bundles of related
log entries named "incidents", automated classification of incidents (to
filter out problems which are understood but not yet fixed, and displaying
logfiles in a web-based viewer application.

The JSON-serialized forms of these log events can expose additional
py2-vs-py3 incompatibilities. In general, the Foolscap logging systems can
tolerate events and files created on a different version of Python, however
these may perform implicit string conversions. As a result the displayed
values may have rendering artifacts: a string ``foo`` might be displayed with
an additional prefix, like ``b'foo'``, especially when the emitter runs py2
and the follower runs py3. Similar problems can cause ``u'foo'`` -type
suffixes, even when both sides use the same version.

Flappserver
-----------

The Foolscap library includes support for running small applications, using
FURLs for access control. One built-in example allows single files to be
uploaded into a target directory. Another one allows a pre-configured command
to be run, with the client allowed to supply additional arguments and to
control stdin/stdout.

These tools have not yet been completely tested to see how they behave when
the two sides are running different versions of Python.
