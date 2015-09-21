Introduction to Foolscap
========================

Introduction
------------

Suppose you find yourself in control of both ends of the wire: you have
two programs that need to talk to each other, and you get to use any protocol
you want. If you can think of your problem in terms of objects that need to
make method calls on each other, then chances are good that you can use the
Foolscap protocol rather than trying to shoehorn your needs into something
like HTTP, or implementing yet another RPC mechanism.

Foolscap is based upon a few central concepts:

- *serialization* : taking fairly arbitrary objects and types,
  turning them into a chunk of bytes, sending them over a wire, then
  reconstituting them on the other end. By keeping careful track of object
  ids, the serialized objects can contain references to other objects and the
  remote copy will still be useful.
- *remote method calls* : doing something to a local proxy and causing a
  method to get run on a distant object. The local proxy is called a
  ``RemoteReference``, and you "do something" by running its ``.callRemote``
  method. The distant object is called a ``Referenceable`` , and it has
  methods like ``remote_foo`` that will be invoked.

Foolscap is the descendant of Perspective Broker (which lived in the
twisted.spread package). For many years it was known as "newpb". A lot of the
API still has the name "PB" in it somewhere. These will probably go away
sooner or later.

A "foolscap" is a size of paper, probably measuring 17 by 13.5 inches. A
twisted foolscap of paper makes a good fool's cap. Also, "cap" makes me think
of capabilities, and Foolscap is a protocol to implement a distributed
object-capabilities model in python.

Getting Started
---------------

Any Foolscap application has at least two sides: one which hosts a
remotely-callable object, and another which calls (remotely) the methods of
that object. We'll start with a simple example that demonstrates both ends.
Later, we'll add more features like RemoteInterface declarations, and
transferring object references.

The most common way to make an object with remotely-callable methods is to
subclass ``Referenceable``. Let's create a simple server which does basic
arithmetic. You might use such a service to perform difficult mathematical
operations, like addition, on a remote machine which is faster and more
capable than your own [#]_ .

.. code-block:: python

    
    from foolscap.api import Referenceable
    
    class MathServer(Referenceable):
        def remote_add(self, a, b):
            return a+b
        def remote_subtract(self, a, b):
            return a-b
        def remote_sum(self, args):
            total = 0
            for a in args: total += a
            return total
    
    myserver = MathServer()

On the other end of the wire (which you might call the "client" side), the
code will have a ``RemoteReference`` to this object. The ``RemoteReference``
has a method named ``callRemote`` which you will use to invoke the method. It
always returns a Deferred, which will fire with the result of the method.
Assuming you've already acquired the ``RemoteReference`` , you would invoke
the method like this:

.. code-block:: python

    
    def gotAnswer(result):
        print "result is", result
    def gotError(err):
        print "error:", err
    d = remote.callRemote("add", 1, 2)
    d.addCallbacks(gotAnswer, gotError)

Ok, now how do you acquire that ``RemoteReference`` ? How do you make the
``Referenceable`` available to the outside world? For this, we'll need to
discuss the "Tub" , and the concept of a "FURL" .


Tubs: The Foolscap Service
--------------------------

The ``Tub`` is the container that you use to publish ``Referenceable`` s, and
is the middle-man you use to access ``Referenceable`` s on other systems. It
is known as the"Tub" , since it provides similar naming and identification
properties as the `E language <http://www.erights.org/>`_ 's "Vat" [#]_ . If
you want to make a ``Referenceable`` available to the world, you create a
Tub, tell it to listen on a TCP port, and then register the ``Referenceable``
with it under a name of your choosing. If you want to access a remote
``Referenceable`` , you create a Tub and ask it to acquire a
``RemoteReference`` using that same name.

The ``Tub`` is a Twisted ``twisted.application.service.Service`` subclass, so
you use it in the same way: once you've created one, you attach it to a
parent Service or Application object. Once the top-level Application object
has been started, the Tub will start listening on any network ports you've
requested. When the Tub is shut down, it will stop listening and drop any
connections it had established since last startup. If you have no parent to
attach it to, you can use ``startService`` and ``stopService`` on the Tub
directly.

Note that no network activity will occur until the Tub's ``startService``
method has been called. This means that any ``getReference`` or ``connectTo``
requests that occur before the Tub is started will be deferred until startup.
If the program forgets to start the Tub, these requests will never be
serviced. A message to this effect is added to the twistd.log file to help
developers discover this kind of problem.


Making your Tub remotely accessible
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To make any of your ``Referenceable`` s available, you must make
your Tub available. There are three parts: give it an identity, have it
listen on a port, and tell it the protocol/hostname/portnumber at which that
port is accessibly to the outside world.

The Tub will generate its own identity, the *TubID* , by creating an SSL
public key certificate and hashing it into a suitably-long random-looking
string. This is the primary identifier of the Tub: everything else is just a
*location hint* that suggests how the Tub might be reached. The fact that the
TubID is tied to the public key allows FURLs to be "secure" references
(meaning that no third party can cause you to connect to the wrong
reference). You can also create a Tub with a pre-existing certificate, which
is how Tubs can retain a persistent identity over multiple executions.

Having the Tub listen on a TCP port is as simple as calling ``Tub.listenOn``
with a ``twisted.application.strports`` -formatted port specification string.
The simplest such string would be "tcp:12345" , to listen on port 12345 on
all interfaces. Using "tcp:12345:interface=127.0.0.1" would cause it to only
listen on the localhost interface, making it available only to other
processes on the same host. The ``strports`` module provides many other
possibilities.

The Tub needs to be told how it can be reached, so it knows what host and
port to put into the FURLs it creates. This location is simply a string in
the format "host:port" , using the host name by which that TCP port you've
just opened can be reached. Foolscap cannot, in general, guess what this name
is, especially if there are NAT boxes or port-forwarding devices in the way.
If your machine is reachable directly over the internet
as "myhost.example.com" , then you could use something like this:

.. code-block:: python

    
    from foolscap.api import Tub
    
    tub = Tub()
    tub.listenOn("tcp:12345")  # start listening on TCP port 12345
    tub.setLocation("myhost.example.com:12345")

If your Tub is client-only, and you don't want it to be remotely accessible,
you should skip the ``listenOn`` and ``setLocation`` calls. You will be able
to connect to remote objects, and objects you send over the wire will be
available to the remote system, but ``registerReference`` will throw an
error.

Registering the Referenceable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once the Tub has a Listener and a location, you can publish your
``Referenceable`` to the entire world by picking a name and registering it:

.. code-block:: python

    
    furl = tub.registerReference(myserver, "math-service")

This returns the "FURL" for your ``Referenceable`` . Remote systems will use
this FURL to access your newly-published object. The registration just maps a
per-Tub name to the ``Referenceable`` : technically the same
``Referenceable`` could be published multiple times, under different names,
or even be published by multiple Tubs in the same application. But in
general, each program will have exactly one Tub, and each object will be
registered under only one name.

In this example (if we pretend the generated TubID was "ABCD" ), the FURL
returned by ``registerReference`` would be
``"pb://ABCD@myhost.example.com:12345/math-service"`` .

If you do not provide a name, a random (and unguessable) name will be
generated for you. This is useful when you want to give access to your
``Referenceable`` to someone specific, but do not want to make it possible
for someone else to acquire it by guessing the name.

Note that the FURL can come from anywhere: typed in by the user, retrieved
from a web page, or hardcoded into the application.


Using a persistent certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Tub uses a TLS public-key certificate as the base of all its
cryptographic operations. If you don't give it one when you create the Tub,
it will generate a brand-new one.

The TubID is simply the hash of this certificate, so if you are writing an
application that should have a stable long-term identity, you will need to
insure that the Tub uses the same certificate every time your app starts. The
easiest way to do this is to pass the ``certFile=`` argument into your
``Tub()`` constructor call. This argument provides a filename where you want
the Tub to store its certificate. The first time the Tub is started (when
this file does not exist), the Tub will generate a new certificate and store
it here. On subsequent invocations, the Tub will read the earlier certificate
from this location. Make sure this filename points to a writable location,
and that you pass the same filename to ``Tub()`` each time.


Using a Persistent FURL
^^^^^^^^^^^^^^^^^^^^^^^

It is often useful to insure that a given Referenceable's FURL is both
unguessable and stable, remaining the same from one invocation of the program
that hosts it to the next. One (bad) way to do this is to have the programmer
choose an unguessable name, embed it in the program, and pass it into
``registerReference`` each time the program runs, but of course this means
that the name will be visible to anyone who sees the source code for the
program, and the same name will be used by all copies of the program
everywhere.

A better approach is to use the ``furlFile=`` argument. This argument
provides a filename that is used to hold the stable FURL for this object. If
the furlfile exists when ``registerReference`` is called, the Tub will use
the name inside it when constructing the new FURL. If it doesn't exist, it
will create a new (unguessable) name. The new FURL will always be written
into the furlfile afterwards. In addition, the tubid in the old FURL will be
checked against the current Tub's tubid to make sure it matches. (this means
that if you use furlFile=, you should also use the certFile= argument when
constructing the Tub).

Retrieving a RemoteReference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On the "client" side, you also need to create a Tub, although you don't need
to perform the (``listenOn`` , ``setLocation`` , ``registerReference`` )
sequence unless you are also publishing` `Referenceable`` s to the world. To
acquire a reference to somebody else's object, just use ``Tub.getReference`` :

.. code-block:: python

    
    from foolscap.api import Tub
    
    tub = Tub()
    tub.startService()
    d = tub.getReference("pb://ABCD@myhost.example.com:12345/math-service")
    def gotReference(remote):
        print "Got the RemoteReference:", remote
    def gotError(err):
        print "error:", err
    d.addCallbacks(gotReference, gotError)

``getReference`` returns a Deferred which will fire with a
``RemoteReference`` that is connected to the remote ``Referenceable`` named
by the FURL. It will use an existing connection, if one is available, and it
will return an existing ``RemoteReference`` , it one has already been
acquired.

Since ``getReference`` requests are queued until the Tub starts, the
following will work too. But don't forget to call ``tub.startService()``
eventually, otherwise your program will hang forever.

.. code-block:: python

    
    from foolscap.api import Tub
    
    tub = Tub()
    d = tub.getReference("pb://ABCD@myhost.example.com:12345/math-service")
    def gotReference(remote):
        print "Got the RemoteReference:", remote
    def gotError(err):
        print "error:", err
    d.addCallbacks(gotReference, gotError)
    tub.startService()

Complete example
~~~~~~~~~~~~~~~~

Here are two programs, one implementing the server side of our
remote-addition protocol, the other behaving as a client. When running this
example, you must copy the FURL printed by the server and provide it as an
argument to the client.

Both of these are standalone programs (you just run them), but normally you
would create an ``twisted.application.service.Application`` object and pass
the file to ``twistd -noy`` . An example of that usage will be provided
later.

(doc/listings/pb2server.py)

.. code-block:: python

    #! /usr/bin/python
    
    from twisted.internet import reactor
    from foolscap.api import Referenceable, Tub
    
    class MathServer(Referenceable):
        def remote_add(self, a, b):
            return a+b
        def remote_subtract(self, a, b):
            return a-b
    
    myserver = MathServer()
    tub = Tub(certFile="pb2server.pem")
    tub.listenOn("tcp:12345")
    tub.setLocation("localhost:12345")
    url = tub.registerReference(myserver, "math-service")
    print "the object is available at:", url
    
    tub.startService()
    reactor.run()

(doc/listings/pb2client.py)

.. code-block:: python

    #! /usr/bin/python
    
    import sys
    from twisted.internet import reactor
    from foolscap.api import Tub
    
    def gotError1(why):
        print "unable to get the RemoteReference:", why
        reactor.stop()
    
    def gotError2(why):
        print "unable to invoke the remote method:", why
        reactor.stop()
    
    def gotReference(remote):
        print "got a RemoteReference"
        print "asking it to add 1+2"
        d = remote.callRemote("add", a=1, b=2)
        d.addCallbacks(gotAnswer, gotError2)
    
    def gotAnswer(answer):
        print "the answer is", answer
        reactor.stop()
    
    if len(sys.argv) < 2:
        print "Usage: pb2client.py URL"
        sys.exit(1)
    url = sys.argv[1]
    tub = Tub()
    tub.startService()
    d = tub.getReference(url)
    d.addCallbacks(gotReference, gotError1)
    
    reactor.run()
    

(server output)

.. code-block:: console

    
    % doc/listings/pb2server.py
    the object is available at: pb://j7oxoz3qzdkpgxgefsqp6xgdqeq4pvad@localhost:12345/math-service

(client output)

.. code-block:: console

    
    % doc/listings/pb2client.py pb://j7oxoz3qzdkpgxgefsqp6xgdqeq4pvad@localhost:12345/math-service
    got a RemoteReference
    asking it to add 1+2
    the answer is 3
    %

FURLs
~~~~~

In Foolscap, each world-accessible Referenceable has one or more FURLs which
are "secure" , where we use the capability-security definition of the term,
meaning those FURLs have the following properties:


- The only way to acquire the FURL is either to get it from someone else who
  already has it, or to be the person who published it in the first place.
- Only that original creator of the FURL gets to determine which
  Referenceable it will connect to. If your ``tub.getReference(url)`` call
  succeeds, the Referenceable you will be connected to will be the right one.

To accomplish the first goal, FURLs must be unguessable. You can register the
reference with a human-readable name if your intention is to make it
available to the world, but in general you will let ``tub.registerReference``
generate a random name for you, preserving the unguessability property.

To accomplish the second goal, the cryptographically-secure TubID is used as
the primary identifier, and the "location hints" are just that: hints. If DNS
has been subverted to point the hostname at a different machine, or if a
man-in-the-middle attack causes you to connect to the wrong box, the TubID
will not match the remote end, and the connection will be dropped. These
attacks can cause a denial-of-service, but they cannot cause you to
mistakenly connect to the wrong target.

The format of a FURL, like
``pb://abcd123@example.com:5901,backup.example.com:8800/math-server`` , is as
follows [#]_ :

#. The literal string ``pb://``
#. The TubID (as a base32-encoded hash of the SSL certificate)
#. A literal ``@`` sign
#. A comma-separated list of "location hints" . Each is one of the
   following:

   - TCP over IPv4 via DNS: ``HOSTNAME:PORTNUM``
   - TCP over IPv4 without DNS: ``A.B.C.D:PORTNUM``
   - TCP over IPv6: (TODO, maybe ``tcp6:HOSTNAME:PORTNUM`` ?
   - TCP over IPv6 w/o DNS: (TODO, maybe ``tcp6:[X:Y::Z]:PORTNUM``)
   - Unix-domain socket: (TODO)

   Each location hint is attempted in turn. Servers can return a "redirect" ,
   which will cause the client to insert the provided redirect targets into
   the hint list and start trying them before continuing with the original
   list.
#. A literal ``/`` character
#. The reference's name

(Unix-domain sockets are represented with only a single location hint, in the
format ``pb://ABCD@unix/path/to/socket/NAME`` , but this needs some work)

Clients vs Servers, Names and Capabilities
------------------------------------------

It is worthwhile to point out that Foolscap is a symmetric protocol.
``Referenceable`` instances can live on either side of a wire, and the only
difference between "client" and "server" is who publishes the object and who
initiates the network connection.

In any Foolscap-using system, the very first object exchanged must be
acquired with a ``tub.getReference(url)`` call [#]_ , which means it must
have been published with a call to ``tub.registerReference(ref, name)`` .
After that, other objects can be passed as an argument to (or a return value
from) a remotely-invoked method of that first object. Any suitable
``Referenceable`` object that is passed over the wire will appear on the
other side as a corresponding ``RemoteReference`` . It is not necessary to
``registerReference`` something to let it pass over the wire.

The converse of this property is thus: if you do *not* ``registerReference``
a particular ``Referenceable`` , and you do *not* give it to anyone else (by
passing it in an argument to somebody's remote method, or return it from one
of your own), then nobody else will be able to get access to that
``Referenceable`` . This property means the ``Referenceable`` is a
"capability" , as holding a corresponding ``RemoteReference`` gives someone a
power that they cannot acquire in any other way [#]_

In the following example, the first program creates an RPN-style
``Calculator`` object which responds to "push" , "pop" ,"add" , and
"subtract" messages from the user. The user can also register an ``Observer``
, to which the Calculator sends an ``event`` message each time something
happens to the calculator's state. When you consider the ``Calculator``
object, the first program is the server and the second program is the client.
When you think about the ``Observer`` object, the first program is a client
and the second program is the server. It also happens that the first program
is listening on a socket, while the second program initiated a network
connection to the first. It *also* happens that the first program published
an object under some well-known name, while the second program has not
published any objects. These are all independent properties.

Also note that the Calculator side of the example is implemented using
``twisted.application.service.Application`` object, which is the way you'd
normally build a real-world application. You therefore use ``twistd`` to
launch the program. The User side is written with the same ``reactor.run()``
style as the earlier example.

The server registers the Calculator instance and prints the FURL at which it
is listening. You need to pass this FURL to the client program so it knows
how to contact the server.

(doc/listings/pb3calculator.py)

.. code-block:: python

    #! /usr/bin/python
    
    from twisted.application import service
    from twisted.internet import reactor
    from foolscap.api import Referenceable, Tub
    
    class Calculator(Referenceable):
        def __init__(self):
            self.stack = []
            self.observers = []
        def remote_addObserver(self, observer):
            self.observers.append(observer)
        def log(self, msg):
            for o in self.observers:
                o.callRemote("event", msg=msg)
        def remote_removeObserver(self, observer):
            self.observers.remove(observer)
    
        def remote_push(self, num):
            self.log("push(%d)" % num)
            self.stack.append(num)
        def remote_add(self):
            self.log("add")
            arg1, arg2 = self.stack.pop(), self.stack.pop()
            self.stack.append(arg1 + arg2)
        def remote_subtract(self):
            self.log("subtract")
            arg1, arg2 = self.stack.pop(), self.stack.pop()
            self.stack.append(arg2 - arg1)
        def remote_pop(self):
            self.log("pop")
            return self.stack.pop()
    
    tub = Tub()
    tub.listenOn("tcp:12345")
    tub.setLocation("localhost:12345")
    url = tub.registerReference(Calculator(), "calculator")
    print "the object is available at:", url
    
    application = service.Application("pb2calculator")
    tub.setServiceParent(application)
    
    if __name__ == '__main__':
        raise RuntimeError("please run this as 'twistd -noy pb3calculator.py'")


(doc/listings/pb3user.py)

.. code-block:: python

    #! /usr/bin/python
    
    import sys
    from twisted.internet import reactor
    from foolscap.api import Referenceable, Tub
    
    class Observer(Referenceable):
        def remote_event(self, msg):
            print "event:", msg
    
    def printResult(number):
        print "the result is", number
    def gotError(err):
        print "got an error:", err
    def gotRemote(remote):
        o = Observer()
        d = remote.callRemote("addObserver", observer=o)
        d.addCallback(lambda res: remote.callRemote("push", num=2))
        d.addCallback(lambda res: remote.callRemote("push", num=3))
        d.addCallback(lambda res: remote.callRemote("add"))
        d.addCallback(lambda res: remote.callRemote("pop"))
        d.addCallback(printResult)
        d.addCallback(lambda res: remote.callRemote("removeObserver", observer=o))
        d.addErrback(gotError)
        d.addCallback(lambda res: reactor.stop())
        return d
    
    url = sys.argv[1]
    tub = Tub()
    tub.startService()
    d = tub.getReference(url)
    d.addCallback(gotRemote)
    
    reactor.run()

(server output)

.. code-block:: console

    
    % twistd -noy doc/listings/pb3calculator.py 
    15:46 PDT [-] Log opened.
    15:46 PDT [-] twistd 2.4.0 (/usr/bin/python 2.4.4) starting up
    15:46 PDT [-] reactor class: twisted.internet.selectreactor.SelectReactor
    15:46 PDT [-] Loading doc/listings/pb3calculator.py...
    15:46 PDT [-] the object is available at:
                  pb://5ojw4cv4u4d5cenxxekjukrogzytnhop@localhost:12345/calculator
    15:46 PDT [-] Loaded.
    15:46 PDT [-] foolscap.pb.Listener starting on 12345
    15:46 PDT [-] Starting factory <Listener at 0x4869c0f4 on tcp:12345
                  with tubs None>

(client output)

.. code-block:: console

    
    % doc/listings/pb3user.py \
       pb://5ojw4cv4u4d5cenxxekjukrogzytnhop@localhost:12345/calculator
    event: push(2)
    event: push(3)
    event: add
    event: pop
    the result is 5
    %


Invoking Methods, Method Arguments
----------------------------------

As you've probably already guessed, all the methods with names that begin
with ``remote_`` will be available to anyone who manages to acquire a
corresponding ``RemoteReference`` . ``remote_foo`` matches a
``ref.callRemote("foo")`` , etc. This name lookup can be changed by
overriding ``Referenceable`` (or, perhaps more usefully, implementing an
``foolscap.ipb.IRemotelyCallable`` adapter).

The arguments of a remote method may be passed as either positional
parameters (``foo(1,2)`` ), or as keyword args (``foo(a=1,b=2)`` ), or a
mixture of both. The usual python rules about not duplicating parameters
apply.

You can pass all sorts of normal objects to a remote method: strings,
numbers, tuples, lists, and dictionaries. The serialization of these objects
is handled by the "Banana" protocol, defined in (doc/specifications/banana),
which knows how to convey arbitrary object graphs over the wire. Things like
containers which contain multiple references to the same object, and
recursive references (cycles in the object graph) are all handled correctly
[#]_ .

Passing instances is handled specially. Foolscap will not send anything over
the wire that it does not know how to serialize, and (unlike the standard
``pickle`` module) it will not make assumptions about how to handle classes
that that have not been explicitly marked as serializable. This is for
security, both for the sender (making sure you don't pass anything over the
wire that you didn't intend to let out of your security perimeter), and for
the recipient (making sure outsiders aren't allowed to create arbitrary
instances inside your memory space, and therefore letting them run somewhat
arbitrary code inside *your* perimeter).

Sending ``Referenceable`` s is straightforward: they always appear as a
corresponding ``RemoteReference`` on the other side. You can send the same
``Referenceable`` as many times as you like, and it will always show up as
the same ``RemoteReference`` instance. A distributed reference count is
maintained, so as long as the remote side hasn't forgotten about the
``RemoteReference`` , the original ``Referenceable`` will be kept alive.

Sending ``RemoteReference`` s fall into two categories. If you are sending a
``RemoteReference`` back to the Tub that you got it from, they will see their
original ``Referenceable`` . If you send it to some other Tub, they will
(eventually) see a ``RemoteReference`` of their own. This last feature is
called an "introduction" , and has a few additional requirements: see the
"Introductions" section of this document for details.

Sending instances of other classes requires that you tell Banana how they
should be serialized. ``Referenceable`` is good for copy-by-reference
semantics [#]_ . For copy-by-value semantics, the easiest route is to
subclass ``foolscap.copyable.Copyable`` . See the "Copyable" section for
details. Note that you can also register an ``ICopyable`` adapter on
third-party classes to avoid subclassing. You will need to register the
``Copyable`` 's name on the receiving end too, otherwise Banana will not know
how to unserialize the incoming data stream.




When returning a value from a remote method, you can do all these things,
plus two more. If you raise an exception, the caller's Deferred will have the
errback fired instead of the callback, with a ``foolscap.call.CopiedFailure``
instance that describes what went wrong. The ``CopiedFailure`` is not quite
as useful as a local ``twisted.python.failure.Failure`` object would be: see
the "failures" document for details.

The other alternative is for your method to return a ``Deferred`` . If this
happens, the caller will not actually get a response until you fire that
Deferred. This is useful when the remote operation being requested cannot
complete right away. The caller's Deferred will fire with whatever value you
eventually fire your own Deferred with. If your Deferred is errbacked, their
Deferred will be errbacked with a ``CopiedFailure`` .


Constraints and RemoteInterfaces
--------------------------------

One major feature introduced by Foolscap (relative to oldpb) is the
serialization ``foolscap.schema.Constraint`` . This lets you place limits on
what kind of data you are willing to accept, which enables safer distributed
programming. Typically python uses "duck typing" , wherein you usually just
throw some arguments at the method and see what happens. When you are less
sure of the origin of those arguments, you may want to be more circumspect.
Enforcing type checking at the boundary between your code and the outside
world may make it safer to use duck typing inside those boundaries. The type
specifications also form a convenient remote API reference you can publish
for prospective clients of your remotely-invokable service.

In addition, these Constraints are enforced on each token as it arrives over
the wire. This means that you can calculate a (small) upper bound on how much
received data your program will store before it decides to hang up on the
violator, minimizing your exposure to DoS attacks that involve sending random
junk at you.

There are three pieces you need to know about: Tokens, Constraints, and
RemoteInterfaces.

Tokens
~~~~~~

The fundamental unit of serialization is the Banana Token. These are
thoroughly documented in the Banana Specification, but what you need to know
here is that each piece of non-container data, like a string or a number, is
represented by a single token. Containers (like lists and dictionaries) are
represented by a special OPEN token, followed by tokens for everything that
is in the container, followed by the CLOSE token. Everything Banana does is
in terms of these nested OPEN/stuff/stuff/CLOSE sequences of tokens.

Each token consists of a header, a type byte, and an optional body. The
header is always a base-128 number with a maximum of 64 digits, and the type
byte is always a single byte. The length of the body (if present) is
indicated by the number encoded in the header.

The length-first token format means that the receiving system never has to
accept more than 65 bytes before it knows the type and size of the token, at
which point it can make a decision about accepting or rejecting the rest of
it.

Constraints
~~~~~~~~~~~

The schema ``foolscap.schema`` module has a variety of
``foolscap.schema.Constraint`` classes that can be applied to incoming data.
Most of them correspond to typical Python types, e.g.
``foolscap.schema.ListOf`` matches a list, with a certain maximum length, and
a child ``Constraint`` that gets applied to the contents of the list. You can
nest ``Constraint`` s in this way to describe the "shape" of the object graph
that you are willing to accept.

At any given time, the receiving Banana protocol has a single ``Constraint``
object that it enforces against the inbound data stream [#]_ .


RemoteInterfaces
~~~~~~~~~~~~~~~~

The ``foolscap.remoteinterface.RemoteInterface`` is how you describe your
constraints. You can provide a constraint for each argument of each method,
as well as one for the return value. You can also specify additional flags on
the methods. The convention (which is actually enforced by the code) is to
name ``RemoteInterface`` objects with an "RI" prefix, like ``RIFoo`` .

``RemoteInterfaces`` are created and used a lot like the usual
``zope.interface`` -style ``Interface`` . They look like class definitions,
inheriting from ``RemoteInterface`` . For each method, the default value of
each argument is used to create a ``Constraint`` for that argument. Basic
types (``int`` , ``str`` , ``bool`` ) are converted into a ``Constraint``
subclass (``IntegerConstraint`` , ``StringConstraint`` ,
``BooleanConstraint``). You can also use instances of other ``Constraint``
subclasses, like ``foolscap.schema.ListOf`` and ``foolscap.schema.DictOf`` .
This ``Constraint`` will be enforced against the value for the given
argument. Unless you specify otherwise, remote callers must match all the
``Constraint`` s you specify, all arguments listed in the RemoteInterface
must be present, and no arguments outside that list will be accepted.

Note that, like zope.interface, these methods should **not** include
"``self``" in their argument list. This is because you are documenting how
*other* people invoke your methods. ``self`` is an implementation detail.
``RemoteInterface`` will complain if you forget.

The "methods" in a ``RemoteInterface`` should return a single value with the
same format as the default arguments: either a basic type (``int`` , ``str``
, etc) or a ``Constraint`` subclass. This ``Constraint`` is enforced on the
return value of the method. If you are calling a method in somebody else's
process, the argument constraints will be applied as a courtesy ("be
conservative in what you send"), and the return value constraint will be
applied to prevent the server from doing evil things to you. If you are
running a method on behalf of a remote client, the argument constraints will
be enforced to protect *you* , while the return value constraint will be
applied as a courtesy.

Attempting to send a value that does not satisfy the Constraint will result
in a ``foolscap.Violation`` exception being raised.

You can also specify methods by defining attributes of the same name in the
``RemoteInterface`` object. Each attribute value should be an instance of
``foolscap.schema.RemoteMethodSchema`` [#]_ . This approach is more flexible:
there are some constraints that are not easy to express with the
default-argument syntax, and this is the only way to set per-method flags.
Note that all such method-defining attributes must be set in the
``RemoteInterface`` body itself, rather than being set on it after the fact
(i.e. ``RIFoo.doBar = stuff`` ). This is required because the
``RemoteInterface`` metaclass magic processes all of these attributes only
once, immediately after the ``RemoteInterface`` body has been evaluated.

The ``RemoteInterface`` "class" has a name. Normally this is the (short)
classname [#]_ . You can override this name by setting a special
``__remote_name__`` attribute on the ``RemoteInterface`` (again, in the
body). This name is important because it is externally visible: all
``RemoteReference`` s that point at your ``Referenceable`` s will remember
the name of the ``RemoteInterface`` s it implements. This is what enables the
type-checking to be performed on both ends of the wire.

In the future, this ought to default to the **fully-qualified** classname
(like ``package.module.RIFoo`` ), so that two RemoteInterfaces with the same
name in different modules can co-exist. In the current release, these two
RemoteInterfaces will collide (and provoke an import-time error message
complaining about the duplicate name). As a result, if you have such classes
(e.g. ``foo.RIBar`` and``baz.RIBar`` ), you **must** use ``__remote_name__``
to distinguish them (by naming one of them something other than``RIBar`` to
avoid this error.

Hopefully this will be improved in a future version, but it looks like a
difficult change to implement, so the standing recommendation is to use
``__remote_name__`` on all your RemoteInterfaces, and set it to a suitably
unique string (like a URI).

Here's an example:

.. code-block:: python

    
    from foolscap.api import RemoteInterface, schema
    
    class RIMath(RemoteInterface):
        __remote_name__ = "RIMath.using-foolscap.docs.foolscap.twistedmatrix.com"
        def add(a=int, b=int):
            return int
        # declare it with an attribute instead of a function definition
        subtract = schema.RemoteMethodSchema(a=int, b=int, _response=int)
        def sum(args=schema.ListOf(int)):
            return int

Using RemoteInterface
~~~~~~~~~~~~~~~~~~~~~

To declare that your ``Referenceable`` responds to a particular
``RemoteInterface`` , use the normal ``implements()`` annotation:

.. code-block:: python

    
    class MathServer(foolscap.Referenceable):
        implements(RIMath)
    
        def remote_add(self, a, b):
            return a+b
        def remote_subtract(self, a, b):
            return a-b
        def remote_sum(self, args):
            total = 0
            for a in args: total += a
            return total

To enforce constraints everywhere, both sides will need to know about the
``RemoteInterface`` , and both must know it by the same name. It is a good
idea to put the ``RemoteInterface`` in a common file that is imported into
the programs running on both sides. It is up to you to make sure that both
sides agree on the interface. Future versions of Foolscap may implement some
sort of checksum-verification or Interface-serialization as a failsafe, but
fundamentally the ``RemoteInterface`` that *you* are using defines what
*your* program is prepared to handle. There is no difference between an old
client accidentally using a different version of the RemoteInterface by
mistake, and a malicious attacker actively trying to confuse your code. The
only promise that Foolscap can make is that the constraints you provide in
the RemoteInterface will be faithfully applied to the incoming data stream,
so that you don't need to do the type checking yourself inside the method.

When making a remote method call, you use the ``RemoteInterface`` to identify
the method instead of a string. This scopes the method name to the
RemoteInterface:

.. code-block:: python

    
    d = remote.callRemote(RIMath["add"], a=1, b=2)
    # or
    d = remote.callRemote(RIMath["add"], 1, 2)

Pass-By-Copy
------------

You can pass (nearly) arbitrary instances over the wire. Foolscap knows how
to serialize all of Python's native data types already: numbers, strings,
unicode strings, booleans, lists, tuples, dictionaries, sets, and the None
object. You can teach it how to serialize instances of other types too.
Foolscap will not serialize (or deserialize) any class that you haven't
taught it about, both for security and because it refuses the temptation to
guess your intentions about how these unknown classes ought to be serialized.

The simplest possible way to pass things by copy is demonstrated in the
following code fragment:

.. code-block:: python

    
    from foolscap.api import Copyable, RemoteCopy
    
    class MyPassByCopy(Copyable, RemoteCopy):
        typeToCopy = copytype = "MyPassByCopy"
        def __init__(self):
            # RemoteCopy subclasses may not accept any __init__ arguments
            pass
        def setCopyableState(self, state):
            self.__dict__ = state

If the code on both sides of the wire import this class, then any instances
of ``MyPassByCopy`` that are present in the arguments of a remote method call
(or returned as the result of a remote method call) will be serialized and
reconstituted into an equivalent instance on the other side.

For more complicated things to do with pass-by-copy, see the documentation on
``Copyable`` . This explains the difference between ``Copyable`` and
``RemoteCopy`` , how to control the serialization and deserialization
process, and how to arrange for serialization of third-party classes that are
not subclasses of ``Copyable`` .


Third-party References
----------------------

Another new feature of Foolscap is the ability to send ``RemoteReference`` s
to third parties. The classic scenario for this is illustrated by the
`three-party Granovetter diagram
<http://www.erights.org/elib/capability/overview.html>`_ . One party (Alice)
has RemoteReferences to two other objects named Bob and Carol. She wants to
share her reference to Carol with Bob, by including it in a message she sends
to Bob (i.e. by using it as an argument when she invokes one of Bob's remote
methods). The Foolscap code for doing this would look like:

.. code-block:: python

    
    bobref.callRemote("foo", intro=carolref)

When Bob receives this message (i.e. when his ``remote_foo`` method is
invoked), he will discover that he's holding a fully-functional
``RemoteReference`` to the object named Carol [#]_ . He can start using this
RemoteReference right away:

.. code-block:: python

    
    class Bob(foolscap.Referenceable):
        def remote_foo(self, intro):
            self.carol = intro
            carol.callRemote("howdy", msg="Pleased to meet you", you=intro)
            return carol

If Bob sends this ``RemoteReference`` back to Alice, her method will see the
same ``RemoteReference`` that she sent to Bob. In this example, Bob sends the
reference by returning it from the original ``remote_foo`` method call, but
he could almost as easily send it in a separate method call.

.. code-block:: python

    
    class Alice(foolscap.Referenceable):
        def start(self, carol):
            self.carol = carol
            d = self.bob.callRemote("foo", intro=carol)
            d.addCallback(self.didFoo)
        def didFoo(self, result):
            assert result is self.carol  # this will be true

Moreover, if Bob sends it back to *Carol* (completing the three-party round
trip), Carol will see it as her original ``Referenceable`` .

.. code-block:: python

    
    class Carol(foolscap.Referenceable):
        def remote_howdy(self, msg, you):
            assert you is self  # this will be true

In addition to this, in the four-party introduction sequence as used by the
`Grant Matcher Puzzle
<http://www.erights.org/elib/equality/grant-matcher/index.html>`_ , when a
Referenceable is sent to the same destination through multiple paths, the
recipient will receive the same ``RemoteReference`` object from both sides.

For a ``RemoteReference`` to be transferrable to third-parties in this
fashion, the original ``Referenceable`` must live in a Tub which has a
working listening port, and an established base FURL. It is not necessary for
the Referenceable to have been published with ``registerReference`` first: if
it is sent over the wire before a name has been associated with it, it will
be registered under a new random and unguessable name. The
``RemoteReference`` will contain the resulting FURL, enabling it to be sent
to third parties.

When this introduction is made, the receiving system must establish a
connection with the Tub that holds the original Referenceable, and acquire
its own RemoteReference. These steps must take place before the remote method
can be invoked, and other method calls might arrive before they do. All
subsequent method calls are queued until the one that involved the
introduction is performed. Foolscap guarantees (by default) that the messages
sent to a given Referenceable will be delivered in the same order. In the
future there may be options to relax this guarantee, in exchange for higher
performance, reduced memory consumption, multiple priority queues, limited
latency, or other features. There might even be an option to turn off
introductions altogether.

Also note that enabling this capability means any of your communication peers
can make you create TCP connections to hosts and port numbers of their
choosing. The fact that those connections can only speak the Foolscap
protocol may reduce the security risk presented, but it still lets other
people be annoying.

If this property bothers you, you can instruct the Tub to disable these
introductions. When disabled, attempts to send or receive an introduction
will fail (with a Violation error).


.. code-block:: python

    tub = Tub()
    tub.setOption("accept-gifts", False)

Note that you should set this option before your Tub has an opportunity to
connect to any other Tub. Doing this before `tub.startService()` is one
approach.



.. rubric:: Footnotes

.. [#] although really, if your client machine is too slow to perform this
       kind of math, it is probably too slow to run python or use a network,
       so you should seriously consider a hardware upgrade
.. [#] but they do not provide quite the same insulation against other
       objects as E's Vats do. In this sense, Tubs are leaky Vats.
.. [#] note that the FURL uses the same format as an `HTTPSY
       <http://www.waterken.com/dev/YURL/httpsy/>`_ URL
.. [#] in fact, the very *very* first object exchanged is a special implicit
       RemoteReference to the remote Tub itself, which implements an internal
       protocol that includes a method named ``remote_getReference`` . The
       ``tub.getReference(url)`` call is turned into one step that connects
       to the remote Tub, and a second step which invokes
       remotetub.callRemote("getReference", refname) on the result
.. [#] of course, the Foolscap connections must be secured with SSL
       (otherwise an eavesdropper or man-in-the-middle could get access), and
       the registered name must be unguessable (or someone else could acquire
       a reference), but both of these are the default.
.. [#] you may not want to accept shared objects in your method arguments, as
       it could lead to surprising behavior depending upon how you have
       written your method. The ``foolscap.schema.Shared`` constraint will
       let you express this, and is described in the "Constraints" section of
       this document
.. [#] In fact, if all you want is referenceability (and not callability),
       you can use ``foolscap.referenceable.OnlyReferenceable`` . Strictly
       speaking, ``Referenceable`` is both "Referenceable" (meaning it is
       sent over the wire using pass-by-reference semantics, and it survives
       a round trip) and "Callable" (meaning you can invoke remote methods on
       it). ``Referenceable`` should really be named ``Callable`` , but the
       existing name has a lot of historical weight behind it.
.. [#] to be precise, each ``Unslicer`` on the receive stack has a
       ``Constraint`` , and the idea is that all of them get to pass
       judgement on the inbound token. A useful syntax to describe this sort
       of thing is still being worked out.
.. [#] although technically it can be any object which implements
       the ``IRemoteMethodConstraint`` interface
.. [#] ``RIFoo.__class__.__name__`` , if ``RemoteInterface`` s were actually
       classes, which they're not
.. [#] and since Tubs are authenticated, Foolscap offers a guarantee, in the
       cryptographic sense, that Bob will wind up with a reference to the
       same object that Alice intended. The authenticated FURLs prevent
       DNS-spoofing and man-in-the-middle attacks.
