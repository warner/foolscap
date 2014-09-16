The Banana Protocol
===================

*NOTE! This is all preliminary and is more an exercise in semiconscious
protocol design than anything else. Do not believe this document. This
sentence is lying. So there.*

Banana tokens
-------------

At the lowest layer, the wire transport takes the form of Tokens. These all
take the shape of header/type-byte/body.

- Header: zero or more bytes, all of which have the high bit clear (they
  range in value from 0 to 127). They form a little-endian base-128 number,
  so 1 is represented as 0x01, 128 is represented as 0x00 0x01, 130 as 0x02
  0x01, etc. 0 can be represented by any string of 0x00 bytes, including an
  empty string. The maximum legal header length is 64 bytes, so it has a
  maximum value of 2**(64*7)-1. Not all tokens have headers.
- Type Byte: the high bit is set to distinguish it from the header bytes
  that precede it (it has a value from 128 to 255). The Type Byte determines
  how to interpret both the header and the body. All valid type bytes are
  listed below.
- Body: zero or more arbitrary bytes, length is specified by the
  header. Not all tokens have bodies.

Tokens are described below as [header-TOKEN-body], where either "header" or
"body" may be empty. For example, [len-LIST-empty] indicates that the length
is put into the header, "LIST" is the token being used, and the body is
empty.

The possible Token types are:

- 
  ``0x80: LIST (old): [len-LIST-empty]``
  
  This token marks the beginning of a list with LEN elements. It acts as the
  "open parenthesis" , and the matching "close parenthesis" is implicit,
  based upon the length of the list. It will be followed by LEN things, which
  may be tokens like INTs or STRINGS, or which may be sublists. Banana keeps
  a list stack to handle nested sublists.
  
  This token (and the notion of length-prefixed lists in general) is from
  oldbanana. In newbanana it is only used during the initial dialect
  negotiation (so that oldbanana peers can be detected). Newbanana requires
  that LIST(old) tokens be followed exclusively by strings and have a rather
  limited allowable length (say, 640 dialects long).

- 
  ``0x81: INT: [value-INT-empty]``
  
  This token defines a single positive integer. The protocol defines its
  range as [0, 2**31), so the largest legal value is 2**31-1. The recipient
  is responsible for choosing an appropriate local type to hold the number.
  For Python, if the value represented by the incoming base-128 digits grows
  larger than a regular Python IntType can accomodate, the receiving system
  will use a LongType or a BigNum as necessary.
  
  Anything larger than this range must be sent with a LONGINT token instead.
  
  (oldbanana compatibility note: a python implementation can accept anything
  in the range [0, 2**448), limited by the 64-byte maximum header size).
  
  The range was chosen to allow INT values to always fit in C's s_int32_t
  type, so an implementation that doesn't have a useful bignum type can
  simply reject LONGINT tokens.

- 
  ``0x82: STRING [len-STRING-chars]``
  
  This token defines a string. To be precise, it defines a sequence of bytes.
  The length is a base-128-encoded integer. The type byte is followed by LEN
  bytes of data which make up the string. LEN is required to be shorter than
  640k: this is intended to reduce the amount of memory that can be consumed
  on the receiving end before user code gets to decide whether to accept the
  data or not.

- 
  ``0x83: NEG: [value-NEG-empty]``
  
  This token defines a negative integer. It is identical to the ``INT`` tag
  except that the results are negated before storage. The range is defined as
  [-2**31, 0), again to make an implementation using s_int32_t easier. Any
  numbers smaller (more negative) than this range must be sent with a LONGNEG
  token.
  
  Implementations should be tolerant when receiving a "negative zero" and
  turn it into a 0, even though they should not send such things.
  
  Note that NEG can represent a number (-2**31) whose absolute value (2**31)
  is one larger than the greatest number that INT can represent (2**31-1).

- 
  ``0x84: FLOAT [empty-FLOAT-value]``
  
  This token defines a floating-point number. There is no header, and the
  type byte is followed by 8 bytes which are a 64-bit IEEE "double" , as
  defined by ``struct.pack("!d", num)`` .

- 
  ``0x85: OLDLONGINT: [value-OLDLONGINT-empty]``
  
  ``0x86: OLDLONGNEG: [value-OLDLONGNEG-empty]``
  
  These were used by oldbanana to represent large numbers. Their size was
  limited by the number of bytes in the header (max 64), so they can
  represent [0, 2**448).

- 
  ``0x87: VOCAB: [index-VOCAB-empty]``
  
  This defines a tokenized string. Banana keeps a mapping of common strings,
  each one is assigned a small integer. These strings can be sent compressed
  as a two-byte (index, VOCAB) sequence. They are delivered to Jelly as plain
  strings with no indication that they were compressed for transit.
  
  The strings in this mapping are populated by the sender when it sends a
  special "vocab" OPEN sequence. The intention is that this mapping will be
  sent just once when the connection is first established, but a sufficiently
  ambituous sender could use this to implement adaptive forward compression.

- 
  ``0x88: OPEN: [[num]-OPEN-empty]``
  
  ``0x89: CLOSE: [[num]-CLOSE-empty]``
  
  These tokens are the newbanana parenthesis markers. They carry an optional
  number in their header: if present, the number counts the appearance of
  OPEN tokens in the stream, starting at 0 for the first OPEN used for a
  given connection and incrementing by 1 for each subsequent OPEN. The
  matching CLOSE token must contain an identical number. These numbers are
  solely for debugging and may be omitted. They may be removed from the
  protocol once development has been completed.
  
  In contrast to oldbanana (with the LIST token), newbanana does not use
  length-prefixed lists. Instead it relies upon the Banana layer to track
  OPEN/CLOSE tokens.
  
  OPEN markers are followed by the "Open Index" tuple: one or more tokens to
  indicate what kind of new sub-expression is being started. The first token
  must be a string (either STRING or VOCAB), the rest may be strings or other
  primitive tokens. The recipient decides when the Open Index has finished
  and the body has begun.
- 
  ``0x8A: ABORT: [[num]-ABORT-empty]``
  
  This token indicates that something has gone wrong on the sender side, and
  that the resulting object must not be handed upwards in the unslicer stack.
  It may be impossible or inconvenient for the sender to stop sending the
  tokens associated with the unfortunate object, so the receiver must be
  prepared to silently drop all further tokens up to the matching STOP
  marker. The STOP token must always follow eventually: this is just a
  courtesy notice.
  
  The number, if present, will be the same one used by the OPEN token.

- 
  ``0x8B: LONGINT: [len-LONGINT-bytes]``
  
  ``0x8C: LONGNEG: [len-LONGNEG-bytes]``
  
  These are processed like STRING tokens, but the bytes form a base-256
  encoded number, most-significant-byte first (note that this may require
  several passes and some intermediate storage). The size is (barely) limited
  by the length field, so the theoretical range is [0, 2**(2**(64*7)-1)-1),
  but the receiver can impose whatever length limit they wish.
  
  LONGNEG is handled exactly like LONGINT but the number is negated first.

- 
  ``0x8D: ERROR [len-ERROR-chars]``
  
  This token defines a string of ASCII characters which hold an error
  message. When a severe protocol violation occurs, the offended side will
  emit an ERROR token and then close the transport. The side which receives
  the ERROR token should put the message in a developer-readable logfile and
  close the transport as well.
  
  The ERROR token is formatted exactly like the STRING token, except that it
  is defined to be encoded in ASCII (the STRING token does not claim to be
  encoded in any particular character set, nor does it necessarily represent
  human-readable characters).
  
  The ERROR token is limited to 1000 characters.

- 
  ``0x8E: PING [[num]-PING-empty]``
  
  ``0x8F: PONG [[num]-PONG-empty]``
  
  These tokens have no semantic value, but are used to implement connection
  timeouts and keepalives. When one side receives a PING message, it should
  immediately queue a PONG message on the return stream. The optional number
  can be used to associate a PONG with the PING that prompted it: if present,
  it must be duplicated in the response.
  
  Other than generating a PONG, these tokens are ignored by both ends. They
  are not delivered to higher levels. They may appear in the middle of an
  OPEN sequence without affecting it.
  
  The intended use is that each side is configured with two timers: the idle
  timer and the disconnect timer. The idle timer specifies how long the
  inbound connection is allowed to remain quiet before poking it. If no data
  has been received for this long, a PING is sent to provoke some kind of
  traffic. The disconnect timer specifies how long the inbound connection is
  allowed to remain quiet before concluding that the other end is dead and
  thus terminating the connection.

These messages can also be used to estimate the connection's round-trip time
(including the depth of the transmit/receive queues at either end). Just send
a PING with a unique number, and measure the time until the corresponding
PONG is seen.

TODO: Add TRUE, FALSE, and NONE tokens. (maybe? These are currently handled
as OPEN sequences)

Serialization
-------------

When serializing an object, it is useful to view it as a directed graph. The
root object is the one you start with, any objects it refers to are children
of that root. Those children may point back to other objects that have
already been serialized, or which will be serialized later.

Banana, like pickle and other serialization schemes, does a depth-first
traversal of this graph. Serialization is begun on each node before going
down into the child nodes. Banana tracks previously-handled nodes and
replaces them with numbered ``reference`` tokens to break loops in the graph.

Banana Slicers
~~~~~~~~~~~~~~

A *Banana Slicer* is responsible for serializing a single user object: it
"slices" that object into a series of smaller pieces, either fundamental
Banana tokens or other Sliceable objects. On the receiving end, there is a
corresponding *Banana Unslicer* which accepts the incoming tokens and
re-creates the user object. There are different kinds of Slicers and
Unslicers for lists, tuples, dictionaries, etc. Classes can provide their own
Slicers if they want more control over the serialization process.

In general, there is a Slicer object for each act of serialization of a given
object (although this is not strictly necessary). This allows the Slicer to
contain state about the serialization process, which enables
producer/consumer -style pauses, and slicer-controlled streaming
serialization. The entire context is stored in a small tuple (which includes
the Slicer), so it can be set aside for a while. In the future, this will
allow interleaved serialization of multiple objects (doing context switching
on the wire), to do things like priority queues and avoid head-of-line
blocking.

The most common pattern is to have the Slicer be the ``ISlicer`` Adapter for
the object, in which it gets a new Slicer case each it is serialized. Classes
which do not need to store a lot of state can have a single Slicer per
serialized object, presumably through some adapter tricks. It is also valid
to have the serialized object be its own Slicer.

The Slicer has other duties (described below), but the main one is to
implement the ``slice`` method, which should return a sequence or an iterable
which yields the Open Index Tokens, followed by the body tokens. (Note that
the Slicer should not include the OPEN or CLOSE tokens: those are supplied by
the SendBanana wrapping code). Any item which is a fundamental type (int,
string, float) will be sent as a banana token, anything else will be handled
by recursion (with a new Slicer).

Most subclasses of ``BaseSlicer`` implement a companion method named
``sliceBody`` , which supplies just the body tokens. (This makes the code a
bit easier to follow). ``sliceBody`` is usually just a "return [token,
token]" , or a series of ``yield`` statements, one per token. However,
classes which wish to have more control over the process can implement
``sliceBody`` or even ``slice`` differently.

.. code-block:: python

    
    class ThingySlicer(slicer.BaseSlicer):
        opentype = ('thingy',)
        trackReferences = True
    
        def sliceBody(self, streamable, banana):
            return [self.obj.attr1, self.obj.attr2]

If "attr1" and "attr2" are integers, the preceding Slicer would create a
token sequence like: OPEN STRING(thingy) 13 16 CLOSE. If "attr2" were
actually another Thingy instance, it might produce OPEN STRING(thingy) 13
OPEN STRING(thingy) 19 18 CLOSE CLOSE.

Doing this with a generator gives the same basic results but avoids the
temporary buffer, which can be important when sending large amounts of data.
The following Slicer could be combined with a concatenating Unslicer to
implement the old FilePager class without the extra round-trip
inefficiencies.

.. code-block:: python

    
    class DemandSlicer(slicer.BaseSlicer):
        opentype = ('demandy',)
        trackReferences = True
    
        def sliceBody(self, streamable, banana):
            f = open("data", "r")
            for chunk in f.read(2048):
                yield chunk

The SendBanana code controls the pacing: if the transport is full, it has the
option of pausing the generator until the receiving end has caught up. It
also has the option of pulling tokens out of the Slicer anyway, and buffering
them in memory. This may be necessary to achieve serialization coherency,
discussed below.

If the "streamable" flag is set, then the *slicer* gets to control the pacing
too: it is allowed to yield a Deferred where it would normally provide a
regular token. This tells Banana that serialization needs to wait for a while
(perhaps we are streaming data from another source which has run dry, or we
are trying to implement some kind of rate limiting). Banana will wait until
the Deferred fires before attempting to retrieve another token. If the
"streamable" flag is *not* set, then a parent Slicer has decided that it is
unwilling to allow streaming (perhaps it needs to serialize a coherent state,
and a pause for streaming would allow that state to change before it was
completely serialized). The Slicer is not allowed to return a Deferred when
streaming is disabled.

.. code-block:: python

    
    class URLGetterSlicer(slicer.BaseSlicer):
        opentype = ('urldata',)
        trackReferences = True
    
        def gotPage(self, page):
            self.page = page
    
        def sliceBody(self, streamable, banana):
            yield self.url
            d = web.client.getPage(self.url)
            d.addCallback(self.gotPage)
            yield d
            # here we hover in limbo until it fires
            yield self.page

(the code is a bit kludgy because generators have no way to pass data back
out of the "yield" statement) (at the time this was first written).

The Slicer can also raise a "Violation" exception, in which case the slicer
will be aborted: no further tokens will be pulled from it. This causes an
ABORT token to be sent over the wire, followed immediately by a CLOSE token.
The dead Slicer's parent is notified with a ``childAborted`` method, then the
Banana continues to extract tokens from the parent as if the child had
finished normally. (TODO: we need a convenient way for the parent to indicate
that it wishes to give up too, such as raising a Violation from within
``childAborted`` ).

Serialization Coherency
~~~~~~~~~~~~~~~~~~~~~~~

Streaming serialization means the object is serialized a little bit at a
time, never consuming too much memory at once. The tradeoff is that, by doing
other useful work inbetween, our object may change state while it is being
serialized. In oldbanana this process was uninterruptible, so coherency was
not an issue. In newbanana it is optional. Some objects may have more trouble
with this than others, so Banana provides Slicers with a means to influence
the process.

Banana makes certain promises about what takes place between successive
"yield" statements, when the Slicer gives up control to Banana. The most
conservative approach is to:

- disable the RootSlicer's "streamable" flag to tell all Slicers that they
  should not return Deferreds: this avoids loss of control due to child
  Slicers giving it away
- set the SendBanana policy to buffer data in memory rather than do a
  .pauseProducing: this removes pauses due to the output channel filling up
- return a list from ``slice`` (or ``sliceBody`` ) instead of using a
  generator: this fixes the object contents at a single point in time. (you
  can also create a list at the beginning of that routine and then yield
  pieces of it, which has exactly the same effect)

Slicers aren't supposed to do anything which changes the state observed by
other Slicers: if this is really the case than it is safe to use a generator.
A parent Slicer which yields a non-primitive object will give up control to
the child Slicer needed to handle that object, but that child should do its
business and finish quickly, so there should be no way for the parent
object's state to change in the meantime.

If the SendBanana is allowed to give up control (.pauseProducing), then
arbitrary code will get to run in between "yield" calls, possibly changing
the state being accessed by those yields. Likewise child Slicers might give
up control, threatening the coherency of one of their parents. Slicers can
invoke ``banana.inhibitStreaming()`` (TODO: need a better name) to inhibit
streaming, which will cause all child serialization to occur immediately,
buffering as much data in memory as necessary to complete the operation
without give up control.

Coherency issues are a new area for Banana, so expect new tools and
techniques to be developed which allow the programmer to make sensible
tradeoffs.

The Slicer Stack
~~~~~~~~~~~~~~~~

(docs note: our directions are inconsistent: the RootSlicer is the parent,
but lives at the bottom of the stack. I think of delegation as going
"upwards" to your parent (like upcalls), so I describe it that way, but that
"up" is at odds with the stack's "bottom")

The serialization context is stored in a "SendBanana" object, which is one of
the two halves of the Banana object (a subclass of Protocol). This holds a
stack of Banana Slicers, one per object currently being serialized (i.e. one
per node in the path from the root object to the object currently being
serialized).

For example, suppose a class instance is being serialized, and this class
chose to use a dictionary to hold its instance state. That dictionary holds a
list of numbers in one of its values. While the list of numbers is being
serialized, the Slicer Stack would hold: the RootSlicer, an InstanceSlicer, a
DictSlicer, and finally a ListSlicer.

The stack is used to determine two things:

- How to handle a child object: which Slicer should be used, or if a
  Violation should be raised
- How to track object references, to break cycles in the object graph

When a new object needs to be sent, it is first submitted to the top-most
Slicer (to its ``slicerForObject`` method), which is responsible for either
returning a suitable Slicer or raising a Violation exception (if the object
is rejected by a security policy). Most Slicers will just delegate this
method up to the RootSlicer, but Slicers which wish to pass judgement upon
enclosed objects (or modify the Slicer selected) can do something else.
Unserializable objects will raise an exception here.

Once the new Slicer is obtained, the OPEN token is emitted, which provides
the "openID" number (just an implicit count of how many OPEN tokens have been
sent over the wire). This is where we break cycles in the object graph:
before serializing the object, we record a reference to it (the openID), and
any time we encounter the object again, we send the reference number instead
of a new copy. This reference number is tracked in the SlicerStack, by
handing the number/object pair to the top-most Slicer's ``registerReference``
method. Most Slicers will delegate this up to the RootSlicer, but again they
can perform additional registrations or consume the request entirely. This is
used in PB to provide "scoped references" , where (for example) a list
*should* be sent twice if it occurs in two separate method calls. In this
case the CallSlicer (which sits above the PBRootSlicer) does its own
registration.

The ``slicerForObject`` process is responsible for catching the second time
the object is sent. It looks in the same mapping created by
``registerReference`` and returns a ``ReferenceSlicer`` instead of the usual
one.

The ``RootSlicer`` , which sits at the bottom of the stack, is a special
case. It is never pushed or popped, and implements most of the policy for the
whole Banana process. The RootSlicer can also be interpreted as a "root
object" , if you imagine that any given user object being serialized is
somehow a child of the overall serialization context. In PB, for example, the
root object would be related to the connection and needs to track things like
which remotely-invokable objects are available.

The default RootSlicer implements the following behavior:

- Allow all objects to be serialized that can be
- Use its ``.slicerTable`` to get a Slicer for an object. If that fails,
  adapt the object to ISlicer
- Record object references in its ``.references`` dict

The ``RootSlicer`` class only does "safe" serialization: basic types and
whatever you've registered an ISlicer adapter for. The ``TrustingRootSlicer``
uses that .slicerTable mapping to serialize unsafe things (arbitrary
instances, classes, etc), which is suitable for local storage instead of
network communication (i.e. when you want to use banana as a pickle
replacement).

TODO: The idea is to let other serialization contexts do other things. For
example, the final tokens could go to the parent slice for handling instead
of straight to the Protocol, which would provide more control over turning
the tokens into bytes and sending over a wire, saving to a file, etc.

Finally, the stack can be queried to find out what path leads from the root
object to the one currently being serialized. If something goes wrong in the
serialization process (an exception is thrown), this path can make it much
easier to find out *when* the trouble happened, as opposed to merely where.
Knowing that the ".oops" method of your FooObject failed during serialization
isn't very useful when you have 500 FooObjects inside your data structure and
you need to know whether it was ``bar.thisfoo`` or ``bar.thatfoo`` which
caused the problem. To this end, each Slicer has a ``.describe`` method which
is supposed to return a short string that explains how to get to the child
node currently being processed. When an error occurs, these strings are
concatenated together and put into the failure object.

Deserialization
---------------

The other half of the Banana class is the ``ReceiveBanana`` , which accepts
incoming tokens and turns them into objects. It is organized just like the
``SendBanana`` , with a stack of "Banana Unslicer" objects, each of which
assembles tokens or child objects into a larger one. Each Unslicer receives
the tokens emitted by the matching Slicer on the sending side. The whole
stack is used to create new Unslicers, enforce restrictions upon what objects
will be accepted, and manage object references.

Each Unslicer accepts tokens that turn into an object of some sort. They pass
this object up to their parent Unslicer. Eventually a finished object is
given to the ``RootUnslicer`` , which decides what to do with it. When the
Banana is being used for data storage (like pickle), the root will just
deliver the object to the caller. When Banana is used in PB, the actual work
is done by some intermediate objects like the ``CallUnslicer`` , which is
responsible for a single method invocation.

The ``ReceiveBanana`` itself is responsible for pulling well-formed tokens
off the incoming data stream, tracking OPEN and CLOSE tokens, maintaining
synchronization with the transmitted token stream, and discarding tokens when
the receiving Unslicers have rejected one of the inbound objects. Unslicer
methods may raise Violation exceptions: these are caught by the Unbanana and
cause the object currently being unserialized to fail: its parent gets a
UnbananaFailure instead of the dict or list or instance that it would
normally have received.

OPEN tokens are followed by a short list of tokens called the "opentype" to
indicate what kind of object is being started. This is looked up in the
UnbananaRegistry just like object types are looked up in the BananaRegistry
(TODO: need sensible adapter-based registration scheme for unslicing). The
new Unslicer is pushed onto the stack.

"ABORT" tokens indicate that something went wrong on the sending side and
that the current object is to be aborted. It causes the receiver to discard
all tokens until the CLOSE token which closes the current node. This is
implemented with a simple counter of how many levels of discarding we have
left to do.

"CLOSE" tokens finish the current node. The Unslicer will pass its completed
object up to the "receiveChild" method of its parent.

Open Index tokens: the Opentype
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OPEN tokens are followed by an arbitrary list of other tokens which are used
to determine which UnslicerFactory should be invoked to create the new
Unslicer. Basic Python types are designated with a simple string, like (OPEN
"list") or (OPEN "dict"), but instances are serialized with two strings (OPEN
"instance" "classname"), and various exotic PB objects like method calls may
involve a list of strings and numbers (OPEN "call" reqID objID methodname).
The unbanana code works with the unslicer stack to apply constraints to these
indexing tokens and finally obtain the new Unslicer when enough indexing
tokens have been received.

The reason for assembling this "opentype" list before creating the Unslicer
(instead of using a generic InstanceUnslicer which switches behavior
depending upon its first received token) is to support classes or PB methods
which wish to push custom Unslicers to handle their deserialization process.
For example, a class could push a StreamingFileUnslicer that accepts a series
of string tokens and appends their contents to a file on disk. This Unslicer
could reduce memory consumption (by only holding one chunk at a time) and
update some kind of progress indicator as the data arrives. This particular
feature was provided by the old StringPager utility, but custom Unslicers
offer more flexibility and better efficiency (no additional round-trips).

(note: none of this affects the serialization side: those Slicers emit both
their indexing tokens and their state tokens. It is only the receiving side
where the index tokens are handled by a different piece of code than the
content tokens).

In yet greater detail:

- Each OPEN sequence is divided into an "Index phase" and a "Contents phase"
  . The first one (or two or three) tokens are the Index Tokens and the rest
  are the Body Tokens. The sequence ends with a CLOSE token.
- Banana.inOpen is a boolean which indicates that we are in the Index Phase.
  It is set to True when the OPEN token is received and returns to False
  after the new Unslicer has been pushed.
- Banana.opentype is a list of Index Tokens that are being accumulated. It is
  cleared each time .inOpen is set to True. The tuple form of opentype is
  passed to Slicer.doOpen, Constraint.checkOpentype, and used as a key in the
  RootSlicer.openRegistry dictionary. Each Unslicer type is indexed by an
  opentype tuple.

If .inOpen is True, each new token type will be passed (through
Banana.getLimit and top.openerCheckToken) to the opener's .openerCheckToken
method, along with the current opentype tuple. The opener gets to decide if
the token is acceptable (possibly raising a Violation exception). Note that
the opener does not maintain state about what phase the decoding process is
in, so it may want to condition its response upon the length of the opentype.

After each index token is complete, it is appended to .opentype, then the
list is passed (through Banana.handleOpen, top.doOpen, and top.open) to the
opener's .open method. This can either return an Unslicer (which will finish
the index phase: all further tokens will be sent to the new Unslicer), return
None (to continue the index phase), raise a Violation (which causes an
UnbananaFailure to be passed to the current top unslicer), or raise another
exception (which causes the connection to be abandoned).

Unslicer Lifecycle
~~~~~~~~~~~~~~~~~~

Each Unslicer has access to the following attributes:

- ``.parent`` : This is set by the ReceiveBanana before ``.start`` is
  invoked, and provides a reference to the Unslicer responsible for the
  containing object. You can follow ``.parent`` all the way up the object
  graph to the single ``RootUnslicer`` object for this connection. It is
  appropriate to invoke ``openerCheckToken`` and ``open`` on your parent.
- ``.protocol`` : This is set by the ReceiveBanana before ``.start`` is
  invoked, and provides access to the Banana object which maintains the
  connection on which this object is being received. It is appropriate to
  examine the ``.debugReceive`` attribute on the protocol. It is also
  appropriate to invoke ``.setObject`` on it to register references for
  shared containers (like lists).
- ``openCount`` : This is set by the ReceiveBanana before ``.start`` is
  invoked, and contains the optional OPEN-count for this object, an implicit
  sequence number incremented for each OPEN token seen on the wire. During
  protocol development and testing the OPEN tokens may include an explicit
  OPEN-count value, but usually it is left out of the packet. If present, it
  is used by Banana.handleClose to assert that the CLOSE token is associated
  with the right OPEN token. Unslicers will not normally have a use for it.
- ``.count`` : This is provided as the "count" argument to ``.start`` , and
  contains the "object counter" for this object. This is incremented for each
  new object which is created by the receive Banana code. This is similar to
  (but not always the same as) the OPEN-count. Containers should call
  ``self.protocol.setObject`` to register a Deferred during ``start`` , then
  call it again in ``receiveClose`` with the real (finished) object. It is
  sometimes also included in a debug message.
- ``.broker`` : PB objects are given .broker, which is exactly equal to the
  .protocol attribute. The synonym exists because it makes several PB
  routines easier to read.

Each Unslicer handles a single "OPEN sequence" , which starts with an
OPEN token and ends with a CLOSE token.

Creation
^^^^^^^^

Acceptance of the OPEN token simply sets a flag to indicate that we are in
the Index Phase. (The OPEN token might not be accepted: it is submitted to
checkToken for approval first, as described below). During the Index Phase,
all tokens are appended to the current ``opentype`` list and handed as a
tuple to the top-most Unslicer's ``doOpen`` method. This method can do one of
the following things:

- Return a new Unslicer object. It does this when there are enough index
  tokens to specify a new Unslicer. The new child is pushed on top of the
  Unslicer stack (Banana.receiveStack) and initialized by calling the
  ``start`` method described below. This ends the Index Phase.
- Return None. This indicates that more index tokens are required. The Banana
  protocol object simply remains in the Index Phase and continues to
  accumulate index tokens.
- Raise a Violation. If the open type is unrecognized, then a Violation is a
  good way to indicate it.

When a new Unslicer object is pushed on the top of the stack, it has its
``.start`` method called, in which it has an opportunity to create whatever
internal state is necessary to record the incoming content tokens. Each
created object will have a separate Unslicer instance. The start method can
run normally, or raise a Violation exception.

``.start`` is distinct from the Unslicer's constructor function to minimize
the parameter-passing requirements for doOpen() and friends. It is also
conceivable that keeping arguments out of ``__init__`` would make it easier
to use adapters in this context, although it is not clear why that might be
useful on the Unslicing side. TODO: consider merging ``.start`` into the
constructor.

This Unslicer is responsible for all incoming tokens until either 1: it
pushes a new one on the stack, or 2: it receives a CLOSE token.

checkToken
^^^^^^^^^^

Each token starts with a length sequence, up to 64 bytes which are turned
into an integer. This is followed by a single type byte, distinguished from
the length bytes by having the high bit set (the type byte is always 0x80 or
greater). When the typebyte is received, the topmost Unslicer is asked about
its suitability by calling the ``.checkToken`` method. (note that CLOSE and
ABORT tokens are always legal, and are not submitted to checkToken). Both the
typebyte and the header's numeric value are passed to this methoed, which is
expected to do one of the following:

- Return None to indicate that the token and the header value are acceptable.
- Raise a ``Violation`` exception to reject the token or the header value.
  This will cause the remainder of the current OPEN sequence to be discarded
  (all tokens through the matching CLOSE token). Unslicers should raise this
  if their constraints will not accept the incoming object: for example a
  constraint which is expecting a series of integers can accept
  INT/NEG/LONGINT/LONGNEG tokens and reject OPEN/STRING/VOCAB/FLOAT tokens.
  They should also raise this if the header indicates, e.g., a STRING which
  is longer than the constraint is willing to accept, or a LONGINT/LONGNEG
  which is too large. The topmost Unslicer (the same one which raised
  Violation) will receive (through its ``.receiveChild`` method) an
  UnbananaFailure object which encapsulates the reason for the rejection

If the token sequence is in the "index phase" (i.e. it is just after an OPEN
token and a new Unslicer has not yet been pushed), then instead of
``.checkToken`` the top unslicer is sent ``.openerCheckToken`` . This method
behaves just like checkToken, but in addition to the type byte it is also
given the opentype list (which is built out of all the index tokens received
during this index phase).

receiveChild
^^^^^^^^^^^^

If the type byte is accepted, and the size limit is obeyed, then the rest of
the token is read and a finished (primitive) object is created: a string or
number (TODO: maybe add boolean and None). This object is handed to the
topmost Unslicer's ``.receiveChild`` method, where again it is has a few
options:

- Run normally: if the object is acceptable, it should append or record it
  somehow.
- Raise Violation, just like checkToken.
- invoke ``self.abort`` , which does ``protocol.abandonUnslicer``

If the child is handed an UnbananaFailure object, and it wishes to pass it
upwards to its parent, then ``self.abort`` is the appropriate thing to do.
Raising a Violation will accomplish the same thing, but with a new
UnbananaFailure that describes the exception raised here instead of the one
raised by a child object. It is bad to both call ``abort`` and raise an
exception.

Finishing
^^^^^^^^^

When the CLOSE token arrives, the Unslicer will have its ``.receiveClose``
method called. This is expected to do:

- Return an object: this object is the finished result of the deserialization
  process. It will be passed to ``.receiveChild`` of the parent Unslicer.
- Return a Deferred: this indicates that the object cannot be created yet
  (tuples that contain references to an enclosing tuple, for example). The
  Deferred will be fired (with the object) when it completes.
- Raise Violation

After receiveClose has finished, the child is told to clean up by calling its
``.finish`` method. This can complete normally or raise a Violation.

Then, the old top-most Unslicer is popped from the stack and discarded. Its
parent is now the new top-most Unslicer, and the newly-unserialized object is
given to it with the ``.receiveChild`` method. Note that this method is used
to deliver both primitive objects (from raw tokens) *and* composite objects
(from other Unslicers).

Error Handling
~~~~~~~~~~~~~~

Schemas are enforced by Constraint objects which are given an opportunity to
pass judgement on each incoming token. When they do not like something they
are given, they respond by raising a ``Violation`` exception. The Violation
exception is sometimes created with an argument that describes the reason for
the rejection, but frequently it is just a bare exception. Most Violations
are raised by the ``checkOpentype`` and ``checkObject`` methods of the
various classes in ``schema.py`` .

Violations which occur in an Unslicer can be confined to a single sub-tree of
the object graph. The object being deserialized (and all of its children) is
abandoned, and all remaining tokens for that object are discarded. However,
the parent object (to which the abandoned object would have been given) gets
to decide what happens next: it can either fail itself, or absorb the failure
(much like an exception handler can choose to re-raise the exception or eat
it).

When a Violation occurs, it is wrapped in an ``UnbananaFailure`` object (just
like Deferreds wrap exceptions in Failure objects). The UnbananaFailure
behaves like a regular ``twisted.python.failure.Failure`` object, except that
it has an attribute named ``.where`` which indicate the object-graph pathname
where the problem occurred.

The Unslicer which caused the Violation is given a chance to do cleanup or
error-reporting by invoking its ``reportViolation`` method. It is given the
UnbananaFailure so it can modify or copy it. The default implementation
simply returns the is expected to return the UnbananaFailure it was given,
but it is also allowed to return a different one. It must return an
UnbananaFailure: it cannot ignore the Violation by returning None. This
method should not raise any exceptions: doing so will cause the connection to
be dropped.

The UnbananaFailure returned by ``reportViolation`` is passed up the Unslicer
stack in lieu of an actual object. Most Unslicers have code in their
``receiveChild`` methods to detect an UnbananaFailure and trigger an abort
(``propagateUnbananaFailures`` ), which causes all further tokens of the
sub-tree to be discarded. The connection is not dropped. Unslicers which
partition their children's sub-graphs (like the PBRootUnslicer, for which
each child is a separate operation) can simply ignore the UnbananaFailure, or
respond to it by sending an error message to the other end.

Other exceptions may occur during deserialization. These indicate coding
errors or severe protocol violations and cause the connection to be dropped
(they are not caught by the Banana code and thus propagate all the way up to
the reactor, which drops the socket). The exception is logged on the local
side with ``log.err`` , but the remote end will not be told any reason for
the disconnection. The banana code uses the BananaError exception to indicate
protocol violations, but others may be encountered.

The Banana object can also choose to respond to Violations by terminating the
connection. For example, the ``.hangupOnLengthViolation`` flag causes
string-too-long violations to be raised directly instead of being handled,
which will cause the connection to be dropped (as it occurs in the
dataReceived method).

Example
~~~~~~~

The serialized form of ``["foo",(1,2)]`` is the following token sequence:
OPEN STRING(list) STRING(foo) OPEN STRING(tuple) INT(1) INT(2) CLOSE CLOSE.
In practice, the STRING(list) would really be something like VOCAB(7),
likewise the STRING(tuple) might be VOCAB(8). Here we walk through how this
sequence is processed.

The initial Unslicer stack consists of the single RootUnslicer ``rootun`` .





::

    
    OPEN
      rootun.checkToken(OPEN) : must not raise Violation
      enter index phase
    
    VOCAB(7)  (equivalent to STRING(list))
      rootun.openerCheckToken(VOCAB, ()) : must not raise Violation
      VOCAB token is looked up in .incomingVocabulary, turned into "list"
      rootun.doOpen(("list",)) : looks in UnslicerRegistry, returns ListUnslicer
      exit index phase
      the ListUnslicer is pushed on the stack
      listun.start()
    
    STRING(foo)
      listun.checkToken(STRING, 3) : must return None
      string is assembled
      listun.receiveChild("foo") : appends to list
    
    OPEN
      listun.checkToken(OPEN) : must not raise Violation
      enter index phase
    
    VOCAB(8)  (equivalent to STRING(tuple))
      listun.openerCheckToken(VOCAB, ()) : must not raise Violation
      VOCAB token is looked up, turned into "tuple"
      listun.doOpen(("tuple",)) : delegates through:
                                     BaseUnslicer.open
                                     self.opener (usually the RootUnslicer)
                                     self.opener.open(("tuple",))
                                  returns TupleUnslicer
      exit index phase
      TupleUnslicer is pushed on the stack
      tupleun.start()
    
    INT(1)
      tupleun.checkToken(INT) : must not raise Violation
      integer is assembled
      tupleun.receiveChild(1) : appends to list
    
    INT(2)
      tupleun.checkToken(INT) : must not raise Violation
      integer is assembled
      tupleun.receiveChild(2) : appends to list
    
    CLOSE
      tupleun.receiveClose() : creates and returns the tuple (1,2)
                               (could also return a Deferred)
      TupleUnslicer is popped from the stack and discarded
      listun.receiveChild((1,2))
    
    CLOSE
      listun.receiveClose() : creates and returns the list ["foo", (1,2)]
      ListUnslicer is popped from the stack and discarded
      rootun.receiveChild(["foo", (1,2)])

Other Issues
------------

Deferred Object Recreation: The Trouble With Tuples
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Types and classes are roughly classified into containers and non-containers.
The containers are further divided into mutable and immutable. Some examples
of immutable containers are tuples and bound methods. Lists and dicts are
mutable containers. Ints and strings are non-containers. Non-containers are
always leaf nodes in the object graph.

During unserialization, objects are in one of three states: uncreated,
referenceable (but not complete), and complete. Only mutable containers can
be referenceable but not complete: immutable containers have no intermediate
referenceable state.

Mutable containers (like lists) are referenceable but not complete during
traversal of their child nodes. This means those children can reference the
list without trouble.

Immutable containers (like tuples) present challenges when unserializing. The
object cannot be created until all its components are referenceable. While it
is guaranteed that these component objects will be complete before the graph
traversal exits the current node, the child nodes are allowed to reference
the current node during that traversal. The classic example is the graph
created by the following Python fragment:

.. code-block:: python

    
    a = ([],)
    a[0].append((a,))

To handle these cases, the TupleUnslicer installs a Deferred into the object
table when it begins unserializing (in the .start method). When the tuple is
finally complete, the object table is updated and the Deferred is fired with
the new tuple.

Containers (both mutable and immutable) are required to pay attention to the
types of their incoming children and notice when they receive Deferreds
instead of normal objects. These containers are not complete (in the sense
described above) until those Deferreds have been replaced with referenceable
objects. When the container receives the Deferred, it should attach a
callback to it which will perform the replacement. In addition, immutable
containers should check after each update to see if all the Deferreds have
been cleared, and if so, complete their own object (and fire their own
Deferreds so any containers *they* are a child of may be updated and/or
completed).

TODO: it would be really handy to have the RootUnslicer do Deferred
Accounting: each time a Deferred is installed instead of a real object, add
its the graph-path to a list. When the Deferred fires and the object becomes
available, remove it. If deserialization completes and there are still
Deferreds hanging around, flag an error that points to the culprits instead
of returning a broken object.

Security Model
~~~~~~~~~~~~~~

Having the whole Slicer stack get a chance to pass judgement on the outbound
object is very flexible. There are optimizations possibly because of the fact
that most Slicers don't care, perhaps a separate stack for the ones that want
to participate, or a chained delegation function. The important thing is to
make sure that exception cases don't leave a "taster" stranded on the stack
when the object that put it there has gone away.

On the receiving side, the top Unslicer gets to make a decision about the
token before its body has arrived (limiting memory exposure to no more than
65 bytes). In addition, each Unslicer receives component tokens one at a
time. This lets you catch the dangerous data before it gets turned into an
object. However, tokens are a pretty low-level place to do security checks.
It might be more useful to have some kind of "instance taster stack" , with
tasters that are asked specifically about (class,state) pairs and whether
they should be turned into objects or not.

Because the Unslicers receive their data one token at a time, things like
InstanceUnslicer can perform security checks one attribute at a time.
"traits" -style attribute constraints (see the Chaco project or the
PyCon-2003 presentation for details) can be implemented by having a per-class
dictionary of tests that attribute values must pass before they will be
accepted. The instance will only be created if all attributes fit the
constraints. The idea is to catch violations before any code is run on the
receiving side. Typical checks would be things like ".foo must be a number" ,
".bar must not be an instance" , ".baz must implement the IBazzer interface"
.

TODO: the rest of this section is somewhat out of date.

Using the stack instead of a single Taster object means that the rules can be
changed depending upon the context of the object being processed. A class
that is valid as the first argument to a method call may not be valid as the
second argument, or inside a list provided as the first argument. The
PBMethodArgumentsUnslicer could change the way its .taste method behaves as
its state machine progresses through the argument list.

There are several different ways to implement this Taster stack:

- Each object in the Unslicer stack gets to raise an exception if they don't
  like what they see: unanimous consent is required to let the token or
  object pass
- The top-most unslicer is asked, and it has the option of asking the next
  slice down. It might not, allowing local "I'm sure this is safe" classes to
  override higher-level paranoia.
- Unslicer objects may add and remove Taster objects on a separate stack.
  This is undoubtedly faster but must be done carefully to make sure Tasters
  and Unslicers stay in sync.

Of course, all this holds true for the sending side as well. A Slicer could
enforce a policy that no objects of type Foo will be sent while it is on the
stack.

It is anticipated that something like the current Jellyable/Unjellyable
classes will be created to offer control over the Slicer/Unslicers used to
handle instance of that class.

One eventual goal is to allow PB to implement E-like argument constraints.

Streaming Slices
~~~~~~~~~~~~~~~~

The big change from the old Jelly scheme is that now
serialization/unserialization is done in a more streaming format. Individual
tokens are the basic unit of information. The basic tokens are just numbers
and strings: anything more complicated (starting at lists) involves
composites of other tokens.

Producer/Consumer-oriented serialization means that large objects which can't
fit into the socket buffers should not consume lots of memory, sitting around
in a serialized state with nowhere to go. This must be balanced against the
confusion caused by time-distributed serialization. PB method calls must
retain their current in-order execution, and it must not be possible to
interleave serialized state (big mess). One interesting possibility is to
allow multiple parallel SlicerStacks, with a context-switch token to let the
receiving end know when they should switch to a different UnslicerStack. This
would allow cleanly interleaved streams at the token level. "Head-of-line
blocking" is when a large request prevents a smaller (quicker) one from
getting through: grocery stores attempt to relieve this frustration by
grouping customers together by expected service time (the express lane).
Parallel stacks would allow the sender to establish policies on immediacy
versus minimizing context switches.

CBanana, CBananaRun, RunBananaRun
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Another goal of the Jelly+Banana->JustBanana change is the hope of writing
Slicers and Unslicers in C. The CBanana module should have C objects (structs
with function pointers) that can be looked up in a registry table and run to
turn python objects into tokens and vice versa. This ought to be faster than
running python code to implement the slices, at the cost of less flexibility.
It would be nice if the resulting tokens could be sent directly to the socket
at the C level without surfacing into python; barring this it is probably a
good idea to accumulate the tokens into a large buffer so the code can do a
few large writes instead of a gazillion small ones.

It ought to be possible to mix C and Python slices here: if the C code
doesn't find the slice in the table, it can fall back to calling a python
method that does a lookup in an extensible registry.

Beyond Banana
-------------

Random notes and wild speculations: take everything beyond here with *two*
grains of salt

Oldbanana usage
~~~~~~~~~~~~~~~

The oldbanana usage model has the layer above banana written in one of two
ways. The simple form is to use the ``banana.encode`` and ``banana.decode``
functions to turn an object into a bytestream. This is used by
twisted.spread.publish . The more flexible model is to subclass Banana. The
largest example of this technique is, of course, twisted.spread.pb.Broker,
but others which use it are twisted.trial.remote and twisted.scripts.conch
(which appears to use it over unix-domain sockets).

Banana itself is a Protocol. The Banana subclass would generally override the
``expressionReceived`` method, which receives s-expressions (lists of lists).
These are processed to figure out what method should be called, etc
(processing which only has to deal with strings, numbers, and lists). Then
the serialized arguments are sent through Unjelly to produce actual objects.

On output, the subclass usually calls ``self.sendEncoded`` with some set of
objects. In the case of PB, the arguments to the remote method are turned
into s-expressions with jelly, then combined with the method meta-data
(object ID, method name, etc), then the whole request is sent to
``sendEncoded`` .

Newbanana
~~~~~~~~~

Newbanana moves the Jelly functionality into a stack of Banana Slices, and
the lowest-level token-to-bytestream conversion into the new Banana object.
Instead of overriding ``expressionReceived`` , users could push a different
root Unslicer. to get more control over the receive process.

Currently, Slicers call Banana.sendOpen/sendToken/sendClose/sendAbort, which
then creates bytes and does transport.write .

To move this into C, the transport should get to call CUnbanana.receiveToken
There should be CBananaUnslicers. Probably a parent.addMe(self) instead of
banana.stack.append(self), maybe addMeC for the C unslicer.

The Banana object is a Protocol, and has a dataReceived method. (maybe in
some C form, data could move directly from a CTransport to a CProtocol). It
parses tokens and hands them to its Unslicer stack. The root Unslicer is
probably created at connectionEstablished time. Subclasses of Banana could
use different RootUnslicer objects, or the users might be responsible for
setting up the root unslicer.

The Banana object is also created with a RootSlicer. Banana.writeToken
serializes the token and does transport.write . (a C form could have CSlicer
objects which hand tokens to a little CBanana which then hands bytes off to a
CTransport).

Doing the bytestream-to-Token conversion in C loses a lot of utility when the
conversion is done token at a time. It made more sense when a whole mess of
s-lists were converted at once.

All Slicers currently have a Banana pointer.. maybe they should have a
transport pointer instead? The Banana pointer is needed to get to top of the
stack.

want to be able to unserialize lists/tuples/dicts/strings/ints ("basic types"
) without surfacing into python. want to deliver the completed object to a
python function.

Streaming Methods
~~~~~~~~~~~~~~~~~

It would be neat if a PB method could indicate that it would like to receive
its arguments in a streaming fashion. This would involve calling the method
early (as soon as the objectID and method name were known), then somehow
feeding objects to it as they arrive. The object could return a handler or
consumer sub-object which would be fed as tokens arrive over the wire. This
consumer should have a way to enforce a constraint on its input.

This consumer object sounds a lot like an Unslicer, so maybe the method
schema should indicate that the method will would like to be called right
away so it can return an Unslicer to be pushed on the stack. That Unslicer
could do whatever it wanted with the incoming tokens, and could enforce
constraints with the usual checkToken/doOpen/receiveChild/receiveClose
methods.

On the sending side, it would be neat to let a callRemote() invocation
provide a Producer or a generator that will supply data as the network buffer
becomes available. This could involve pushing a Slicer. Slicers are
generators.

Common token sequences
----------------------

Any given Banana instance has a way to map objects to the Open Index tuples
needed to represent them, and a similar map from such tuples to incoming
object factories. These maps give rise to various "classes" of objects,
depending upon how widespread any particular object type is. A List is a
fairly common type of object, something you would expect to find implemented
in pretty much any high-level language, so you would expect a Banana
implementation in that language to be capable of accepting an (OPEN, 'list')
sequence. However, a Failure object (found in ``twisted.python.failure`` ,
providing an asynchronous-friendly way of reporting python exceptions) is
both Python- and Twisted- specific. Is it reasonable for one program to emit
an (OPEN, 'failure') sequence and expect another speaker of the generic
"Banana" protocol to understand it?

This level of compatibility is (somewhat arbitrarily) named "dialect
compatibility" . The set of acceptable sequences will depend upon many
things: the language in which the program at each end of the wire is
implemented, the nature of the higher-level software that is using Banana at
that moment (PB is one such layer), and application-specific registrations
that have been performed by the time the sequence is received (the set of
``pb.Copyable`` sequences that can be received without error will depend upon
which ``RemoteCopyable`` class definitions and ``registerRemoteCopy`` calls
have been made).

Ideally, when two Banana instances first establish a connection, they will go
through a negotiation phase where they come to an agreement on what will be
sent across the wire. There are two goals to this negotiation:

#. least-surprise: if one side cannot handle a construct which the other
   side might emit at some point in the future, it would be nice to know
   about it up front rather than encountering a Violation or
   connection-dropping BananaError later down the line. This could be
   described as the "strong-typing" argument. It is important to note
   that different arguments (both for and against strong typing) may exist
   when talking about remote interfaces rather than local ones.
#. adapability: if one side cannot handle a newer construct, it may be
   possible for the other side to back down to some simpler variation without
   too much loss of data.

Dialect negotiation is a very much still an active area of development.

Base Python Types
~~~~~~~~~~~~~~~~~

The basic python types are considered "safe" : the code which is invoked by
their receipt is well-understood and there is no way to cause unsafe behavior
during unserialization. Resource consumption attacks are mitigated by
Constraints imposed by the receiving schema.

Note that the OPEN(dict) slicer is implemented with code that sorts the list
of keys before serializing them. It does this to provide deterministic
behavior and make testing easier.

+----------------------------+-------------------------------------------------+
| IntType, LongType (small+) | INT(value)                                      |
+----------------------------+-------------------------------------------------+
| IntType, LongType (small-) | NEG(value)                                      |
+----------------------------+-------------------------------------------------+
| IntType, LongType (large+) | LONGINT(value)                                  |
+----------------------------+-------------------------------------------------+
| IntType, LongType (large-) | LONGNEG(value)                                  |
+----------------------------+-------------------------------------------------+
| FloatType                  | FLOAT(value)                                    |
+----------------------------+-------------------------------------------------+
| StringType                 | STRING(value)                                   |
+----------------------------+-------------------------------------------------+
| StringType (tokenized)     | VOCAB(tokennum)                                 |
+----------------------------+-------------------------------------------------+
| UnicodeType                | OPEN(unicode) STRING(str.encode('UTF-8')) CLOSE |
+----------------------------+-------------------------------------------------+
| ListType                   | OPEN(list) elem.. CLOSE                         |
+----------------------------+-------------------------------------------------+
| TupleType                  | OPEN(tuple) elem.. CLOSE                        |
+----------------------------+-------------------------------------------------+
| DictType, DictionaryType   | OPEN(dict) (key,value).. CLOSE                  |
+----------------------------+-------------------------------------------------+
| NoneType                   | OPEN(none) CLOSE                                |
+----------------------------+-------------------------------------------------+
| BooleanType                | OPEN(boolean) INT(0/1) CLOSE                    |
+----------------------------+-------------------------------------------------+

Extended (unsafe) Python Types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To serialize arbitrary python object graphs (including instances) requires
that we allow more types in. This begins to get dangerous: with complex
graphs of inter-dependent objects, instances may need to be used (by
referencing objects) before they are fully initialized. A schema can be used
to make assertions about what object types live where, but in general the
contents of those objects are difficult to constrain.

For this reason, these types should only be used in places where you trust
the creator of the serialized stream (the same places where you would be
willing to use the standard Pickle module). Saving application state to disk
and reading it back at startup time is one example.

+--------------+------------------------------------------------------+
| InstanceType | OPEN(instance) STRING(reflect.qual(class))           |
|              | (attr,value).. CLOSE                                 |
+--------------+------------------------------------------------------+
| ModuleType   | OPEN(module) STRING(__name__) CLOSE                  |
+--------------+------------------------------------------------------+
| ClassType    | OPEN(class) STRING(reflect.qual(class)) CLOSE        |
+--------------+------------------------------------------------------+
| MethodType   | OPEN(method) STRING(__name__) im_self im_class CLOSE |
+--------------+------------------------------------------------------+
| FunctionType | OPEN(function) STRING(module.__name__) CLOSE         |
+--------------+------------------------------------------------------+

PB Sequences
~~~~~~~~~~~~

See the "specifications/pb" document for details.

Unhandled types
~~~~~~~~~~~~~~~

The following types are not handled by any slicer, and will raise a KeyError
if one is referenced by an object being sliced. This technically imposes a
limit upon the kinds of objects that can be serialized, even by a "unsafe"
serializer, but in practice it is not really an issue, as many of these
objects have no meaning outside the program invocation which created them.

- - types that might be nice to have
- ComplexType
- SliceType
- TypeType
- XRangeType
- - types that aren't really that useful
- BufferType
- BuiltinFunctionType
- BuiltinMethodType
- CodeType
- DictProxyType
- EllipsisType
- NotImplementedType
- UnboundMethodType
- - types that are meaningless outside the creator
- TracebackType
- FileType
- FrameType
- GeneratorType
- LambdaType

Unhandled (but don't worry about it) types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``ObjectType`` is the root class of all other types. All objects are known by
some other type in addition to ``ObjectType`` , so the fact that it is not
handled explicitly does not matter.

``StringTypes`` is simply a list of ``StringType`` and ``UnicodeType`` , so
it does not need to be explicitly handled either.

Internal types
~~~~~~~~~~~~~~

The following sequences are internal.

The OPEN(vocab) sequence is used to update the forward compression
token-to-string table used by the VOCAB token. It is followed by a series of
number/string pairs. All numbers that appear in VOCAB tokens must be
associated with a string by appearing in the most recent OPEN(vocab)
sequence.

+------------+----------------------------------+
| vocab dict | OPEN(vocab) (num,string).. CLOSE |
+------------+----------------------------------+
