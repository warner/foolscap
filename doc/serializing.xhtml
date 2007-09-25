<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Using Foolscap for Serialization</title>
<style src="stylesheet-unprocessed.css"></style>
</head>

<body>
<h1>Using Foolscap for Serialization</h1>

<p>The same code that Foolscap uses to transport object graphs from one
process to another (over a wire) can be used to transport those graphs from
one process to another (over time). This code serializes an object (and the
other objects it references) into a series of bytes: these bytes can then
either be written to a network socket, or written to a file.</p>

<p>The main difference between the two cases is the way that certain special
objects are represented (and whether they can be represented at all). Inert
data like strings, lists, and numbers are equally serializable.
<code>foolscap.Copyable</code> objects are also serializable. But
<code>foolscap.Referenceable</code> objects only make sense to serialize in
the context of a connection through which <code>callRemote</code> messages
can eventually be sent. So trying to serialize a <code>Referenceable</code>
when the results are going to be written to disk should cause an error.</p>

<p>The way that Foolscap enables the re-use of its serialization code is to
allow it to be called with a different "Root Slicer". This root gets to
decide how all objects are serialized. The Root Slicer for a live Foolscap
connection knows that Referenceables can be serialized with a special marker
that tells the other end of the connection how to construct a corresponding
<code>RemoteReference</code> (one which will be able to send
<code>callRemote</code>s over the connection).</p>

<h2>Serializing to Bytes</h2>

<p>To use Foolscap to serialize an object graph to a big string, use
<code>foolscap.serialize</code>. Note that this returns a Deferred.:</p>

<code class="python">
import foolscap

obj = ["look at the pretty graph", 3, True]
obj.append(obj) # and look at the pretty cycle

d = foolscap.serialize(obj)
d.addCallback(lambda data: foolscap.unserialize(data))
def _check(obj2):
    assert obj2[1] == "3"
    assert obj2[3] is obj2
d.addCallback(_check)
</code>

<p>This form of serialization has the following restrictions:</p>

<ul>
  <li>it can serialize any inert Python type</li>
  <li>it can serialize <code>foolscap.Copyable</code> instances, and any
  other instance that has an ISlicer or ICopyable adapter registered for
  it</li>
  <li>it cannot serialize Referenceables</li>
  <li>it cannot serialize non-Copyable instances</li>
</ul>

<p>These restrictions mean that <code>foolscap.serialize</code> cannot
serialize everything that Python's stdlib <code>pickle</code> module can
handle. However, it is safer (since <code>foolscap.unserialize</code> will
never import or execute arbitrary code like <code>pickle.load</code> will
do), and more extensible (since ISlicer/ICopyable adapters can be registered
for third-party classes).</p>

<h2>Including Referenceables</h2>

<p>To include Referenceables in the serialized data, you must use a Tub to do
the serialization, and the process returns a Deferred rather than running
synchronously:</p>


<code class="python">
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
</code>

<p>For this to work, the first Tub must have a location set on it, so that
you could do <code>registerReference</code>. The first Tub will serialize the
Referenceable with a special marker that the second Tub will be able to use
to establish a connection to the original object. This will only succeed if
the original Tub is still running and still knows about the Referenceable:
think of the embedded marker as a weakref.</p>

</body>
</html>
