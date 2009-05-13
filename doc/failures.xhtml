<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Foolscap Failure Reporting</title>
<style src="stylesheet-unprocessed.css"></style>
</head>

<body>
<h1>Foolscap Failure Reporting</h1>

<h2>Signalling Remote Exceptions</h2>

<p>The <code>remote_</code> -prefixed methods which Foolscap invokes, just
like their local counterparts, can either return a value or raise an
exception. Foolscap callers can use the normal Twisted conventions for
handling asyncronous failures: <code>callRemote</code> returns a Deferred
object, which will eventually either fire its callback function (if the
remote method returned a normal value), or its errback function (if the
remote method raised an exception).</p>

<p>There are several reasons that the Deferred returned
by <code>callRemote</code> might fire its errback:</p>

<ul>
 <li>local outbound schema violation: the outbound method arguments did not
     match the <code>RemoteInterface</code> that is in force. This is an
     optional form of typechecking for remote calls, and is activated when
     the remote object describes itself as conforming to a named
     <code>RemoteInterface</code> which is also declared in a local class.
     The local constraints are checked before the message is transmitted over
     the wire. A constraint violation is indicated by
     raising <code>foolscap.schema.Violation</code>, which is delivered
     through the Deferred's errback.</li>
 <li>network partition: if the underlying TCP connection is lost before the
     response has been received, the Deferred will errback with
     a <code>foolscap.ipb.DeadReferenceError</code> exception. Several things
     can cause this: the remote process shutting down (intentionally or
     otherwise), a network partition or timeout, or the local process
     shutting down (<code>Tub.stopService</code> will terminate all
     outstanding remote messages before shutdown).</li>
 <li>remote inbound schema violation: as the serialized method arguments were
     unpacked by the remote process, one of them violated that processes
     inbound <code>RemoteInterface</code>. This check serves to protect each
     process from incorrect types which might either confuse the subsequent
     code or consume a lot of memory. These constraints are enforced as the
     tokens are read off the wire, and are signalled with the
     same <code>Violation</code> exception as above (but this may be wrapped
     in a <code>RemoteException</code>: see below).</li>
 <li>remote method exception: if the <code>remote_</code> method raises an
     exception, or returns a Deferred which subsequently fires its errback,
     the remote side will send the caller that an exception occurred, and may
     attempt to provide some information about this exception. The caller
     will see an errback that may or may not attempt to replicate the remote
     exception. This may be wrapped in a <code>RemoteException</code>. See
     below for more details.</li>
 <li>remote outbound schema violation: as the remote method's return value is
     serialized and put on the wire, the values are compared against the
     return-value constraint (if a <code>RemoteInterface</code> is in
     effect). If it does not match the constraint, a Violation will be raised
     (but may be wrapped in a <code>RemoteException</code>).</li>
 <li>local inbound schema violation: when the serialized return value arrives
     on the original caller's side of the wire, the return-value constraint
     of any effective <code>RemoteInterface</code> will be applied. This
     protects the caller's response code from unexpected values. Any
     mismatches will be signalled with a Violation exception.</li>
</ul>

<h2>Distinguishing Remote Exceptions</h2>

<p>When a remote call fails, what should you do about it? There are several
factors to consider. Raising exceptions may be part of your remote API:
easy-to-use exceptions are a big part of Python's success, and Foolscap
provides the tools to use them in a remote-calling environment as well.
Exceptions which are not meant to be part of the API frequently indicate
bugs, sometimes as precondition assertions (of which schema Violations are a
subset). It might be useful to react to the specific type of remote
exception, and/or it might be important to log as much information as
possible so a programmer can find out what went wrong, and in either case it
might be appropriate to react by falling back to some alternative code
path.</p>

<p>Good debuggability frequently requires at least one side of the connection
to get lots of information about errors that indicate possible bugs. Note
that the <code>Tub.setOption("logLocalFailures", True)</code>
and <code>Tub.setOption("logRemoteFailures", True)</code> options are
relevant: when these options are enabled, exceptions that are sent over the
wire (in one direction or the other) are recorded in the Foolscap log stream.
If you use exceptions as part of your regular remote-object API, you may want
to consider disabling both options. Otherwise the logs may be cluttered with
perfectly harmless exceptions.</p>

<p>Should your code pay attention to the details of a remote exception (other
than the fact that an exception happened at all)? There are roughly two
schools of thought:</p>

<ul>
  <li>Distrust Outsiders: assume, like any sensible program which connects to
  the internet, that the entire world is out to get you. Use external
  services to the extent you can, but don't allow them to confuse you or
  trick you into some code path that will expose a vulnerability. Treat all
  remote exceptions as identical.</li>

  <li>"E" mode: treat external code with the same level of trust or distrust
  that you would apply to local code. In the "E" programming language (which
  inspires much of Foolscap's feature set), each object is a separate trust
  domain, and the only distinction made between "local" and "remote" objects
  is that the former may be called synchronously, while the latter may become
  partitioned. Treat remote exceptions just like local ones, interpreting
  their type as best you can.</li>
</ul>

<p>From Foolscap's point of view, what we care about is how to handle
exceptions raised by the remote code. When operating in the first mode,
Foolscap will merge all remote exceptions into a single exception type
named <code>foolscap.api.RemoteException</code>, which cannot be confused
with regular Python exceptions like <code>KeyError</code>
and <code>AttributeError</code>. In the second mode, Foolscap will try to
convert each remote exception into a corresponding local object, so that
error-handling code can catch e.g. <code>KeyError</code> and use it as part
of the remote API.</p>

<p>To tell Foolscap which mode you want to use,
call <code>tub.setOption("expose-remote-exception-types", BOOL)</code>, where
BOOL is either True (for the "E mode") or False (for the "Distrust Outsiders"
mode). The default is True.</p>

<p>In "Distrust Outsiders" mode, a remote exception will cause the caller's
errback handler to be called with a regular <code>Failure</code> object which
contains a <code>foolscap.api.RemoteException</code>, effectively hiding all
information about the nature of the problem except that it was caused by some
other system. Caller code can test for this with <code>f.check</code>
and <code>f.trap</code> as usual. If the caller's code decides to investigate
further, it can use <code>f.value.failure</code> to obtain
the <code>CopiedFailure</code> (see below) that arrived from the remote
system. Note that schema Violations which are caught on the local system are
reported normally, whereas Violations which are caught on the remote system
are reported as RemoteExceptions.</p>

<p>In "E mode", a remote exception will cause the errback handler to be
called with a <code>CopiedFailure</code> object.
This <code>CopiedFailure</code> will behave as much as possible like the
corresponding Failure from the remote side, given the limitations of the
serialization process (see below for details). In particular, if the remote
side raises e.g. a standard Python <code>IndexError</code>, the local side
can use <code>f.trap(IndexError)</code> to catch it. However, this same
f.trap call would also catch locally-generated IndexErrors, which could be
confusing.</p>

<h3>Examples: Distrust Outsiders</h3>

<p>Since Deferreds can be chained, it is quite common to see remote calls
sandwiched in the middle of two (possibly asynchronous) local calls. The
following snippet performs a local processing step, then asks a remote server
for information, then adds that information into a local database. All three
steps are asynchronous.</p>

<pre class="python">
# Example 1
def get_and_store_record(name):
    d = local_db.getIDNumber(name)
    d.addCallback(lambda idnum: rref.callRemote("get_record", idnum))
    d.addCallback(lambda record: local_db.storeRecord(name))
    return d
</pre>

<p>To motivate an examination of error handling, we'll extend this example to
use two separate servers for the record: if one of them doesn't have it, we
ask the other. The first server might raise <code>KeyError</code> to tell us
it can't find the record, or it might experience some other internal error,
or we might lose the connection to that server before it can get us an
answer: all three cases should prompt us to talk to the second server.</p>

<pre class="python">
# Example 2
from foolscap.api import Tub, RemoteException
t = Tub()
t.setOption("expose-remote-exception-types", False) # Distrust Outsiders
...

def get_and_store_record(name):
    d = local_db.getIDNumber(name)
    def get_record(idnum):
        d2 = server1.callRemote("get_record", idnum) # could raise KeyError
        def maybe_try_server2(f):
            f.trap(RemoteException)
            return server2.callRemote("get_record", idnum) # or KeyError
        d2.addErrback(maybe_try_server2)
        return d2
    d.addCallback(get_record)
    d.addCallback(lambda record: local_db.storeRecord(name))
    return d
</pre>

<p>In this example, only a failure that occurs on server1 will cause the code
to attempt to use server2. A locally-triggered error will be trapped by the
first line of <code>maybe_try_server2</code> and will not proceed to the
second <code>callRemote</code>. This allows a more complex control flow like
the following:</p>

<pre class="python">
# Example 3
def get_and_store_record(name):
    d = local_db.getIDNumber(name) # could raise IndexError

    def get_record(idnum):
        d2 = server1.callRemote("get_record", idnum) # or KeyError
        def maybe_try_server2(f):
            f.trap(RemoteException)
            return server2.callRemote("get_record", idnum) # or KeyError
        d2.addErrback(maybe_try_server2)
        return d2
    d.addCallback(get_record)

    d.addCallback(lambda record: local_db.storeRecord(name))

    def ignore_unknown_names(f):
        f.trap(IndexError)
        print "Couldn't get ID for name, ignoring"
        return None
    d.addErrback(ignore_unknown_names)

    def failed(f):
        print "didn't get data!"
        if f.check(RemoteException):
            if f.value.failure.check(KeyError):
                print "both servers claim to not have the record"
            else:
                print "both servers had error"
        else:
           print "local error"
        print "error details:", f
    d.addErrback(failed)

    return d
</pre>

<p>The final <code>failed</code> method will catch any unexpected error: this
is the place where you want to log enough information to diagnose a code bug.
For example, if the database fetch had returned a string, but the
RemoteInterface had declared <code>get_record</code> as taking an integer,
then the <code>callRemote</code> would signal a (local) Violation exception,
causing control to drop directly to the <code>failed()</code> error handler.
On the other hand, if the first server decided to throw a Violation on its
inbound argument, the <code>callRemote</code> would signal a RemoteException
(wrapping a Violation), and control would flow to
the <code>maybe_try_server2</code> fallback.</p>

<p>It is usually best to put the errback as close as possible to the call
which might fail, since this provides the highest "signal to noise ratio"
(i.e. it reduces the number of possibilities that the error-handler code must
handle). But it is frequently more convenient to place the errback later in
the Deferred chain, so it can be useful to distinguish between the
local <code>IndexError</code> and a remote exception of the same type. This
is the same decision that needs to be made with synchronous code: whether to
use lots of <code>try:/except:</code> blocks wrapped around individual method
calls, or to use one big block around a whole sequence of calls. Smaller
blocks will catch an exception sooner, but larger blocks are less effort to
write, and can be more appropriate, especially if you do not expect
exceptions to happen very often.</p>

<p>Note that if this example had used "E mode" and the first remote server
decided (perhaps maliciously) to raise <code>IndexError</code>, then the
client could be tricked into following the same ignore-unknown-names code
path that was meant to be reserved for a local database miss.</p>

<p>To examine the type of failure more closely, the error-handling code
should access the <code>RemoteException</code>'s <code>.value.failure</code>
attribute. By making the following change to <code>maybe_try_server2</code>,
the behavior is changed to only query the second server in the specific case
of a remote <code>KeyError</code>. Other remote exceptions (and all local
exceptions) will skip the second query and signal an error
to <code>failed()</code>. You might want to do this if you believe that a
remote failure like <code>AttributeError</code> is worthy of error-logging
rather than fallback behavior.</p>

<pre class="python">
# Example 4
        def maybe_try_server2(f):
            f.trap(RemoteException)
            if f.value.failure.check(KeyError):
                return server2.callRemote("get_record", idnum) # or KeyError
            return f
</pre>

<p>Note that you should probably not use <code>f.value.failure.trap</code>,
since if the exception type does not match, that will raise the inner
exception (i.e. the <code>KeyError</code>) instead of
the <code>RemoteException</code>, potentially confusing subsequent
error-handling code.</p>


<h3>Examples: E Mode</h3>

<p>Systems which use a lot of remote exceptions as part of their
inter-process API can reduce the size of the remote-error-handling code by
switching modes, at the expense of risking confusion between local and remote
occurrences of the same exception type. In the following example, we use "E
Mode" and look for <code>KeyError</code> to indicate a
remote <code>get_record</code> miss.</p>

<pre class="python">
# Example 5
from foolscap.api import Tub
t = Tub()
t.setOption("expose-remote-exception-types", True) # E Mode
...

def get_and_store_record(name):
    d = local_db.getIDNumber(name)

    def get_record(idnum):
        d2 = server1.callRemote("get_record", idnum) # or KeyError
        def maybe_try_server2(f):
            f.trap(KeyError)
            return server2.callRemote("get_record", idnum) # or KeyError
        d2.addErrback(maybe_try_server2)
        return d2
    d.addCallback(get_record)

    d.addCallback(lambda record: local_db.storeRecord(name))

    def ignore_unknown_names(f):
        f.trap(IndexError)
        print "Couldn't get ID for name, ignoring"
        return None
    d.addErrback(ignore_unknown_names)

    def failed(f):
        print "didn't get data!"
        if f.check(KeyError):
            # don't bother showing details
            print "both servers claim to not have the record"
        else:
            # show details by printing "f", the Failure instance
            print "other error", f
    d.addErrback(failed)

    return d
</pre>

<p>In this example, <code>KeyError</code> is part of the
remote <code>get_record</code> method's API: it either returns the data, or
it raises KeyError, and anything else indicates a bug. The caller explicitly
catches KeyError and responds by either falling back to the second server
(the first time) or announcing a servers-have-no-record error (if the
fallback failed too). But if something else goes wrong, the client indicates
a different error, along with the exception that triggered it, so that a
programmer can investigate.</p>

<p>The remote error-handling code is slightly simpler, relative to the
identical behavior expressed in Example 4,
since <code>maybe_try_server2</code> only needs to
use <code>f.trap(KeyError)</code>, instead of needing to unwrap
a <code>RemoteException</code> first. But when this error-handling code is at
the end of a larger block (such as the <code>f.trap(IndexError)</code>
in <code>ignore_unknown_names()</code>, or the <code>f.check(KeyError)</code>
in <code>failed()</code>), it is vulnerable to confusion:
if <code>local_db.getIDNumber</code> raised <code>KeyError</code> (instead of
the expected <code>IndexError</code>), or if the remote server
raised <code>IndexError</code> (instead of <code>KeyError</code>), then the
error-handling logic would follow the wrong path.</p>

<h3>Default Mode</h3>

<p>Exception modes were introduced in Foolscap-0.4.0 . Releases before that
only offered "E mode". The default in 0.4.0 is "E mode"
(expose-remote-exception-types=True), to retain compatibility with the
exception-handling code in existing applications. A future release of
Foolscap may change the default mode to expose-remote-exception-types=False,
since it seems likely that apps written in this style are less likely to be
confused by remote exceptions of unexpected types.</p>

<h2>CopiedFailures</h2>

<p>Twisted uses the <code>twisted.python.failure.Failure</code> class to
encapsulate Python exceptions in an instance which can be passed around,
tested, and examined in an asynchronous fashion. It does this by copying much
of the information out of the original exception context (including a stack
trace and the exception instance itself) into the <code>Failure</code>
instance. When an exception is raised during a Deferred callback function, it
is converted into a Failure instance and passed to the next errback handler
in the chain.</p>

<p>When <code>RemoteReference.callRemote</code> needs to transport
information about a remote exception over the wire, it uses the same
convention. However, Failure objects cannot be cleanly serialized and sent
over the wire, because they contain references to local state which cannot be
precisely replicated on a different system (stack frames and exception
classes). So, when an exception happens on the remote side of
a <code>callRemote</code> invocation, and the exception-handling mode passes
the remote exception back to the calling code somehow, that code will receive
a <code>CopiedFailure</code> instance instead.</p>

<p>In "E mode", the <code>callRemote</code>'s errback function will receive
a <code>CopiedFailure</code> in response to a remote exception, and will
receive a regular <code>Failure</code> in response to locally-generated
exceptions. In "Distrust Outsiders" mode, the errback will always receive a
regular <code>Failure</code>, but
if <code>f.check(foolscap.api.RemoteException)</code> is True, then
the <code>CopiedFailure</code> can be obtained
with <code>f.value.failure</code> and examined further.</p>

<p><code>CopiedFailure</code> is designed to behave very much like a
regular <code>Failure</code> object. The <code>check</code>
and <code>trap</code> methods work on <code>CopiedFailure</code>s just like
they do on <code>Failure</code>s.</p>

<p>However, all of the Failure's attributes must be converted into strings
for serialization. As a result, the original <code>.value</code> attribute
(which contains the exception instance, which might contain additional
information about the problem) is replaced by a stringified representation,
which tends to lose information. The frames of the original stack trace are
also replaced with a string, so they can be printed but not examined. The
exception class is also passed as a string (using
Twisted's <code>reflect.qual</code> fully-qualified-name utility),
but <code>check</code> and <code>trap</code> both compare by string name
instead of object equality, so most applications won't notice the
difference.</p>

<p>The default behavior of CopiedFailure is to include a string copy of the
stack trace, generated with <code>printTraceback()</code>, which will include
lines of source code when available. To reduce the amount of information sent
over the wire, stack trace strings larger than about 2000 bytes are truncated
in a fashion that tries to preserve the top and bottom of the stack.</p>

<h3>unsafeTracebacks</h3>

<p>Applications which consider their lines of source code or their
exceptions' list of (filename, line number) tuples to be sensitive
information can set the "unsafeTracebacks" flag in their Tub to False; the
server will then remove stack information from the CopiedFailure objects it
sends to other systems.</p>

<pre class="python">
t = Tub()
t.unsafeTracebacks = False
</pre>

<p>When unsafeTracebacks is False, the <code>CopiedFailure</code> will only
contain the stringified exception type, value, and parent class names.</p>

</body>
</html>
