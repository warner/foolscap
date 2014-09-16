<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Foolscap Logging Formats</title>
<link href="stylesheet-unprocessed.css" type="text/css" rel="style" />
</head>

<body>
<h1>Foolscap Logging Formats</h1>

<p>This document describes the Foolscap logging format. Foolscap logging uses
event dictionaries in memory. Certain tools will serialize these events onto
disk. These on-disk files may have additional metadata stored in adjunct
index files. This document describes the formats of all these objects.</p>

<h2>Events</h2>

<p>Each call to <code>log.msg</code> produces an <b>event</b>. These events
are stored in memory as dictionaries, with the following keys:</p>

<ul>
  <li><code>num</code> (integer): this defines a full ordering of events
  within a single invocation of a program. The counter that produces these is
  maintained in the singleton <code>FoolscapLogger</code> instance known as
  <code>log.theLogger</code>. </li>

  <li><code>time</code> (float): the time at which <code>log.msg</code> was
  called.</li>

  <li><code>incarnation</code> (pair of binary strings or Nones): the
  "incarnation record", used to distinguish between distinct invocations of
  the same program/Tub. Each time the program is started, it gets a distinct
  incarnation record. The IR contains a (unique, sequential) tuple of values.
  'unique' is a random binary string. At present, 'sequential' is always
  None. In a future release, Tubs which are given persistent storage will use
  an incrementing integer as 'sequential', to allow total ordering of events
  from multiple incarnations. Without 'sequential', events from one
  invocation of the program cannot be reliably sorted with respect to events
  from other invocations (except by timestamp, which depends upon comparable
  clocks).</li>

  <li><code>level</code> (integer): the severity level of the event. These
  are typically obtained by using one of the pre-defined constants like
  <code>log.NOISY</code> (10), <code>log.WEIRD</code> (30), or
  <code>log.BAD</code> (40). The default value is
  <code>log.OPERATIONAL</code> (20). </li>

  <li><code>facility</code> (string, optional): a facility name, like
  <code>foolscap.negotiation</code>. Strings are unconstrained, but foolscap
  tools are designed to treat the facility as a big-endian period-separated
  hierarchical list, i.e. <code>foolscap.negotiation</code> and
  <code>foolscap.promises</code> would be related. One such tool would be the
  <code>flogtool filter --strip-facility "foolscap"</code> command. </li>

  <li><code>message</code> (string, optional): the logged message. The first
  positional argument to <code>log.msg</code> will be stored here. All
  messages will either have <code>["message"]</code> or
  <code>["format"]</code>. </li>

  <li><code>format</code> (string, optional): a printf-style format
  specification string for the message. When the message is turned into a
  string, the event dictionary will be used for the string format operation,
  so <code>log.msg(format="%(count)d apples", count=4)</code> is a more
  structured way to say <code>log.msg("%d apples" % count)</code>. By using
  <code>format=</code> and delaying string interpolation until later,
  log-analysis tools will have more information to work with. </li>

  <li><code>isError</code> (integer, optional): <code>log.err</code> will set
  this to 1. <code>log.msg</code> will not set this. This is a simple test to
  see which entry point was used to record the message. </li>

  <li><code>failure</code> (Failure instance, optional): if
  <code>["failure"]</code> is present, formatting tools will render a brief
  traceback. The first positional argument to <code>log.err</code> will be
  stored here. </li>

  <li><code>stacktrace</code> (list of strings, optional): if
  <code>log.msg</code> is called with <code>stacktrace=True</code>, then
  <code>traceback.format_stack()</code> will be used to generate a stack
  trace string, storing it in this key. </li>
  
</ul>

<p>In addition to these keys, all other keyword arguments to the
<code>log.msg</code> and <code>log.err</code> calls are recorded in the event
dictionary. Some keys are reserved: those that begin with an underscore, and
those that are not legal python identifiers (i.e. they contain dots). Some of
these reserved keys are used for internal purposes.</p>

<p>Developers are encouraged to store log parameters with keyword arguments
rather than with string interpolation into the <code>message=</code>
argument, so that later analysis/filtering tools can take advantage of it.
For example, if you use this:</p>

<pre class="python">
log.msg(format="Uploading %(size)d byte file", size=SIZE)
</pre>

<p>instead of:</p>

<pre class="python">
log.msg("Uploading %d byte file" % SIZE)
</pre>

<p>Then later, you can write a filter expression that can do:</p>

<pre class="python">
def _big_uploads(e):
    return bool(e["format"] == "Uploading %(size)d byte file" and
                e["size"] > 1000)
subset = filter(_big_uploads, all_events)
</pre>

<p>Other tools will be provided in the future to make this more concise. This
also makes it easier to write filtering expressions that can be serialized
and sent over the wire, so that <code>flogtool tail</code> can subscribe to a
narrowly-defined subset of events, rather than to everything.</p>

<h2>Logfiles</h2>

<p>Several foolscap logging tools will record a sequence of events to disk:
<code>flogtool tail --save-to FILENAME</code> and the gatherer created by
<code>flogtool create-gatherer</code> are two of them.</p>

<p>These tools know about two file formats, compressed and uncompressed. If
the filename ends in <code>.bz2</code>, then the file is opened with the
<code>bzip</code> module, but otherwise treated exactly like the uncompressed
form. No support is provided for gzip or other compression schemes.</p>

<p>The uncompressed save-file format contains a sequence of pickled "received
event wrapper dictionaries". Each wrapper dict is pickled separately, such
that code which wants to iterate over the contents needs to call
<code>pickle.load(f)</code> repeatedly (this enables streaming
processing).</p>

<p>The wrapper dictionary is used to record some information that is not
stored in the event dictionary itself, sometimes because it is the same for
long runs of events from a single source (like the tubid that generated the
event). (TODO: some of this split is arbitrary and historical, and ought to
be cleaned up). The wrapper dictionary contains the following keys:</p>

<ul>
  <li><code>from</code> (base32 string): the TubID that recorded the
  event. </li>

  <li><code>d</code> (dictionary): the event dictionary defined above. </li>
  
  <li><code>rx_time</code> (float): the time at which the recipient (e.g.
  <code>flogtool tail</code>) received the event. If the generator and the
  recipient have synchronized clocks, then a significant delta between
  <code>e["rx_time"]</code> and <code>e["d"]["time"]</code> indicates delays
  in the event publishing process, possibly the result of reactor or network
  load. </li>

</ul>


<h2>Logfile Headers</h2>

<p>The first wrapper dict in the logfile may be special: it contains
<b>headers</b>. This header dict is distinguished by the fact that it does
not contain a <code>["d"]</code> member. Instead, it contains a
<code>["header"]</code> member. The tools which iterate over events in
logfiles know to ignore the wrapper dicts which lack a <code>["d"]</code>
key.</p>

<p>On the other hand, the first wrapper dict might be a regular event. Older
versions of foolscap (0.2.5 and earlier) did not produce header dicts. Tools
which process logfiles must tolerate the lack of a header dict.</p>

<p>The header dict allows the logfile to be used for various purposes,
somewhat open-ended to allow for future extensions.</p>

<p>All header dicts contain a key named <code>type</code> that describe the
purpose of the logfile. The currently assigned values for type are:</p>

<ul>
  <li><code>log-file-observer</code>: this indicates that the logfile was
  created by a <code>LogFileObserver</code> instance, for example the one
  created when the <code>FLOGFILE=out.flog</code> environment variable is
  used. </li>

  <li><code>tail</code>: this indicates that the logfile was created by the
  <code>--save-to</code> option of <code>flogtool tail</code>. </li>

  <li><code>gatherer</code>: the logfile was created by the foolscap
  log-gatherer, for which the <code>flogtool create-gatherer</code> command
  is provided. </li>

  <li><code>incident</code>: the logfile was created by an application
  as part of the incident reporting process. </li>
</ul>

<h3>log-file-observer</h3>

<p>The header dict produced by a <code>LogFileObserver</code> contains the
following additional keys:</p>

<ul>
  <li><code>threshold</code> (int): the severity threshold that was used for
  this logfile: no events below the threshold will be saved. </li>
</ul>

<p>Also note that the wrapper dicts recorded by the
<code>LogFileObserver</code> will use a "from" value of "local", instead of a
particular TubID, since these events are not recorded through a path that
uses any specific Tub.</p>

<h3>flogtool tail</h3>

<p>The header dict produced by <code>flogtool tail</code> contains the
following additional keys:</p>

<ul>
  <li><code>pid</code> (int): if present, this value contains the process id
  of the process which was being followed by 'flogtool tail'.</li>

  <li><code>versions</code> (dict): this contains a dictionary of component
  versions, mapping a string component name like "foolscap" to a version
  string.</li>
</ul>

<h3>log-gatherer</h3>

<p>The header dict produced by the flogtool log-gatherer contains the
following additional keys:</p>

<ul>
  <li><code>start</code> (float): the time at which this logfile was first
  opened. </li>
</ul>

<h3>Incident Reports</h3>

<p>An <b>Incident Report</b> is a logfile that was recorded because of an
important triggering event: a dump of the short-term history buffers that
saves the activity of the application just prior to the trigger. It can also
contain some number of subsequent events, to record recovery efforts or
additional information that is logged after the triggering event.</p>

<p>Incident Reports are distinguished by their header type:
<code>e["header"]["type"]=="incident"</code>. Their header dicts contain the
following additional keys:</p>

<ul>
  <li><code>trigger</code> (event dict): a copy of the event which triggered
  the incident. This event will also be present somewhere in the rest of the
  logfile, at its normal position in the event stream. </li>

  <li><code>pid</code> (int): this value contains the process id of the
  process which experienced the incident.</li>

  <li><code>versions</code> (dict): this contains a dictionary of component
  versions, mapping a string component name like "foolscap" to a version
  string.</li>
</ul>


<h2>Index Files</h2>

<p>No index files have been defined yet. The vague idea is that each logfile
could contain a summary in an index file of the same name (but with an extra
.index suffix). This index would be used by other tools to quickly identify
what is inside the main file without actually reading the whole contents.</p>

<p>In addition, it may be possible to put a table of offsets into the index
file, to accelerate random-access reads of the main logfile (i.e. put the
offset of every 100 events into the index, reducing the worst-case access
time to two seeks and a read of no more than 100 events). Some sort of
restartable compression could make such an offset table useful for compressed
files as well.</p>

<p>These index files would need to exist as distinct files (rather than as a
header in the main logfile) because they are variable-size and cannot be
generated until after the main logfile is closed. Placing them at the start
of the main logfile would require rewriting or copying the whole file.
Further complications are present when the main logfile is compressed.</p>


</body> </html>
