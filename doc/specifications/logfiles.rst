Foolscap Logging Formats
========================

This document describes the Foolscap logging format. Foolscap logging uses
event dictionaries in memory. Certain tools will serialize these events onto
disk. These on-disk files may have additional metadata stored in adjunct
index files. This document describes the formats of all these objects.

Events
------

Each call to ``log.msg`` produces an **event** . These events are stored in
memory as dictionaries, with the following keys:

- ``num`` (integer): this defines a full ordering of events within a single
  invocation of a program. The counter that produces these is maintained in
  the singleton ``FoolscapLogger`` instance known as ``log.theLogger`` .
- ``time`` (float): the time at which ``log.msg`` was called.
- ``incarnation`` (pair of binary strings or Nones): the "incarnation
  record", used to distinguish between distinct invocations of the same
  program/Tub. Each time the program is started, it gets a distinct
  incarnation record. The IR contains a (unique, sequential) tuple of values.
  'unique' is a random binary string. At present, 'sequential' is always
  None. In a future release, Tubs which are given persistent storage will use
  an incrementing integer as 'sequential', to allow total ordering of events
  from multiple incarnations. Without 'sequential', events from one
  invocation of the program cannot be reliably sorted with respect to events
  from other invocations (except by timestamp, which depends upon comparable
  clocks).
- ``level`` (integer): the severity level of the event. These are typically
  obtained by using one of the pre-defined constants like ``log.NOISY`` (10),
  ``log.WEIRD`` (30), or ``log.BAD`` (40). The default value is
  ``log.OPERATIONAL`` (20).
- ``facility`` (string, optional): a facility name, like
  ``foolscap.negotiation`` . Strings are unconstrained, but foolscap tools
  are designed to treat the facility as a big-endian period-separated
  hierarchical list, i.e. ``foolscap.negotiation`` and ``foolscap.promises``
  would be related. One such tool would be the ``flogtool
  filter --strip-facility "foolscap"`` command.
- ``message`` (string, optional): the logged message. The first positional
  argument to ``log.msg`` will be stored here. All messages will either have
  ``["message"]`` or ``["format"]`` .
- ``format`` (string, optional): a printf-style format specification string
  for the message. When the message is turned into a string, the event
  dictionary will be used for the string format operation, so
  ``log.msg(format="%(count)d apples", count=4)`` is a more structured way to
  say ``log.msg("%d apples" % count)`` . By using ``format=`` and delaying
  string interpolation until later, log-analysis tools will have more
  information to work with.
- ``isError`` (integer, optional): ``log.err`` will set this to 1.
  ``log.msg`` will not set this. This is a simple test to see which entry
  point was used to record the message.
- ``failure`` (Failure instance, optional): if ``["failure"]`` is present,
  formatting tools will render a brief traceback. The first positional
  argument to ``log.err`` will be stored here.
- ``stacktrace`` (list of strings, optional): if ``log.msg`` is called with
  ``stacktrace=True`` , then ``traceback.format_stack()`` will be used to
  generate a stack trace string, storing it in this key.

In addition to these keys, all other keyword arguments to the ``log.msg`` and
``log.err`` calls are recorded in the event dictionary. Some keys are
reserved: those that begin with an underscore, and those that are not legal
python identifiers (i.e. they contain dots). Some of these reserved keys are
used for internal purposes.

Developers are encouraged to store log parameters with keyword arguments
rather than with string interpolation into the ``message=`` argument, so that
later analysis/filtering tools can take advantage of it. For example, if you
use this:

.. code-block:: python

    
    log.msg(format="Uploading %(size)d byte file", size=SIZE)

instead of:

.. code-block:: python

    
    log.msg("Uploading %d byte file" % SIZE)

Then later, you can write a filter expression that can do:

.. code-block:: python

    
    def _big_uploads(e):
        return bool(e["format"] == "Uploading %(size)d byte file" and
                    e["size"] > 1000)
    subset = filter(_big_uploads, all_events)

Other tools will be provided in the future to make this more concise. This
also makes it easier to write filtering expressions that can be serialized
and sent over the wire, so that ``flogtool tail`` can subscribe to a
narrowly-defined subset of events, rather than to everything.

Logfiles
--------

Several foolscap logging tools will record a sequence of events to disk:
``flogtool tail --save-to FILENAME`` and the gatherer created by ``flogtool
create-gatherer`` are two of them.

These tools know about two file formats, compressed and uncompressed. If the
filename ends in ``.bz2`` , then the file is opened with the ``bzip`` module,
but otherwise treated exactly like the uncompressed form. No support is
provided for gzip or other compression schemes.

The uncompressed save-file format contains a sequence of pickled "received
event wrapper dictionaries". Each wrapper dict is pickled separately, such
that code which wants to iterate over the contents needs to call
``pickle.load(f)`` repeatedly (this enables streaming processing).

The wrapper dictionary is used to record some information that is not stored
in the event dictionary itself, sometimes because it is the same for long
runs of events from a single source (like the tubid that generated the
event). (TODO: some of this split is arbitrary and historical, and ought to
be cleaned up). The wrapper dictionary contains the following keys:

- ``from`` (base32 string): the TubID that recorded the event.
- ``d`` (dictionary): the event dictionary defined above.
- ``rx_time`` (float): the time at which the recipient (e.g. ``flogtool
  tail`` ) received the event. If the generator and the recipient have
  synchronized clocks, then a significant delta between ``e["rx_time"]`` and
  ``e["d"]["time"]`` indicates delays in the event publishing process,
  possibly the result of reactor or network load.

Logfile Headers
---------------

The first wrapper dict in the logfile may be special: it contains **headers**
. This header dict is distinguished by the fact that it does not contain a
``["d"]`` member. Instead, it contains a ``["header"]`` member. The tools
which iterate over events in logfiles know to ignore the wrapper dicts which
lack a ``["d"]`` key.

On the other hand, the first wrapper dict might be a regular event. Older
versions of foolscap (0.2.5 and earlier) did not produce header dicts. Tools
which process logfiles must tolerate the lack of a header dict.

The header dict allows the logfile to be used for various purposes,
somewhat open-ended to allow for future extensions.

All header dicts contain a key named ``type`` that describe the
purpose of the logfile. The currently assigned values for type are:

- ``log-file-observer`` : this indicates that the logfile was created by a
  ``LogFileObserver`` instance, for example the one created when the
  ``FLOGFILE=out.flog`` environment variable is used.
- ``tail`` : this indicates that the logfile was created by the ``--save-to``
  option of ``flogtool tail`` .
- ``gatherer`` : the logfile was created by the foolscap log-gatherer, for
  which the ``flogtool create-gatherer`` command is provided.
- ``incident`` : the logfile was created by an application as part of the
  incident reporting process.

log-file-observer
~~~~~~~~~~~~~~~~~

The header dict produced by a ``LogFileObserver`` contains the
following additional keys:

- ``threshold`` (int): the severity threshold that was used for this logfile:
  no events below the threshold will be saved.

Also note that the wrapper dicts recorded by the ``LogFileObserver`` will use
a "from" value of "local", instead of a particular TubID, since these events
are not recorded through a path that uses any specific Tub.

flogtool tail
~~~~~~~~~~~~~

The header dict produced by ``flogtool tail`` contains the following
additional keys:

- ``pid`` (int): if present, this value contains the process id of the
  process which was being followed by 'flogtool tail'.
- ``versions`` (dict): this contains a dictionary of component versions,
  mapping a string component name like "foolscap" to a version string.

log-gatherer
~~~~~~~~~~~~

The header dict produced by the flogtool log-gatherer contains the
following additional keys:

- ``start`` (float): the time at which this logfile was first opened.

Incident Reports
~~~~~~~~~~~~~~~~

An **Incident Report** is a logfile that was recorded because of an important
triggering event: a dump of the short-term history buffers that saves the
activity of the application just prior to the trigger. It can also contain
some number of subsequent events, to record recovery efforts or additional
information that is logged after the triggering event.

Incident Reports are distinguished by their header type:
``e["header"]["type"]=="incident"`` . Their header dicts contain the
following additional keys:

- ``trigger`` (event dict): a copy of the event which triggered the incident.
  This event will also be present somewhere in the rest of the logfile, at
  its normal position in the event stream.
- ``pid`` (int): this value contains the process id of the process which
  experienced the incident.
- ``versions`` (dict): this contains a dictionary of component versions,
  mapping a string component name like "foolscap" to a version string.

Index Files
-----------

No index files have been defined yet. The vague idea is that each logfile
could contain a summary in an index file of the same name (but with an extra
.index suffix). This index would be used by other tools to quickly identify
what is inside the main file without actually reading the whole contents.

In addition, it may be possible to put a table of offsets into the index
file, to accelerate random-access reads of the main logfile (i.e. put the
offset of every 100 events into the index, reducing the worst-case access
time to two seeks and a read of no more than 100 events). Some sort of
restartable compression could make such an offset table useful for compressed
files as well.

These index files would need to exist as distinct files (rather than as a
header in the main logfile) because they are variable-size and cannot be
generated until after the main logfile is closed. Placing them at the start
of the main logfile would require rewriting or copying the whole file.
Further complications are present when the main logfile is compressed.
