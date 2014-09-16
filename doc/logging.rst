Foolscap Logging
================

Foolscap comes with an advanced event-logging package. This package is used
internally to record connection establishment, remote message delivery, and
errors. It can also be used by applications built on top of Foolscap for
their own needs.

This logging package includes a viewer application that processes locally
saved log data or data retrieved over a foolscap connection, and displays a
selected subset of the events. It also includes code to create a web page
inside your application that presents the same kind of log view.

Philosophy
----------

My background is in embedded systems, specifically routers, in which bugs and
unexpected operations happen from time to time, causing problems. In this
environment, storage space is at a premium (most routers do not have hard
drives, and only a limited amount of RAM and non-volatile flash memory), and
devices are often deployed at remote sites with no operator at the console.
Embedded devices are expected to function properly without human
intervention, and crashes or other malfunctions are rare compared to
interactive applications.

In this environment, when an error occurs, it is a good idea to record as
much information as possible, because asking the operator to turn on extra
event logging and then try to re-create the failure is only going to make the
customer more angry ("my network has already broken once today, you want me
to intentionally break it again?"). That one crash is the only chance you
have to learn about the cause.

In addition, as new features are being developed (or completed ones are being
debugged), it is important to have visibility into certain internal state.
Extra logging messages are added to illuminate this state, sometimes
resulting in hundreds of messages per second. These messages are useful only
while the problem is being investigated. Since most log formats involve flat
text files, lots of additional log messages tend to obscure important things
like unhandled exceptions and assertion failures, so once the messages have
outlived their usefulness they are just getting in the way. Each message
costs a certain amount of human attention, so we are motiviated to minimize
that cost by removing the unhelpful messages.

Logging also gets removed because it consumes CPU time, disk IO, disk space,
or memory space. Many operations that can be done in linear time can expand
to super-linear time if additional work is required to log the actions taking
place, or the current state of the program.

As a result, many formerly-useful log messages are commented out once they
have served their purpose. Having been disabled, the cost to re-enable them
if the bug should resurface is fairly high: at the very least it requires
modifying the source code and restarting the program, and for some languages
requires a complete recompile/rebuild. Even worse, to keep the source code
readable, disabled log messages are frequently deleted altogether. After many
months it may not be obvious where the log messages should be put back, and
developers will need to re-acquaint themselves with the code base to find
suitable places for those messages.

To balance these costs, developers try to leave enough log messages in place
that unexpected events will be captured with enough detail to start
debugging, but not so many that it impacts performance or a human's ability
to spot problems while scanning the logs. But it would be nice if certain log
messages could be disabled or disregarded in a way that didn't abandon all of
the work that went into developing and placing them.

Memory-limited, strangeness-triggered log dumping
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each potential log message could be described (to a human) as being useful in
a particular set of circumstances. For example, if the program tried to read
from a file and got a permission-denied error, it would be useful to know
which file it was trying to read from, and how it came to decide upon that
particular filename, and what user command was responsible for triggering
this action. If a protocol parser which implements a state machine finds
itself in an invalid state, it would be useful to know what series of input
messages had arrived recently, to work backwards to the place where things
started to go awry.

Flip this around and you can phrase it as: the filename we compute will be
interesting only if we get an error when we finally try to access it.
Likewise, the series of input messages **would** be interesting to know if,
at some point in the near future, an invalid protocol state is reached.

The thing to note about these patterns is that an event at time T **causes**
events before time T to become interesting. Interesting messages are worth
keeping (and storing, and examining). Non-interesting messages are not worth
as much, but there are different kinds of costs, and as the message becomes
less interesting (or loses the potential to become interesting), we want to
lower our costs. Displaying a message to a human is pretty expensive, since
it tends to obscure other, more important messages. Storing messages is less
expensive, depending upon how long we expect to store them (and how much
storage space is available). Generating messages may be expensive or cheap,
depending upon their frequency and complexity.

Foolscap's logging library seeks to capture this ex-post-facto
interestingness by categorizing messages into "severity levels", recording
each level into a separate size-limited circular buffer, and provoking a dump
of all buffers when an "Incident" occurs. An "Incident Qualifier" is used to
classify certain higher-severity events as worthy of triggering the log dump.
The idea is that, at any given time, we have a record (in memory) of a lot of
low-frequency important things (like program startup, user actions, and
unhandled exceptions), and only the most recent high-frequency events
(verbose debugging data). But, if something strange happens, we dump
everything we've got to disk, because it is likely that some of these noisy
high-frequency not-normally-interesting events will be helpful to track down
the cause of the unusual event. The viewing tools then rearrange all of these
events into a linear order, and make it easy to filter out events by severity
level or origin.

Each severity level is (roughly) inversely proportional to a message rate.
Assertion checks in code are in the "this should never happen" category, and
their resulting low expected rate puts them in a high-severity level. Routine
actions are expected to happen all the time, which puts them into a
low-severity level.

(you might think of severity as a separate axis than frequency. Severity
would mean "how much damage will this cause". Frequency equals cost,
controlling how long we keep the message around in the hopes of it becoming
interesting. But things which cause a lot of damage should not be happening
very frequently, and things which happen frequently must not cause a lot of
damage. So these axes are sufficiently aligned for us to use just a single
parameter for now.)

Structured Logging
~~~~~~~~~~~~~~~~~~

The usual approach to event logging involves a single file with a sequence of
lines of text, new events being continually appended at the end, perhaps with
the files being rotated once they become too large or old. Typically the
source code is peppered with lines like:

.. code-block:: python

    
    log.msg(text)
    Log.Log(source, facility, severity, text)
    log.log_stacktrace()
    log.err(failure)

Each such function call adds some more text to the logfile, encoding the
various parameters into a new line.

Using a text-based file format enables the use of certain unix tools like
'grep' and 'wc' to analyze the log entries, but frequently inhbits the use of
more complex tools because they must first parse the human-readable lines
back into the structured arguments that were originally passed to the log()
call. Frequently, the free-form text portion of the log cannot be reliably
distinguished from the stringified metadata (the quoting issue), making
analysis tools more difficult to write. In addition, the desire to make both
logfiles and the generating source code more greppable is occasionally at
odds with clean code structure (putting everything on a single line) or
refactoring goals (sending all logging for a given module through a common
function).

The Foolscap log system uses binary logfiles that accurately and reversibly
serialize all the metadata associated with a given event. Tools are provided
to turn this data into a human-readable greppable form, but better tools are
provided to perform many of the same tasks that 'grep' is typically used for.
For example, a log viewer can apply a python expression to each event as a
filter, and the expression can do arbitrary comparison of event parameters
(e.g. "show me all events related to failing uploads of files larger than
20MB").

To accomplish this, all unrecognized keyword arguments to the ``log.msg``
call are recorded as additional keys in the log event. To encourage
structured usage, the message string be provided as a format specifier
instead of a pre-interpolated string, using the keyword args as a formatting
dictionary. Any time the string is displayed to a human, the keyword args are
interpolated into the format string first.

(in compiled languages, it would be useful and cheap to embed the source file
and line number of the log() call inside the log event. Unfortunately, in
Python, this would require expensive stack crawling, so developers are
generally stuck with grepping for the log message in their source tree to
backtrack from a log message to the code that generated it)

Remote log aggregation
~~~~~~~~~~~~~~~~~~~~~~

Code is provided to allow a Foolscap-based application to easily publish a
'logport': an object which providers remote callers with access to that
application's accumulated log data. Events are delivered over a secure
Foolscap connection, to prevent eavesdroppers from seeing sensitive data
inside the log messages themselves. This can be useful for a developer who
wants to find out what just happened inside a given application, or who is
about to do something to the application and wants to see how it responds
from the inside. The ``flogtool tail`` tool is provided for this job.

Each Tub always activates a logport, and a Tub option makes it possible to
use a persistent FURL for remote access.

(TODO: really?) The log-viewer application can either read log data from a
local log directory, or it can connect to the logport on a remote host.

A centralized "log gatherer" program can connect to multiple logports and
aggregate all the logs collected from each, similar to the unix 'syslog'
facility. This is most useful when the gatherer is configured to store more
messages than the applications (perhaps it stores all of them), since it
allows the costs to be shifted to a secondary machine with extra disk and
fewer CPU-intensive responsibilities.

To facilitate this, each Tub can either be given the FURL of a Log Gatherer,
or the name of a file that might contain this FURL. This makes deployment
easier: just copy the FURL of your central gatherer into this file in each of
your application's working directories.

A basic log gatherer is created by running ``flogtool create-gatherer`` and
giving it a storage directory: this emits a gatherer FURL that can be used in
the app configuration, and saves all incoming log events to disk.

Causality Tracing
~~~~~~~~~~~~~~~~~

Log messages correspond to events. Events are triggered by other events.
Sometimes the relationship between events is visible to the local programmer,
sometimes it involves external hosts that can confuse the relationships.

For local "application-level" causality, Foolscap's logging system makes it
possible to define hierarchies of log events. Each call to ``log.msg``
returns an identifier (really just a number). If you pass this same
identifier into a later ``log.msg`` call as the``parent=`` parameter, that
second message is said to be a "child" of the first. This creates multiple
trees of log events, in which the tree tops are the parentless messages. For
example, a user command like "copy this file" could be a top-level event,
while the various steps involved in copying the file (compute source
filename, open source file, compute target filename, open target file, read
data, write data, close) would be children of that top-level event.

The viewer application has a way to hide or expand the nodes of these trees,
to make it easy to look at just the messages that are related to a specific
action. This lets you prioritize events along both severity (is this a common
event?) and relevance (is this event related to the one of interest?)

In the future, Foolscap's logging system will be enhanced to offer tools for
analyzing causality relationships between multiple systems, taking
inspiration from the E `Causeway
<http://www.erights.org/elang/tools/causeway/index.html>`_ debugger. In this
system, when one Tub sends a message to another, enough data is logged to
enable a third party (with access to all the logs) to figure out the set of
operations that were **caused** by the first message. Each message send is
recorded, with an index that includes the TubID, current event number, and
stack trace. Event A on tub 1 triggers event B on tub 2, along with certain
operations and log messages. Event B triggers further operations, etc.

The viewer application will offer a causality-oriented view in addition to
the temporal one.

Using Foolscap Logging
----------------------

The majority of your application's interaction with the Foolscap logging
system will be in the form of calls to its ``log.msg`` function.

Logging Messages From Application Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To emit log messages from application code, just use the ``foolscap.log.msg``
function:

.. code-block:: python

    
    from foolscap.logging import log
    
    log.msg("hello world")

You can add arguments that will be lazily evaluated and stringified by
treating the log message as a normal format string:

.. code-block:: python

    
    log.msg("queue depth %d exceeds limit %d", current_depth, limit)

Or you can use keyword arguments instead. The format string can use
positional parameters, or keyword arguments, but not both.

.. code-block:: python

    
    log.msg(format="Danger %(name)s %(surname)s", name="Will", surname="Robinson")

Passing arguments as separate parameters (instead of interpolating them
before calling ``log.msg`` has the benefit of preserving more information:
later, when you view the log messages, you can apply python filter
expressions that use these parameters as search criteria.

Regardless of how you format the main log message, you can always pass
additional keyword arguments, and their values will be serialized into the
log event. This will not be automatically stringified into a printed form of
the message, but it will be available to other tools (either to filter upon
or to display):

.. code-block:: python

    
    log.msg("state changed", previous=states[now-1], current=stats[now])

Modifying Log Messages
^^^^^^^^^^^^^^^^^^^^^^

There are a number of arguments you can add to the ``log.msg`` call that
foolscap will treat specially:

.. code-block:: python

    
    parent = log.msg(facility="app.initialization", level=log.INFREQUENT,
                     msg="hello world", stacktrace=False)
    log.msg(facility="app.storage", level=log.OPERATIONAL,
            msg="init storage", stacktrace=False, parent=parent)

The ``level`` argument is how you specify a severity level, and takes a
constant from the list defined in ``foolscap/log.py`` :

- ``BAD`` : something which significantly breaks functionality. Unhandled
  exceptions and broken invariants fall into this category.
- ``SCARY`` : something which is a problem, and shouldn't happen in normal
  operation, but which causes minimal functional impact, or from which the
  application can somehow recover.
- ``WEIRD`` : not as much of a problem as SCARY, but still not right.
- ``CURIOUS``
- ``INFREQUENT`` : messages which are emitted as a normal course of
  operation, but which happen infrequently, perhaps once every ten to one
  hundred seconds. User actions like triggering an upload or sending a
  message fall into this category.
- ``UNUSUAL`` : messages which indicate events that are not normal, but not
  particularly fatal. Examples include excessive memory or CPU usage, minor
  errors which can be corrected by fallback code.
- ``OPERATIONAL`` : messages which are emitted as a normal course of
  operation, like all the steps involved in uploading a file, potentially one
  to ten per second..
- ``NOISY`` : verbose debugging about small operations, potentially emitting
  tens or hundreds per second

The ``stacktrace`` argument controls whether or not a stack trace is recorded
along with the rest of the log message.

The ``parent`` argument allows messages to be related to earlier messages.

Logging Messages Through a Tub
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each Tub offers a log method: this is just like the process-wide ``log.msg``
described above, but it adds an additional parameter named ``tubid`` . This
is convenient during analysis, to identify which messages came from which
applications.

.. code-block:: python

    
    class Example:
      def __init__(self):
        self.tub = Tub()
        ...
      def query(self, args):
        self.tub.log("about to send query to server")
        self.server.callRemote("query", args).addCallback(self._query_done)

Facilities
~~~~~~~~~~

Facility names are up to the application: the viewer app will show a list of
checkboxes, one for each facility name discovered in the logged data.
Facility names should be divided along functional boundaries, so that
developers who do not care about, say, UI events can turn all of them off
with a single click. Related facilities can be given names separated with
dots, for example "ui.internationalization" and "ui.toolkit", and the viewer
app may make it easy to enable or disable entire groups at once. Facilities
can also be associated with more descriptive strings by calling
``log.explain_facility`` at least once:

.. code-block:: python

    
    log.explain_facility("ui.web", "rendering pages for the web UI")

"That Was Weird" Buttons
~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes it is the user of your application who is in the best position to
decide that something weird has taken place. Internal consistency checks are
useful, but the user is the final judge of what meets their needs. So if they
were expecting one thing to happen and something else happened instead, they
should be able to declare that an Incident has taken place, perhaps by
pushing a special "That Was Weird" button in your UI.

To implement this sort of button for your user, just take the user's
reason string and log it in an event at level WEIRD or higher. Since events
at this level trigger Incidents by default, Foolscap's normal
incident-handling behavior will take care of the rest for you.

.. code-block:: python

    
    def that_was_weird_button_pushed(reason):
        log.msg(format="The user said that was weird: %(reason)s",
                reason=reason,
                level=log.WEIRD)

Configuring Logging
-------------------

Foolscap's logging system is always enabled, but the unconfigured initial
state is lacking a number of useful features. By configuring the logging
system at application startup, you can enable these features.

Saving Log Events to Disk
~~~~~~~~~~~~~~~~~~~~~~~~~

The first missing piece is that it does not have a place to save log events
in the event of something strange happening, so the short-term circular
buffers are the only source of historical log events.

To give the logging system some disk space to work with, just give it a
logdir. The logging system will dump the circular buffers into this directory
any time something strange happens, and both the in-memory buffers and the
on-disk records are made available to viewing applications:

.. code-block:: python

    
    from foolscap.logging import log
    log.setLogDir("~/saved-log-events")   # == log.theLogger.setLogDir

The foolscap logging code does not delete files from this directory.
Applications which set up a logdir should arrange to delete old files once
storage space becomes a problem. TODO: we could provide a maximum size for
the logdir and have Foolscap automatically delete the oldest logfiles to stay
under the size limit: this would make the disk-based logdir an extension of
the memory-based circular buffers.

Incidents
^^^^^^^^^

Foolscap's logging subsystem uses the term "Incident" to describe the
"something strange" that causes the buffered log events to be dumped. The
logger has an "Incident Qualifier" that controls what counts as an incident.
The default qualifier simply fires on events at severity level ``log.WEIRD``
or higher. You can override the qualifier by subclassing
``foolscap.logging.incident.IncidentQualifier`` and calling
``log.setIncidentQualifier`` with an instance of your new class. For example,
certain facilities might be more important than others, and you might want to
declare an Incident for unusual but relatively low-severity events in those
facilities:

.. code-block:: python

    
    from foolscap.logging import log, incident
    
    class BetterQualifier(incident.IncidentQualifier):
        def check_event(self, ev):
            if ev.get('facility',"").startswith("lifesupport"):
                if ev['level'] > log.UNUSUAL:
                    return True
            return incident.IncidentQualifier.check_event(self, ev)
    
    log.setIncidentQualifier(BetterQualifier())

The qualifier could also keep track of how many events of a given type had
occurred, and trigger an incident if too many UNUSUAL events happen in rapid
succession, or if too many recoverable errors are observed within a single
operation.

Once the Incident has been declared, the "Incident Reporter" is responsible
for recording the recent events to the file on disk. The default reporter
copies everything from the circular buffers into the logfiles, then waits an
additional 5 seconds or 100 events (whichever comes first), recording any
trailing events into the logfile too. The idea is to capture the
application's error-recovery behavior: if the application experiences a
problem, it should log something at the ``log.WEIRD`` level (or similar),
then attempt to fix the problem. The post-trigger trailing event logging code
should capture the otherwise-ordinary events performed by this recovery code.

Overlapping incidents will be combined: if an incident reporter is already
active when the qualifier sees a new triggering event, that event is just
added to the existing reporter.

The incident reporter can be overridden as well, by calling
``log.setIncidentReporterFactory`` with a **class** that will produce
reporter instances. For example, if you wanted to increase the post-trigger
event recording to 1000 events or 10 seconds, then you could do something
like this:

.. code-block:: python

    
    from foolscap.logging import log, incident
    
    class MoreRecoveryIncidentReporter(incident.IncidentReporter):
        TRAILING_DELAY = 10.0
        TRAILING_EVENT_LIMIT = 1000
    
    log.setIncidentReporterFactory(MoreRecoveryIncidentReporter)

Recorded Incidents will be saved in the logdir with filenames like
``incident-2008-05-02--01-12-35Z-w2qn32q.flog.bz2`` , containing both a (UTC)
timestamp and a random/unique suffix. These can be read with tools like
``flogtool dump`` and ``flogtool web-viewer`` .

Setting up the logport
~~~~~~~~~~~~~~~~~~~~~~

The ``logport`` is a ``foolscap.Referenceable`` object which provides access
to all available log events. Viewer applications can either retrieve old
events (buffered in RAM or on disk), or subscribe to hear about new events
that occur later. The logport implements the
``foolscap.logging.interfaces.RILogPublisher`` interface, which defines the
methods that can be called on it. Each Tub automatically creates and
registers a logport: the ``tub.getLogPort()`` and ``tub.getLogPortFURL()``
methods make it possible to grant access to others:

.. code-block:: python

    
    t = Tub()
    ... # usual Tub setup: startService, listenOn, setLocation
    
    logport_furl = t.getLogPortFURL() # this is how you learn the logport furl
    print "please point your log viewer at: %s" % logport_furl
    
    logport = t.getLogPort() # a Referenceable you can pass over the wire
    rref.callRemote("please_use_my_logport", logport)

The default behavior is register the logport object with an ephemeral name,
and therefore its FURL will change from one run of the program to the next.
This can be an operational nuisance, since the external log viewing program
you're running (``flogtool tail LOGPORT`` ) would need a new FURL each time
the target program is restarted. By giving the logport a place to store its
FURL between program runs, the logport gets a persistent name. The
``logport-furlfile`` option is used to identify this file. If the file
exists, the desired FURL will be read out of it. If it does not, the
newly-generated FURL will be written into it.

If you use ``logport-furlfile`` , it must be set before you call
``getLogPortFURL`` (and also before you pass the result of ``getLogPort``
over the wire), otherwise an ephemeral name will have already been registered
and the persistent one will be ignored. The call to ``setOption`` can take
place before ``setLocation`` , and the logport-furlfile will be created as
soon as both the filename and the location hints are known. However, note
that the logport will not be available until after ``setLocation`` is called:
``getLogPortFURL`` and ``getLogPort`` will raise exceptions.

.. code-block:: python

    
    tub.setOption("logport-furlfile", "~/logport.furl")
    print "please point your log viewer at: %s" % tub.getLogPortFURL()

This ``logport.furl`` file can be read directly by other tools if you want to
point them at an operating directory rather than the actual logport FURL. For
example, the ``flogtool tail`` command (described below) can accept either an
actual FURL, or the directory in which a file named ``logport.furl`` can be
located, making it easier to examine the logs of a local application. Note
that the ``logport-furlfile`` is chmod'ed ``go-r`` , since it is a secret:
the idea is that only people with access to the application's working
directory (and presumeably to the application itself) should get access to
the logs.

Configuring a Log Gatherer
~~~~~~~~~~~~~~~~~~~~~~~~~~

The third feature that requires special setup is the log gatherer. You can
either tell the Tub a specific gatherer to use, or give it a filename where
the FURL of a log gatherer is stored.

The ``tub.setOption("log-gatherer-furl", gatherer_FURL)`` call can be used to
have the Tub automatically connect to the log gatherer and offer its logport.
The Tub uses a Reconnector to make sure the gatherer connection is
reestablished each time it gets dropped.

.. code-block:: python

    
    t = Tub()
    t.setOption("log-gatherer-furl", gatherer_FURL)

Alternatively, you can use the ``tub.setOption("log-gatherer-furlfile",
"~/gatherer.furl")`` call to tell the Tub about a file where a gatherer FURL
might be found. If that file exists, the Tub will read a FURL from it,
otherwise the Tub will not use a gatherer. The file can contain multiple
log-gatherer FURLs, one per line. This is probably the easiest deployment
mode:

.. code-block:: python

    
    t = Tub()
    t.setOption("log-gatherer-furlfile", "~/gatherer.furl")

In both cases, the gatherer FURL is expected to point to a remote object
which implements the ``foolscap.logging.RILogGatherer`` interface (such as
the service created by ``flogtool create-gatherer`` ). The Tub will connect
to the gatherer and offer it the logport.

The ``log-gatherer-furl`` and ``log-gatherer-furlfile`` options can be set at
any time, however the connection to the gatherer will not be initiated until
``setLocation`` is called.

Interacting With Other Logging Systems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two other logging systems that the Foolscap logging code knows how
to handle: ``twisted.python.log`` and the stdlib ``logging`` system.

First, a brief discussion of the single-instance nature of Foolscap's logging
is in order. Each process that uses Foolscap gets a single instance of the
Foolscap logging code (named ``theLogger`` and defined at module level in
``foolscap.logging.log`` ). This maintains a single logdir. Each time a
process is started it gets a new "incarnation record", which consists of a
randomly generated (unique) number, and (if a logdir is available) (TODO) a
continuously incrementing sequence number. All log events are tagged with
this incarnation record: it is used to distinguish between event#23 in one
process versus the same event number from a different process.

Each Tub has a distinct TubID, and all log events that go through the Tub
(via ``tub.log`` ) are tagged with this TubID. Each Tub maintains its own
logport (specifically there is a single ``LogPublisher`` object, but like all
Referenceables it can be registered in multiple Tubs and gets a distinct FURL
for each one).

twisted.python.log
^^^^^^^^^^^^^^^^^^

Twisted's logging mechanism is used by importing ``twisted.python.log`` and
invoking its ``log.msg()`` and ``log.err`` methods. This mechanism is used
extensively by Twisted itself; the most important messages are those
concerning "Unhandled Error in Deferred" and other exceptions in processing
received data and timed calls. The normal destination for Twisted log
messages depends upon how the application is run: the ``twistd``
daemonization tool sends the log messages to a file named ``twistd.log`` ,
the ``trial`` unit-test tool puts them in ``_trial_temp/test.log`` , and
standalone scripts discard these logs by default (unless you use something
like ``log.startLogging(sys.stderr)`` ).

To capture these log messages, you need a "bridge", which will add a Twisted
log observer and copy each Twisted log message into Foolscap. There can be at
most one such bridge per python process. Either you will use a generic bridge
(which tags each message with the incarnation record), or you will use a Tub
as a bridge (which additionally tags each message with the TubID). Each time
you set the twisted log bridge, any previous bridge is discarded.

When you have only one Tub in an application, use the Tub bridge. Likewise if
you have multiple Tubs but there is one that is long-lived, use that Tub for
the bridge. If you have mutiple Tubs with no real primary one, use the
generic bridge. Using a Tub bridge adds slightly more information to the log
events, and may make it a bit easier to correlate Twisted log messages with
actions of your application code, especially when you're combining events
from several applications together for analysis.

To set up the generic bridge, use the following code:

.. code-block:: python

    
    from foolcap.logging import log
    log.bridgeTwistedLogs()

To set up a Tub bridge, use this instead:

.. code-block:: python

    
    t = Tub()
    t.setOption("bridge-twisted-logs", True)

Note that for Tub bridges, the Twisted log messages will only be delivered
while the Tub is running (specifically from the time its startService()
method is until its stopService() method is called). TODO: review this
behavior, we want earlier messages to be bridged too.

To bridge log events in the other direction (i.e. taking foolscap log
messages and copying them into twisted), use the
``log.bridgeLogsToTwisted()`` call, or the ``FLOGTOTWISTED`` environment
variable. This is useful to get foolscap.logging.log.msg() events copied into
``twistd.log`` . The default filter only bridges non-noisy events (i.e. those
at level OPERATIONAL or higher), and does not bridge foolscal internal
events.

You might use this if you don't buy into the foolscap logging philosophy
and really want log events to be continually written out to disk. You might
also use it if you want a long-term record of operationally-significant
events, or a record that will survive application crashes which don't get
handled by the existing Incident-recording mechanism.

.. code-block:: python

    
    from foolscap.logging import log
    log.bridgeLogsToTwisted()

stdlib 'logging' module
^^^^^^^^^^^^^^^^^^^^^^^

stdlib ``logging`` messages must be bridged in the same way. TODO:
define and implement the bridge setup

Preferred Logging API
^^^^^^^^^^^^^^^^^^^^^

To take advantage of the parent/child causality mechanism, you must use
Foolscap's native API. (to be precise, you can pass in ``parent=`` to either
Twisted's ``log.msg`` or stdlib's ``logging.log`` , but to get a handle to
use as a value to ``parent=`` you must use ``foolscap.log.msg`` , because
neither stdlib's nor Twisted's log calls provide a return value)

Controlling Buffer Sizes
~~~~~~~~~~~~~~~~~~~~~~~~

There is a separate circular buffer (with some maximum size) for each
combination of level and facility. After each message is added, the size of
the buffer is checked and enough old messages are discarded to bring the size
back down to the limit. Each facility uses a separate set of buffers, so that
e.g. the NOISY messages from the "ui" facility do not evict the NOISY
messages from the "upload" facility.

The sizes of these buffers can be controlled with the ``log.set_buffer_size``
function, which is called with the severity level, the facility name, and the
desired buffer size (maximum number of messages). If ``set_buffer_size`` is
called without a facility name, then it will set the default size that will
be used when a log.msg call references an as-yet-unknown facility).

.. code-block:: python

    
    log.set_buffer_size(log.NOISY, 10000)
    log.set_buffer_size(level=log.NOISY, facility="upload", size=10000)
    log.allocate_facility_buffers("web")
    print log.get_buffer_size(log.NOISY, facility="upload")

Some Messages Are Not Worth Generating
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If the message to be logged is below some threshold, it will not even be
generated. This makes it easy to leave the log line in the source code, but
not consume CPU time or memory space by actually using it. Such messages must
be enabled before use (either through the logport (TODO) or by restarting the
application with different log settings(TODO)), but at least developers will
not have to re-learn the source code to figure out where it might be useful
to add some messages. This threshold can be configured for all facilities at
the same time, or on a facility-by-facility basis.

.. code-block:: python

    
    log.set_generation_threshold(log.NOISY)
    log.set_generation_threshold(level=log.OPERATIONAL, facility="web")
    print log.get_generation_threshold()
    print log.get_generation_threshold(facility="web")

Viewing Log Messages
--------------------

There are a variety of ways for humans (and their tools) to read and analyze
log messages. The ``flogtool`` program, provided with Foolscap, provides
access to many of them.

- ``flogtool dump`` : look at the saved log events (in a logdir) and display
  their contents to stdout. Options are provided to specify the log source,
  the facilities and severity levels to display, and grep-like filters on the
  messages to emit.
- ``flogtool tail`` : connect to a logport and display new log events to
  stdout. The ``--catchup`` option will also display old events.
- ``flogtool gtk-viewer`` : a Gtk-based graphical tool to examine log
  messages.
- ``flogtool web-viewer`` : runs a local web server, through which log events
  can be examined.

This tool uses a log-viewing API defined in
``foolscap/logging/interfaces.py`` . (TODO) Application code can use the same
API to get access to log messages from inside a python program.

Log Views
~~~~~~~~~

(NOTE: this section is incomplete and has not been implemented)

Many of these tools share the concept of "Log Views". This is a particular
set of filters which can be applied to the overall log event stream. For
example, one view might show all events that are UNUSUAL or worse. Another
view might show NOISY messages for the "ui" facility but nothing else.

Each view is described by a set of thresholds: each facility gets a severity
threshold, and all messages at or above the threshold will be included in the
view. While in principle there is a threshold for each facility, this may be
expressed as a single generic threshold combined with overrides for a few
specific facilities.

Log Observers
~~~~~~~~~~~~~

A "Log Observer" can be attached to a foolscap-using program (either
internally or by subscribing through the flogport). Once attached, this
observer will receive a stream of log messages, which the observer is then
free to format, store, or ignore as it sees fit.

Each log message is a dictionary, as defined in doc/specifications/logfiles .

.. code-block:: python

    
    def observe(event):
        print strftime(fmt, event.timestamp)
        print event["level"] # a number
        print event.get("facility" # a string like "ui"
        print event["message"]  # a unicode object with the actual event text
    
    log.theLogger.addObserver(observe)

Running a Log Gatherer
~~~~~~~~~~~~~~~~~~~~~~

A "Log Gatherer" is a python server to which the process under examination
sends some or all of its log messages. These messages are saved to a file as
they arrive, so they can be examined later. The resulting logfiles can be
compressed, and they can be automatically rotated (saved, rename, reopened)
on a periodic interval. In addition, sending a SIGHUP to the gatherer will
cause it to rotate the logfiles.

To create one, choose a new directory for it to live in, and run "``flogtool
create-gatherer`` ". You can then start it with "twistd", and stop it by
using the ``twistd.pid`` file:

.. code-block:: console

    
    % flogtool create-gatherer lg
    Gatherer created in directory lg
    Now run '(cd lg && twistd -y gatherer.tac)' to launch the daemon
    % cd lg
    % ls
    gatherer.tac
    % twistd -y gatherer.tac
    % ls
    from-2008-07-28--13-30-34Z--to-present.flog  log_gatherer.furl  twistd.pid
    gatherer.pem                                 portnum
    gatherer.tac                                 twistd.log
    % cat log_gatherer.furl
    pb://g7yntwfu24w2hhb54oniqowfgizpk73d@192.168.69.172:54611,127.0.0.1:54611/z4ntcdg4jpdg3pnabhmyu3qvi3a7mdp3
    % kill `cat twistd.pid`
    %

The ``log_gatherer.furl`` string is the one that should be provided to all
applications whose logs should be gathered here. By using
``tub.setOption("log-gatherer-furlfile", "log_gatherer.furl")`` in the
application, you can just copy this .furl file into the application's working
directory.

Running an Incident Gatherer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An "Incident Gatherer" is like a Log Gatherer, but it only gathers
weirdness-triggered Incidents. It records these incidents into files on the
local disk, and provides access to them through a web server. The Incident
Gatherer can also be configured to classify the incidents into various
categories (perhaps expressions of a specific bug), to facilitate analysis by
separating known problems from new ones.

To create one, choose a new directory for it to live in, and run "``flogtool
create-incident-gatherer`` ", just like the log gatherer:

.. code-block:: console

    
    % flogtool create-incident-gatherer ig
    Gatherer created in directory ig
    Now run '(cd ig && twistd -y gatherer.tac)' to launch the daemon
    % cd ig
    % ls
    gatherer.tac
    % twistd -y gatherer.tac
    %

Incident Storage
^^^^^^^^^^^^^^^^

Inside the gatherer's base directory (which we refer to as BASEDIR here), the
``incidents/`` directory will contain a subdirectory for each tub that
connects to the gatherer. Each subdir will contain the incident files, named
``incident-TIMESTAMP-UNIQUE.flog.bz2`` .

A simple unix command like ``find BASEDIR/incidents -name
'incident-*.flog.bz2'`` will locate all incident files. Each incident file
can be examined with a tool like ``flogtool dump`` . The format is described
in the doc/specifications/logfiles docs.

Classification
^^^^^^^^^^^^^^

The Incident Gatherer uses a collection of user-supplied classification
functions to analyze each Incident and place it into one or more categories.
To add a classification function, create a file with a name like
"``classify_*.py`` " (such as ``classify_foolscap.py`` or ``classify_db.py``
), and define a function in it named "``classify_incident()`` ". Place this
file in the gatherer's directory. All such files will be loaded and evaluated
when the gatherer starts.

The ``classify_incident()`` function will accept a single triggering event (a
regular log Event dictionary, see logfiles.xhtml for details, which can be
examined as follows:

.. code-block:: python

    
    def classify_incident(trigger):
        m = trigger.get('message', '')
        if "Tub.connectorFinished:" in m:
            return 'foolscap-tubconnector'

The function should return a list (or set) of categories, or a single
category string, or None. Each incident can wind up in multiple categories.
If no function finds a category for the incident, it will be added to the
"unknown" category. All incidents are added to the "all" category.

The ``classified/`` directory will contain a file for each defined
classification. This file will contain one line for each incident that falls
into that category, containing the BASEDIR-relative pathname of the incident
file (i.e. each line will look like
``incidents/TUBID/incident-TIMESTAMP-UNIQUE.flog.bz2`` ). The
``classified/all`` file will contain the same filenames as the ``find``
command described earlier.

If the ``classified/`` directory does not exist when the gatherer is started,
all stored Incidents will be re-classified. After modifying or adding
classification functions, you should delete the ``classified/`` directory and
restart the gatherer.

Incident Gatherer Web Server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Incident Gatherer can run a small webserver, to publish information about
the incidents it collects. The plan is to have it publish an RSS feed of
incidents by category, and to serve incidents as HTML just like the
``foolscap web-viewer`` command. This code is not yet written.

Incident Reports by Email
^^^^^^^^^^^^^^^^^^^^^^^^^

The Incident Gatherer can also be configured to send email with a description
of the incident for various categories. The incident report will be included
as an attachment for further analysis. This code is not yet written.

Incomplete And Misleading Notes On stdlib 'Logging' Module
---------

(NOTE: this section is incomplete and has not been implemented. In addition
it may be entirely false and misleading.)

The Python stdlib ``logging`` module offers portions of the desired
functionality. The Foolscap logging framework is built as an extension to the
native Python facilities.

The ``logging`` module provides a tree of facilities, one ``Logger`` instance
per facility (in which the child path names are joined with periods to form
the Logger's name). Each ``Logger`` gets a set of ``Handlers`` which receive
all messages sent to that ``Logger`` or below; the ``Handlers`` attached to
the root ``Logger`` see all messages. Each message arrives as a ``LogRecord``
instance, and handlers are responsible for formatting them into text or a
record on disk or whatever is necessary. Each log message has a severity
(from DEBUG at 10 up to CRITICAL at 50), and both ``Loggers`` and
``Handlers`` have thresholds to discard low-severity messages.

``logging``

Plan of attack:

foolscap installs a root Logger handler, with a threshold set very low (0),
so it gets everything. The root Logger is set to a low threshold (since it
defaults to WARNING=30), to make sure that all events are passed through to
its handlers. Foolscap's handler splits the events it receives out by
facility (Logger name) and severity level, and appends them to a
space-limited buffer (probably a dequeue).

That covers all native users of logging.py . Foolscap users deal with
foolscap.log.msg(), which massages the arguments before passing them through
to logging.log(). In particular, each log message processed by the foolscap
handler gets a serial number assigned to it. This number is used as a marker,
which can be passed to later msg() calls. The foolscap.log.msg code manages
these serial numbers and uses them to construct the call to logging.log(),
then the foolscap handler pulls the serial number out of the event and
records it.
