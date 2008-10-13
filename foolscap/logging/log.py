
import os, sys, time, pickle, weakref
import traceback
import collections
from twisted.python import log as twisted_log
from twisted.python import failure
from foolscap import eventual
from foolscap.logging.interfaces import IIncidentReporter
from foolscap.logging.incident import IncidentQualifier, IncidentReporter

from foolscap.logging.levels import NOISY, OPERATIONAL, UNUSUAL, \
     INFREQUENT, CURIOUS, WEIRD, SCARY, BAD

# hush pyflakes, these are imported to be available to other callers
_unused = [NOISY, OPERATIONAL, UNUSUAL, INFREQUENT, CURIOUS, WEIRD, SCARY, BAD]

def format_message(e):
    try:
        if "format" in e:
            assert isinstance(e['format'], str)
            return e['format'] % e
        elif "args" in e:
            assert "message" in e
            assert isinstance(e['message'], str)
            return e['message'] % e['args']
        elif "message" in e:
            assert isinstance(e['message'], str)
            return e['message']
        else:
            return ""
    except (ValueError, TypeError):
        return e.get('message', "[no message]") + " [formatting failed]"


class Count:
    """A fixed version of itertools.count .

    This class counts up from zero, just like the Python 2.5.2 docs claim
    that itertools.count() does, but this class does not overflow with an
    error like itertools.count() does:

      File 'foolscap/logging/log.py', line 137, in msg
          num = self.seqnum.next()
      exceptions.OverflowError: cannot count beyond PY_SSIZE_T_MAX
    """

    def __init__(self, firstval=0):
        self.n = firstval - 1

    def next(self):
        self.n += 1
        return self.n

class FoolscapLogger:
    DEFAULT_SIZELIMIT = 100
    DEFAULT_THRESHOLD = NOISY
    MAX_RECORDED_INCIDENTS = 20 # records filenames of incident logfiles

    def __init__(self):
        self.incarnation = self.get_incarnation()
        self.seqnum = Count()
        self.facility_explanations = {}
        self.buffer_sizes = {} # k: facility or None, v: dict(level->sizelimit)
        self.buffer_sizes[None] = {}
        self.buffers = {} # k: facility or None, v: dict(level->deque)
        self.thresholds = {}
        self._observers = []
        self._immediate_observers = []
        self._immediate_incident_observers = []
        self.logdir = None # nowhere to put our incidents
        self.inactive_incident_qualifier = IncidentQualifier()
        self.active_incident_qualifier = None
        self.incident_reporter_factory = IncidentReporter
        self.active_incident_reporter_weakref = None
        self.incidents_declared = 0
        self.incidents_recorded = 0
        self.recent_recorded_incidents = []

    def get_incarnation(self):
        unique = os.urandom(8)
        sequential = None
        return (unique, sequential)

    def addObserver(self, observer):
        self._observers.append(observer)
    def removeObserver(self, observer):
        self._observers.remove(observer)

    def addImmediateObserver(self, observer):
        # by using this, you solemly swear that your observer will not raise
        # an exception, nor will it recurse or cause more log messages to be
        # emitted. Immediate Observers are notified without an eventual-send.
        self._immediate_observers.append(observer)
    def removeImmediateObserver(self, observer):
        self._immediate_observers.remove(observer)


    def setLogDir(self, directory):
        # TODO: change self.incarnation to reflect next seqnum
        self.logdir = os.path.abspath(os.path.expanduser(directory))
        if not os.path.isdir(self.logdir):
            os.makedirs(self.logdir)
        self.activate_incident_qualifier()

    def setIncidentQualifier(self, iq):
        assert iq.event
        self.deactivate_incident_qualifier()
        self.inactive_incident_qualifier = iq
        if self.logdir:
            self.activate_incident_qualifier()

    def deactivate_incident_qualifier(self):
        if self.active_incident_qualifier:
            self.active_incident_qualifier.set_handler(None)
            self.active_incident_qualifier = None

    def activate_incident_qualifier(self):
        self.active_incident_qualifier = self.inactive_incident_qualifier
        self.active_incident_qualifier.set_handler(self)

    def setIncidentReporterFactory(self, ir):
        assert IIncidentReporter.implementedBy(ir)
        self.incident_reporter_factory = ir

    def addImmediateIncidentObserver(self, observer):
        self._immediate_incident_observers.append(observer)
    def removeImmediateIncidentObserver(self, observer):
        self._immediate_incident_observers.remove(observer)

    def explain_facility(self, facility, description):
        self.facility_explanations[facility] = description

    def set_buffer_size(self, level, sizelimit, facility=None):
        if facility not in self.buffer_sizes:
            self.buffer_sizes[facility] = {}
        self.buffer_sizes[facility][level] = sizelimit

    def set_generation_threshold(self, level, facility=None):
        self.thresholds[facility] = level
    def get_generation_threshold(self, facility=None):
        return self.thresholds.get(facility, self.DEFAULT_THRESHOLD)

    def msg(self, *args, **kwargs):
        """
        @param parent: the event number of the most direct parent of this
                       event
        @param facility: the slash-joined facility name, or None
        @param level: the numeric severity level, like NOISY or SCARY
        @param stacktrace: a string stacktrace, or True to generate one
        @returns: the event number for this logevent, intended to be passed
                  to parent= in a subsequent call to msg()
        """

        if "num" not in kwargs:
            num = self.seqnum.next()
        else:
            num = kwargs['num']
        facility = kwargs.get('facility')
        if "level" not in kwargs:
            kwargs['level'] = OPERATIONAL
        level = kwargs["level"]
        threshold = self.get_generation_threshold(facility)
        if level < threshold:
            return # not worth logging

        event = kwargs

        if "format" in event:
            pass
        elif "message" in event:
            event['message'] = str(event['message'])
        elif args:
            event['message'], posargs = str(args[0]), args[1:]
            if posargs:
                event['args'] = posargs
        else:
            event['message'] = ""

        if "time" not in event:
            event['time'] = time.time()

        if "failure" in event:
            f = event["failure"]
            # we need to avoid pickling the exception class, since that will
            # require the original application code to unpickle, and log
            # viewers may not have it installed. A CopiedFailure works great
            # for this purpose. TODO: I'd prefer to not use a local import
            # here, but doing at the top level causes a circular import
            # failure.
            from foolscap.call import FailureSlicer, CopiedFailure
            class FakeBroker:
                unsafeTracebacks = True
            if not isinstance(f, CopiedFailure):
                fs = FailureSlicer(f)
                f2 = CopiedFailure()
                f2.setCopyableState(fs.getStateToCopy(f, FakeBroker))
                event["failure"] = f2

        # verify that we can stringify the event correctly
        try:
            format_message(event)
        except Exception, e:
            print "problem in log message %s: %r %s" % (event, e, e)
            pass
        if event.get('stacktrace', False) is True:
            event['stacktrace'] = traceback.format_stack()
        event['incarnation'] = self.incarnation
        event['num'] = num
        self.add_event(facility, level, event)
        return num

    def err(self, _stuff=None, _why=None, **kw):
        """
        Write a failure to the log.
        """
        if _stuff is None:
            _stuff = failure.Failure()
        if isinstance(_stuff, failure.Failure):
            return self.msg(failure=_stuff, why=_why, isError=1, **kw)
        elif isinstance(_stuff, Exception):
            return self.msg(failure=failure.Failure(_stuff), why=_why,
                            isError=1, **kw)
        else:
            return self.msg(repr(_stuff), why=_why, isError=1, **kw)

    def add_event(self, facility, level, event):
        # send to observers
        for o in self._immediate_observers:
            o(event)
        for o in self._observers:
            eventual.eventually(o, event)

        # buffer locally
        d1 = self.buffers.get(facility)
        if not d1:
            d1 = self.buffers[facility] = {}
        buffer = d1.get(level)
        if not buffer:
            buffer = d1[level] = collections.deque()
        buffer.append(event)

        # enforce size limits on local buffers
        d2 = self.buffer_sizes.get(facility)
        if d2:
            sizelimit = d2.get(level, self.DEFAULT_SIZELIMIT)
        else:
            sizelimit = self.DEFAULT_SIZELIMIT
        while len(buffer) > sizelimit:
            buffer.popleft()

        # check with incident reporter. This is done synchronously rather
        # than via the usual eventual-send to allow the application to do:
        #  log.msg("abandon ship", level=log.BAD)
        #  sys.exit(1)
        #
        # This means the IncidentReporter will do most of its work right
        # here. The reporter is not allowed to make any foolscap calls, and
        # the call to incident_recorded() is required to pass through an
        # eventual-send.

        if self.active_incident_qualifier:
            try:
                # this might call declare_incident
                self.active_incident_qualifier.event(event)
            except:
                print failure.Failure() # for debugging

    def declare_incident(self, triggering_event):
        self.incidents_declared += 1
        ir = self.get_active_incident_reporter()
        if ir:
            ir.new_trigger(triggering_event)
            return
        if self.logdir: # just in case
            ir = self.incident_reporter_factory(self.logdir, self, "local")
            self.active_incident_reporter_weakref = weakref.ref(ir)
            ir.incident_declared(triggering_event) # this takes a few seconds

    def incident_recorded(self, filename, name, trigger):
        # 'name' is incident-TIMESTAMP-UNIQUE, whereas filename is an
        # absolute pathname to the NAME.flog.bz2 file.
        self.incidents_recorded += 1
        self.recent_recorded_incidents.append(filename)
        while len(self.recent_recorded_incidents) > self.MAX_RECORDED_INCIDENTS:
            self.recent_recorded_incidents.pop(0)
        # publish these to interested parties
        for o in self._immediate_incident_observers:
            o(name, trigger)

    def get_active_incident_reporter(self):
        if self.active_incident_reporter_weakref:
            ir = self.active_incident_reporter_weakref()
            if ir and ir.is_active():
                return ir
        return None

    def setLogPort(self, logport):
        self._logport = logport
    def getLogPort(self):
        return self._logport

    def get_buffered_events(self):
        # iterates over all current log events in no particular order. The
        # caller should sort them by event number. If this isn't iterated
        # quickly enough, more events may arrive.
        for facility,b1 in self.buffers.iteritems():
            for level,q in b1.iteritems():
                for event in q:
                    yield event


theLogger = FoolscapLogger()

# def msg(stuff):
msg = theLogger.msg
err = theLogger.err
setLogDir = theLogger.setLogDir
explain_facility = theLogger.explain_facility
set_buffer_size = theLogger.set_buffer_size
set_generation_threshold = theLogger.set_generation_threshold
get_generation_threshold = theLogger.get_generation_threshold

# code to bridge twisted.python.log.msg() to foolscap

class TwistedLogBridge:
    def __init__(self, tubID=None, foolscap_logger=theLogger):
        self.tubID = tubID
        self.logger = foolscap_logger

        # newer versions of Twisted have a function called
        # textFromEventDict() that we can use to format the message. Older
        # versions (twisted-2.5.0 and earlier) have this functionality buried
        # in the FileLogObserver where it isn't very easy to get to.
        if hasattr(twisted_log, "textFromEventDict"):
            self.observer = self._new_twisted_log_observer
        else:
            self.observer = self._old_twisted_log_observer

    def _new_twisted_log_observer(self, d):
        # Twisted will remove this for us if it fails.
        # keys:
        #  ['message']: *args
        #  ['time']: float
        #  ['isError']: bool, usually False
        #  ['system']: string

        if "from-foolscap" in d:
            return
        event = d.copy()
        event['tubID'] = self.tubID
        message = twisted_log.textFromEventDict(d)
        event.pop('message', None)
        event['from-twisted'] = True
        self.logger.msg(message, **event)

    def _old_twisted_log_observer(self, d):
        if "from-foolscap" in d:
            return
        event = d.copy()
        if "format" in d:
            # 'message' will be treated as a format string, with the rest of
            # the arguments as its % dictionary.
            pass
        else:
            # no string interpolation, but if there are multiple args, then
            # join them together, to match what twisted does.
            event['message'] = " ".join([str(m) for m in d['message']])
        event.pop('args', None)
        event['tubID'] = self.tubID
        event['from-twisted'] = True
        self.logger.msg(**event)

def bridgeLogsFromTwisted(tubID=None,
                          twisted_logger=twisted_log.theLogPublisher,
                          foolscap_logger=theLogger):
    """Called without arguments, this arranges for all twisted log messages
    to be bridged into the default foolscap logger.

    I can also be called with a specific twisted and/or foolscap logger,
    mostly for unit tests that don't want to modify the default instances.
    For their benefit, I return the bridge.
    """
    tlb = TwistedLogBridge(tubID, foolscap_logger)
    twisted_logger.addObserver(tlb.observer)
    return tlb

def bridgeLogsToTwisted(filter=None,
                        foolscap_logger=theLogger,
                        twisted_logger=twisted_log):
    # foolscap_logger and twisted_logger are for testing purposes
    def non_foolscap_operational_or_better(e):
        if e.get("facility","").startswith("foolscap"):
            return False
        if e['level'] < OPERATIONAL:
            return False
        return True
    if not filter:
        filter = non_foolscap_operational_or_better
    def _to_twisted(event):
        if "from-twisted" in event:
            return
        if not filter(event):
            return
        args = {"from-foolscap": True,
                "num": event["num"],
                "level": event["level"],
                }
        twisted_logger.msg(format_message(event), **args)
    foolscap_logger.addObserver(_to_twisted)

class LogFileObserver:
    def __init__(self, filename, level=OPERATIONAL):
        if filename.endswith(".bz2"):
            import bz2
            self._logFile = bz2.BZ2File(filename, "w")
        else:
            self._logFile = open(filename, "wb")
        self._level = level
        header = {"header": {"type": "log-file-observer",
                             "threshold": level,
                             }}
        pickle.dump(header, self._logFile)

    def stop_on_shutdown(self):
        from twisted.internet import reactor
        reactor.addSystemEventTrigger("after", "shutdown", self._stop)

    def msg(self, event):
        threshold = self._level
        #if event.get('facility', '').startswith('foolscap'):
        #    threshold = UNUSUAL
        if event['level'] >= threshold:
            e = {"from": "local",
                 "rx_time": time.time(),
                 "d": event,
                 }
            pickle.dump(e, self._logFile, 2)

    def _stop(self):
        self._logFile.close()
        del self._logFile


# remove the key, so any child processes won't try to log to (and thus
# clobber) the same file. This doesn't always seem to work reliably
# (allmydata.test.test_runner.RunNode.test_client uses os.system and the
# child process still has $FLOGFILE set).

_flogfile = os.environ.pop("FLOGFILE", None)
if _flogfile:
    try:
        _floglevel = int(os.environ.get("FLOGLEVEL", str(OPERATIONAL)))
        lfo = LogFileObserver(_flogfile, _floglevel)
        lfo.stop_on_shutdown()
        theLogger.addObserver(lfo.msg)
        #theLogger.set_generation_threshold(UNUSUAL, "foolscap.negotiation")
    except IOError:
        print >>sys.stderr, "FLOGFILE: unable to write to %s, ignoring" % \
              (_flogfile,)

if "FLOGTWISTED" in os.environ:
    bridgeLogsFromTwisted()

if "FLOGTOTWISTED" in os.environ:
    bridgeLogsToTwisted()
