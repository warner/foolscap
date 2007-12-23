
import os, sys, time, pickle
import itertools
import logging
import traceback
import collections
from twisted.python import log as twisted_log
from foolscap import eventual

NOISY = logging.DEBUG # 10
OPERATIONAL = logging.INFO # 20
UNUSUAL = logging.INFO+3
INFREQUENT = logging.INFO+5
CURIOUS = logging.INFO+8
WEIRD = logging.WARNING # 30
SCARY = logging.WARNING+5
BAD = logging.ERROR # 40


class FoolscapLogger:
    DEFAULT_SIZELIMIT = 100
    DEFAULT_THRESHOLD = NOISY

    def __init__(self):
        self.incarnation = self.get_incarnation()
        self.seqnum = itertools.count(0)
        self.facility_explanations = {}
        self.buffer_sizes = {} # k: facility or None, v: dict(level->sizelimit)
        self.buffer_sizes[None] = {}
        self.buffers = {} # k: facility or None, v: dict(level->deque)
        self.buffer = collections.deque()
        self.thresholds = {}
        self._observers = []

    def get_incarnation(self):
        unique = os.urandom(8)
        sequential = None
        return (unique, sequential)

    def addObserver(self, observer):
        self._observers.append(observer)
    def removeObserver(self, observer):
        self._observers.remove(observer)

    def setLogDir(self, directory):
        # TODO: not implemented yet
        # TODO: change self.incarnation to reflect next seqnum
        pass

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

        if not args:
            message, args = "", ()
        else:
            message, args = args[0], args[1:]
        message = str(message)
        event = kwargs
        if "time" not in event:
            event['time'] = time.time()
        event['message'] = message
        event['args'] = args
        # verify that we can stringify the event correctly
        try:
            if args:
                s = message % args
            else:
                s = message % kwargs
        except (ValueError, TypeError), ex:
            #print "problem in log message: %s" % (message,)
            pass
        if event.get('stacktrace', False) is True:
            event['stacktrace'] = traceback.format_stack()
        event['incarnation'] = self.incarnation
        event['num'] = num
        self.add_event(facility, level, event)
        return num

    def add_event(self, facility, level, event):
        # send to observers
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


    def setLogPort(self, logport):
        self._logport = logport
    def getLogPort(self):
        return self._logport


theLogger = FoolscapLogger()

# def msg(stuff):
msg = theLogger.msg
setLogDir = theLogger.setLogDir
explain_facility = theLogger.explain_facility
set_buffer_size = theLogger.set_buffer_size
set_generation_threshold = theLogger.set_generation_threshold
get_generation_threshold = theLogger.get_generation_threshold

# code to bridge twisted.python.log.msg() to foolscap

class TwistedLogBridge:
    def __init__(self, tubID=None):
        self.tubID = tubID

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

        event = d.copy()
        event['tubID'] = self.tubID
        message = twisted_log.textFromEventDict(d)
        event.pop('message', None)
        msg(message, **event)

    def _old_twisted_log_observer(self, d):
        event = d.copy()
        if "format" in d:
            # 'message' will be treated as a format string, with the rest of
            # the arguments as its % dictionary.
            message = d['format']
            del event['format']
        else:
            # put empty ['args'] in the event to trigger tuple-interpolation
            # instead of dictionary-interpolation. The message text is in
            # ['message']
            message = " ".join([str(m) for m in d['message']])
            event.pop('message', None)
        event.pop('args', None)
        event['tubID'] = self.tubID
        msg(message, **event)

theTwistedLogBridge = None

def setTwistedLogBridge(bridge):
    global theTwistedLogBridge
    if theTwistedLogBridge:
        try:
            twisted_log.removeObserver(theTwistedLogBridge.observer)
        except ValueError:
            pass
    if bridge:
        theTwistedLogBridge = bridge
        twisted_log.addObserver(bridge.observer)

def bridgeTwistedLogs():
    setTwistedLogBridge(TwistedLogBridge())

class LogFileObserver:
    def __init__(self, filename, level=OPERATIONAL):
        if filename.endswith(".bz2"):
            import bz2
            self._logFile = bz2.BZ2File(filename, "w")
        else:
            self._logFile = open(filename, "ab")
        self._level = level
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
        theLogger.addObserver(lfo.msg)
        #theLogger.set_generation_threshold(UNUSUAL, "foolscap.negotiation")
    except IOError:
        print >>sys.stderr, "FLOGFILE: unable to write to %s, ignoring" % \
              (_flogfile,)

if "FLOGTWISTED" in os.environ:
    bridgeTwistedLogs()
