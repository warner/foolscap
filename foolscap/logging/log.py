
import os
import itertools
import logging
import traceback
import collections
from twisted.python import log as twisted_log

(NOISY,
 OPERATIONAL,
 UNUSUAL,
 INFREQUENT,
 CURIOUS,
 WEIRD,
 SCARY,
 BAD,
 ) = range(8)

levelmap = {
    NOISY: logging.DEBUG,
    OPERATIONAL: logging.INFO,
    UNUSUAL: logging.WARNING,
    INFREQUENT: logging.WARNING,
    CURIOUS: logging.WARNING,
    WEIRD: logging.ERROR,
    SCARY: logging.ERROR,
    BAD: logging.CRITICAL,
    }



class FoolscapLogger:
    DEFAULT_SIZELIMIT = 100

    def __init__(self):
        self.incarnation = self.get_incarnation()
        self.seqnum = itertools.count(0)
        self.facility_explanations = {}
        self.buffer_sizes = {} # k: facility or None, v: dict(level->sizelimit)
        self.buffer_sizes[None] = {}
        self.buffers = {} # k: facility or None, v: dict(level->deque)
        self.buffer = collections.deque()
        self._observers = []

    def get_incarnation(self):
        unique = os.urandom(8)
        sequential = None
        return (unique, sequential)

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

    def msg(self, message, stacktrace=None, **kwargs):
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
            kwargs['num'] = num = self.seqnum.next()
        if stacktrace is True:
            stacktrace = traceback.format_stack()
        kwargs['stacktrace'] = stacktrace
        facility = kwargs.get("facility")
        level = kwargs.get("level", NOISY)
        kwargs['incarnation'] = self.incarnation
        kwargs['message'] = message
        event = kwargs
        self.add_event(facility, level, event)
        return event['num']

    def add_event(self, facility, level, event):
        # send to observers
        for o in self._observers:
            o.callRemoteOnly("msg", event)

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

class LogPort:
    # TODO
    def __init__(self, logger):
        self._logger = logger

theLogger = FoolscapLogger()
theLogPort = LogPort(theLogger)

# def msg(stuff):
msg = theLogger.msg
setLogDir = theLogger.setLogDir
explain_facility = theLogger.explain_facility
set_buffer_size = theLogger.set_buffer_size

class TwistedLogBridge:
    def __init__(self, tubID=None):
        self.tubID = tubID

    def _twisted_log_observer(self, d):
        # Twisted will remove this for us if it fails.

        # keys:
        #  ['message']: *args
        #  ['time']: float
        #  ['isError']: bool, usually False
        #  ['system']: string

        # note that this modifies the event that any other twisted observers
        # will see, however for right now I prefer that to the slowdown that
        # copying the dictionary would require.
        d['tubID'] = self.tubID
        msg(**d)

theTwistedLogBridge = None

def setTwistedLogBridge(bridge):
    if theTwistedLogBridge:
        twisted_log.removeObserver(theTwistedLogBridge._twisted_log_observer)
    if bridge:
        theTwistedLogBridge = bridge
        twisted_log.addObserver(bridge._twisted_log_observer)

def bridgeTwistedLogs():
    setTwistedLogBridge(TwistedLogBridge())

