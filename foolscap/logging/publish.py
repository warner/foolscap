
import os
import pickle
from collections import deque
from zope.interface import implements
from twisted.python import filepath
from foolscap.referenceable import Referenceable
from foolscap.logging.interfaces import RISubscription, RILogPublisher
from foolscap.logging import app_versions
from foolscap.eventual import eventually

class Subscription(Referenceable):
    implements(RISubscription)
    # used as a marker, and as an unsubscribe() method. We use this to manage
    # the outbound size-limited queue.
    MAX_QUEUE_SIZE = 2000
    MAX_IN_FLIGHT = 10

    def __init__(self, observer, logger):
        self.observer = observer
        self.logger = logger
        self.subscribed = False
        self.queue = deque()
        self.in_flight = 0
        self.marked_for_sending = False
        #self.messages_dropped = 0

    def subscribe(self, catch_up):
        self.subscribed = True
        # If we have to discard messages, discard them as early as possible,
        # and provide backpressure. So we add our method as an "immediate
        # observer" instead of a regular one.
        self.logger.addImmediateObserver(self.send)
        self._nod_marker = self.observer.notifyOnDisconnect(self.unsubscribe)
        if catch_up:
            # send any catch-up events in a single batch, before we allow any
            # other events to be generated (and sent). This lets the
            # subscriber see events in sorted order. We bypass the bounded
            # queue for this.
            events = list(self.logger.get_buffered_events())
            events.sort(lambda a,b: cmp(a['num'], b['num']))
            for e in events:
                self.observer.callRemoteOnly("msg", e)

    def unsubscribe(self):
        if self.subscribed:
            self.logger.removeImmediateObserver(self.send)
            self.observer.dontNotifyOnDisconnect(self._nod_marker)
            self.subscribed = False
    def remote_unsubscribe(self):
        return self.unsubscribe()

    def send(self, event):
        if len(self.queue) < self.MAX_QUEUE_SIZE:
            self.queue.append(event)
        else:
            # preserve old messages, discard new ones.
            #self.messages_dropped += 1
            pass
        if not self.marked_for_sending:
            self.marked_for_sending = True
            eventually(self.start_sending)

    def start_sending(self):
        self.marked_for_sending = False
        while self.queue and (self.MAX_IN_FLIGHT - self.in_flight > 0):
            event = self.queue.popleft()
            self.in_flight += 1
            d = self.observer.callRemote("msg", event)
            d.addCallback(self._event_received)
            d.addErrback(self._error)

    def _event_received(self, res):
        self.in_flight -= 1
        # the following would be nice to have, but requires very careful
        # analysis to avoid recursion, reentrancy, or even more overload
        #if self.messages_dropped and not self.queue:
        #    count = self.messages_dropped
        #    self.messages_dropped = 0
        #    log.msg(format="log-publisher: %(dropped)d messages dropped",
        #            dropped=count,
        #            facility="foolscap.log.publisher",
        #            level=log.UNUSUAL)
        if not self.marked_for_sending:
            self.marked_for_sending = True
            eventually(self.start_sending)

    def _error(self, f):
        #print "PUBLISH FAILED: %s" % f
        self.unsubscribe()

class IncidentSubscription(Referenceable):
    implements(RISubscription)

    def __init__(self, observer, logger, publisher):
        self.observer = observer
        self.logger = logger
        self.publisher = publisher
        self.subscribed = False

    def subscribe(self, catch_up=False, since=None):
        self.subscribed = True
        self.logger.addImmediateIncidentObserver(self.send)
        self._nod_marker = self.observer.notifyOnDisconnect(self.unsubscribe)
        if catch_up:
            self.catch_up(since)

    def catch_up(self, since):
        new = dict(self.publisher.list_incident_names(since))
        for name in sorted(new.keys()):
            fn = new[name]
            trigger = self.publisher.get_incident_trigger(fn)
            if trigger:
                self.observer.callRemoteOnly("new_incident", name, trigger)
        self.observer.callRemoteOnly("done_with_incident_catchup")

    def unsubscribe(self):
        if self.subscribed:
            self.logger.removeImmediateIncidentObserver(self.send)
            self.observer.dontNotifyOnDisconnect(self._nod_marker)
            self.subscribed = False
    def remote_unsubscribe(self):
        return self.unsubscribe()

    def send(self, name, trigger):
        d = self.observer.callRemote("new_incident", name, trigger)
        d.addErrback(self._error)

    def _error(self, f):
        print "INCIDENT PUBLISH FAILED: %s" % f
        self.unsubscribe()


class LogPublisher(Referenceable):
    """Publish log events to anyone subscribed to our 'logport'.

    This class manages the subscriptions.

    Enable this by asking the Tub for a reference to me, or by telling the
    Tub to offer me to a log gatherer::

     lp = tub.getLogPort()
     rref.callRemote('have_a_logport', lp)
     print 'logport at:', tub.getLogPortFURL()

     tub.setOption('log-gatherer-furl', gatherer_furl)

    Running 'flogtool tail LOGPORT_FURL' will connect to the logport and
    print all events that subsequently get logged.

    To make the logport use the same furl from one run to the next, give the
    Tub a filename where it can store the furl. Make sure you do this before
    touching the logport::

     logport_furlfile = 'logport.furl'
     tub.setOption('logport-furlfile', logport_furlfile)

    If you're using a LogGatherer, pass its FURL into the Tub with
    tub.setOption('log-gatherer-furl'), or pass the name of a file where it
    is stored with tub.setOption('log-gatherer-furlfile'). This will cause
    the Tub to connect to the gatherer and grant it access to the logport.
    """

    implements(RILogPublisher)

    # the 'versions' dict used to live here in LogPublisher, but now it lives
    # in foolscap.logging.app_versions and should be accessed from there.
    # This copy remains for backwards-compatibility.
    versions = app_versions.versions

    def __init__(self, logger):
        self._logger = logger
        logger.setLogPort(self)

    def remote_get_versions(self):
        return app_versions.versions
    def remote_get_pid(self):
        return os.getpid()


    def remote_subscribe_to_all(self, observer, catch_up=False):
        s = Subscription(observer, self._logger)
        eventually(s.subscribe, catch_up)
        # allow the call to return before we send them any events
        return s

    def remote_unsubscribe(self, s):
        return s.unsubscribe()


    def trim(self, s, *suffixes):
        for suffix in suffixes:
            if s.endswith(suffix):
                s = s[:-len(suffix)]
        return s

    def list_incident_names(self, since=""):
        # yields (name, absfilename) pairs
        basedir = self._logger.logdir
        for fn in os.listdir(basedir):
            if fn.startswith("incident") and not fn.endswith(".tmp"):
                basename = self.trim(fn, ".bz2", ".flog")
                if basename > since:
                    yield (basename, os.path.join(basedir, fn))

    def get_incident_trigger(self, abs_fn):
        if abs_fn.endswith(".bz2"):
            import bz2
            f = bz2.BZ2File(abs_fn, "r")
        else:
            f = open(abs_fn, "rb")
        try:
            header = pickle.load(f)
        except (EOFError, ValueError):
            return None
        assert header["header"]["type"] == "incident"
        trigger = header["header"]["trigger"]
        return trigger

    def remote_list_incidents(self, since=""):
        incidents = {}
        for (name,fn) in self.list_incident_names(since):
            trigger = self.get_incident_trigger(fn)
            if trigger:
                incidents[name] = trigger
        return incidents

    def remote_get_incident(self, name):
        if not name.startswith("incident"):
            raise KeyError("bad incident name %s" % name)
        incident_dir = filepath.FilePath(self._logger.logdir)
        abs_fn = incident_dir.child(name).path + ".flog"
        try:
            if os.path.exists(abs_fn + ".bz2"):
                import bz2
                f = bz2.BZ2File(abs_fn + ".bz2", "r")
            else:
                f = open(abs_fn, "rb")
        except EnvironmentError:
            raise KeyError("no incident named %s" % name)
        header = pickle.load(f)["header"]
        events = []
        while True:
            try:
                wrapped = pickle.load(f)
            except (EOFError, ValueError):
                break
            events.append(wrapped["d"])
        f.close()
        return (header, events)

    def remote_subscribe_to_incidents(self, observer, catch_up=False, since=""):
        s = IncidentSubscription(observer, self._logger, self)
        eventually(s.subscribe, catch_up, since)
        # allow the call to return before we send them any events
        return s
