
import os
import pickle
from zope.interface import implements
import twisted
from twisted.python import filepath
import foolscap
from foolscap.referenceable import Referenceable
from foolscap.logging.interfaces import RISubscription, RILogPublisher
from foolscap.eventual import eventually

class Subscription(Referenceable):
    implements(RISubscription)
    # used as a marker, but has no remote methods. We use this to manage
    # the outbound size-limited queue.

    def __init__(self, observer, logger):
        self.observer = observer
        self.logger = logger
        self.subscribed = False

    def subscribe(self, catch_up):
        self.subscribed = True
        self.logger.addObserver(self.send)
        self._nod_marker = self.observer.notifyOnDisconnect(self.unsubscribe)
        if catch_up:
            # send any catch-up events in a single batch, before we allow any
            # other events to be generated (and sent). This lets the
            # subscriber see events in sorted order.
            events = list(self.logger.get_buffered_events())
            events.sort(lambda a,b: cmp(a['num'], b['num']))
            for e in events:
                self.observer.callRemoteOnly("msg", e)

    def unsubscribe(self):
        if self.subscribed:
            self.logger.removeObserver(self.send)
            self.observer.dontNotifyOnDisconnect(self._nod_marker)
            self.subscribed = False

    def send(self, event):
        self.observer.callRemoteOnly("msg", event)
        #def _oops(f):
        #    print "PUBLISH FAILED: %s" % f
        #d.addErrback(_oops)

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

    # you might want to modify this to include the version of your
    # application. Just do:
    #  from foolscap.logging.publish import LogPublisher
    #  LogPublisher.versions['myapp'] = myversion

    versions = {"twisted": twisted.__version__,
                "foolscap": foolscap.__version__,
                }

    def __init__(self, logger):
        self._logger = logger
        logger.setLogPort(self)

    def remote_get_versions(self):
        return self.versions
    def remote_get_pid(self):
        return os.getpid()


    def remote_subscribe_to_all(self, observer, catch_up=False):
        s = Subscription(observer, self._logger)
        eventually(s.subscribe, catch_up)
        # allow the call to return before we send them any events
        return s

    def remote_unsubscribe(self, s):
        return s.unsubscribe()


    def remote_list_incidents(self):
        basedir = self._logger.logdir
        filenames = [fn
                     for fn in os.listdir(basedir)
                     if fn.startswith("incident") and not fn.endswith(".tmp")]
        filenames.sort()
        incidents = {}
        for fn in filenames:
            abs_fn = os.path.join(basedir, fn)
            if abs_fn.endswith(".bz2"):
                import bz2
                f = bz2.BZ2File(abs_fn, "r")
            else:
                f = open(abs_fn, "rb")
            try:
                header = pickle.load(f)
            except (EOFError, ValueError):
                continue
            assert header["header"]["type"] == "incident"
            trigger = header["header"]["trigger"]
            incidents[fn] = ("local", trigger["incarnation"], trigger)
        return incidents

    def remote_get_incident(self, fn):
        incident_dir = filepath.FilePath(self._logger.logdir)
        abs_fn = incident_dir.child(fn).path
        if abs_fn.endswith(".bz2"):
            import bz2
            f = bz2.BZ2File(abs_fn, "r")
        else:
            f = open(abs_fn, "rb")
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
