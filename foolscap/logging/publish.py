
from zope.interface import implements
import twisted
import foolscap
from foolscap.referenceable import Referenceable
from foolscap.logging.interfaces import RISubscription, RILogPublisher

class Subscription(Referenceable):
    implements(RISubscription)
    # used as a marker, but has no actual behavior

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
        self._subscribers = {} # k: Subscription instance, v: RILogObserver
        self._notifyOnDisconnectors = {}

    def remote_get_versions(self):
        return self.versions

    def remote_subscribe_to_all(self, observer):
        s = Subscription()
        self._subscribers[s] = observer
        self._logger.addObserver(observer)
        c = observer.notifyOnDisconnect(self.remote_unsubscribe, s)
        self._notifyOnDisconnectors[s] = c
        return s

    def remote_unsubscribe(self, s):
        observer = self._subscribers.pop(s)
        self._logger.removeObserver(observer)
        c = self._notifyOnDisconnectors.pop(s)
        observer.dontNotifyOnDisconnect(c)

