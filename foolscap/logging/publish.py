
import os
from zope.interface import implements
import twisted
from twisted.python import log as twisted_log
from twisted.application import service
import foolscap
from foolscap import Referenceable
from interfaces import RISubscription, RILogPublisher

class Subscription(Referenceable):
    implements(RISubscription)
    # used as a marker, but has no actual behavior

class LogPublisher(Referenceable, service.MultiService):
    """Publish log events to anyone subscribed to our 'logport'.

    Create this and attach it to a Tub by doing this::

     lp = LogPublisher()
     lp.setServiceParent(tub)
     logport_furl = lp.getLogport()

    It will hook into the twisted log system and make them available to a
    remote reader. Give that reader the logport_furl so they can connect.
    Running 'flogtool tail LOGPORT_FURL' will connect to the logport and
    print all logs thus received.

    To make the logport use the same furl from one run to the next, give it a
    filename where it can store the furl::

     logport_furlfile = 'logport.furl'
     lp = LogPublisher(logport_furlfile)

    If you're using a LogGatherer, pass its FURL to gathererFurl=, or a file
    where it is stored to gathererFurlFile= . This will cause the
    LogPublisher to connect and offer itself to the gatherer.
    """

    implements(RILogPublisher)
    name = "log_publisher"

    def __init__(self, furlFile=None, gathererFurl=None, gathererFurlFile=None):
        service.MultiService.__init__(self)
        self._subscribers = {}
        self._notifyOnDisconnectors = {}
        self._furlFile = furlFile
        self._gatherer_furl = None
        if gathererFurlFile:
            try:
                gatherer_furl = open(gathererFurlFile, "r").read().strip()
                self._gatherer_furl = gatherer_furl
            except EnvironmentError:
                pass
        else:
            self._gatherer_furl = gathererFurl

    def startService(self):
        service.MultiService.startService(self)
        self._my_furl = self.parent.registerReference(self,
                                                      furlFile=self._furlFile)
        if self._furlFile:
            os.chmod(self._furlFile, 0600)
        if self._gatherer_furl:
            self.parent.connectTo(self._gatherer_furl,
                                  self._log_gatherer_connected)

        twisted_log.addObserver(self._twisted_log_observer)

    def stopService(self):
        twisted_log.removeObserver(self._twisted_log_observer)
        return service.MultiService.stopService(self)

    def _log_gatherer_connected(self, rref):
        rref.callRemote('logport', self.parent.tubID, self)

    def getLogport(self):
        return self._my_furl

    def _twisted_log_observer(self, d):
        # Twisted will remove this for us if it fails.

        # keys:
        #  ['message']: *args
        #  ['time']: float
        #  ['isError']: bool, usually False
        #  ['system']: string

        for o in self._subscribers.values():
            o.callRemoteOnly("msg", d)
            #d2 = o.callRemote("msg", d)
            #def _oops(f):
            #    print "PUBLISH FAILED: %s" % f
            #d2.addErrback(_oops)

        #f = open("/tmp/f.out", "a")
        #print >>f, d['message']
        #f.close()

    def remote_get_versions(self):
        # you might want to override this to include the version of your
        # application.
        versions = {"twisted": twisted.__version__,
                    "foolscap": foolscap.__version__,
                    }
        return versions

    def remote_subscribe_to_all(self, observer):
        s = Subscription()
        self._subscribers[s] = observer
        c = observer.notifyOnDisconnect(self.remote_unsubscribe, s)
        self._notifyOnDisconnectors[s] = c
        return s

    def remote_unsubscribe(self, s):
        observer = self._subscribers.pop(s)
        c = self._notifyOnDisconnectors.pop(s)
        observer.dontNotifyOnDisconnect(c)

