
from zope.interface import implements
from twisted.internet import reactor
import foolscap
from foolscap import base32
from foolscap.eventual import fireEventually
from interfaces import RILogObserver

class LogPrinter(foolscap.Referenceable):
    implements(RILogObserver)

    def remote_msg(self, d):
        print d

def short_tubid_b2a(tubid):
    return base32.encode(tubid)[:8]

class LogTail:

    def run(self, target_furl):
        d = fireEventually(target_furl)
        d.addCallback(self.start)
        d.addErrback(self._error)
        print "starting.."
        reactor.run()

    def _error(self, f):
        print "ERROR", f
        reactor.stop()

    def start(self, target_furl):
        print "Connecting.."
        self._tub = foolscap.Tub()
        self._tub.startService()
        self._tub.connectTo(target_furl, self._got_logpublisher)

    def _got_logpublisher(self, publisher):
        print "Connected"
        publisher.notifyOnDisconnect(self._lost_logpublisher)
        lp = LogPrinter()
        d = publisher.callRemote("subscribe_to_all", lp)
        return d

    def _lost_logpublisher(publisher):
        print "Disconnected"


