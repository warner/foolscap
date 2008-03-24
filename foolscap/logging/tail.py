
import os, time
from zope.interface import implements
from twisted.internet import reactor
from twisted.python import usage
import foolscap
from foolscap import base32
from foolscap.eventual import fireEventually
from foolscap.logging import log
from interfaces import RILogObserver

class TailOptions(usage.Options):
    synopsis = "Usage: flogtool tail (LOGPORT.furl/furlfile/nodedir)"

    optFlags = [
        ("verbose", "v", "Show all event arguments"),
        ]

    def parseArgs(self, target):
        if target.startswith("pb:"):
            self.target_furl = target
        elif os.path.isfile(target):
            self.target_furl = open(target, "r").read().strip()
        elif os.path.isdir(target):
            fn = os.path.join(target, "logport.furl")
            self.target_furl = open(fn, "r").read().strip()
        else:
            raise RuntimeError("Can't use tail target: %s" % target)

class LogPrinter(foolscap.Referenceable):
    implements(RILogObserver)

    def __init__(self, options):
        self.options = options

    def remote_msg(self, d):
        if self.options['verbose']:
            self.simple_print(d)
        else:
            self.formatted_print(d)

    def simple_print(self, d):
        print d

    def formatted_print(self, d):
        time_s = time.strftime("%H:%M:%S", time.localtime(d['time']))
        time_s = time_s + "%.3f" % (d['time'] - int(d['time']))

        msg = log.format_message(d)
        level = d.get('level', log.OPERATIONAL)

        tubid = "" # TODO
        print "%s L%d [%s]#%d %s" % (time_s, level, tubid, d["num"], msg)
        if 'failure' in d:
            print " FAILURE:"
            lines = str(d['failure']).split("\n")
            for line in lines:
                print " %s" % (line,)


def short_tubid_b2a(tubid):
    return base32.encode(tubid)[:8]

class LogTail:
    def __init__(self, options):
        self.options = options

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
        lp = LogPrinter(self.options)
        d = publisher.callRemote("subscribe_to_all", lp)
        return d

    def _lost_logpublisher(publisher):
        print "Disconnected"


