
import os, sys, time, pickle
from zope.interface import implements
from twisted.internet import reactor
from twisted.python import usage
from foolscap import base32
from foolscap.api import Tub, Referenceable, fireEventually
from foolscap.logging import log
from foolscap.referenceable import SturdyRef
from interfaces import RILogObserver

def short_tubid_b2a(tubid):
    return base32.encode(tubid)[:8]

class LogSaver(Referenceable):
    implements(RILogObserver)
    def __init__(self, nodeid_s, savefile):
        self.nodeid_s = nodeid_s
        self.f = savefile

    def emit_header(self, versions, pid):
        header = {"header": {"type": "tail",
                             "versions": versions}}
        if pid is not None:
            header["header"]["pid"] = pid
        pickle.dump(header, self.f)

    def remote_msg(self, d):
        e = {"from": self.nodeid_s,
             "rx_time": time.time(),
             "d": d,
             }
        try:
            pickle.dump(e, self.f)
        except Exception, ex:
            print "GATHERER: unable to pickle %s: %s" % (e, ex)

    def disconnected(self):
        del self.f

class TailOptions(usage.Options):
    synopsis = "Usage: flogtool tail (LOGPORT.furl/furlfile/nodedir)"

    optFlags = [
        ("verbose", "v", "Show all event arguments"),
        ("catch-up", "c", "Catch up with recent events"),
        ]
    optParameters = [
        ("save-to", "s", None,
         "Save events to the given file. The file will be overwritten."),
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

class LogPrinter(Referenceable):
    implements(RILogObserver)

    def __init__(self, options, target_tubid_s, output=sys.stdout):
        self.options = options
        self.saver = None
        if options["save-to"]:
            f = open(options["save-to"], "wb")
            self.saver = LogSaver(target_tubid_s[:8], f)
        self.output = output

    def got_versions(self, versions, pid=None):
        print >>self.output, "Remote Versions:"
        for k in sorted(versions.keys()):
            print >>self.output, " %s: %s" % (k, versions[k])
        if self.saver:
            self.saver.emit_header(versions, pid)

    def remote_msg(self, d):
        if self.options['verbose']:
            self.simple_print(d)
        else:
            self.formatted_print(d)
        if self.saver:
            self.saver.remote_msg(d)

    def simple_print(self, d):
        print >>self.output, d

    def formatted_print(self, d):
        time_s = time.strftime("%H:%M:%S", time.localtime(d['time']))
        time_s = time_s + ".%03d" % int(1000*(d['time'] - int(d['time'])))

        msg = log.format_message(d)
        level = d.get('level', log.OPERATIONAL)

        tubid = "" # TODO
        print >>self.output, "%s L%d [%s]#%d %s" % (time_s, level, tubid,
                                                    d["num"], msg)
        if 'failure' in d:
            print >>self.output, " FAILURE:"
            lines = str(d['failure']).split("\n")
            for line in lines:
                print >>self.output, " %s" % (line,)


class LogTail:
    def __init__(self, options):
        self.options = options

    def run(self, target_furl):
        target_tubid = SturdyRef(target_furl).getTubRef().getTubID()
        d = fireEventually(target_furl)
        d.addCallback(self.start, target_tubid)
        d.addErrback(self._error)
        print "starting.."
        reactor.run()

    def _error(self, f):
        print "ERROR", f
        reactor.stop()

    def start(self, target_furl, target_tubid):
        print "Connecting.."
        self._tub = Tub()
        self._tub.startService()
        self._tub.connectTo(target_furl, self._got_logpublisher, target_tubid)

    def _got_logpublisher(self, publisher, target_tubid):
        d = publisher.callRemote("get_pid")
        def _announce(pid_or_failure):
            if isinstance(pid_or_failure, int):
                print "Connected (to pid %d)" % pid_or_failure
                return pid_or_failure
            else:
                # the logport is probably foolscap-0.2.8 or earlier and
                # doesn't offer get_pid()
                print "Connected (unable to get pid)"
                return None
        d.addBoth(_announce)
        publisher.notifyOnDisconnect(self._lost_logpublisher)
        lp = LogPrinter(self.options, target_tubid)
        def _ask_for_versions(pid):
            d = publisher.callRemote("get_versions")
            d.addCallback(lp.got_versions, pid)
            return d
        d.addCallback(_ask_for_versions)
        catch_up = bool(self.options["catch-up"])
        if catch_up:
            d.addCallback(lambda res:
                          publisher.callRemote("subscribe_to_all", lp, True))
        else:
            # provide compatibility with foolscap-0.2.4 and earlier, which
            # didn't accept a catchup= argument
            d.addCallback(lambda res:
                          publisher.callRemote("subscribe_to_all", lp))
        d.addErrback(self._error)
        return d

    def _lost_logpublisher(publisher):
        print "Disconnected"


