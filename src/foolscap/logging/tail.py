from __future__ import print_function, unicode_literals
import six, os, sys, time
from zope.interface import implementer
from twisted.internet import reactor
from twisted.python import usage
from foolscap import base32
from foolscap.api import Tub, Referenceable, fireEventually
from foolscap.logging import log, flogfile
from foolscap.referenceable import SturdyRef
from foolscap.util import format_time, FORMAT_TIME_MODES, ensure_dict_str, ensure_dict_str_keys
from .interfaces import RILogObserver

def short_tubid_b2a(tubid):
    return base32.encode(tubid)[:8]

@implementer(RILogObserver)
class LogSaver(Referenceable):
    def __init__(self, nodeid_s, savefile):
        self.nodeid_s = nodeid_s
        self.f = savefile # we own this, and may close it
        self.f.write(flogfile.MAGIC)

    def emit_header(self, versions, pid):
        flogfile.serialize_header(self.f, "tail", versions=versions, pid=pid)

    def remote_msg(self, d):
        try:
            flogfile.serialize_wrapper(self.f, d,
                                       from_=self.nodeid_s,
                                       rx_time=time.time())
        except Exception as ex:
            print("GATHERER: unable to serialize %s: %s" % (d, ex))

    def disconnected(self):
        self.f.close()
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
        ("timestamps", "t", "short-local",
         "Format for timestamps: " + " ".join(FORMAT_TIME_MODES)),
        ]

    def opt_timestamps(self, arg):
        if arg not in FORMAT_TIME_MODES:
            raise usage.UsageError("--timestamps= must be one of (%s)" %
                                   ", ".join(FORMAT_TIME_MODES))
        self["timestamps"] = arg

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

@implementer(RILogObserver)
class LogPrinter(Referenceable):
    def __init__(self, options, target_tubid_s, output=sys.stdout):
        self.options = options
        self.saver = None
        if options["save-to"]:
            self.saver = LogSaver(target_tubid_s[:8],
                                  open(options["save-to"], "wb"))
        self.output = output

    def got_versions(self, versions, pid=None):
        versions = ensure_dict_str(versions)
        print("Remote Versions:", file=self.output)
        for k in sorted(versions.keys()):
            print(" %s: %s" % (k, versions[k]), file=self.output)
        if self.saver:
            self.saver.emit_header(versions, pid)

    def remote_msg(self, d):
        d = ensure_dict_str_keys(d)
        if self.options['verbose']:
            self.simple_print(d)
        else:
            self.formatted_print(d)
        if self.saver:
            self.saver.remote_msg(d)

    def simple_print(self, d):
        print(six.text_type(d), file=self.output)

    def formatted_print(self, d):
        time_s = format_time(d['time'], self.options["timestamps"])

        msg = log.format_message(d)
        level = d.get('level', log.OPERATIONAL)

        tubid = "" # TODO
        print("%s L%d [%s]#%d %s" % (time_s, level, tubid,
                                     d["num"], msg), file=self.output)
        if 'failure' in d:
            print(" FAILURE:", file=self.output)
            lines = str(d['failure']).split("\n")
            for line in lines:
                print(" %s" % (line,), file=self.output)


class LogTail:
    def __init__(self, options):
        self.options = options

    def run(self, target_furl):
        target_tubid = SturdyRef(target_furl).getTubRef().getTubID()
        d = fireEventually(target_furl)
        d.addCallback(self.start, target_tubid)
        d.addErrback(self._error)
        print("starting..")
        reactor.run()

    def _error(self, f):
        print("ERROR", f)
        reactor.stop()

    def start(self, target_furl, target_tubid):
        print("Connecting..")
        self._tub = Tub()
        self._tub.startService()
        self._tub.connectTo(target_furl, self._got_logpublisher, target_tubid)

    def _got_logpublisher(self, publisher, target_tubid):
        d = publisher.callRemote("get_pid")
        def _announce(pid_or_failure):
            if isinstance(pid_or_failure, int):
                print("Connected (to pid %d)" % pid_or_failure)
                return pid_or_failure
            else:
                # the logport is probably foolscap-0.2.8 or earlier and
                # doesn't offer get_pid()
                print("Connected (unable to get pid)")
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
        print("Disconnected")


