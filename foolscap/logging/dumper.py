
import sys, pickle, time, errno
from twisted.python import usage
from foolscap.logging.log import format_message

class DumpOptions(usage.Options):
    stdout = sys.stdout
    stderr = sys.stderr
    synopsis = "Usage: flogtool dump DUMPFILE.pickle"
    optParameters = [
        ("timestamps", "t", "short-local",
         "Format for timestamps: short-local, utc, long-local"),
        ]
    optFlags = [
        ("verbose", "v", "Show all event arguments"),
        ("just-numbers", "n", "Show only event numbers"),
        ("rx-time", "r", "Show event receipt time (in addition to emit time)"),
        ]

    def opt_timestamps(self, arg):
        if arg not in ("short-local", "utc", "long-local"):
            raise usage.UsageError("--timestamps= must be one of 'short-local', 'utc', or 'long-local'")
        self["timestamps"] = arg

    def parseArgs(self, dumpfile):
        self.dumpfile = dumpfile

class LogDumper:
    def __init__(self):
        self.trigger = None

    def run(self, options):
        self.options = options
        f = self.open_dumpfile()
        try:
            self.start(f)
        except EnvironmentError, e:
            # "flogtool dump FLOGFILE |less" is very common, and if you quit
            # it early with "q", the stdout pipe is broken and python dies
            # with a messy stacktrace. Catch and ignore that.
            if e.errno == errno.EPIPE:
                sys.exit(1)
            raise

    def start(self, f):
        stdout = self.options.stdout
        for e in self.get_events(f):
            if "header" in e:
                h = e["header"]
                if h["type"] == "incident":
                    t = h["trigger"]
                    self.trigger = (t["incarnation"], t["num"])
                if self.options['verbose']:
                    print >>stdout, e
                if not self.options["just-numbers"] and not self.options["verbose"]:
                    if "versions" in h:
                        print >>stdout, "Application versions (embedded in logfile):"
                        versions = h["versions"]
                        longest = max([len(name) for name in versions] + [0])
                        fmt = "%" + str(longest) + "s: %s"
                        for name in sorted(versions.keys()):
                            print >>stdout, fmt % (name, versions[name])
                    if "pid" in h:
                        print >>stdout, "PID: %s" % (h["pid"],)
                    print >>stdout
            if "d" in e:
                self.print_event(e)

    def format_time(self, when):
        mode = self.options["timestamps"]
        if mode == "short-local":
            time_s = time.strftime("%H:%M:%S", time.localtime(when))
            time_s = time_s + ".%03d" % int(1000*(when - int(when)))
        elif mode == "long-local":
            lt = time.localtime(when)
            time_s = time.strftime("%Y-%m-%d_%H:%M:%S", lt)
            time_s = time_s + ".%06d" % int(1000000*(when - int(when)))
            time_s += time.strftime("%z", lt)
        elif mode == "utc":
            time_s = time.strftime("%Y-%m-%d_%H:%M:%S", time.gmtime(when))
            time_s = time_s + ".%06d" % int(1000000*(when - int(when)))
            time_s += "Z"
        return time_s

    def print_event(self, e):
        short = e['from'][:8]
        d = e['d']
        when = self.format_time(d['time'])
        if self.options['just-numbers']:
            print >>self.options.stdout, when, d.get('num')
            return

        eid = (d["incarnation"], d["num"])
        # let's mark the trigger event from incident reports with
        # [INCIDENT-TRIGGER] at the end of the line
        is_trigger = bool(self.trigger and (eid == self.trigger))
        text = format_message(d)

        t = "%s#%d " % (short, d['num'])
        if self.options['rx-time']:
            rx_when = self.format_time(e['rx_time'])
            t += "rx(%s) " % rx_when
            t += "emit(%s)" % when
        else:
            t += "%s" % when
        t += ": %s" % text
        if self.options['verbose']:
            t += ": %r" % d
        if is_trigger:
            t += " [INCIDENT-TRIGGER]"
        print >>self.options.stdout, t
        if 'failure' in d:
            print >>self.options.stdout," FAILURE:"
            lines = str(d['failure']).split("\n")
            for line in lines:
                print >>self.options.stdout, " %s" % (line,)

    def open_dumpfile(self):
        fn = self.options.dumpfile
        if fn.endswith(".bz2"):
            import bz2
            f = bz2.BZ2File(fn, "r")
        else:
            f = open(fn, "rb")
        return f

    def get_events(self, f):
        while True:
            try:
                e = pickle.load(f)
                yield e
            except EOFError:
                break

