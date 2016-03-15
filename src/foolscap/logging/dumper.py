
import sys, errno
from twisted.python import usage
from foolscap.logging import flogfile
from foolscap.logging.log import format_message
from foolscap.util import format_time, FORMAT_TIME_MODES

class DumpOptions(usage.Options):
    stdout = sys.stdout
    stderr = sys.stderr
    synopsis = "Usage: flogtool dump DUMPFILE.flog[.bz2]"
    optParameters = [
        ("timestamps", "t", "short-local",
         "Format for timestamps: " + " ".join(FORMAT_TIME_MODES)),
        ]
    optFlags = [
        ("verbose", "v", "Show all event arguments"),
        ("just-numbers", "n", "Show only event numbers"),
        ("rx-time", "r", "Show event receipt time (in addition to emit time)"),
        ]

    def opt_timestamps(self, arg):
        if arg not in FORMAT_TIME_MODES:
            raise usage.UsageError("--timestamps= must be one of (%s)" %
                                   ", ".join(FORMAT_TIME_MODES))
        self["timestamps"] = arg

    def parseArgs(self, dumpfile):
        self.dumpfile = dumpfile

class LogDumper:
    def __init__(self):
        self.trigger = None

    def run(self, options):
        try:
            for e in flogfile.get_events(options.dumpfile):
                if "header" in e:
                    self.print_header(e, options)
                if "d" in e:
                    self.print_event(e, options)
        except EnvironmentError, e:
            # "flogtool dump FLOGFILE |less" is very common, and if you quit
            # it early with "q", the stdout pipe is broken and python dies
            # with a messy stacktrace. Catch and ignore that.
            if e.errno == errno.EPIPE:
                return 1
            raise
        except flogfile.ThisIsActuallyAFurlFileError:
            print >>options.stderr, (
                "Error: %s appears to be a FURL file.\n"
                "Perhaps you meant to run"
                " 'flogtool tail' instead of 'flogtool dump'?"
                % (options.dumpfile,))
            return 1
        except ValueError, ex:
            print >>options.stderr, (
                "truncated pickle file? (%s): %s" % (options.dumpfile, ex))
            return 1

    def print_header(self, e, options):
        stdout = options.stdout
        h = e["header"]
        if h["type"] == "incident":
            t = h["trigger"]
            self.trigger = (t["incarnation"], t["num"])
        if options['verbose']:
            print >>stdout, e
        if not options["just-numbers"] and not options["verbose"]:
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

    def print_event(self, e, options):
        stdout = options.stdout
        short = e['from'][:8]
        d = e['d']
        when = format_time(d['time'], options["timestamps"])
        if options['just-numbers']:
            print >>stdout, when, d.get('num')
            return

        eid = (d["incarnation"], d["num"])
        # let's mark the trigger event from incident reports with
        # [INCIDENT-TRIGGER] at the end of the line
        is_trigger = bool(self.trigger and (eid == self.trigger))
        text = format_message(d)

        t = "%s#%d " % (short, d['num'])
        if options['rx-time']:
            rx_when = format_time(e['rx_time'], options["timestamps"])
            t += "rx(%s) " % rx_when
            t += "emit(%s)" % when
        else:
            t += "%s" % when
        t += ": %s" % text
        if options['verbose']:
            t += ": %r" % d
        if is_trigger:
            t += " [INCIDENT-TRIGGER]"
        print >>stdout, t
        if 'failure' in d:
            print >>stdout," FAILURE:"
            lines = str(d['failure']).split("\n")
            for line in lines:
                print >>stdout, " %s" % (line,)
