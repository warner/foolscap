from __future__ import print_function, unicode_literals
import six, sys, errno, textwrap
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
        except EnvironmentError as e:
            # "flogtool dump FLOGFILE |less" is very common, and if you quit
            # it early with "q", the stdout pipe is broken and python dies
            # with a messy stacktrace. Catch and ignore that.
            if e.errno == errno.EPIPE:
                return 1
            raise
        except flogfile.ThisIsActuallyAFurlFileError:
            print(textwrap.dedent(u"""\
                Error: %s appears to be a FURL file.
                Perhaps you meant to run 'flogtool tail' instead of 'flogtool dump'?"""
                % (options.dumpfile,)), file=options.stderr)
            return 1
        except flogfile.EvilPickleFlogFile:
            print(textwrap.dedent("""\
            Error: %s appears to be an old-style
            (pickle-based) flogfile, which cannot be loaded safely. If you
            wish to allow the author of the flogfile to take over your
            computer (and incidentally allow you to view the content), please
            use the flogtool from a copy of foolscap-0.12.7 or earlier."""
                                                    % (options.dumpfile,)), file=options.stderr)
            return 1
        except flogfile.BadMagic:
            print(textwrap.dedent("""\
            Error: %s does not appear to be a flogfile.
            """ % (options.dumpfile,)), file=options.stderr)
            return 1
        except ValueError as ex:
            print(u"truncated pickle file? (%s): %s" % (options.dumpfile, ex), file=options.stderr)
            return 1

    def print_header(self, e, options):
        stdout = options.stdout
        h = e["header"]
        if h["type"] == "incident":
            t = h["trigger"]
            self.trigger = (t["incarnation"], t["num"])
        if options['verbose']:
            print(six.text_type(e), file=stdout)
        if not options["just-numbers"] and not options["verbose"]:
            if "versions" in h:
                print(u"Application versions (embedded in logfile):", file=stdout)
                versions = h["versions"]
                longest = max([len(name) for name in versions] + [0])
                fmt = "%" + str(longest) + "s: %s"
                for name in sorted(versions.keys()):
                    print(fmt % (name, versions[name]), file=stdout)
            if "pid" in h:
                print(u"PID: %s" % (h["pid"],), file=stdout)
            print(u"", file=stdout)

    def print_event(self, e, options):
        stdout = options.stdout
        short = e['from'][:8]
        d = e['d']
        when = format_time(d['time'], options["timestamps"])
        if options['just-numbers']:
            print(six.text_type(when), six.text_type(d.get('num')), file=stdout)
            return

        eid = (d["incarnation"], d["num"])
        # let's mark the trigger event from incident reports with
        # [INCIDENT-TRIGGER] at the end of the line
        is_trigger = bool(self.trigger and (eid == self.trigger))
        try:
            text = format_message(d)
        except:
            print(u"unformattable event", d)
            raise

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
        print(t, file=stdout)
        if 'failure' in d:
            print(u" FAILURE:", file=stdout)
            lines = str(d['failure'].get('str', d['failure'])).split("\n")
            for line in lines:
                print(u" %s" % (line,), file=stdout)
