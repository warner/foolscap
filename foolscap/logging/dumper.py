
import sys, pickle
from twisted.python import usage
from foolscap.logging.log import format_message

class DumpOptions(usage.Options):
    synopsis = "Usage: flogtool dump DUMPFILE.pickle"
    optFlags = [
        ("verbose", "v", "Show all event arguments"),
        ("just-numbers", "n", "Show only event numbers"),
        ]

    def parseArgs(self, dumpfile):
        self.dumpfile = dumpfile

class LogDumper:

    def run(self, options):
        try:
            self.start(options)
        except IOError:
            sys.exit(1)

    def start(self, options):
        for e in self.get_events(options):
            self.print_event(e, options)

    def print_event(self, e, options):
        short = e['from'][:8]
        when = e['rx_time']
        d = e['d']
        if options['just-numbers']:
            print when, d.get('num')
            return
        text = format_message(d)

        t = "%s %r: %s" % (short, when, text)
        if options['verbose']:
            t += ": %r" % d
        print t

    def get_events(self, options):
        fn = options.dumpfile
        if fn.endswith(".bz2"):
            import bz2
            f = bz2.BZ2File(fn, "r")
        else:
            f = open(fn, "rb")
        while True:
            try:
                e = pickle.load(f)
                yield e
            except EOFError:
                break

