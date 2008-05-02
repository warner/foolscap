
import sys, pickle, time
from twisted.python import usage
from foolscap.logging.log import format_message

class DumpOptions(usage.Options):
    synopsis = "Usage: flogtool dump DUMPFILE.pickle"
    optFlags = [
        ("verbose", "v", "Show all event arguments"),
        ("just-numbers", "n", "Show only event numbers"),
        ("rx-time", "r", "Show event receipt time (in addition to emit time)"),
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
            if "d" in e:
                self.print_event(e, options)

    def format_time(self, when):
        time_s = time.strftime("%H:%M:%S", time.localtime(when))
        time_s = time_s + ".%03d" % int(1000*(when - int(when)))
        return time_s

    def print_event(self, e, options):
        short = e['from'][:8]
        d = e['d']
        when = self.format_time(d['time'])
        if options['just-numbers']:
            print when, d.get('num')
            return
        text = format_message(d)

        t = "%s#%d " % (short, d['num'])
        if options['rx-time']:
            rx_when = self.format_time(e['rx_time'])
            t += "rx(%s) " % rx_when
            t += "emit(%s)" % when
        else:
            t += "%s" % when
        t += ": %s" % text
        if options['verbose']:
            t += ": %r" % d
        print t
        if 'failure' in d:
            print " FAILURE:"
            lines = str(d['failure']).split("\n")
            for line in lines:
                print " %s" % (line,)

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

