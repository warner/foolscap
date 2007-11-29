
import pickle
from foolscap.logging.tail import short_tubid_b2a

class LogDumper:

    def run(self, options):
        self.start(options)

    def start(self, options):
        for e in self.get_events(options):
            short = short_tubid_b2a(e['from'])
            when = e['rx_time']
            print "%s %r: %r" % (short, when, e['d'])

    def get_events(self, options):
        fn = options.dumpfile
        f = open(fn, "rb")
        while True:
            try:
                e = pickle.load(f)
                yield e
            except EOFError:
                break

