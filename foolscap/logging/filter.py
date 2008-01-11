
from twisted.python import usage
import pickle, bz2, time

class FilterOptions(usage.Options):
    synopsis = "Usage: flogtool filter [options] OLDFILE.pickle NEWFILE.pickle"

    optParameters = [
        ["after", None, None, "include events after timestamp (seconds since epoch)"],
        ["before", None, None, "include events before timestamp"],
        ]

    def parseArgs(self, oldfile, newfile):
        self.oldfile = oldfile
        self.newfile = newfile

    def opt_after(self, arg):
        self['after'] = int(arg)

    def opt_before(self, arg):
        self['before'] = int(arg)


class Filter:

    def run(self, options):
        if options.newfile.endswith(".bz2"):
            newfile = bz2.BZ2File(options.newfile, "w")
        else:
            newfile = open(options.newfile, "w")
        after = options['after']
        if after is not None:
            print " --after: removing events before %s" % time.ctime(after)
        before = options['before']
        if before is not None:
            print " --before: removing events after %s" % time.ctime(before)
        total = 0
        copied = 0
        for e in self.get_events(options.oldfile):
            total += 1
            if before is not None and e['d']['time'] >= before:
                continue
            if after is not None and e['d']['time'] <= after:
                continue
            copied += 1
            pickle.dump(e, newfile, 2)
        newfile.close()
        print "copied %d of %d events into new file" % (copied, total)

    def get_events(self, fn):
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
