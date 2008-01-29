
from twisted.python import usage
import os, pickle, bz2, time

class FilterOptions(usage.Options):
    synopsis = "Usage: flogtool filter [options] OLDFILE.pickle NEWFILE.pickle"

    optParameters = [
        ["after", None, None, "include events after timestamp (seconds since epoch)"],
        ["before", None, None, "include events before timestamp"],
        ["strip-facility", None, None, "remove events with the given facility prefix"],
        ]

    optFlags = [
        ["verbose", "v", "emit event numbers during processing (useful to isolate an unloadable event pickle"],
        ]

    def parseArgs(self, oldfile, newfile=None):
        self.oldfile = oldfile
        self.newfile = newfile
        if newfile is None:
            print "modifying event file in place"
            self.newfile = oldfile

    def opt_after(self, arg):
        self['after'] = int(arg)

    def opt_before(self, arg):
        self['before'] = int(arg)


class Filter:

    def run(self, options):
        newfilename = options.newfile
        if options.newfile == options.oldfile:
            newfilename = newfilename + ".tmp"
        if options.newfile.endswith(".bz2"):
            newfile = bz2.BZ2File(newfilename, "w")
        else:
            newfile = open(newfilename, "w")
        after = options['after']
        if after is not None:
            print " --after: removing events before %s" % time.ctime(after)
        before = options['before']
        if before is not None:
            print " --before: removing events after %s" % time.ctime(before)
        strip_facility = options['strip-facility']
        if strip_facility is not None:
            print "--strip-facility: removing events for %s and children" % strip_facility
        total = 0
        copied = 0
        for e in self.get_events(options.oldfile):
            if options['verbose']:
                print e['d']['num']
            total += 1
            if before is not None and e['d']['time'] >= before:
                continue
            if after is not None and e['d']['time'] <= after:
                continue
            if (strip_facility is not None
                and e['d'].get('facility', "").startswith(strip_facility)):
                continue
            copied += 1
            pickle.dump(e, newfile, 2)
        newfile.close()
        if options.newfile == options.oldfile:
            os.rename(newfilename, options.newfile)
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
