
from twisted.python import usage
import sys, os, pickle, bz2, time
from foolscap.logging import log

class FilterOptions(usage.Options):
    stdout = sys.stdout
    stderr = sys.stderr
    synopsis = "Usage: flogtool filter [options] OLDFILE.pickle NEWFILE.pickle"

    optParameters = [
        ["after", None, None, "include events after timestamp (seconds since epoch)"],
        ["before", None, None, "include events before timestamp"],
        ["strip-facility", None, None, "remove events with the given facility prefix"],
        ["above", None, None, "include events at the given severity level or above"],
        ["from", None, None, "include events from the given tubid prefix"],
        ]

    optFlags = [
        ["verbose", "v", "emit event numbers during processing (useful to isolate an unloadable event pickle"],
        ]

    def parseArgs(self, oldfile, newfile=None):
        self.oldfile = oldfile
        self.newfile = newfile
        if newfile is None:
            self.newfile = oldfile

    def opt_after(self, arg):
        self['after'] = int(arg)

    def opt_before(self, arg):
        self['before'] = int(arg)

    def opt_above(self, arg):
        try:
            self['above'] = int(arg)
        except ValueError:
            levelmap = {"NOISY": log.NOISY,
                        "OPERATIONAL": log.OPERATIONAL,
                        "UNUSUAL": log.UNUSUAL,
                        "INFREQUENT": log.INFREQUENT,
                        "CURIOUS": log.CURIOUS,
                        "WEIRD": log.WEIRD,
                        "SCARY": log.SCARY,
                        "BAD": log.BAD,
                        }
            self['above'] = levelmap[arg]


class Filter:

    def run(self, options):
        stdout = options.stdout
        newfilename = options.newfile
        if options.newfile == options.oldfile:
            print >>stdout, "modifying event file in place"
            newfilename = newfilename + ".tmp"
        if options.newfile.endswith(".bz2"):
            newfile = bz2.BZ2File(newfilename, "w")
        else:
            newfile = open(newfilename, "w")
        after = options['after']
        if after is not None:
            print >>stdout, " --after: removing events before %s" % time.ctime(after)
        before = options['before']
        if before is not None:
            print >>stdout, " --before: removing events after %s" % time.ctime(before)
        above = options['above']
        if above:
            print >>stdout, " --above: removing events below level %d" % above
        from_tubid = options['from']
        if from_tubid:
            print >>stdout, " --from: retaining events only from tubid prefix %s" % from_tubid
        strip_facility = options['strip-facility']
        if strip_facility is not None:
            print >>stdout, "--strip-facility: removing events for %s and children" % strip_facility
        total = 0
        copied = 0
        for e in self.get_events(options.oldfile):
            if options['verbose']:
                if "d" in e:
                    print >>stdout, e['d']['num']
                else:
                    print >>stdout, "HEADER"
            total += 1
            if "d" in e:
                if before is not None and e['d']['time'] >= before:
                    continue
                if after is not None and e['d']['time'] <= after:
                    continue
                if above is not None and e['d']['level'] < above:
                    continue
                if from_tubid is not None and not e['from'].startswith(from_tubid):
                    continue
                if (strip_facility is not None
                    and e['d'].get('facility', "").startswith(strip_facility)):
                    continue
            copied += 1
            pickle.dump(e, newfile, 2)
        newfile.close()
        if options.newfile == options.oldfile:
            os.rename(newfilename, options.newfile)
        print >>stdout, "copied %d of %d events into new file" % (copied, total)

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
