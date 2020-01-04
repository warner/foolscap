from __future__ import print_function
import six
from twisted.python import usage
import sys, os, bz2, time
from foolscap.logging import log, flogfile
from foolscap.util import move_into_place

class FilterOptions(usage.Options):
    stdout = sys.stdout
    stderr = sys.stderr
    synopsis = "Usage: flogtool filter [options] OLDFILE NEWFILE"

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
            print(u"modifying event file in place", file=stdout)
            newfilename = newfilename + ".tmp"
        if options.newfile.endswith(".bz2"):
            newfile = bz2.BZ2File(newfilename, "w")
        else:
            newfile = open(newfilename, "wb")
        newfile.write(flogfile.MAGIC)
        after = options['after']
        if after is not None:
            print(u" --after: removing events before %s" % time.ctime(after), file=stdout)
        before = options['before']
        if before is not None:
            print(u" --before: removing events after %s" % time.ctime(before), file=stdout)
        above = options['above']
        if above:
            print(u" --above: removing events below level %d" % above, file=stdout)
        from_tubid = options['from']
        if from_tubid:
            print(u" --from: retaining events only from tubid prefix %s" % from_tubid, file=stdout)
        strip_facility = options['strip-facility']
        if strip_facility is not None:
            print(u"--strip-facility: removing events for %s and children" % strip_facility, file=stdout)
        total = 0
        copied = 0
        for e in flogfile.get_events(options.oldfile):
            if options['verbose']:
                if "d" in e:
                    print(six.text_type(e['d']['num']), file=stdout)
                else:
                    print(u"HEADER", file=stdout)
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
            flogfile.serialize_raw_wrapper(newfile, e)
        newfile.close()
        if options.newfile == options.oldfile:
            if sys.platform == "win32":
                # Win32 can't do an atomic rename to an existing file.
                try:
                    os.unlink(options.newfile)
                except OSError:
                    pass
            move_into_place(newfilename, options.newfile)
        print(u"copied %d of %d events into new file" % (copied, total), file=stdout)
