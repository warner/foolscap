
import os, sys
from StringIO import StringIO
from twisted.python import usage
from twisted.internet import defer

# does "flappserver start" need us to refrain from importing the reactor here?
import foolscap
from foolscap.api import Tub, Referenceable, fireEventually

class UploadOptions(usage.Options):
    def parseArgs(self, sourcefile):
        self.sourcefile = sourcefile

class Upload(Referenceable):
    def run(self, rref, options):
        name = os.path.basename(options.sourcefile)
        self.f = open(options.sourcefile, "rb")
        d = rref.callRemote("putfile", name, self)
        d.addCallback(self._done, options)
        return d

    def remote_read(self, size):
        return self.f.read(size)

    def _done(self, _ignored, options):
        print >>options.stdout, "File uploaded"
        return 0


class ExecOptions(usage.Options):
    pass
class Exec:
    def run(self, rref, options):
        pass

class ClientOptions(usage.Options):
    synopsis = "Usage: flappclient (upload|exec)"

    optParameters = [
        ("furl", None, None, "FURL of the service to contact"),
        ("furlfile", "f", None, "file containing the FURL of the service"),
        ]

    subCommands = [
        ("upload", None, UploadOptions, "upload a file (to file-uploader)"),
        ("exec", None, ExecOptions, "cause a command to be run (to exec)"),
        ]

    def read_furlfile(self):
        for line in open(self["furlfile"]).readlines():
            line = line.strip()
            if line.startswith("pb://"):
                return line
        return None

    def postOptions(self):
        self.furl = self["furl"]
        if self["furlfile"]:
            self.furl = self.read_furlfile()
        if not self.furl:
            raise usage.UsageError("must provide --furl or --furlfile")
        if not hasattr(self, 'subOptions'):
            raise usage.UsageError("must specify a command")

    def opt_help(self):
        print self.synopsis
        sys.exit(0)

    def opt_version(self):
        from twisted import copyright
        print "Foolscap version:", foolscap.__version__
        print "Twisted version:", copyright.version
        sys.exit(0)

dispatch_table = {
    "upload": Upload,
    "exec": Exec,
    }

def run_cli(argv=None, run_by_human=True):
    if run_by_human:
        stdout = sys.stdout
        stderr = sys.stderr
    else:
        stdout = StringIO()
        stderr = StringIO()
    if argv:
        command_name,argv = argv[0],argv[1:]
    else:
        command_name = sys.argv[0]

    config = ClientOptions()

    try:
        config.parseOptions(argv)
    except usage.error, e:
        print >>stderr, "%s:  %s" % (command_name, e)
        print >>stderr
        c = getattr(config, 'subOptions', config)
        print >>stderr, str(c)
        if run_by_human:
            sys.exit(1)
        else:
            return defer.succeed((1, stdout.getvalue(), stderr.getvalue()))

    command = config.subCommand
    so = config.subOptions
    so.stdout = stdout
    so.stderr = stderr

    c = dispatch_table[command]()
    tub = Tub()
    d = fireEventually()
    d.addCallback(lambda _ign: tub.startService())
    d.addCallback(lambda _ign: tub.getReference(config.furl))
    d.addCallback(c.run, so) # might provide tub here
    d.addBoth(lambda res: tub.stopService().addCallback(lambda _ign: res))

    if run_by_human:
        # this command needs a reactor
        from twisted.internet import reactor
        stash_rc = []
        def good(rc):
            stash_rc.append(rc)
            reactor.stop()
        def oops(f):
            print "Command failed:"
            print f
            stash_rc.append(-1)
            reactor.stop()
        d.addCallbacks(good, oops)
        reactor.run()
        sys.exit(stash_rc[0])
    else:
        def done(rc):
            return (rc, stdout.getvalue(), stderr.getvalue())
        d.addCallback(done)
        return d
