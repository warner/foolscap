
import os, sys
from StringIO import StringIO
from twisted.python import usage
from twisted.internet import defer

# does "flappserver start" need us to refrain from importing the reactor here?
import foolscap
from foolscap.api import Tub, Referenceable, fireEventually

class UploadFileOptions(usage.Options):
    #synopsis = "flappclient upload SOURCEFILE"
    def parseArgs(self, *sourcefiles):
        self.sourcefiles = sourcefiles

class Uploader(Referenceable):
    def run(self, rref, sourcefile, name):
        self.f = open(sourcefile, "rb")
        return rref.callRemote("putfile", name, self)

    def remote_read(self, size):
        return self.f.read(size)

class UploadFile(Referenceable):
    def run(self, rref, options):
        d = defer.succeed(None)
        for sf in options.sourcefiles:
            name = os.path.basename(sf)
            d.addCallback(lambda _ign: Uploader().run(rref, sf, name))
            d.addCallback(self._done, options, name)
        d.addCallback(lambda _ign: 0)
        return d

    def _done(self, _ignored, options, name):
        print >>options.stdout, "%s: uploaded" % name


class RunCommandOptions(usage.Options):
    pass

from twisted.internet.stdio import StandardIO
from twisted.internet.protocol import Protocol

class RunCommand(Referenceable, Protocol):
    def run(self, rref, options):
        self.done = False
        self.d = defer.Deferred()
        rref.notifyOnDisconnect(self._done, 3)
        self.stdin_writer = None
        self.stdio = options.stdio
        self.stdout = options.stdout
        self.stderr = options.stderr
        d = rref.callRemote("execute", self)
        d.addCallback(self._started)
        d.addErrback(self._err)
        return self.d

    def dataReceived(self, data):
        # this is from stdin. It shouldn't be called until after _started
        # sets up stdio and self.stdin_writer
        self.stdin_writer.callRemoteOnly("feed_stdin", data)

    def connectionLost(self, reason):
        # likewise, this won't be called unless _started wanted stdin
        self.stdin_writer.callRemoteOnly("close_stdin")

    def _started(self, stdin_writer):
        if stdin_writer:
            self.stdin_writer = stdin_writer # rref
            self.stdio(self) # start accepting stdin
        # otherwise they don't want our stdin, so leave stdin_writer=None

    def remote_stdout(self, data):
        self.stdout.write(data)
        self.stdout.flush()
    def remote_stderr(self, data):
        self.stderr.write(data)
        self.stderr.flush()
    def remote_done(self, signal, exitcode):
        if signal:
            self._done(127)
        else:
            self._done(exitcode)
    def _err(self, f):
        self._done(f)
    def _done(self, res):
        if not self.done:
            self.done = True
            self.d.callback(res)

class ClientOptions(usage.Options):
    synopsis = "Usage: flappclient [--furl=|--furlfile=] (upload|exec)"

    optParameters = [
        ("furl", None, None, "FURL of the service to contact"),
        ("furlfile", "f", None, "file containing the FURL of the service"),
        ]

    subCommands = [
        ("upload-file", None, UploadFileOptions, "upload a file"),
        ("run-command", None, RunCommandOptions, "cause a command to be run"),
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
        print >>self.stdout, self.synopsis
        sys.exit(0)

    def opt_version(self):
        from twisted import copyright
        print >>self.stdout, "Foolscap version:", foolscap.__version__
        print >>self.stdout, "Twisted version:", copyright.version
        sys.exit(0)

dispatch_table = {
    "upload-file": UploadFile,
    "run-command": RunCommand,
    }


def parse_options(command_name, argv, stdio, stdout, stderr):
    try:
        config = ClientOptions()
        config.stdout = stdout
        config.stderr = stderr
        config.parseOptions(argv)

        config.subOptions.stdio = stdio # for streaming input
        config.subOptions.stdout = stdout
        config.subOptions.stderr = stderr

    except usage.error, e:
        print >>stderr, "%s:  %s" % (command_name, e)
        print >>stderr
        c = getattr(config, 'subOptions', config)
        print >>stderr, str(c)
        sys.exit(1)

    return config

def run_command(config):
    c = dispatch_table[config.subCommand]()
    tub = Tub()
    d = defer.succeed(None)
    d.addCallback(lambda _ign: tub.startService())
    d.addCallback(lambda _ign: tub.getReference(config.furl))
    d.addCallback(c.run, config.subOptions) # might provide tub here
    d.addBoth(lambda res: tub.stopService().addCallback(lambda _ign: res))
    return d


def run_flappclient(argv=None, run_by_human=True, stdio=StandardIO):
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

    d = fireEventually()
    d.addCallback(lambda _ign: parse_options(command_name, argv,
                                             stdio, stdout, stderr))
    d.addCallback(run_command)

    if run_by_human:
        # we need to spin up our own reactor
        from twisted.internet import reactor
        stash_rc = []
        def good(rc):
            stash_rc.append(rc)
            reactor.stop()
        def oops(f):
            if f.check(SystemExit):
                stash_rc.append(f.value.args[0])
            else:
                print "Command failed:"
                print f
                stash_rc.append(-1)
            reactor.stop()
        d.addCallbacks(good, oops)
        reactor.run()
        sys.exit(stash_rc[0])
    else:
        def _convert_system_exit(f):
            f.trap(SystemExit)
            return f.value.args[0]
        d.addErrback(_convert_system_exit)
        def done(rc):
            return (rc, stdout.getvalue(), stderr.getvalue())
        d.addCallback(done)
        return d
