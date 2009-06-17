
import os
from twisted.python import usage, runtime, filepath, log
from twisted.application import service
from twisted.internet import defer, reactor, protocol
from foolscap.api import Referenceable

class BadServiceArguments(Exception):
    pass
class UnknownServiceType(Exception):
    pass

class FileUploaderOptions(usage.Options):
    synopsis = "Usage: flappserver add BASEDIR file-uploader [options] TARGETDIR"

    optFlags = [
        ("allow-subdirectories", None, "allow client to write to subdirectories"),
        ]
    optParameters = [
        ("mode", None, 0644,
         "(octal) mode to set uploaded files to, use 0644 for world-readable")
        ]

    def opt_mode(self, mode):
        if mode.startswith("0"):
            self["mode"] = int(mode, 8)
        else:
            self["mode"] = int(mode)

    def parseArgs(self, targetdir):
        self.targetdir = os.path.abspath(targetdir)
        if self["allow-subdirectories"]:
            raise BadServiceArguments("--allow-subdirectories is not yet implemented")
        if not os.path.exists(self.targetdir):
            raise BadServiceArguments("targetdir '%s' must already exist"
                                      % self.targetdir)
        if not os.access(self.targetdir, os.W_OK):
            raise BadServiceArguments("targetdir '%s' must be writeable"
                                      % self.targetdir)

class FileUploaderReader(Referenceable):
    BLOCKSIZE = 1024*1024
    def __init__(self, f, source):
        self.f = f
        self.source = source
        self.d = defer.Deferred()

    def read_file(self):
        self.read_block()
        return self.d

    def read_block(self):
        d = self.source.callRemote("read", self.BLOCKSIZE)
        d.addCallback(self._got_data)
        d.addErrback(self._got_error)

    def _got_data(self, data):
        if data:
            self.f.write(data)
            self.read_block()
        else:
            # no more data: we're done
            self.d.callback(None)

    def _got_error(self, f):
        self.d.errback(f)


class BadFilenameError(Exception):
    pass

class FileUploader(service.MultiService, Referenceable):
    def __init__(self, basedir, tub, options):
        # tub might be None. No network activity should be done until
        # startService. Validate all options in the constructor. Do not use
        # the Service/MultiService ".name" attribute (which would prevent
        # having multiple instances of a single service type in the same
        # server).
        service.MultiService.__init__(self)
        self.basedir = basedir
        self.tub = tub
        self.options = options
        self.targetdir = filepath.FilePath(options.targetdir)

    def remote_putfile(self, name, source):
        #if "/" in name or name == "..":
        #    raise BadFilenameError()
        #targetfile = os.path.join(self.options.targetdir, name)

        # I think that .child() will reject attempts to follow symlinks out
        # of the target directory. It will also reject the use of
        # subdirectories: 'name' must not contain any slashes. To implement
        # allow-subdirectories, we should pass a list of dirnames and handle
        # it specially.
        targetfile = self.targetdir.child(name)

        #tmpfile = targetfile.temporarySibling()
        #
        # temporarySibling() creates a tempfile with the same extension as
        # the targetfile, which is useless for our purposes: one goal of
        # file-uploader is to let you send .deb packages to an APT
        # repository, and we need to hide the .deb from the package-index
        # building scripts until the whole file is present, so we want an
        # atomic rename from foo.deb.partial to foo.deb

        tmpfile = targetfile.siblingExtension(".partial")

        # TODO: use os.open and set the file mode earlier
        #f = open(tmpfile, "w")
        f = tmpfile.open("w")
        reader = FileUploaderReader(f, source)
        d = reader.read_file()
        def _done(res):
            f.close()
            if runtime.platform.isWindows() and targetfile.exists():
                os.unlink(targetfile.path)
            tmpfile.moveTo(targetfile)
            #targetfile.chmod(self.options["mode"])
            # older Twisteds do not have FilePath.chmod
            os.chmod(targetfile.path, self.options["mode"])
            return None
        def _err(f):
            f.close()
            os.unlink(tmpfile.path)
            return f
        d.addCallbacks(_done, _err)
        return d

class CommandRunnerOptions(usage.Options):
    synopsis = "Usage: flappserver add BASEDIR exec [options] TARGETDIR COMMAND.."

    optFlags = [
        ("accept-stdin", None, "allow client to write to COMMAND stdin"),
        ("no-stdin", None, "do not write to COMMAND stdin [default]"),
        ("log-stdin", None, "log incoming stdin (to twistd.log)"),
        ("no-log-stdin", None, "do not log incoming stdin [default]"),

        ("send-stdout", None, "send COMMAND stdout to client [default]"),
        ("no-stdout", None, "do not send COMMAND stdout to client"),
        ("log-stdout", None, "log outbound stdout (to twistd.log)"),
        ("no-log-stdout", None, "do not log oubound stdout [default]"),

        ("send-stderr", None, "send COMMAND stderr to client [default]"),
        ("no-stderr", None, "do not send COMMAND stderr to client"),
        ("log-stderr", None, "log outbound stderr (to twistd.log) [default]"),
        ("no-log-stderr", None, "do not log outbound stderr"),
        ]
    optParameters = [
        ]

    accept_stdin = False
    def opt_accept_stdin(self):
        self.accept_stdin = True
    def opt_no_stdin(self):
        self.accept_stdin = False

    send_stdout = True
    def opt_send_stdout(self):
        self.send_stdout = True
    def opt_no_stdout(self):
        self.send_stdout = False

    send_stderr = True
    def opt_send_stderr(self):
        self.send_stderr = True
    def opt_no_stderr(self):
        self.send_stderr = False

    log_stdin = False
    def opt_log_stdin(self):
        self.log_stdin = True
    def opt_no_log_stdin(self):
        self.log_stdin = False

    log_stdout = False
    def opt_log_stdout(self):
        self.log_stdout = True
    def opt_no_log_stdout(self):
        self.log_stdout = False

    log_stderr = True
    def opt_log_stderr(self):
        self.log_stderr = True
    def opt_no_log_stderr(self):
        self.log_stderr = False

    def parseArgs(self, targetdir, *command_argv):
        self.targetdir = targetdir
        self.command_argv = command_argv

class CommandPP(protocol.ProcessProtocol):
    def __init__(self, outpipe, errpipe, watcher, log_stdout, log_stderr):
        self.outpipe = outpipe
        self.errpipe = errpipe
        self.watcher = watcher
        self.log_stdout = log_stdout
        self.log_stderr = log_stderr
    def outReceived(self, data):
        if self.outpipe:
            self.outpipe.callRemoteOnly("stdout", data)
        if self.log_stdout:
            sent = {True:"sent", False:"not sent"}[bool(self.outpipe)]
            log.msg("stdout (%s): %r" % (sent, data))
    def errReceived(self, data):
        if self.errpipe:
            self.errpipe.callRemoteOnly("stderr", data)
        if self.log_stderr:
            sent = {True:"sent", False:"not sent"}[bool(self.errpipe)]
            log.msg("stderr (%s): %r" % (sent, data))

    def processEnded(self, reason):
        e = reason.value
        code = e.exitCode
        log.msg("process ended (signal=%s, rc=%s)" % (e.signal, code))
        self.watcher.callRemoteOnly("done", e.signal, code)

class Command(Referenceable):
    def __init__(self, process, log_stdin):
        self.process = process
        self.log_stdin = log_stdin
        self.closed = False
    def remote_feed_stdin(self, data):
        if self.log_stdin:
            log.msg("stdin: %r" % data)
        self.process.write(data)
    def remote_close_stdin(self):
        if not self.closed:
            self.closed = True
            if self.log_stdin:
                log.msg("stdin closed")
            self.process.closeStdin()

class CommandRunner(service.MultiService, Referenceable):
    def __init__(self, basedir, tub, options):
        service.MultiService.__init__(self)
        self.basedir = basedir
        self.tub = tub
        self.options = options

    def remote_execute(self, watcher):
        o = self.options
        outpipe = None
        if o.send_stdout:
            outpipe = watcher
        errpipe = None
        if o.send_stderr:
            errpipe = watcher
        pp = CommandPP(outpipe, errpipe, watcher, o.log_stdout, o.log_stderr)

        # spawnProcess uses os.execvpe, which will search your $PATH
        executable = o.command_argv[0]

        log.msg("command started in dir %s: %s" % (o.targetdir, o.command_argv))
        p = reactor.spawnProcess(pp,
                                 executable,
                                 o.command_argv,
                                 os.environ,
                                 o.targetdir)
        if o.accept_stdin:
            c = Command(p, o.log_stdin)
            watcher.notifyOnDisconnect(c.remote_close_stdin)
            return c
        return None

all_services = {
    "upload-file": (FileUploaderOptions, FileUploader),
    "run-command": (CommandRunnerOptions, CommandRunner),
    }

def build_service(basedir, tub, service_type, service_args):
    # this will be replaced by a plugin system. For now it's pretty static.
    if service_type in all_services:
        (optclass, svcclass) = all_services[service_type]
        options = optclass()
        options.parseOptions(service_args)
        service = svcclass(basedir, tub, options)
        return service
    else:
        raise UnknownServiceType(service_type)

