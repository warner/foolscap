
import os
from twisted.python import usage, runtime, filepath
from twisted.application import service
from twisted.internet import defer
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
        ("mode", None, "0644",
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

        tmpfile = targetfile.siblingExtensionSearch(".partial")

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
            targetfile.chmod(self.options["mode"])
            return None
        def _err(f):
            f.close()
            os.unlink(tmpfile.path)
            return f
        d.addCallbacks(_done, _err)
        return d

class ExecOptions(usage.Options):
    synopsis = "Usage: flappserver add BASEDIR exec [options] TARGETDIR COMMAND.."

    optFlags = [
        ("accept-stdin", None, "allow client to write to COMMAND stdin"),
        ("no-stdin", None, "do not write to COMMAND stdin [default]"),
        ("send-stdout", None, "send COMMAND stdout to client [default]"),
        ("no-stdout", None, "do not send COMMAND stdout to client"),
        ("send-stderr", None, "send COMMAND stderr to client [default]"),
        ("no-stderr", None, "do not send COMMAND stderr to client"),
        ]
    optParameters = [
        ]

    def parseArgs(self, targetdir, *command_argv):
        self.targetdir = targetdir
        self.command_argv = command_argv

class Exec(service.MultiService, Referenceable):
    def __init__(self, basedir, tub, options):
        service.MultiService.__init__(self)
        self.basedir = basedir
        self.tub = tub
        self.options = options

all_services = {
    "file-uploader": (FileUploaderOptions, FileUploader),
    "exec": (ExecOptions, Exec),
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

