
from twisted.python import usage
from twisted.application import service
from foolscap.api import Referenceable

class FileUploaderOptions(usage.Options):
    synopsis = "Usage: flappserver add BASEDIR file-uploader [options] TARGETDIR"

    optFlags = [
        ("allow-subdirectories", None, "allow client to write to subdirectories"),
        ]
    optParameters = [
        ]

    def parseArgs(self, targetdir):
        self.targetdir = targetdir

class FileUploader(service.MultiService, Referenceable):
    def __init__(self, basedir, tub, options):
        service.MultiService.__init__(self)
        self.basedir = basedir
        self.tub = tub
        self.options = options

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

class UnknownServiceType(Exception):
    pass

def build_service(basedir, tub, service_type, service_args):
    # this will be replaced by a plugin system. For now it's pretty static.
    if service_type == "file-uploader":
        options = FileUploaderOptions().parseOptions(service_args)
        service = FileUploader(basedir, tub, options)
    elif service_type == "exec":
        options = ExecOptions().parseOptions(service_args)
        service = Exec(basedir, tub, options)
    else:
        raise UnknownServiceType(service_type)
    return service
