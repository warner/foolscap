
import os, sys, shutil, errno, time, signal
from StringIO import StringIO
from twisted.python import usage

# does "flappserver start" need us to refrain from importing the reactor here?
import foolscap
from foolscap.api import Tub, Referenceable, fireEventually
from foolscap.appserver.services import build_service
from foolscap.appserver.server import create_tub

class CreateOptions(usage.Options):
    synopsis = "Usage: flappserver create [options] BASEDIR"

    optFlags = [
        ("quiet", "q", "Be silent upon success"),
        ]
    optParameters = [
        ("port", "p", "tcp:0", "TCP port to listen on"),
        ("location", "l", None, "Tub location hints to use in generated FURLs"),
        ]

    def parseArgs(self, basedir):
        self.basedir = basedir

FLAPPSERVER_TACFILE = """\
# -*- python -*-

# we record the path when 'flappserver create' is run, in case it was run out
# of a source tree. This is somewhat fragile, of course.

stashed_path = [
%(path)s]

import sys
needed = [p for p in stashed_path if p not in sys.path]
sys.path = needed + sys.path
#print 'NEEDED', needed

from foolscap.appserver import server
from twisted.application import service

appserver = server.AppServer()
application = service.Application('flappserver')
appserver.setServiceParent(application)
"""

class Create:
    def run(self, options):
        basedir = options.basedir
        stdout = options.stdout
        stderr = options.stderr
        quiet = options["quiet"]
        if os.path.exists(basedir):
            print >>stderr, "Refusing to touch pre-existing directory %s" % basedir
            return 1

        os.makedirs(basedir)
        os.makedirs(os.path.join(basedir, "services"))

        # start the server briefly, to let the Tub spin up and create the
        # key, and decide upon a port
        t = Tub(certFile=os.path.join(basedir, "tub.pem"))
        t.startService()
        port = options["port"]
        if port == "0" or port == "tcp:0":
            got_port = "tcp:%d" % t.listenOn(port).getPortnum() # handle port=0
        else:
            got_port = port
        tubid = t.getTubID()
        t.stopService()

        f = open(os.path.join(basedir, "flappserver.tac"), "w")
        stashed_path = ""
        for p in sys.path:
            stashed_path += "  %r,\n" % p
        location = options["location"]
        f.write(FLAPPSERVER_TACFILE % { 'path': stashed_path,
                                        })
        f.close()

        f = open(os.path.join(basedir, "port"), "w")
        f.write("%r\n" % got_port)
        f.close()

        f = open(os.path.join(basedir, "location"), "w")
        f.write("%r\n" % location)
        f.close()

        if not quiet:
            print >>stdout, "Foolscap Application Server created in %s" % basedir
            print >>stdout, "TubID %s, listening on port %s" % (tubid, got_port)
            print >>stdout, "Now launch the daemon with 'flappserver start %s'" % basedir
        return 0

class AddOptions(usage.Options):
    synopsis = "Usage: flappserver add [--comment C] BASEDIR SERVICE-TYPE SERVICE-ARGS.."

    optFlags = [
        ("quiet", "q", "Be silent upon success"),
        ]
    optParameters = [
        ("comment", "c", None, "optional comment describing this service"),
        ]

    def parseArgs(self, basedir, service_type, *service_args):
        self.basedir = basedir
        self.service_type = service_type
        self.service_args = service_args

class Add:
    def run(self, options):
        server_basedir = options.basedir
        stdout = options.stdout
        stderr = options.stderr
        service_type = options.service_type
        service_args = options.service_args

        tub = create_tub(server_basedir)

        swissnum = tub.generateSwissnumber(tub.NAMEBITS)
        service_basedir = os.path.join(server_basedir, "services", swissnum)
        os.makedirs(service_basedir)

        try:
            # validate the service args by instantiating one
            s = build_service(service_basedir, tub, service_type, service_args)
            print "service args look ok"
        except:
            shutil.rmtree(service_basedir)
            raise

        f = open(os.path.join(service_basedir, "service_type"), "w")
        f.write(service_type + "\n")
        f.close()
        f = open(os.path.join(service_basedir, "service_args"), "w")
        f.write(repr(service_args) + "\n")
        f.close()
        if options["comment"]:
            f = open(os.path.join(service_basedir, "comment"), "w")
            f.write(options["comment"] + "\n")
            f.close()

        if not options["quiet"]:
            print >>stdout, "Service added in %s" % service_basedir
        return 0

class ListOptions(usage.Options):
    synopsis = "Usage: flappserver list BASEDIR"

    optFlags = [
        ]
    optParameters = [
        ]

    def parseArgs(self, basedir):
        self.basedir = basedir

class List:
    def run(self, options):
        server_basedir = options.basedir
        stdout = options.stdout
        stderr = options.stderr

        tub = create_tub(server_basedir)
        # the Tub needs to be running before we can use registerReference to
        # build URLs, especially if we don't provide it with an explicit
        # location.
        tub.startService()
        d = fireEventually()
        d.addCallback(self.list, tub, server_basedir, stdout)
        return d

    def list(self, _ign, tub, server_basedir, stdout):
        services_basedir = os.path.join(server_basedir, "services")

        for swissnum in sorted(os.listdir(services_basedir)):
            service_basedir = os.path.join(services_basedir, swissnum)
            print >>stdout
            print >>stdout, "%s:" % swissnum
            service_type_f = os.path.join(service_basedir, "service_type")
            service_type = open(service_type_f).read().strip()
            service_args_f = os.path.join(service_basedir, "service_args")
            service_args = eval(open(service_args_f).read().strip())
            print >>stdout, " %s %s" % (service_type, " ".join(service_args))
            comment_f = os.path.join(service_basedir, "comment")
            if os.path.exists(comment_f):
                comment = open(comment_f).read().strip()
                print >>stdout, " # %s" % comment
            furl = tub.registerReference(Referenceable(), swissnum)
            print >>stdout, " %s" % furl
        print >>stdout
        return 0

class StartOptions(usage.Options):
    synopsis = "Usage: flappserver start BASEDIR [twistd options]"

    optFlags = [
        ]
    optParameters = [
        ]

    def parseArgs(self, basedir, *twistd_args):
        self.basedir = basedir
        self.twistd_args = twistd_args

def try_to_run_command(command, args):
    # if it works, this will not return
    # if the command is not found (ENOENT), this returns False
    # some other exception might be raised
    argv = [command] + list(args)
    try:
        os.execvp(command, argv)
        # doesn't return
    except OSError, e:
        if e.errno == errno.ENOENT:
            return False
        raise

class Start:
    def run(self, options):
        basedir = options.basedir
        stderr = options.stderr
        for fn in os.listdir(basedir):
            if fn.endswith(".tac"):
                tac = fn
                break
        else:
            print >>stderr, "%s does not look like a node directory (no .tac file)" % basedir
            return 1

        # this requires that "twistd" or "twistd.exe" be somewhere on your
        # $PATH. It will probably fail on windows if you must run "python
        # twistd.py" or something like that. I'm not sure it's appropriate to
        # try to accomodate argv[0]="python": too many decisions to make
        # about how to run some tool which ought to have a proper shbang line
        # of its own. It will certainly fail if you don't have Twisted and
        # twistd installed somewhere: I don't think it's appropriate to try
        # to run a twistd that was installed outside of $PATH.

        args = ["--no_save", "--python", tac] + list(options.twistd_args)

        print >>stderr, "Launching server"
        os.chdir(options.basedir)
        try_to_run_command("twistd", args)
        # if we get here, we couldn't find twistd

        if sys.platform == "win32":
            try_to_run_command("twistd.exe", args)
            # if we get here, we couldn't find twistd.exe

            print >>stderr, "twistd.exe: command not found"
            print >>stderr, "Neither 'twistd' nor 'twistd.exe' were found on $PATH"
        else:
            print >>stderr, "twistd: command not found"
            print >>stderr, "'twistd' was not found on $PATH"

        print >>stderr, "You must install Twisted (and its bin/twistd) to use this command"
        return 127


class StopOptions(usage.Options):
    synopsis = "Usage: flappserver stop BASEDIR"

    optFlags = [
        ]
    optParameters = [
        ]

    def parseArgs(self, basedir):
        self.basedir = basedir


def try_to_kill(pid, signum):
    # return True if we successfully sent the signal
    # return False if the process was already gone
    # might raise some other exception
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError, e:
        if e.errno == errno.ESRCH:
            # the process disappeared before we got to it
            return False
        raise
    return True

def try_to_remove_pidfile(pidfile):
    try:
        os.remove(pidfile)
    except OSError:
        pass

class Stop:
    def run(self, options):
        basedir = options.basedir
        stderr = options.stderr
        pidfile = os.path.join(basedir, "twistd.pid")
        if not os.path.exists(pidfile):
            print >>stderr, "%s does not look like a running node directory (no twistd.pid)" % basedir
            # we define rc=2 to mean "nothing is running, but it wasn't me
            # who stopped it"
            return 2
        pid = int(open(pidfile, "r").read().strip())

        # kill it softly (SIGTERM), watch for it to go away, give it 15
        # seconds, then kill it hard (SIGKILL) and delete the twistd.pid
        # file.
        if not try_to_kill(pid, signal.SIGTERM):
            try_to_remove_pidfile(pidfile)
            print >>stderr, "process %d wasn't running, removing twistd.pid to cleanup" % pid
            return 2

        print >>stderr, "SIGKILL sent to process %d, waiting for shutdown" % pid
        counter = 30 # failsafe in case a timequake occurs
        timeout = time.time() + 15
        while time.time() < timeout and counter > 0:
            counter += 1
            if not try_to_kill(pid, 0):
                # it's gone
                try_to_remove_pidfile(pidfile)
                print >>stderr, "process %d terminated" % pid
                return 0
            time.sleep(0.5)

        print >>stderr, "Process %d didn't respond to SIGTERM, sending SIGKILL." % pid
        try_to_kill(pid, signal.SIGKILL)
        try_to_remove_pidfile(pidfile)
        return 0


class Options(usage.Options):
    synopsis = "Usage: flappserver (create|add|list|start|stop)"

    subCommands = [
        ("create", None, CreateOptions, "create a new app server"),
        ("add", None, AddOptions, "add new service to an app server"),
        ("list", None, ListOptions, "list services in an app server"),
        ("start", None, StartOptions, "launch an app server"),
        ("stop", None, StopOptions, "shut down an app server"),
        ]

    def postOptions(self):
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
    "create": Create,
    "add": Add,
    "list": List,
    "start": Start,
    "stop": Stop,
    }

def dispatch(command, options):
    if command in dispatch_table:
        c = dispatch_table[command]()
        return c.run(options)
    else:
        print "unknown command '%s'" % command
        raise NotImplementedError

def run_flappserver(argv=None, run_by_human=True):
    if argv:
        command_name = argv[0]
    else:
        command_name = sys.argv[0]
    config = Options()
    try:
        config.parseOptions(argv)
    except usage.error, e:
        if not run_by_human:
            raise
        print "%s:  %s" % (command_name, e)
        print
        c = getattr(config, 'subOptions', config)
        print str(c)
        sys.exit(1)

    command = config.subCommand
    so = config.subOptions
    if run_by_human:
        so.stdout = sys.stdout
        so.stderr = sys.stderr
    else:
        so.stdout = StringIO()
        so.stderr = StringIO()
    r = dispatch(command, so)
    from twisted.internet import defer
    if run_by_human:
        if isinstance(r, defer.Deferred):
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
            r.addCallbacks(good, oops)
            reactor.run()
            sys.exit(stash_rc[0])
        else:
            sys.exit(r)
    else:
        if isinstance(r, defer.Deferred):
            def done(rc):
                return (rc, so.stdout.getvalue(), so.stderr.getvalue())
            r.addCallback(done)
            return r
        else:
            return (r, so.stdout.getvalue(), so.stderr.getvalue())
