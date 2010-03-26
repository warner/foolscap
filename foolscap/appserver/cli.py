
import os, sys, shutil, errno, time, signal
from StringIO import StringIO
from twisted.python import usage
from twisted.internet import defer
from twisted.scripts import twistd

# does "flappserver start" need us to refrain from importing the reactor here?
# A: probably, to allow --reactor= to work
import foolscap
from foolscap.api import Tub, Referenceable, fireEventually
from foolscap.pb import generateSwissnumber
from foolscap.appserver.services import build_service, BadServiceArguments
from foolscap.appserver.server import AppServer

def get_umask():
    oldmask = os.umask(0)
    os.umask(oldmask)
    return oldmask

class CreateOptions(usage.Options):
    synopsis = "Usage: flappserver create [options] BASEDIR"

    optFlags = [
        ("quiet", "q", "Be silent upon success"),
        ]
    optParameters = [
        ("port", "p", "tcp:0", "TCP port to listen on (strports string)"),
        ("location", "l", "", "Tub location hints to use in generated FURLs. An empty location means to generate one automatically, by looking at the active network interfaces."),
        ("umask", None, None, "(octal) file creation mask to use for the server. If not provided, the current umask (%04o) is copied." % get_umask()),
        ]

    def opt_port(self, port):
        assert not port.startswith("ssl:")
        self["port"] = port
    def opt_umask(self, value):
        self["umask"] = int(value, 8)

    def parseArgs(self, basedir):
        self.basedir = basedir
    def postOptions(self):
        if self["umask"] is None:
            self["umask"] = get_umask()

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
        if os.path.exists(basedir):
            print >>stderr, "Refusing to touch pre-existing directory %s" % basedir
            return 1

        os.makedirs(basedir)
        os.makedirs(os.path.join(basedir, "services"))
        os.chmod(basedir, 0700)

        # start the server and let it run briefly. This lets the Tub spin up,
        # create the key, decide upon a port, and auto-determine its location
        # (if one was not provided with --location=). The base FURL will be
        # written to a file so that subsequent 'add' and 'list' can compute
        # FURLs without needing to run the Tub (which might already be
        # running).

        f = open(os.path.join(basedir, "port"), "w")
        f.write("%s\n" % options["port"])
        f.close()
        # we'll overwrite BASEDIR/port if necessary

        f = open(os.path.join(basedir, "location"), "w")
        f.write("%s\n" % options["location"])
        f.close()

        f = open(os.path.join(basedir, "umask"), "w")
        f.write("%04o\n" % options["umask"])
        f.close()

        self.server = None
        d = fireEventually(basedir)
        d.addCallback(AppServer, stdout)
        d.addCallback(self.stash_and_start_appserver)
        d.addCallback(self.appserver_ready, options)
        d.addBoth(self.stop_appserver)
        d.addCallback(lambda ign: 0)
        return d

    def stash_and_start_appserver(self, ap):
        self.server = ap
        self.server.startService()
        return ap.when_ready()

    def appserver_ready(self, _ignored, options):
        basedir = options.basedir
        stdout = options.stdout
        quiet = options["quiet"]

        tub = self.server.tub
        # what port is it actually listening on?
        l0 = tub.getListeners()[0]

        port = options["port"]
        got_port = port
        pieces = port.split(":")
        if "0" in pieces:
            # If the --port argument didn't tightly specify the port to use,
            # write down the one we actually got, so we'll keep using the
            # same one later
            pieces[pieces.index("0")] = str(l0.getPortnum())
            if pieces[0] != "tcp":
                pieces = ["tcp"] + pieces
            got_port = ":".join(pieces)
            f = open(os.path.join(basedir, "port"), "w")
            f.write(got_port + "\n")
            f.close()

        tubid = tub.getTubID()

        sample_furl = tub.registerReference(Referenceable())
        furl_prefix = sample_furl[:sample_furl.rfind("/")+1]
        f = open(os.path.join(basedir, "furl_prefix"), "w")
        f.write(furl_prefix + "\n")
        f.close()

        f = open(os.path.join(basedir, "flappserver.tac"), "w")
        stashed_path = ""
        for p in sys.path:
            stashed_path += "  %r,\n" % p
        f.write(FLAPPSERVER_TACFILE % { 'path': stashed_path })
        f.close()

        if not quiet:
            print >>stdout, "Foolscap Application Server created in %s" % basedir
            print >>stdout, "TubID %s, listening on port %s" % (tubid, got_port)
            print >>stdout, "Now launch the daemon with 'flappserver start %s'" % basedir

    def stop_appserver(self, res):
        d = defer.succeed(None)
        if self.server:
            d.addCallback(lambda ign: self.server.stopService())
        d.addCallback(lambda ign: res)
        return d

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
        basedir = options.basedir
        stdout = options.stdout
        service_type = options.service_type
        service_args = options.service_args

        swissnum = generateSwissnumber(Tub.NAMEBITS)
        service_basedir = os.path.join(basedir, "services", swissnum)
        os.makedirs(service_basedir)

        try:
            # validate the service args by instantiating one
            s = build_service(service_basedir, None, service_type, service_args)
            del s
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

        furl_prefix = open(os.path.join(basedir, "furl_prefix")).read().strip()
        furl = furl_prefix + swissnum
        if not options["quiet"]:
            print >>stdout, "Service added in %s" % service_basedir
            print >>stdout, "FURL is %s" % furl

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
        basedir = options.basedir
        stdout = options.stdout

        furl_prefix = open(os.path.join(basedir, "furl_prefix")).read().strip()

        services_basedir = os.path.join(basedir, "services")

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
            furl = furl_prefix + swissnum
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

        os.chdir(options.basedir)
        twistd_args = list(options.twistd_args)
        sys.argv[1:] = ["--no_save", "--python", tac] + twistd_args
        print >>stderr, "Launching Server..."
        twistd.run()


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

class RestartOptions(usage.Options):
    synopsis = "Usage: flappserver restart BASEDIR [twistd options]"

    def parseArgs(self, basedir, *twistd_args):
        self.basedir = basedir
        self.twistd_args = twistd_args

class Restart:
    def run(self, options):
        rc = Stop().run(options) # ignore rc
        rc = Start().run(options)
        return rc

class Options(usage.Options):
    synopsis = "Usage: flappserver (create|add|list|start|stop)"

    subCommands = [
        ("create", None, CreateOptions, "create a new app server"),
        ("add", None, AddOptions, "add new service to an app server"),
        ("list", None, ListOptions, "list services in an app server"),
        ("start", None, StartOptions, "launch an app server"),
        ("stop", None, StopOptions, "shut down an app server"),
        ("restart", None, RestartOptions, "(first stop if necessary, then) start a server"),
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
    "restart": Restart,
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
        command_name,argv = argv[0],argv[1:]
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
    try:
        r = dispatch(command, so)
    except (usage.UsageError, BadServiceArguments), e:
        r = 1
        print >>so.stderr, "Error:", e
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
