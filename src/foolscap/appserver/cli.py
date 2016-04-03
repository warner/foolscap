
import os, sys, shutil, errno, time, signal
from StringIO import StringIO
from twisted.python import usage
from twisted.internet import defer
from twisted.scripts import twistd

# does "flappserver start" need us to refrain from importing the reactor here?
# A: probably, to allow --reactor= to work
import foolscap
from foolscap.api import Tub, Referenceable
from foolscap.pb import generateSwissnumber
from foolscap.appserver.services import build_service, BadServiceArguments
from foolscap.appserver.server import AppServer, load_service_data, save_service_data

# external code can rely upon the stability of add_service() and
# list_services(), as well as the following properties:
# * services are instantiated with (basedir,tub,type,args)
# * their basedir will already exist by the time they're instantiated
# * their basedir will be somewhere inside the flappserver's basedir
# all other functions and classes are for foolscap's own use, and may change
# in future versions

def get_umask():
    oldmask = os.umask(0)
    os.umask(oldmask)
    return oldmask

class BaseOptions(usage.Options):
    opt_h = usage.Options.opt_help

    def getSynopsis(self):
        # the default usage.Options.getSynopsis prepends 'flappserver'
        # Options.synopsis, which looks weird
        return self.synopsis

class CreateOptions(BaseOptions):
    synopsis = "Usage: flappserver create [options] BASEDIR"

    optFlags = [
        ("quiet", "q", "Be silent upon success"),
        ]
    optParameters = [
        ("port", "p", "tcp:3116", "TCP port to listen on (strports string)"),
        ("location", "l", None, "(required) Tub location hints to use in generated FURLs. e.g. 'example.org:3116'"),
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
        if not self["location"]:
            raise usage.UsageError("--location= is mandatory")

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

        assert options["port"]
        assert options["location"]

        os.makedirs(basedir)
        os.makedirs(os.path.join(basedir, "services"))
        os.chmod(basedir, 0700)

        # Start the server and let it create the key. The base FURL will be
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

        save_service_data(basedir, {"version": 1, "services": {}})

        a = AppServer(basedir, stdout)
        tub = a.tub

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

        if not options["quiet"]:
            print >>stdout, "Foolscap Application Server created in %s" % basedir
            print >>stdout, "TubID %s, listening on port %s" % (tub.getTubID(),
                                                                options["port"])
            print >>stdout, "Now launch the daemon with 'flappserver start %s'" % basedir
        return defer.succeed(0)

class AddOptions(BaseOptions):
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

    def getUsage(self, width=None):
        t = usage.Options.getUsage(self, width)
        t += "\nUse 'flappserver add BASEDIR SERVICE-TYPE --help' for details."
        t += "\n\nSERVICE-TYPE can be one of the following:\n"
        from services import all_services
        for name in sorted(all_services.keys()):
            t += "  %s\n" % name
        return t

def make_swissnum():
    return generateSwissnumber(Tub.NAMEBITS)

def find_next_service_basedir(basedir):
    services_basedir = os.path.join(basedir, "services")
    nums = []
    for dirname in os.listdir(services_basedir):
        try:
            nums.append(int(dirname))
            # this might also catch old-style swissnum-named directories, if
            # their name contains entirely digits. The chances of that are
            # (6/32)^32, or 5.4e-24, so we're probably safe.
        except ValueError:
            pass
    # return value is relative to basedir
    return os.path.join("services", str(max([0]+nums)+1))

def add_service(basedir, service_type, service_args, comment, swissnum=None):
    if not swissnum:
        swissnum = make_swissnum()
    services_data = load_service_data(basedir)
    relative_service_basedir = find_next_service_basedir(basedir)
    service_basedir = os.path.join(basedir, relative_service_basedir)
    os.makedirs(service_basedir)
    try:
        # validate the service args by instantiating one
        s = build_service(service_basedir, None, service_type, service_args)
        del s
    except:
        shutil.rmtree(service_basedir)
        raise

    services_data["services"][swissnum] = {
        "relative_basedir": relative_service_basedir,
        "type": service_type,
        "args": service_args,
        "comment": comment,
        }
    save_service_data(basedir, services_data)

    furl_prefix = open(os.path.join(basedir, "furl_prefix")).read().strip()
    furl = furl_prefix + swissnum
    return furl, service_basedir

class Add:
    def run(self, options):
        basedir = options.basedir
        stdout = options.stdout
        service_type = options.service_type
        service_args = options.service_args
        furl, service_basedir = add_service(basedir,
                                            service_type, service_args,
                                            options["comment"])
        if not options["quiet"]:
            print >>stdout, "Service added in %s" % service_basedir
            print >>stdout, "FURL is %s" % furl

        return 0

class ListOptions(BaseOptions):
    synopsis = "Usage: flappserver list BASEDIR"

    optFlags = [
        ]
    optParameters = [
        ]

    def parseArgs(self, basedir):
        self.basedir = basedir

class FlappService:
    pass

def list_services(basedir):
    furl_prefix = open(os.path.join(basedir, "furl_prefix")).read().strip()
    services_data = load_service_data(basedir)["services"]
    services = []
    for swissnum, data in sorted(services_data.items()):
        s = FlappService()
        s.swissnum = swissnum
        s.service_basedir = os.path.join(basedir, data["relative_basedir"])
        s.service_type = data["type"]
        s.service_args = data["args"]
        s.comment = data["comment"] # maybe None
        s.furl = furl_prefix + swissnum
        services.append(s)
    return services

class List:
    def run(self, options):
        basedir = options.basedir
        stdout = options.stdout
        for s in list_services(basedir):
            print >>stdout
            print >>stdout, "%s:" % s.swissnum
            print >>stdout, " %s %s" % (s.service_type, " ".join(s.service_args))
            if s.comment:
                print >>stdout, " # %s" % s.comment
            print >>stdout, " %s" % s.furl
            print >>stdout, " %s" % s.service_basedir
        print >>stdout

        return 0

class StartOptions(BaseOptions):
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


class StopOptions(BaseOptions):
    synopsis = "Usage: flappserver stop BASEDIR"

    optFlags = [
        ("quiet", "q", "Be silent when the server is not already running"),
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
            if not options["quiet"]:
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

class RestartOptions(BaseOptions):
    synopsis = "Usage: flappserver restart BASEDIR [twistd options]"

    def parseArgs(self, basedir, *twistd_args):
        self.basedir = basedir
        self.twistd_args = twistd_args

class Restart:
    def run(self, options):
        options["quiet"] = True
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
