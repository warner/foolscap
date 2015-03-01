
import os, sys, json, ast
from twisted.application import service
from twisted.python import log
from twisted.internet import defer
from foolscap.api import Tub
from foolscap.appserver.services import build_service
from foolscap.observer import OneShotObserverList

class UnknownVersion(Exception):
    pass

def load_service_data(basedir):
    services_file = os.path.join(basedir, "services.json")
    if os.path.exists(services_file):
        data = json.load(open(services_file, "rb"))
        if data["version"] != 1:
            raise UnknownVersion("unable to handle version %d" % data["version"])
    else:
        # otherwise look for the old-style separate files
        services = {}
        services_basedir = os.path.join(basedir, "services")
        for (service_basedir, dirnames, filenames) in os.walk(services_basedir):
            if "service_type" not in filenames:
                continue
            assert service_basedir.startswith(services_basedir)
            swissnum = service_basedir[len(services_basedir):].lstrip(os.sep)
            s = services[swissnum] = {}

            s["relative_basedir"] = os.path.join("services", swissnum)

            service_type_f = os.path.join(service_basedir, "service_type")
            s["type"] = open(service_type_f).read().strip()

            # old-style service_args was written with repr(), before the days
            # of JSON. It was always a tuple, though. It's safe to load this
            # with ast.literal_eval() . Note that json.loads() wouldn't work
            # here because repr() emits single-quotes (\x27) and JSON
            # requires double-quotes (\x22).
            service_args_f = os.path.join(service_basedir, "service_args")
            f = open(service_args_f, "rb")
            args_s = f.read().decode("utf-8")
            f.close()
            args = ast.literal_eval(args_s)
            if isinstance(args, tuple):
                args = list(args) # make it more like the JSON equivalent
            s["args"] = args

            comment_f = os.path.join(service_basedir, "comment")
            s["comment"] = None
            if os.path.exists(comment_f):
                s["comment"] = open(comment_f).read().strip()
        data = {"version": 1, "services": services}
    return data # has ["version"]=1 and ["services"]

def save_service_data(basedir, data):
    assert data["version"] == 1
    services_file = os.path.join(basedir, "services.json")
    tmpfile = services_file+".tmp"
    f = open(tmpfile, "wb")
    json.dump(data, f, indent=2)
    f.close()
    os.rename(tmpfile, services_file)

class AppServer(service.MultiService):
    def __init__(self, basedir=".", stdout=sys.stdout):
        service.MultiService.__init__(self)
        self.basedir = os.path.abspath(basedir)
        try:
            umask = open(os.path.join(basedir, "umask")).read().strip()
            self.umask = int(umask, 8) # octal string like 0022
        except EnvironmentError:
            self.umask = None
        port = open(os.path.join(basedir, "port")).read().strip().decode('utf-8')
        self.tub = Tub(certFile=os.path.join(basedir, "tub.pem"))
        self.tub.listenOn(port)
        self.tub.setServiceParent(self)
        self.tub.registerNameLookupHandler(self.lookup)
        print >>stdout, "Server Running"
        self.ready_observers = OneShotObserverList()
        # make sure we log any problems
        self.when_ready().addErrback(log.err)

    def when_ready(self):
        # return a Deferred that fires (with this AppServer instance) when
        # the service is running and the location is set.
        return self.ready_observers.whenFired()

    def startService(self):
        if self.umask is not None:
            os.umask(self.umask)
        service.MultiService.startService(self)
        d = self.setMyLocation()
        d.addBoth(self.ready_observers.fire)

    def setMyLocation(self):
        location = open(os.path.join(self.basedir, "location")).read().strip()
        if location:
            self.tub.setLocation(location)
            return defer.succeed(self)
        d = self.tub.setLocationAutomatically()
        d.addCallback(lambda ign: self)
        return d

    def lookup(self, name):
        # walk through our configured services, see if we know about this one
        services = load_service_data(self.basedir)["services"]
        s = services.get(name)
        if not s:
            return None
        service_basedir = os.path.join(self.basedir, s["relative_basedir"])
        service_type = s["type"]
        service_args = s["args"]
        s = build_service(service_basedir, self.tub, service_type, service_args)
        s.setServiceParent(self)
        return s
