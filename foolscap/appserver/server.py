
import sys
import os.path
from twisted.application import service
from twisted.python import log
from twisted.internet import defer
from foolscap.api import Tub
from foolscap.appserver.services import build_service
from foolscap.observer import OneShotObserverList

class AppServer(service.MultiService):
    def __init__(self, basedir=".", stdout=sys.stdout):
        service.MultiService.__init__(self)
        self.basedir = os.path.abspath(basedir)
        try:
            umask = open(os.path.join(basedir, "umask")).read().strip()
            self.umask = int(umask, 8) # octal string like 0022
        except EnvironmentError:
            self.umask = None
        port = open(os.path.join(basedir, "port")).read().strip()
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
        service_basedir = os.path.join(self.basedir, "services", name)
        if not os.path.exists(service_basedir):
            return None
        service_type_f = os.path.join(service_basedir, "service_type")
        service_type = open(service_type_f).read().strip()
        service_args_f = os.path.join(service_basedir, "service_args")
        service_args = eval(open(service_args_f).read().strip())
        s = build_service(service_basedir, self.tub, service_type, service_args)
        s.setServiceParent(self)
        return s
