
import os.path
from twisted.application import service
from foolscap.api import Tub
#from foolscap.appserver.services import build_service

def create_tub(basedir):
    port = eval(open(os.path.join(basedir, "port")).read())
    location = eval(open(os.path.join(basedir, "location")).read())
    tub = Tub(certFile=os.path.join(basedir, "tub.pem"))
    tub.listenOn(port)
    if location:
        tub.setLocation(location)
    else:
        tub.setLocationAutomatically()
    return tub

class AppServer(service.MultiService):
    def __init__(self, basedir="."):
        service.MultiService.__init__(self)
        self.basedir = os.path.abspath(basedir)
        self.tub = create_tub(basedir)
        self.tub.setServiceParent(self)
        self.tub.registerNameLookupHandler(self.lookup)
        print "SERVER RUNNING"

    def lookup(self, name):
        # walk through our configured services, see if we know about this one
        print "LOOKUP", name
        return None

