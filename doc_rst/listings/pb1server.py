#! /usr/bin/python

from twisted.internet import reactor
from foolscap.api import Referenceable, UnauthenticatedTub

class MathServer(Referenceable):
    def remote_add(self, a, b):
        return a+b
    def remote_subtract(self, a, b):
        return a-b

myserver = MathServer()
tub = UnauthenticatedTub()
tub.listenOn("tcp:12345")
tub.setLocation("localhost:12345")
url = tub.registerReference(myserver, "math-service")
print "the object is available at:", url

tub.startService()
reactor.run()
