#! /usr/bin/python

# This is the server side of a manual test for the socks/tor
# connection-handler code. On the server host, configure Tor to route a
# hidden service to our port with something like:
#
#   HiddenServiceDir /var/lib/tor/foolscap-calc-HS/
#   HiddenServicePort 16545 127.0.0.1:7006
#
# Then restart Tor, and look in /var/lib/tor/foolscap-calc-HS/hostname to
# learn the .onion address that was allocated. Copy that into this file:

ONION = "kwmjlhmn5runa4bv.onion"
ONIONPORT = 16545
LOCALPORT = 7006

# Then launch this server with "twistd -y check-connections-server.py", and
# copy our hostname (and the other values above) into
# check-connections-client.py . Then run the client in tcp/socks/tor modes.

from twisted.application import service
from foolscap.api import Referenceable, Tub

class Calculator(Referenceable):
    def __init__(self):
        self.stack = []
        self.observers = []
    def remote_addObserver(self, observer):
        self.observers.append(observer)
        print "observer is from", observer.getPeer()
    def log(self, msg):
        for o in self.observers:
            o.callRemote("event", msg=msg)
    def remote_removeObserver(self, observer):
        self.observers.remove(observer)

    def remote_push(self, num):
        self.log("push(%d)" % num)
        self.stack.append(num)
    def remote_add(self):
        self.log("add")
        arg1, arg2 = self.stack.pop(), self.stack.pop()
        self.stack.append(arg1 + arg2)
    def remote_subtract(self):
        self.log("subtract")
        arg1, arg2 = self.stack.pop(), self.stack.pop()
        self.stack.append(arg2 - arg1)
    def remote_pop(self):
        self.log("pop")
        return self.stack.pop()

tub = Tub(certFile="tub.pem")
lp = "tcp:%d" % LOCALPORT
if 0:
    lp += ":interface=127.0.0.1"
tub.listenOn(lp)
tub.setLocation("tor:%s:%d" % (ONION, ONIONPORT))
url = tub.registerReference(Calculator(), "calculator")
print "the object is available at:", url

application = service.Application("check-connections-server")
tub.setServiceParent(application)

if __name__ == '__main__':
    raise RuntimeError("please run this as 'twistd -noy check-connections-server.py'")
