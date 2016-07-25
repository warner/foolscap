#! /usr/bin/python

# This is the client side of a manual test for the socks/tor
# connection-handler code. To use it, first set up the server as described in
# the other file, then copy the hostname, tubid, and .onion address into this
# file:

HOSTNAME = "foolscap.lothar.com"
TUBID = "qy4aezcyd3mppt7arodl4mzaguls6m2o"
ONION = "kwmjlhmn5runa4bv.onion"
ONIONPORT = 16545
LOCALPORT = 7006

# Then run 'check-connections-client.py tcp', then with 'socks', then with
# 'tor'.

import sys
from twisted.internet import reactor
from foolscap.api import Referenceable, Tub

class Observer(Referenceable):
    def remote_event(self, msg):
        print "event:", msg

def printResult(number):
    print "the result is", number
def gotError(err):
    print "got an error:", err
def gotRemote(remote):
    o = Observer()
    d = remote.callRemote("addObserver", observer=o)
    d.addCallback(lambda res: remote.callRemote("push", num=2))
    d.addCallback(lambda res: remote.callRemote("push", num=3))
    d.addCallback(lambda res: remote.callRemote("add"))
    d.addCallback(lambda res: remote.callRemote("pop"))
    d.addCallback(printResult)
    d.addCallback(lambda res: remote.callRemote("removeObserver", observer=o))
    d.addErrback(gotError)
    d.addCallback(lambda res: reactor.stop())
    return d


tub = Tub()

which = sys.argv[1] if len(sys.argv) > 1 else None
if which == "tcp":
    furl = "pb://%s@tcp:%s:%d/calculator" % (TUBID, HOSTNAME, LOCALPORT)
elif which == "socks":
    # "slogin -D 8013 HOSTNAME" starts a SOCKS server on localhost 8013, for
    # which connections will emerge from the other end. Check the server logs
    # to see the peer address of each addObserver call to verify that it is
    # coming from 127.0.0.1 rather than the client host.
    from twisted.internet import endpoints
    from foolscap.connections import socks
    h = socks.SOCKS(endpoints.HostnameEndpoint(reactor, "localhost", 8013))
    tub.removeAllConnectionHintHandlers()
    tub.addConnectionHintHandler("tcp", h)
    furl = "pb://%s@tcp:localhost:%d/calculator" % (TUBID, LOCALPORT)
elif which == "tor":
    from twisted.internet import endpoints
    from foolscap.connections import tor
    h = tor.Tor()
    tub.removeAllConnectionHintHandlers()
    tub.addConnectionHintHandler("tor", h)
    furl = "pb://%s@tor:%s:%d/calculator" % (TUBID, ONION, ONIONPORT)
    print "using tor:", furl
else:
    print "run as 'check-connections-client.py [tcp|socks|tor]'"
    sys.exit(1)
print "using %s: %s" % (which, furl)

tub.startService()
d = tub.getReference(furl)
d.addCallback(gotRemote)
def _oops(f):
    print "error", f
    reactor.stop()
d.addErrback(_oops)

reactor.run()
