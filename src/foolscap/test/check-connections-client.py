#! /usr/bin/python

# This is the client side of a manual test for the socks/tor
# connection-handler code. To use it, first set up the server as described in
# the other file, then copy the hostname, tubid, and .onion address into this
# file:

HOSTNAME = "foolscap.lothar.com"
TUBID = "qy4aezcyd3mppt7arodl4mzaguls6m2o"
ONION = "kwmjlhmn5runa4bv.onion"
ONIONPORT = 16545
I2P = "???"
I2PPORT = 0
LOCALPORT = 7006

# Then run 'check-connections-client.py tcp', then with 'socks', then with
# 'tor'.

import os, sys, time
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import HostnameEndpoint, clientFromString
from foolscap.api import Referenceable, Tub


tub = Tub()

which = sys.argv[1] if len(sys.argv) > 1 else None
if which == "tcp":
    furl = "pb://%s@tcp:%s:%d/calculator" % (TUBID, HOSTNAME, LOCALPORT)
elif which == "socks":
    # "slogin -D 8013 HOSTNAME" starts a SOCKS server on localhost 8013, for
    # which connections will emerge from the other end. Check the server logs
    # to see the peer address of each addObserver call to verify that it is
    # coming from 127.0.0.1 rather than the client host.
    from foolscap.connections import socks
    h = socks.socks_endpoint(HostnameEndpoint(reactor, "localhost", 8013))
    tub.removeAllConnectionHintHandlers()
    tub.addConnectionHintHandler("tcp", h)
    furl = "pb://%s@tcp:localhost:%d/calculator" % (TUBID, LOCALPORT)
elif which in ("tor-default", "tor-socks", "tor-control", "tor-launch"):
    from foolscap.connections import tor
    if which == "tor-default":
        h = tor.default_socks()
    elif which == "tor-socks":
        h = tor.socks_port(int(sys.argv[2]))
    elif which == "tor-control":
        control_ep = clientFromString(reactor, sys.argv[2])
        h = tor.control_endpoint(control_ep)
    elif which == "tor-launch":
        data_directory = None
        if len(sys.argv) > 2:
            data_directory = os.path.abspath(sys.argv[2])
        h = tor.launch(data_directory)
    tub.removeAllConnectionHintHandlers()
    tub.addConnectionHintHandler("tor", h)
    furl = "pb://%s@tor:%s:%d/calculator" % (TUBID, ONION, ONIONPORT)
elif which in ("i2p-default", "i2p-sam"):
    from foolscap.connections import i2p
    if which == "i2p-default":
        h = i2p.default(reactor)
    else:
        sam_ep = clientFromString(reactor, sys.argv[2])
        h = i2p.sam_endpoint(sam_ep)
    tub.removeAllConnectionHintHandlers()
    tub.addConnectionHintHandler("i2p", h)
    furl = "pb://%s@i2p:%s:%d/calculator" % (TUBID, I2P, I2PPORT)
else:
    print "run as 'check-connections-client.py [tcp|socks|tor-default|tor-socks|tor-control|tor-launch|i2p-default|i2p-sam]'"
    sys.exit(1)
print "using %s: %s" % (which, furl)

class Observer(Referenceable):
    def remote_event(self, msg):
        pass

@inlineCallbacks
def go():
    tub.startService()
    start = time.time()
    rtts = []
    remote = yield tub.getReference(furl)
    t_connect = time.time() - start

    o = Observer()
    start = time.time()
    yield remote.callRemote("addObserver", observer=o)
    rtts.append(time.time() - start)

    start = time.time()
    yield remote.callRemote("removeObserver", observer=o)
    rtts.append(time.time() - start)

    start = time.time()
    yield remote.callRemote("push", num=2)
    rtts.append(time.time() - start)

    start = time.time()
    yield remote.callRemote("push", num=3)
    rtts.append(time.time() - start)

    start = time.time()
    yield remote.callRemote("add")
    rtts.append(time.time() - start)

    start = time.time()
    number = yield remote.callRemote("pop")
    rtts.append(time.time() - start)
    print "the result is", number

    print "t_connect:", t_connect
    print "avg rtt:", sum(rtts) / len(rtts)

d = go()
def _oops(f):
    print "error", f
d.addErrback(_oops)
d.addCallback(lambda res: reactor.stop())

reactor.run()
