#! /usr/bin/python

import sys
from twisted.internet import reactor
from foolscap.api import Tub

def gotError1(why):
    print "unable to get the RemoteReference:", why
    reactor.stop()

def gotError2(why):
    print "unable to invoke the remote method:", why
    reactor.stop()

def gotReference(remote):
    print "got a RemoteReference"
    print "asking it to add 1+2"
    d = remote.callRemote("add", a=1, b=2)
    d.addCallbacks(gotAnswer, gotError2)

def gotAnswer(answer):
    print "the answer is", answer
    reactor.stop()

if len(sys.argv) < 2:
    print "Usage: pb2client.py URL"
    sys.exit(1)
url = sys.argv[1]
tub = Tub()
tub.startService()
d = tub.getReference(url)
d.addCallbacks(gotReference, gotError1)

reactor.run()


