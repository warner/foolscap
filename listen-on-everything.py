from foolscap.api import Tub
from twisted.internet import reactor, defer

@defer.inlineCallbacks
def go():
    bottom = None
    top = None
    prev = 0
    for i in range(70000):
        tub = Tub()
        tub.startService()
        l = tub.listenOn("tcp:0")
        port = l.getPortnum()
        if bottom is None or (port < bottom):
            bottom = port
        if top is None or (port > top):
            top = port
        print "%d (%d-%d)" % (port, bottom, top)
        if port != prev+1:
            print "----", port
            with open("skipped-ports.txt", "a") as f:
                f.write("skipped %d, got %d instead\n" % (prev+1, port))
        prev = port
        yield tub.stopService()
    reactor.stop()

reactor.callLater(0, go)
reactor.run()
