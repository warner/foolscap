from zope.interface import implementer
from twisted.trial import unittest
from twisted.internet import reactor, endpoints
from twisted.application import service
from foolscap.api import Tub
from foolscap.connection_plugins import DefaultTCP
from foolscap.tokens import NoLocationHintsError
from foolscap.test.common import (certData_low, certData_high, Target,
                                  ShouldFailMixin)
from foolscap import ipb, util

class Convert(unittest.TestCase):
    def checkTCPEndpoint(self, hint, expected_host, expected_port):
        p = DefaultTCP()
        ep, host = p.hint_to_endpoint(hint, reactor)
        self.failUnless(isinstance(ep, endpoints.TCP4ClientEndpoint), ep)
        # note: this is fragile, and will break when Twisted changes the
        # internals of TCP4ClientEndpoint. Hopefully we'll switch to
        # HostnameEndpoint before then. Although that will break too.
        self.failUnlessEqual(ep._host, expected_host)
        self.failUnlessEqual(ep._port, expected_port)

    def checkUnknownEndpoint(self, hint):
        p = DefaultTCP()
        self.failUnlessEqual(p.hint_to_endpoint(hint, reactor), (None,None))

    def testLegacyTCP(self):
        self.checkTCPEndpoint("127.0.0.1:9900",
                              "127.0.0.1", 9900)

    def testTCP(self):
        self.checkTCPEndpoint("tcp:127.0.0.1:9900",
                              "127.0.0.1", 9900)

    def testExtensionsFromFuture(self):
        self.checkUnknownEndpoint("udp:127.0.0.1:7700")
        self.checkUnknownEndpoint("127.0.0.1:7700:postextension")

@implementer(ipb.IConnectionHintHandler)
class TYPEn:
    def __init__(self, n):
        self.n = n
        self.asked = 0
        self.accepted = 0
    def hint_to_endpoint(self, hint, reactor):
        self.asked += 1
        pieces = hint.split(":")
        if pieces[0] != "type%d" % self.n:
            return (None, None)
        self.accepted += 1
        new_hint = "tcp:%s:%d" % (pieces[1], int(pieces[2])+0)
        return DefaultTCP().hint_to_endpoint(new_hint, reactor)

class Handlers(ShouldFailMixin, unittest.TestCase):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        return self.s.stopService()

    def makeTub(self, hint_type):
        tubA = Tub(certData=certData_low)
        tubA.setServiceParent(self.s)
        tubB = Tub(certData=certData_high)
        tubB.setServiceParent(self.s)
        portnum = util.allocate_tcp_port()
        tubA.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        tubA.setLocation("%s:127.0.0.1:%d" % (hint_type, portnum))
        furl = tubA.registerReference(Target())
        return furl, tubB

    def testNoHandlers(self):
        furl, tubB = self.makeTub("type2")
        tubB.removeAllConnectionHintHandlers()
        d = self.shouldFail(NoLocationHintsError, "no handlers", None,
                            tubB.getReference, furl)
        return d

    def testNoSuccessfulHandlers(self):
        furl, tubB = self.makeTub("type2")
        d = self.shouldFail(NoLocationHintsError, "no handlers", None,
                            tubB.getReference, furl)
        return d

    def testExtraHandler(self):
        furl, tubB = self.makeTub("type2")
        h = TYPEn(2)
        tubB.addConnectionHintHandler(h)
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h.asked, 1)
            self.failUnlessEqual(h.accepted, 1)
        d.addCallback(_got)
        return d

    def testOnlyHandler(self):
        furl, tubB = self.makeTub("type2")
        h = TYPEn(2)
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler(h)
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h.asked, 1)
            self.failUnlessEqual(h.accepted, 1)
        d.addCallback(_got)
        return d

    def testOrdering(self):
        furl, tubB = self.makeTub("type2")
        h1 = TYPEn(2)
        h2 = TYPEn(2)
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler(h1) # this short-circuits the lookup
        tubB.addConnectionHintHandler(h2)
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h1.asked, 1)
            self.failUnlessEqual(h1.accepted, 1)
            self.failUnlessEqual(h2.asked, 0)
            self.failUnlessEqual(h2.accepted, 0)
        d.addCallback(_got)
        return d

    def testUnhelpfulHandlers(self):
        furl, tubB = self.makeTub("type2")
        h1 = TYPEn(1)
        h2 = TYPEn(2)
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler(h1) # this says no
        tubB.addConnectionHintHandler(h2) # so we fall through to here
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h1.asked, 1)
            self.failUnlessEqual(h1.accepted, 0)
            self.failUnlessEqual(h2.asked, 1)
            self.failUnlessEqual(h2.accepted, 1)
        d.addCallback(_got)
        return d
