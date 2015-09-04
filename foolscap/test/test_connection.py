from twisted.trial import unittest
from twisted.internet import reactor, endpoints
from foolscap.connection_plugins import DefaultTCP

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
