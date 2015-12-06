
from txsocksx.client import SOCKS5ClientEndpoint
from txsocksx.test.util import FakeEndpoint

from zope.interface import implementer
from twisted.trial import unittest
from twisted.internet import endpoints, reactor
from twisted.application import service
from foolscap.api import Tub
from foolscap.connection import get_endpoint
from foolscap.connection_plugins import convert_legacy_hint, DefaultTCP, SocksPlugin
from foolscap.tokens import NoLocationHintsError
from foolscap.test.common import (certData_low, certData_high, Target,
                                  ShouldFailMixin)
from foolscap import ipb, util

class SocksPluginTests(unittest.TestCase):
    def test_defaultFactory(self):
        def SocksEndpointGenerator(*args, **kw):
            return FakeEndpoint()
        plugin = SocksPlugin("127.0.0.1", "9050", proxy_endpoint_generator = SocksEndpointGenerator)
        hint = "tor:meowhost:80"
        endpoint, host = plugin.hint_to_endpoint(hint, reactor)

        self.failUnlessEqual("meowhost", host)
        self.failUnless(isinstance(endpoint, SOCKS5ClientEndpoint))

        endpoint.connect(None)
        # equivalent to the TestSOCKS5ClientEndpoint.test_defaultFactory test-case.
        self.assertEqual(endpoint.proxyEndpoint.transport.value(), '\x05\x01\x00')

class Convert(unittest.TestCase):
    def checkTCPEndpoint(self, hint, expected_host, expected_port):
        ep, host = get_endpoint(hint, {"tcp": DefaultTCP()})
        self.failUnless(isinstance(ep, endpoints.TCP4ClientEndpoint), ep)
        # note: this is fragile, and will break when Twisted changes the
        # internals of TCP4ClientEndpoint. Hopefully we'll switch to
        # HostnameEndpoint before then. Although that will break too.
        self.failUnlessEqual(ep._host, expected_host)
        self.failUnlessEqual(ep._port, expected_port)

    def checkUnknownEndpoint(self, hint):
        self.failUnlessRaises(ipb.InvalidHintError,
                              get_endpoint, hint, {"tcp": DefaultTCP()})

    def testConvertLegacyHint(self):
        self.failUnlessEqual(convert_legacy_hint("127.0.0.1:9900"),
                             "tcp:127.0.0.1:9900")
        self.failUnlessEqual(convert_legacy_hint("tcp:127.0.0.1:9900"),
                             "tcp:127.0.0.1:9900")
        self.failUnlessEqual(convert_legacy_hint("other:127.0.0.1:9900"),
                             "other:127.0.0.1:9900")
        # this is unfortunate
        self.failUnlessEqual(convert_legacy_hint("unix:1"), "tcp:unix:1")
        # so new hints should do one of these:
        self.failUnlessEqual(convert_legacy_hint("tor:host:1234"),
                             "tor:host:1234") # multiple colons
        self.failUnlessEqual(convert_legacy_hint("unix:fd=1"),
                             "unix:fd=1") # equals signs, key=value -style

    def testTCP(self):
        self.checkTCPEndpoint("tcp:127.0.0.1:9900",
                              "127.0.0.1", 9900)

    def testLegacyTCP(self):
        self.checkTCPEndpoint("127.0.0.1:9900",
                              "127.0.0.1", 9900)

    def testExtensionsFromFuture(self):
        self.checkUnknownEndpoint("udp:127.0.0.1:7700")
        self.checkUnknownEndpoint("127.0.0.1:7700:postextension")

@implementer(ipb.IConnectionHintHandler)
class NewHandler:
    def __init__(self):
        self.asked = 0
        self.accepted = 0
    def hint_to_endpoint(self, hint, reactor):
        self.asked += 1
        if "bad" in hint:
            raise ipb.InvalidHintError
        self.accepted += 1
        pieces = hint.split(":")
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
        h = NewHandler()
        tubB.addConnectionHintHandler("type2", h)
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h.asked, 1)
            self.failUnlessEqual(h.accepted, 1)
        d.addCallback(_got)
        return d

    def testOnlyHandler(self):
        furl, tubB = self.makeTub("type2")
        h = NewHandler()
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler("type2", h)
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h.asked, 1)
            self.failUnlessEqual(h.accepted, 1)
        d.addCallback(_got)
        return d

    def testOrdering(self):
        furl, tubB = self.makeTub("type2")
        h1 = NewHandler()
        h2 = NewHandler()
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler("type2", h1) # replaced by h2
        tubB.addConnectionHintHandler("type2", h2)
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h1.asked, 0)
            self.failUnlessEqual(h1.accepted, 0)
            self.failUnlessEqual(h2.asked, 1)
            self.failUnlessEqual(h2.accepted, 1)
        d.addCallback(_got)
        return d

    def testUnhelpfulHandlers(self):
        furl, tubB = self.makeTub("type2")
        h1 = NewHandler()
        h2 = NewHandler()
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler("type1", h1) # this is ignored
        tubB.addConnectionHintHandler("type2", h2) # this handles it
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h1.asked, 0)
            self.failUnlessEqual(h1.accepted, 0)
            self.failUnlessEqual(h2.asked, 1)
            self.failUnlessEqual(h2.accepted, 1)
        d.addCallback(_got)
        return d
