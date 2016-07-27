import mock
from zope.interface import implementer
from twisted.trial import unittest
from twisted.internet import endpoints, defer, reactor
from twisted.internet.defer import inlineCallbacks
from twisted.application import service
from txsocksx.client import SOCKS5ClientEndpoint
from foolscap.api import Tub
from foolscap.connection import get_endpoint
from foolscap.connections import tcp, socks, tor, i2p
from foolscap.tokens import NoLocationHintsError
from foolscap.ipb import InvalidHintError
from foolscap.test.common import (certData_low, certData_high, Target,
                                  ShouldFailMixin)
from foolscap import ipb, util

class Convert(unittest.TestCase):
    def checkTCPEndpoint(self, hint, expected_host, expected_port):
        d = get_endpoint(hint, {"tcp": tcp.default()})
        (ep, host) = self.successResultOf(d)
        self.failUnless(isinstance(ep, endpoints.HostnameEndpoint), ep)
        # note: this is fragile, and will break when Twisted changes the
        # internals of HostnameEndpoint.
        self.failUnlessEqual(ep._host, expected_host)
        self.failUnlessEqual(ep._port, expected_port)

    def checkBadTCPEndpoint(self, hint):
        d = get_endpoint(hint, {"tcp": tcp.default()})
        self.failureResultOf(d, ipb.InvalidHintError)

    def checkUnknownEndpoint(self, hint):
        d = get_endpoint(hint, {"tcp": tcp.default()})
        self.failureResultOf(d, ipb.InvalidHintError)

    def testConvertLegacyHint(self):
        self.failUnlessEqual(tcp.convert_legacy_hint("127.0.0.1:9900"),
                             "tcp:127.0.0.1:9900")
        self.failUnlessEqual(tcp.convert_legacy_hint("tcp:127.0.0.1:9900"),
                             "tcp:127.0.0.1:9900")
        self.failUnlessEqual(tcp.convert_legacy_hint("other:127.0.0.1:9900"),
                             "other:127.0.0.1:9900")
        # this is unfortunate
        self.failUnlessEqual(tcp.convert_legacy_hint("unix:1"), "tcp:unix:1")
        # so new hints should do one of these:
        self.failUnlessEqual(tcp.convert_legacy_hint("tor:host:1234"),
                             "tor:host:1234") # multiple colons
        self.failUnlessEqual(tcp.convert_legacy_hint("unix:fd=1"),
                             "unix:fd=1") # equals signs, key=value -style

    def testTCP(self):
        self.checkTCPEndpoint("tcp:127.0.0.1:9900", "127.0.0.1", 9900)
        self.checkTCPEndpoint("tcp:hostname:9900", "hostname", 9900)
        self.checkBadTCPEndpoint("tcp:hostname:NOTAPORT")

    def testLegacyTCP(self):
        self.checkTCPEndpoint("127.0.0.1:9900", "127.0.0.1", 9900)
        self.checkTCPEndpoint("hostname:9900", "hostname", 9900)
        self.checkBadTCPEndpoint("hostname:NOTAPORT")

    def testNoColon(self):
        self.checkBadTCPEndpoint("hostname")

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
        ep = tcp.default().hint_to_endpoint(new_hint, reactor)
        if pieces[0] == "slow":
            d = defer.Deferred()
            reactor.callLater(0.01, d.callback, ep)
            return d
        return ep

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

    def testDeferredHandler(self):
        furl, tubB = self.makeTub("slow")
        h = NewHandler()
        tubB.removeAllConnectionHintHandlers()
        tubB.addConnectionHintHandler("slow", h)
        d = tubB.getReference(furl)
        def _got(rref):
            self.failUnlessEqual(h.asked, 1)
            self.failUnlessEqual(h.accepted, 1)
        d.addCallback(_got)
        return d

class Socks(unittest.TestCase):
    @mock.patch("foolscap.connections.socks.SOCKS5ClientEndpoint")
    def test_ep(self, scep):
        proxy_ep = endpoints.HostnameEndpoint(reactor, "localhost", 8080)
        h = socks.socks_endpoint(proxy_ep)

        rv = scep.return_value = mock.Mock()
        ep, host = h.hint_to_endpoint("tor:example.com:1234", reactor)
        self.assertEqual(scep.mock_calls,
                         [mock.call("example.com", 1234, proxy_ep)])
        self.assertIdentical(ep, rv)
        self.assertEqual(host, "example.com")

    def test_real_ep(self):
        proxy_ep = endpoints.HostnameEndpoint(reactor, "localhost", 8080)
        h = socks.socks_endpoint(proxy_ep)
        ep, host = h.hint_to_endpoint("tcp:example.com:1234", reactor)
        self.assertIsInstance(ep, SOCKS5ClientEndpoint)
        self.assertEqual(host, "example.com")


    def test_bad_hint(self):
        proxy_ep = endpoints.HostnameEndpoint(reactor, "localhost", 8080)
        h = socks.socks_endpoint(proxy_ep)
        # legacy hints will be upgraded before the connection handler is
        # invoked, so the handler should not handle them
        self.assertRaises(ipb.InvalidHintError,
                          h.hint_to_endpoint, "example.com:1234", reactor)
        self.assertRaises(ipb.InvalidHintError,
                          h.hint_to_endpoint, "tcp:example.com:noport", reactor)
        self.assertRaises(ipb.InvalidHintError,
                          h.hint_to_endpoint, "tcp:@:1234", reactor)

class Tor(unittest.TestCase):
    @inlineCallbacks
    def test_default_socks(self):
        with mock.patch("foolscap.connections.tor.txtorcon") as ttc:
            ttc.TorClientEndpoint = tce = mock.Mock()
            tce.return_value = expected_ep = object()
            h = tor.default_socks()
            res = yield h.hint_to_endpoint("tcp:example.com:1234", reactor)
            self.assertEqual(tce.mock_calls,
                             [mock.call("example.com", 1234,
                                        socks_hostname="127.0.0.1",
                                        socks_port=None)])
            ep, host = res
            self.assertIdentical(ep, expected_ep)
            self.assertEqual(host, "example.com")

    def test_badaddr(self):
        isnon = tor.is_non_public_numeric_address
        self.assertTrue(isnon("10.0.0.1"))
        self.assertTrue(isnon("127.0.0.1"))
        self.assertTrue(isnon("192.168.78.254"))
        self.assertFalse(isnon("8.8.8.8"))
        self.assertFalse(isnon("example.org"))

    @inlineCallbacks
    def test_default_socks_badaddr(self):
        h = tor.default_socks()
        d = h.hint_to_endpoint("tcp:10.0.0.1:1234", reactor)
        f = yield self.assertFailure(d, InvalidHintError)
        self.assertEqual(str(f), "ignoring non-Tor-able ipaddr 10.0.0.1")

        d = h.hint_to_endpoint("tcp:127.0.0.1:1234", reactor)
        f = yield self.assertFailure(d, InvalidHintError)
        self.assertEqual(str(f), "ignoring non-Tor-able ipaddr 127.0.0.1")

    # TODO: exercise launch_tor and with_control_port somehow

class I2P(unittest.TestCase):
    @inlineCallbacks
    def test_default(self):
        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            n.return_value = expected_ep = object()
            h = i2p.default(reactor)
            res = yield h.hint_to_endpoint("i2p:fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p", reactor)
            self.assertEqual(len(n.mock_calls), 1)
            args = n.mock_calls[0][1]
            got_sep, got_host, got_portnum = args
            self.assertIsInstance(got_sep, endpoints.TCP4ClientEndpoint)
            self.failUnlessEqual(got_sep._host, "127.0.0.1") # fragile
            self.failUnlessEqual(got_sep._port, 7656)
            self.failUnlessEqual(got_host, "fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p")
            self.failUnlessEqual(got_portnum, None)
            ep, host = res
            self.assertIdentical(ep, expected_ep)
            self.assertEqual(host, "fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p")

    @inlineCallbacks
    def test_default_with_portnum(self):
        # I2P addresses generally don't use port numbers, but the parser is
        # supposed to handle them
        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            n.return_value = expected_ep = object()
            h = i2p.default(reactor)
            res = yield h.hint_to_endpoint("i2p:fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p:1234", reactor)
            self.assertEqual(len(n.mock_calls), 1)
            args = n.mock_calls[0][1]
            got_sep, got_host, got_portnum = args
            self.assertIsInstance(got_sep, endpoints.TCP4ClientEndpoint)
            self.failUnlessEqual(got_sep._host, "127.0.0.1") # fragile
            self.failUnlessEqual(got_sep._port, 7656)
            self.failUnlessEqual(got_host, "fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p")
            self.failUnlessEqual(got_portnum, 1234)
            ep, host = res
            self.assertIdentical(ep, expected_ep)
            self.assertEqual(host, "fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p")

    @inlineCallbacks
    def test_sam_endpoint(self):
        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            n.return_value = expected_ep = object()
            my_ep = endpoints.HostnameEndpoint(reactor, "localhost", 1234)
            h = i2p.sam_endpoint(my_ep)
            res = yield h.hint_to_endpoint("i2p:fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p", reactor)
            self.assertEqual(len(n.mock_calls), 1)
            args = n.mock_calls[0][1]
            got_sep, got_host, got_portnum = args
            self.assertIdentical(got_sep, my_ep)
            self.failUnlessEqual(got_host, "fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p")
            self.failUnlessEqual(got_portnum, None)
            ep, host = res
            self.assertIdentical(ep, expected_ep)
            self.assertEqual(host, "fppymhuqbd3klxfqbxbz67t3fk6puzeludedp3a4avym5s4wqs3a.b32.i2p")
