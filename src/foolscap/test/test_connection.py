import os
import mock
from zope.interface import implementer
from twisted.trial import unittest
from twisted.internet import endpoints, defer, reactor
from twisted.internet.endpoints import clientFromString
from twisted.internet.defer import inlineCallbacks
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.application import service
import txtorcon
from txsocksx.client import SOCKS5ClientEndpoint
from foolscap.api import Tub
from foolscap.info import ConnectionInfo
from foolscap.connection import get_endpoint
from foolscap.connections import tcp, socks, tor, i2p
from foolscap.tokens import NoLocationHintsError
from foolscap.ipb import InvalidHintError
from foolscap.test.common import (certData_low, certData_high, Target,
                                  ShouldFailMixin)
from foolscap import ipb, util

def discard_status(status):
    pass

@implementer(IStreamClientEndpoint)
class FakeHostnameEndpoint:
    def __init__(self, reactor, host, port):
        self.reactor = reactor
        self.host = host
        self.port = port

class Convert(unittest.TestCase):
    def checkTCPEndpoint(self, hint, expected_host, expected_port):
        with mock.patch("foolscap.connections.tcp.HostnameEndpoint",
                        side_effect=FakeHostnameEndpoint):
            d = get_endpoint(hint, {"tcp": tcp.default()}, ConnectionInfo())
        (ep, host) = self.successResultOf(d)
        self.failUnless(isinstance(ep, FakeHostnameEndpoint), ep)
        self.failUnlessIdentical(ep.reactor, reactor)
        self.failUnlessEqual(ep.host, expected_host)
        self.failUnlessEqual(ep.port, expected_port)

    def checkBadTCPEndpoint(self, hint):
        d = get_endpoint(hint, {"tcp": tcp.default()}, ConnectionInfo())
        self.failureResultOf(d, ipb.InvalidHintError)

    def checkUnknownEndpoint(self, hint):
        d = get_endpoint(hint, {"tcp": tcp.default()}, ConnectionInfo())
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

    def testTCP6(self):
        self.checkTCPEndpoint("tcp:[2001:0DB8:f00e:eb00::1]:9900",
                              "2001:0DB8:f00e:eb00::1", 9900)
        self.checkBadTCPEndpoint("tcp:[2001:0DB8:f00e:eb00::1]:NOTAPORT")
        self.checkBadTCPEndpoint("tcp:2001:0DB8:f00e:eb00::1]:9900")
        self.checkBadTCPEndpoint("tcp:[2001:0DB8:f00e:eb00::1:9900")
        self.checkBadTCPEndpoint("tcp:2001:0DB8:f00e:eb00::1:9900")

        # IPv4-mapped addresses
        self.checkTCPEndpoint("tcp:[::FFFF:1.2.3.4]:99", "::FFFF:1.2.3.4", 99)
        self.checkBadTCPEndpoint("tcp:[::FFFF:1.2.3]:99")
        self.checkBadTCPEndpoint("tcp:[::FFFF:1.2.3.4567]:99")

        # local-scoped address with good/bad zone-ids (like "123" or "en0")
        self.checkTCPEndpoint("tcp:[FE8::1%123]:9900", "FE8::1%123", 9900)
        self.checkTCPEndpoint("tcp:[FE8::1%en1.2]:9900", "FE8::1%en1.2", 9900)
        self.checkBadTCPEndpoint("tcp:[FE8::1%%]:9900")
        self.checkBadTCPEndpoint("tcp:[FE8::1%$]:9900")
        self.checkBadTCPEndpoint("tcp:[FE8::1%]:9900")
        self.checkBadTCPEndpoint("tcp:[FE8::1%en0%nomultiple]:9900")

        # not both IPv4-mapped and zone-id
        self.checkBadTCPEndpoint("tcp:[::FFFF:1.2.3.4%en0]:9900")

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
    def hint_to_endpoint(self, hint, reactor, update_status):
        self.asked += 1
        if "bad" in hint:
            raise ipb.InvalidHintError
        self.accepted += 1
        pieces = hint.split(":")
        new_hint = "tcp:%s:%d" % (pieces[1], int(pieces[2])+0)
        ep = tcp.default().hint_to_endpoint(new_hint, reactor, update_status)
        if pieces[0] == "slow":
            update_status("being slow")
            self._d = defer.Deferred()
            self._d.addCallback(lambda _: ep)
            return self._d
        return ep

class ErrorSuffix(unittest.TestCase):
    def test_context(self):
        statuses = []
        with tor.add_context(statuses.append, "context"):
            pass
        self.assertEqual(statuses, ["context"])
        statuses = []
        def _try():
            with tor.add_context(statuses.append, "context"):
                raise ValueError("foo")
        e = self.assertRaises(ValueError, _try)
        self.assertEqual(statuses, ["context"])
        self.assert_(hasattr(e, "foolscap_connection_handler_error_suffix"))
        self.assertEqual(e.foolscap_connection_handler_error_suffix,
                         " (while context)")

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
        d = tubB.getReference(furl)
        self.failureResultOf(d, NoLocationHintsError)

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
        self.assertNoResult(d)
        h._d.callback(None)
        def _got(rref):
            self.failUnlessEqual(h.asked, 1)
            self.failUnlessEqual(h.accepted, 1)
        d.addCallback(_got)
        return d

class Socks(unittest.TestCase):
    @mock.patch("foolscap.connections.socks.SOCKS5ClientEndpoint")
    def test_ep(self, scep):
        proxy_ep = FakeHostnameEndpoint(reactor, "localhost", 8080)
        h = socks.socks_endpoint(proxy_ep)

        rv = scep.return_value = mock.Mock()
        ep, host = h.hint_to_endpoint("tor:example.com:1234", reactor,
                                      discard_status)
        self.assertEqual(scep.mock_calls,
                         [mock.call("example.com", 1234, proxy_ep)])
        self.assertIdentical(ep, rv)
        self.assertEqual(host, "example.com")

    def test_real_ep(self):
        proxy_ep = FakeHostnameEndpoint(reactor, "localhost", 8080)
        h = socks.socks_endpoint(proxy_ep)
        ep, host = h.hint_to_endpoint("tcp:example.com:1234", reactor,
                                      discard_status)
        self.assertIsInstance(ep, SOCKS5ClientEndpoint)
        self.assertEqual(host, "example.com")


    def test_bad_hint(self):
        proxy_ep = FakeHostnameEndpoint(reactor, "localhost", 8080)
        h = socks.socks_endpoint(proxy_ep)
        # legacy hints will be upgraded before the connection handler is
        # invoked, so the handler should not handle them
        self.assertRaises(ipb.InvalidHintError,
                          h.hint_to_endpoint, "example.com:1234", reactor,
                          discard_status)
        self.assertRaises(ipb.InvalidHintError,
                          h.hint_to_endpoint, "tcp:example.com:noport", reactor,
                          discard_status)
        self.assertRaises(ipb.InvalidHintError,
                          h.hint_to_endpoint, "tcp:@:1234", reactor,
                          discard_status)

class Empty:
    pass

class Tor(unittest.TestCase):
    @inlineCallbacks
    def test_default_socks(self):
        with mock.patch("foolscap.connections.tor.txtorcon.TorClientEndpoint"
                        ) as tce:
            tce.return_value = expected_ep = object()
            h = tor.default_socks()
            res = yield h.hint_to_endpoint("tcp:example.com:1234", reactor,
                                           discard_status)
            self.assertEqual(tce.mock_calls,
                             [mock.call("example.com", 1234,
                                        socks_endpoint=None)])
        ep, host = res
        self.assertIdentical(ep, expected_ep)
        self.assertEqual(host, "example.com")

    @inlineCallbacks
    def test_default_socks_real(self):
        h = tor.default_socks()
        res = yield h.hint_to_endpoint("tcp:example.com:1234", reactor,
                                       discard_status)
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "example.com")
        self.assertEqual(h.describe(), "tor")

    def test_badaddr(self):
        isnon = tor.is_non_public_numeric_address
        self.assertTrue(isnon("10.0.0.1"))
        self.assertTrue(isnon("127.0.0.1"))
        self.assertTrue(isnon("192.168.78.254"))
        self.assertTrue(isnon("::1"))
        self.assertFalse(isnon("8.8.8.8"))
        self.assertFalse(isnon("example.org"))

    @inlineCallbacks
    def test_default_socks_badaddr(self):
        h = tor.default_socks()
        d = h.hint_to_endpoint("tcp:10.0.0.1:1234", reactor, discard_status)
        f = yield self.assertFailure(d, InvalidHintError)
        self.assertEqual(str(f), "ignoring non-Tor-able ipaddr 10.0.0.1")

        d = h.hint_to_endpoint("tcp:127.0.0.1:1234", reactor, discard_status)
        f = yield self.assertFailure(d, InvalidHintError)
        self.assertEqual(str(f), "ignoring non-Tor-able ipaddr 127.0.0.1")

        d = h.hint_to_endpoint("tcp:not@a@hint:123", reactor, discard_status)
        f = yield self.assertFailure(d, InvalidHintError)
        self.assertEqual(str(f), "unrecognized TCP/Tor hint")

    @inlineCallbacks
    def test_socks_endpoint(self):
        tor_socks_endpoint = clientFromString(reactor, "tcp:socks_host:100")
        with mock.patch("foolscap.connections.tor.txtorcon.TorClientEndpoint"
                        ) as tce:
            tce.return_value = expected_ep = object()
            h = tor.socks_endpoint(tor_socks_endpoint)
            res = yield h.hint_to_endpoint("tcp:example.com:1234", reactor,
                                           discard_status)
            self.assertEqual(tce.mock_calls,
                             [mock.call("example.com", 1234,
                                        socks_endpoint=tor_socks_endpoint)])
        ep, host = res
        self.assertIs(ep, expected_ep)
        self.assertEqual(host, "example.com")

    @inlineCallbacks
    def test_socks_endpoint_real(self):
        tor_socks_endpoint = clientFromString(reactor, "tcp:socks_host:100")
        h = tor.socks_endpoint(tor_socks_endpoint)
        res = yield h.hint_to_endpoint("tcp:example.com:1234", reactor,
                                       discard_status)
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "example.com")

    @inlineCallbacks
    def test_launch(self):
        tpp = Empty()
        tpp.tor_protocol = None
        h = tor.launch()
        fake_reactor = object()
        with mock.patch("txtorcon.launch_tor", return_value=tpp) as lt:
            res = yield h.hint_to_endpoint("tor:foo.onion:29212", fake_reactor,
                                           discard_status)
            self.assertEqual(len(lt.mock_calls), 1)
            args,kwargs = lt.mock_calls[0][1:]
            self.assertIdentical(args[0], h.config)
            self.assertIdentical(args[1], fake_reactor)
            self.assertEqual(kwargs, {"tor_binary": None})
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "foo.onion")
        # launch_tor will allocate a local TCP port for SOCKS
        self.assert_(h._socks_desc.startswith("tcp:127.0.0.1:"), h._socks_desc)

    @inlineCallbacks
    def test_launch_tor_binary(self):
        tpp = Empty()
        tpp.tor_protocol = None
        h = tor.launch(tor_binary="/bin/tor")
        fake_reactor = object()
        with mock.patch("txtorcon.launch_tor", return_value=tpp) as lt:
            res = yield h.hint_to_endpoint("tor:foo.onion:29212", fake_reactor,
                                           discard_status)
            self.assertEqual(len(lt.mock_calls), 1)
            args,kwargs = lt.mock_calls[0][1:]
            self.assertIdentical(args[0], h.config)
            self.assertIdentical(args[1], fake_reactor)
            self.assertEqual(kwargs, {"tor_binary": "/bin/tor"})
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "foo.onion")
        self.assert_(h._socks_desc.startswith("tcp:127.0.0.1:"), h._socks_desc)

    @inlineCallbacks
    def test_launch_data_directory(self):
        datadir = self.mktemp()
        tpp = Empty()
        tpp.tor_protocol = None
        h = tor.launch(data_directory=datadir)
        fake_reactor = object()
        with mock.patch("txtorcon.launch_tor", return_value=tpp) as lt:
            res = yield h.hint_to_endpoint("tor:foo.onion:29212", fake_reactor,
                                           discard_status)
            self.assertEqual(len(lt.mock_calls), 1)
            args,kwargs = lt.mock_calls[0][1:]
            self.assertIdentical(args[0], h.config)
            self.assertIdentical(args[1], fake_reactor)
            self.assertEqual(kwargs, {"tor_binary": None})
            self.assertEqual(h.config.DataDirectory, datadir)
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "foo.onion")
        self.assert_(h._socks_desc.startswith("tcp:127.0.0.1:"), h._socks_desc)

    @inlineCallbacks
    def test_launch_data_directory_exists(self):
        datadir = self.mktemp()
        os.mkdir(datadir)
        tpp = Empty()
        tpp.tor_protocol = None
        h = tor.launch(data_directory=datadir)
        fake_reactor = object()
        with mock.patch("txtorcon.launch_tor", return_value=tpp) as lt:
            res = yield h.hint_to_endpoint("tor:foo.onion:29212", fake_reactor,
                                           discard_status)
            self.assertEqual(len(lt.mock_calls), 1)
            args,kwargs = lt.mock_calls[0][1:]
            self.assertIdentical(args[0], h.config)
            self.assertIdentical(args[1], fake_reactor)
            self.assertEqual(kwargs, {"tor_binary": None})
            self.assertEqual(h.config.DataDirectory, datadir)
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "foo.onion")
        self.assert_(h._socks_desc.startswith("tcp:127.0.0.1:"), h._socks_desc)

    @inlineCallbacks
    def test_control_endpoint(self):
        control_ep = FakeHostnameEndpoint(reactor, "localhost", 9051)
        h = tor.control_endpoint(control_ep)
        # We don't actually care about the generated endpoint, just the state
        # that the handler builds up internally. But we need to provoke a
        # connection to build that state, and we need to prevent the handler
        # from actually talking to a Tor daemon (which probably doesn't exist
        # on this host).
        config = Empty()
        config.SocksPort = ["1234"]
        with mock.patch("txtorcon.build_tor_connection",
                        return_value=None):
            with mock.patch("txtorcon.TorConfig.from_protocol",
                            return_value=config):
                res = yield h.hint_to_endpoint("tor:foo.onion:29212", reactor,
                                               discard_status)
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "foo.onion")
        self.assertEqual(h._socks_desc, "tcp:127.0.0.1:1234")

    @inlineCallbacks
    def test_control_endpoint_default(self):
        control_ep = FakeHostnameEndpoint(reactor, "localhost", 9051)
        h = tor.control_endpoint(control_ep)
        config = Empty()
        config.SocksPort = [txtorcon.DEFAULT_VALUE]
        with mock.patch("txtorcon.build_tor_connection",
                        return_value=None):
            with mock.patch("txtorcon.TorConfig.from_protocol",
                            return_value=config):
                res = yield h.hint_to_endpoint("tor:foo.onion:29212", reactor,
                                               discard_status)
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "foo.onion")
        self.assertEqual(h._socks_desc, "tcp:127.0.0.1:9050")

    @inlineCallbacks
    def test_control_endpoint_non_numeric(self):
        control_ep = FakeHostnameEndpoint(reactor, "localhost", 9051)
        h = tor.control_endpoint(control_ep)
        config = Empty()
        config.SocksPort = ["unix:var/run/tor/socks WorldWritable", "1234"]
        with mock.patch("txtorcon.build_tor_connection",
                        return_value=None):
            with mock.patch("txtorcon.TorConfig.from_protocol",
                            return_value=config):
                res = yield h.hint_to_endpoint("tor:foo.onion:29212", reactor,
                                               discard_status)
        ep, host = res
        self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
        self.assertEqual(host, "foo.onion")
        self.assertEqual(h._socks_desc, "tcp:127.0.0.1:1234")

    @inlineCallbacks
    def test_control_endpoint_no_port(self):
        control_ep = FakeHostnameEndpoint(reactor, "localhost", 9051)
        h = tor.control_endpoint(control_ep)
        config = Empty()
        config.SocksPort = ["unparseable"]
        with mock.patch("txtorcon.build_tor_connection",
                        return_value=None):
            with mock.patch("txtorcon.TorConfig.from_protocol",
                            return_value=config):
                d = h.hint_to_endpoint("tor:foo.onion:29212", reactor,
                                       discard_status)
                f = yield self.assertFailure(d, ValueError)
        self.assertIn("could not use config.SocksPort", str(f))

    def test_control_endpoint_maker_immediate(self):
        return self.do_test_control_endpoint_maker(False)
    def test_control_endpoint_maker_deferred(self):
        return self.do_test_control_endpoint_maker(True)
    def test_control_endpoint_maker_nostatus(self):
        return self.do_test_control_endpoint_maker(True, takes_status=False)

    @inlineCallbacks
    def do_test_control_endpoint_maker(self, use_deferred, takes_status=True):
        control_ep = FakeHostnameEndpoint(reactor, "localhost", 9051)
        results = []
        def make(arg):
            results.append(arg)
            if use_deferred:
                return defer.succeed(control_ep)
            else:
                return control_ep # immediate
        def make_takes_status(arg, update_status):
            return make(arg)
        if takes_status:
            h = tor.control_endpoint_maker(make_takes_status, takes_status=True)
        else:
            h = tor.control_endpoint_maker(make, takes_status=False)
        self.assertEqual(results, []) # not called yet
        # We don't actually care about the generated endpoint, just the state
        # that the handler builds up internally. But we need to provoke a
        # connection to build that state, and we need to prevent the handler
        # from actually talking to a Tor daemon (which probably doesn't exist
        # on this host).
        config = Empty()
        config.SocksPort = ["1234"]
        with mock.patch("txtorcon.build_tor_connection",
                        return_value=None):
            with mock.patch("txtorcon.TorConfig.from_protocol",
                            return_value=config):
                res = yield h.hint_to_endpoint("tor:foo.onion:29212", reactor,
                                               discard_status)
                self.assertEqual(results, [reactor]) # called once
                ep, host = res
                self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
                self.assertEqual(host, "foo.onion")
                self.assertEqual(h._socks_desc, "tcp:127.0.0.1:1234")

                res = yield h.hint_to_endpoint("tor:foo.onion:29213", reactor,
                                               discard_status)
                self.assertEqual(results, [reactor]) # still only called once
                ep, host = res
                self.assertIsInstance(ep, txtorcon.endpoints.TorClientEndpoint)
                self.assertEqual(host, "foo.onion")
                self.assertEqual(h._socks_desc, "tcp:127.0.0.1:1234")



class I2P(unittest.TestCase):
    @inlineCallbacks
    def test_default(self):
        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            n.return_value = expected_ep = object()
            h = i2p.default(reactor, misc_kwarg="foo")
            res = yield h.hint_to_endpoint("i2p:fppym.b32.i2p", reactor,
                                           discard_status)
        self.assertEqual(len(n.mock_calls), 1)
        args = n.mock_calls[0][1]
        got_sep, got_host, got_portnum = args
        self.assertIsInstance(got_sep, endpoints.TCP4ClientEndpoint)
        self.failUnlessEqual(got_sep._host, "127.0.0.1") # fragile
        self.failUnlessEqual(got_sep._port, 7656)
        self.failUnlessEqual(got_host, "fppym.b32.i2p")
        self.failUnlessEqual(got_portnum, None)
        kwargs = n.mock_calls[0][2]
        self.failUnlessEqual(kwargs, {"misc_kwarg": "foo"})

        ep, host = res
        self.assertIdentical(ep, expected_ep)
        self.assertEqual(host, "fppym.b32.i2p")
        self.assertEqual(h.describe(), "i2p")

    @inlineCallbacks
    def test_default_with_portnum(self):
        # I2P addresses generally don't use port numbers, but the parser is
        # supposed to handle them
        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            n.return_value = expected_ep = object()
            h = i2p.default(reactor)
            res = yield h.hint_to_endpoint("i2p:fppym.b32.i2p:1234", reactor,
                                           discard_status)
        self.assertEqual(len(n.mock_calls), 1)
        args = n.mock_calls[0][1]
        got_sep, got_host, got_portnum = args
        self.assertIsInstance(got_sep, endpoints.TCP4ClientEndpoint)
        self.failUnlessEqual(got_sep._host, "127.0.0.1") # fragile
        self.failUnlessEqual(got_sep._port, 7656)
        self.failUnlessEqual(got_host, "fppym.b32.i2p")
        self.failUnlessEqual(got_portnum, 1234)
        ep, host = res
        self.assertIdentical(ep, expected_ep)
        self.assertEqual(host, "fppym.b32.i2p")

    @inlineCallbacks
    def test_default_with_portnum_kwarg(self):
        # setting extra kwargs on the handler should provide a default for
        # the portnum. sequential calls with/without portnums in the hints
        # should get the right values.
        h = i2p.default(reactor, port=1234)

        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            yield h.hint_to_endpoint("i2p:fppym.b32.i2p", reactor,
                                     discard_status)
        got_portnum = n.mock_calls[0][1][2]
        self.failUnlessEqual(got_portnum, 1234)

        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            yield h.hint_to_endpoint("i2p:fppym.b32.i2p:3456", reactor,
                                     discard_status)
        got_portnum = n.mock_calls[0][1][2]
        self.failUnlessEqual(got_portnum, 3456)

        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            yield h.hint_to_endpoint("i2p:fppym.b32.i2p", reactor,
                                     discard_status)
        got_portnum = n.mock_calls[0][1][2]
        self.failUnlessEqual(got_portnum, 1234)

    def test_default_badhint(self):
        h = i2p.default(reactor)
        d = defer.maybeDeferred(h.hint_to_endpoint, "i2p:not@a@hint", reactor,
                                discard_status)
        f = self.failureResultOf(d, InvalidHintError)
        self.assertEqual(str(f.value), "unrecognized I2P hint")

    @inlineCallbacks
    def test_sam_endpoint(self):
        with mock.patch("foolscap.connections.i2p.SAMI2PStreamClientEndpoint") as sep:
            sep.new = n = mock.Mock()
            n.return_value = expected_ep = object()
            my_ep = FakeHostnameEndpoint(reactor, "localhost", 1234)
            h = i2p.sam_endpoint(my_ep, misc_kwarg="foo")
            res = yield h.hint_to_endpoint("i2p:fppym.b32.i2p", reactor,
                                           discard_status)
        self.assertEqual(len(n.mock_calls), 1)
        args = n.mock_calls[0][1]
        got_sep, got_host, got_portnum = args
        self.assertIdentical(got_sep, my_ep)
        self.failUnlessEqual(got_host, "fppym.b32.i2p")
        self.failUnlessEqual(got_portnum, None)
        kwargs = n.mock_calls[0][2]
        self.failUnlessEqual(kwargs, {"misc_kwarg": "foo"})
        ep, host = res
        self.assertIdentical(ep, expected_ep)
        self.assertEqual(host, "fppym.b32.i2p")
