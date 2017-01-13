from twisted.trial import unittest
from twisted.internet import reactor, endpoints
from twisted.internet.defer import inlineCallbacks
from twisted.application import service
from foolscap.api import Tub
from foolscap.test.common import (certData_low, certData_high, Target,
                                  ShouldFailMixin)
from foolscap import util

class Listeners(ShouldFailMixin, unittest.TestCase):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        return self.s.stopService()

    def makeTubs(self):
        tubA = Tub(certData=certData_low)
        tubA.setServiceParent(self.s)
        tubB = Tub(certData=certData_high)
        tubB.setServiceParent(self.s)
        return tubA, tubB

    @inlineCallbacks
    def test_string(self):
        tubA, tubB = self.makeTubs()
        portnum = util.allocate_tcp_port()
        tubA.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        tubA.setLocation("tcp:127.0.0.1:%d" % portnum)
        furl = tubA.registerReference(Target())
        yield tubB.getReference(furl)

    @inlineCallbacks
    def test_endpoint(self):
        tubA, tubB = self.makeTubs()
        portnum = util.allocate_tcp_port()
        ep = endpoints.TCP4ServerEndpoint(reactor, portnum,
                                          interface="127.0.0.1")
        tubA.listenOn(ep)
        tubA.setLocation("tcp:127.0.0.1:%d" % portnum)
        furl = tubA.registerReference(Target())
        yield tubB.getReference(furl)

    @inlineCallbacks
    def test_parsed_endpoint(self):
        tubA, tubB = self.makeTubs()
        portnum = util.allocate_tcp_port()
        ep = endpoints.serverFromString(reactor,
                                        "tcp:%d:interface=127.0.0.1" % portnum)
        tubA.listenOn(ep)
        tubA.setLocation("tcp:127.0.0.1:%d" % portnum)
        furl = tubA.registerReference(Target())
        yield tubB.getReference(furl)

    @inlineCallbacks
    def test_nonqualified_port(self):
        tubA, tubB = self.makeTubs()
        portnum = util.allocate_tcp_port()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tubA.listenOn("%d" % portnum) # this is deprecated
        tubA.setLocation("tcp:127.0.0.1:%d" % portnum)
        furl = tubA.registerReference(Target())
        yield tubB.getReference(furl)

    def test_invalid(self):
        tubA, tubB = self.makeTubs()
        self.assertRaises(TypeError, tubA.listenOn, 42)
