import os
from twisted.trial import unittest
from twisted.application import service
from foolscap.api import Tub, Referenceable
from foolscap.tokens import NoLocationError
from foolscap.util import allocate_tcp_port
from foolscap.eventual import flushEventualQueue

class Receiver(Referenceable):
    def __init__(self):
        self.obj = None
    def remote_call(self, obj):
        self.obj = obj
        return 1

class References(unittest.TestCase):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        d = self.s.stopService()
        d.addCallback(flushEventualQueue)
        return d

    def test_unreachable_client(self):
        # A "client-only" Tub has no location set. It should still be
        # possible to connect to objects in other (location-bearing) server
        # Tubs, and objects in the client Tub can still be sent to (and used
        # by) the server Tub.

        client_tub = Tub()
        client_tub.setServiceParent(self.s)
        server_tub = Tub()
        server_tub.setServiceParent(self.s)

        portnum = allocate_tcp_port()
        server_tub.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        server_tub.setLocation("tcp:127.0.0.1:%d" % portnum)
        s = Receiver() # no FURL, not directly reachable
        r = Receiver()
        furl = server_tub.registerReference(r)

        d = client_tub.getReference(furl)
        d.addCallback(lambda rref: rref.callRemote("call", s))
        d.addCallback(lambda res: self.failUnlessEqual(res, 1))
        d.addCallback(lambda _: self.failIfEqual(r.obj, None))
        def _inspect_obj(_):
            self.failUnlessEqual(r.obj.getSturdyRef().getURL(), None)
        d.addCallback(_inspect_obj)
        d.addCallback(lambda _: r.obj.callRemote("call", 2))
        d.addCallback(lambda _: self.failUnlessEqual(s.obj, 2))
        return d

    def test_logport_furlfile1(self):
        basedir = "unreachable/References/logport_furlfile1"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = Tub()
        # setOption before setServiceParent
        t.setOption("logport-furlfile", furlfile)
        t.setServiceParent(self.s)
        self.failUnlessRaises(NoLocationError, t.getLogPort)
        self.failUnlessRaises(NoLocationError, t.getLogPortFURL)
        self.failIf(os.path.exists(furlfile))
        # without .setLocation, the furlfile will never be created
