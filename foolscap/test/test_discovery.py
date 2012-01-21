# -*- test-case-name: foolscap.test.test_discovery -*-
from twisted.internet import glib2reactor
glib2reactor.install()
from twisted.trial import unittest
from twisted.internet import defer, reactor, error
from twisted.application import service
from foolscap.eventual import eventually, fireEventually, flushEventualQueue

import time
from foolscap.test.common import HelperTarget, GoodEnoughTub
from foolscap.api import *

class Discovery(unittest.TestCase):
    def setUp(self):
        self.services = []

    def startTub(self, tub):
        self.services.append(tub)
        tub.startService()
        l = tub.listenOn("tcp:0")
        return tub

    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d

    def test_mdns(self):
        """ Check that we can actually publish a Tub
        and read it back again.
        """

        tub = GoodEnoughTub()
        self.startTub(tub)
        tub.setLocation("mdns-sd")
        
        target = HelperTarget()

        furl = tub.registerReference(target)
        print furl
        
        rtub = GoodEnoughTub()
        self.startTub(rtub)
        d = rtub.getReference(furl)
        def _connected(ref):
            return ref.callRemote("set", furl)
        d.addCallback(_connected)
        
        def _check(res):
            self.failUnlessEqual(target.obj, furl)
        d.addCallback(_check)
        
        return d

