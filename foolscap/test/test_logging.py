
import os, pickle
from zope.interface import implements
from twisted.trial import unittest
from twisted.application import service
from twisted.internet import defer, reactor
from twisted.python import log as twisted_log
import foolscap
from foolscap.logging import publish, gatherer
from foolscap.logging.interfaces import RILogObserver
from foolscap.eventual import flushEventualQueue
from foolscap import Tub, UnauthenticatedTub, Referenceable

crypto_available = False
try:
    from foolscap import crypto
    crypto_available = crypto.available
except ImportError:
    pass

# we use authenticated tubs if possible. If crypto is not available, fall
# back to unauthenticated ones
GoodEnoughTub = UnauthenticatedTub
if crypto_available:
    GoodEnoughTub = Tub

class Observer(Referenceable):
    implements(RILogObserver)
    def __init__(self):
        self.messages = []
    def remote_msg(self, d):
        self.messages.append(d)

class MyGatherer(gatherer.LogGatherer):
    verbose = False
    furlFile = None

    def remote_logport(self, nodeid, publisher):
        gatherer.LogGatherer.remote_logport(self, nodeid, publisher)
        self.d.callback(publisher)

class Logging(unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

    def test_logpublisher(self):
        basedir = "test_logging/test_logpublisher"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        lp = publish.LogPublisher(furlfile)
        lp.setServiceParent(t)

        logport_furl = lp.getLogport()
        logport_furl2 = open(furlfile, "r").read().strip()
        self.failUnlessEqual(logport_furl, logport_furl2)

        t2 = GoodEnoughTub()
        t2.setServiceParent(self.parent)
        ob = Observer()

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            d = logport.callRemote("get_versions")
            def _check(versions):
                self.failUnlessEqual(versions["foolscap"],
                                     foolscap.__version__)
            d.addCallback(_check)
            d.addCallback(lambda res:
                          logport.callRemote("subscribe_to_all", ob))
            def _emit(subscription):
                self._subscription = subscription
                twisted_log.msg("message here")
            d.addCallback(_emit)
            d.addCallback(self.stall, 1.0)
            # TODO: I'm not content with that absolute-time stall, and would
            # prefer to do something faster and more deterministic
            #d.addCallback(fireEventually)
            #d.addCallback(fireEventually)
            def _check_observer(res):
                msgs = ob.messages
                self.failUnlessEqual(len(msgs), 1)
                #print msgs
                self.failUnlessEqual(msgs[0]["message"], ("message here",) )
            d.addCallback(_check_observer)
            def _done(res):
                return logport.callRemote("unsubscribe", self._subscription)
            d.addCallback(_done)
            return d
        d.addCallback(_got_logport)
        return d

    def stall(self, res, delay=1.0):
        d = defer.Deferred()
        reactor.callLater(delay, d.callback, res)
        return d

    def _test_gatherer(self, basedir, gatherer, t2):
        # about now, the node will be contacting the Gatherer and
        # offering its logport.

        d = gatherer.d
        d.addCallback(self.stall, 1.0) # give subscribe_to_all() a chance
        def _go(res):
            twisted_log.msg("message here")
        d.addCallback(_go)
        d.addCallback(self.stall, 1.0)
        d.addCallback(lambda res: t2.disownServiceParent())
        # that will disconnect from the gatherer, which will flush the logfile
        d.addCallback(self.stall, 1.0)
        def _check(res):
            gatherer._savefile.close()
            fn = os.path.join(basedir, "logs.pickle")
            # grab the first event from the log
            data = pickle.load(open(fn, "r"))
            self.failUnless(isinstance(data, dict))
            self.failUnlessEqual(data['from'], t2.tubID)
            self.failUnlessEqual(data['d']['message'],
                                 ("message here",) )
        d.addCallback(_check)
        return d

    def test_log_gatherer(self):
        basedir = "test_logging/test_log_gatherer"
        os.makedirs(basedir)

        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        gatherer = MyGatherer()
        gatherer.d = defer.Deferred()
        fn = os.path.join(basedir, "logs.pickle")
        gatherer._savefile = open(fn, "ab")
        gatherer._tub_ready(t)
        gatherer_furl = t.registerReference(gatherer)

        t2 = GoodEnoughTub()
        t2.setServiceParent(self.parent)
        l = t2.listenOn("tcp:0:interface=127.0.0.1")
        t2.setLocation("127.0.0.1:%d" % l.getPortnum())
        lp = publish.LogPublisher(gathererFurl=gatherer_furl)
        lp.setServiceParent(t2)

        return self._test_gatherer(basedir, gatherer, t2)

    def test_log_gatherer_furlfile(self):
        basedir = "test_logging/test_log_gatherer_furlfile"
        os.makedirs(basedir)

        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        gatherer = MyGatherer()
        gatherer.d = defer.Deferred()
        fn = os.path.join(basedir, "logs.pickle")
        gatherer._savefile = open(fn, "ab")
        gatherer._tub_ready(t)
        gatherer_furl = t.registerReference(gatherer)

        gatherer_fn = os.path.join(basedir, "log_gatherer.furl")
        f = open(gatherer_fn, "w")
        f.write(gatherer_furl + "\n")
        f.close()

        t2 = GoodEnoughTub()
        t2.setServiceParent(self.parent)
        l = t2.listenOn("tcp:0:interface=127.0.0.1")
        t2.setLocation("127.0.0.1:%d" % l.getPortnum())
        lp = publish.LogPublisher(gathererFurlFile=gatherer_fn)
        lp.setServiceParent(t2)

        return self._test_gatherer(basedir, gatherer, t2)

