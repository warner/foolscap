
import os, pickle
from zope.interface import implements
from twisted.trial import unittest
from twisted.application import service
from twisted.internet import defer, reactor
from twisted.python import log as twisted_log
import foolscap
from foolscap.logging import gatherer, log
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


class Basic(unittest.TestCase):
    def testLog(self):
        l = log.FoolscapLogger()
        l.explain_facility("ui", "this terse string fully describes the gui")
        l.msg("one")
        l.msg("two")
        l.msg("three")
        l.msg("ui message", facility="ui")
        l.msg("blah blah", level=log.NOISY)
        l.msg("opening file", level=log.OPERATIONAL)
        l.msg("funny, that doesn't usually happen", level=log.UNUSUAL)
        l.msg("configuration change noticed", level=log.INFREQUENT)
        l.msg("error, but recoverable", level=log.CURIOUS)
        l.msg("ok, that shouldn't have happened", level=log.WEIRD)
        l.msg("hash doesn't match.. what the hell?", level=log.SCARY)
        l.msg("I looked into the trap, ray", level=log.BAD)

    def testStacktrace(self):
        l = log.FoolscapLogger()
        l.msg("how did we get here?", stacktrace=True)

    def testParent(self):
        l = log.FoolscapLogger()
        p1 = l.msg("operation requested", level=log.OPERATIONAL)
        l.msg("first step", level=log.NOISY, parent=p1)
        l.msg("second step", level=log.NOISY, parent=p1)
        l.msg("second step EXPLODED", level=log.WEIRD, parent=p1)
        p2 = l.msg("third step", parent=p1)
        l.msg("fourth step", parent=p1)
        l.msg("third step deferred activity finally completed", parent=p2)
        l.msg("operation complete", level=log.OPERATIONAL, parent=p1)

    def testTheLogger(self):
        log.msg("This goes to the One True Logger")

    def testTubLogger(self):
        t = GoodEnoughTub()
        t.log("this goes into the tub")

class Advanced(unittest.TestCase):

    def testDisplace(self):
        l = log.FoolscapLogger()
        l.set_buffer_size(log.NOISY, 3)
        l.msg("one")
        l.msg("two")
        l.msg("three")
        items = l.buffers[None][log.NOISY]
        self.failUnlessEqual(len(items), 3)
        l.msg("four") # should displace "one"
        self.failUnlessEqual(len(items), 3)
        m0 = items[0]
        self.failUnlessEqual(type(m0), dict)
        self.failUnlessEqual(m0['message'], "two")
        self.failUnlessEqual(items[-1]['message'], "four")

    def testFacilities(self):
        l = log.FoolscapLogger()
        l.explain_facility("ui", "This is the UI.")
        l.msg("one", facility="ui")
        l.msg("two")

        items = l.buffers["ui"][log.NOISY]
        self.failUnlessEqual(len(items), 1)
        self.failUnlessEqual(items[0]["message"], "one")

    def testOnePriority(self):
        l = log.FoolscapLogger()
        l.msg("one", level=log.NOISY)
        l.msg("two", level=log.WEIRD)
        l.msg("three", level=log.NOISY)

        items = l.buffers[None][log.NOISY]
        self.failUnlessEqual(len(items), 2)
        self.failUnlessEqual(items[0]['message'], "one")
        self.failUnlessEqual(items[1]['message'], "three")

        items = l.buffers[None][log.WEIRD]
        self.failUnlessEqual(len(items), 1)
        self.failUnlessEqual(items[0]['message'], "two")

    def testPriorities(self):
        l = log.FoolscapLogger()
        l.set_buffer_size(log.NOISY, 3)
        l.set_buffer_size(log.WEIRD, 3)

        l.msg("one", level=log.WEIRD)
        l.msg("two", level=log.NOISY)
        l.msg("three", level=log.NOISY)
        l.msg("four", level=log.WEIRD)
        l.msg("five", level=log.NOISY)
        l.msg("six", level=log.NOISY)
        l.msg("seven", level=log.NOISY)

        items = l.buffers[None][log.NOISY]
        self.failUnlessEqual(len(items), 3)
        self.failUnlessEqual(items[0]['message'], "five")
        self.failUnlessEqual(items[-1]['message'], "seven")

        items = l.buffers[None][log.WEIRD]
        self.failUnlessEqual(len(items), 2)
        self.failUnlessEqual(items[0]['message'], "one")
        self.failUnlessEqual(items[-1]['message'], "four")

    def testHierarchy(self):
        l = log.FoolscapLogger()

        n = l.msg("one")
        n2 = l.msg("two", parent=n)
        l.msg("three", parent=n2)


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

class Publish(unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        log.setTwistedLogBridge(None) # disable any bridge still in place
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

        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()
        logport_furl2 = open(furlfile, "r").read().strip()
        self.failUnlessEqual(logport_furl, logport_furl2)
        t.setOption("bridge-twisted-logs", True)

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
                log.msg("message 1 here")
                twisted_log.msg("message 2 here")
                # switch to generic (no tubid) bridge
                log.bridgeTwistedLogs()
                twisted_log.msg("message 3 here")
            d.addCallback(_emit)
            d.addCallback(self.stall, 1.0)
            # TODO: I'm not content with that absolute-time stall, and would
            # prefer to do something faster and more deterministic
            #d.addCallback(fireEventually)
            #d.addCallback(fireEventually)
            def _check_observer(res):
                msgs = ob.messages
                self.failUnlessEqual(len(msgs), 3)
                #print msgs
                self.failUnlessEqual(msgs[0]["message"], "message 1 here")
                # twisted's log.msg records a tuple of args, whereas
                # foolscap's log.msg only records a single string
                self.failUnlessEqual(msgs[1]["message"], ("message 2 here",) )
                self.failUnlessEqual(msgs[1]["tubID"], t.tubID)
                self.failUnlessEqual(msgs[2]["message"], ("message 3 here",) )
                self.failUnlessEqual(msgs[2]["tubID"], None)
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
            log.msg("gathered message here")
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
            self.failUnlessEqual(data['d']['message'], "gathered message here")
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
        t2.setOption("log-gatherer-furl", gatherer_furl)

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
        t2.setOption("log-gatherer-furlfile", gatherer_fn)

        return self._test_gatherer(basedir, gatherer, t2)

    def test_log_gatherer_empty_furlfile(self):
        basedir = "test_logging/test_log_gatherer_empty_furlfile"
        os.makedirs(basedir)

        gatherer_fn = os.path.join(basedir, "log_gatherer.furl")
        # leave the furlfile blank: use no gatherer

        t2 = GoodEnoughTub()
        t2.setServiceParent(self.parent)
        l = t2.listenOn("tcp:0:interface=127.0.0.1")
        t2.setLocation("127.0.0.1:%d" % l.getPortnum())
        t2.setOption("log-gatherer-furlfile", gatherer_fn)

        lp_furl = t2.getLogPortFURL()
        t2.log("this message shouldn't make anything explode")



