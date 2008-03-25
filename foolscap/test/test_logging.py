
import os, pickle, time
from zope.interface import implements
from twisted.trial import unittest
from twisted.application import service
from twisted.internet import defer, reactor
from twisted.python import log as twisted_log
from twisted.python import failure
import foolscap
from foolscap.logging import gatherer, log
from foolscap.logging.interfaces import RILogObserver
from foolscap.eventual import fireEventually, flushEventualQueue
from foolscap import Tub, UnauthenticatedTub, Referenceable
from foolscap.test.common import PollMixin

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
        l.msg(message="three")
        l.msg("one=%d, two=%d", 1, 2)
        l.msg("survive 100% of weird inputs")
        l.msg(format="foo=%(foo)s, bar=%(bar)s", foo="foo", bar="bar")
        l.msg() # useless, but make sure it doesn't crash
        l.msg("ui message", facility="ui")
        l.msg("so boring it won't even be generated", level=log.NOISY-1)
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
        l.msg("override number, for some unknown reason", num=45)

    def testTheLogger(self):
        log.msg("This goes to the One True Logger")

    def testTubLogger(self):
        t = GoodEnoughTub()
        t.log("this goes into the tub")

class Advanced(unittest.TestCase):

    def testObserver(self):
        l = log.FoolscapLogger()
        out = []
        l.addObserver(out.append)
        l.set_generation_threshold(log.OPERATIONAL)
        l.msg("one")
        l.msg("two")
        l.msg("ignored", level=log.NOISY)
        d = fireEventually()
        def _check(res):
            self.failUnlessEqual(len(out), 2)
            self.failUnlessEqual(out[0]["message"], "one")
            self.failUnlessEqual(out[1]["message"], "two")
        d.addCallback(_check)
        return d

    def testFileObserver(self):
        l = log.FoolscapLogger()
        ob = log.LogFileObserver("observer-log.out")
        l.addObserver(ob.msg)
        l.msg("one")
        l.msg("two")
        d = fireEventually()
        def _check(res):
            l.removeObserver(ob.msg)
            ob._logFile.close()
            f = open("observer-log.out", "rb")
            events = []
            while True:
                try:
                    e = pickle.load(f)
                    events.append(e)
                except EOFError:
                    break
            self.failUnlessEqual(len(events), 2)
            self.failUnlessEqual(events[0]["from"], "local")
            self.failUnlessEqual(events[1]["d"]["message"], "two")
        d.addCallback(_check)
        return d

    def testDisplace(self):
        l = log.FoolscapLogger()
        l.set_buffer_size(log.OPERATIONAL, 3)
        l.msg("one")
        l.msg("two")
        l.msg("three")
        items = l.buffers[None][log.OPERATIONAL]
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

        items = l.buffers["ui"][log.OPERATIONAL]
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
        l.set_buffer_size(log.WEIRD, 4, "new.facility")

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
        self.last_received = time.time()
    def remote_msg(self, d):
        self.messages.append(d)
        self.last_received = time.time()

class MyGatherer(gatherer.LogGatherer):
    verbose = False
    furlFile = None

    def remote_logport(self, nodeid, publisher):
        gatherer.LogGatherer.remote_logport(self, nodeid, publisher)
        self.d.callback(publisher)

class SampleError(Exception):
    """a sample error"""

class Publish(PollMixin, unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        log.setTwistedLogBridge(None) # disable any bridge still in place
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

    def test_logport_furlfile1(self):
        basedir = "test_logging/test_logport_furlfile1"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        t.setOption("logport-furlfile", furlfile)
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        self.failIf(os.path.exists(furlfile))
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        logport_furl = open(furlfile, "r").read().strip()

    def test_logport_furlfile2(self):
        basedir = "test_logging/test_logport_furlfile2"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setOption("logport-furlfile", furlfile)
        self.failIf(os.path.exists(furlfile))
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        logport_furl = open(furlfile, "r").read().strip()

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

        do_twisted_errors = hasattr(self, "flushLoggedErrors")

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            d = logport.callRemote("get_versions")
            def _check(versions):
                self.failUnlessEqual(versions["foolscap"],
                                     foolscap.__version__)
            d.addCallback(_check)
            # note: catch_up=False, so this message won't be sent
            log.msg("message 0 here, before your time")
            d.addCallback(lambda res:
                          logport.callRemote("subscribe_to_all", ob))
            def _emit(subscription):
                self._subscription = subscription
                ob.last_received = time.time()
                log.msg("message 1 here")
                twisted_log.msg("message 2 here")
                # switch to generic (no tubid) bridge
                log.bridgeTwistedLogs()
                twisted_log.msg("message 3 here")
                twisted_log.msg(format="%(foo)s is foo", foo="foo")
                log.err(failure.Failure(SampleError("err1")))
                log.err(SampleError("err2"))
                if do_twisted_errors:
                    twisted_log.err(failure.Failure(SampleError("err3")))
                    twisted_log.err(SampleError("err4"))
                    # twisted-2.5.0 added flushLoggedErrors, which makes
                    # it much easier for unit test to exercise error logging
                    errors = self.flushLoggedErrors(SampleError)
                    self.failUnlessEqual(len(errors), 2)
            d.addCallback(_emit)
            # now we wait until the observer has seen nothing for a full
            # second. I'd prefer something faster and more deterministic, but
            # this ought to handle the normal slow-host cases.
            def _check_f():
                if ob.last_received < time.time() - 1.0:
                    return True
                return False
            d.addCallback(lambda res: self.poll(_check_f))
            # TODO: I'm not content with that absolute-time stall, and would
            # prefer to do something faster and more deterministic
            #d.addCallback(fireEventually)
            #d.addCallback(fireEventually)
            def _check_observer(res):
                msgs = ob.messages
                expected = 6
                if do_twisted_errors:
                    expected += 2
                self.failUnlessEqual(len(msgs), expected)
                #print msgs
                self.failUnlessEqual(msgs[0]["message"], "message 1 here")
                self.failUnlessEqual(msgs[1]["message"], "message 2 here")
                self.failUnlessEqual(msgs[1]["tubID"], t.tubID)
                self.failUnlessEqual(msgs[2]["message"], "message 3 here")
                self.failUnlessEqual(msgs[2]["tubID"], None)
                self.failUnlessEqual(msgs[3]["format"], "%(foo)s is foo")
                self.failUnlessEqual(msgs[3]["foo"], "foo")

                # check the errors
                self.failUnlessEqual(msgs[4]["message"], "")
                self.failUnless(msgs[4]["isError"])
                self.failUnless("failure" in msgs[4])
                self.failUnless(msgs[4]["failure"].check(SampleError))
                self.failUnless("err1" in str(msgs[4]["failure"]))
                self.failUnlessEqual(msgs[5]["message"], "")
                self.failUnless(msgs[5]["isError"])
                self.failUnless("failure" in msgs[5])
                self.failUnless(msgs[5]["failure"].check(SampleError))
                self.failUnless("err2" in str(msgs[5]["failure"]))

                if do_twisted_errors:
                    self.failUnlessEqual(msgs[6]["message"], "")
                    self.failUnless(msgs[6]["isError"])
                    self.failUnless("failure" in msgs[6])
                    self.failUnless(msgs[6]["failure"].check(SampleError))
                    self.failUnless("err3" in str(msgs[6]["failure"]))

                    self.failUnlessEqual(msgs[7]["message"], "")
                    self.failUnless(msgs[7]["isError"])
                    self.failUnless("failure" in msgs[7])
                    self.failUnless(msgs[7]["failure"].check(SampleError))
                    self.failUnless("err4" in str(msgs[7]["failure"]))

            d.addCallback(_check_observer)
            def _done(res):
                return logport.callRemote("unsubscribe", self._subscription)
            d.addCallback(_done)
            return d
        d.addCallback(_got_logport)
        return d

    def test_logpublisher_catchup(self):
        basedir = "test_logging/test_logpublisher_catchup"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()

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
            # note: catch_up=True, so this message *will* be sent. Also note
            # that we need this message to be unique, since our logger will
            # stash messages recorded by other test cases, and we don't want
            # to confuse the two.
            log.msg("this is an early message")
            d.addCallback(lambda res:
                          logport.callRemote("subscribe_to_all", ob, True))
            def _emit(subscription):
                self._subscription = subscription
                ob.last_received = time.time()
                log.msg("this is a later message")
            d.addCallback(_emit)
            # wait until the observer has seen nothing for a full second
            def _check_f():
                if ob.last_received < time.time() - 1.0:
                    return True
                return False
            d.addCallback(lambda res: self.poll(_check_f))
            def _check_observer(res):
                msgs = ob.messages
                # this gets everything that's been logged since the unit
                # tests began. The Reconnector that's used by
                # logport-furlfile will cause some uncertainty.. negotiation
                # messages might be interleaved with the ones that we
                # actually care about. So what we verify is that both of our
                # messages appear *somewhere*, and that they show up in the
                # correct order.
                self.failUnless(len(msgs) >= 2, len(msgs))
                first = None
                second = None
                for i,m in enumerate(msgs):
                    if m.get("message") == "this is an early message":
                        first = i
                    if m.get("message") == "this is a later message":
                        second = i
                self.failUnless(first is not None)
                self.failUnless(second is not None)
                self.failUnless(first < second,
                                "%d is not before %d" % (first, second))
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
            try:
                raise SampleError("whoops1")
            except:
                log.err()
            def _oops():
                raise SampleError("whoops2")
            d2 = defer.maybeDeferred(_oops)
            d2.addErrback(log.err)
            return d2
        d.addCallback(_go)
        d.addCallback(self.stall, 1.0)
        d.addCallback(lambda res: t2.disownServiceParent())
        # that will disconnect from the gatherer, which will flush the logfile
        d.addCallback(self.stall, 1.0)
        def _check(res):
            gatherer._savefile.close()
            fn = os.path.join(basedir, "logs.pickle")
            f = open(fn, "r")
            events = []
            while True:
                try:
                    events.append(pickle.load(f))
                except EOFError:
                    break
            self.failUnlessEqual(len(events), 3)

            # grab the first event from the log
            data = events[0]
            self.failUnless(isinstance(data, dict))
            expected_tubid = t2.tubID
            if t2.tubID is None:
                expected_tubid = "<unauth>"
            self.failUnlessEqual(data['from'], expected_tubid)
            self.failUnlessEqual(data['d']['message'], "gathered message here")

            # grab the second event from the log
            data = events[1]
            self.failUnless(isinstance(data, dict))
            expected_tubid = t2.tubID
            if t2.tubID is None:
                expected_tubid = "<unauth>"
            self.failUnlessEqual(data['from'], expected_tubid)
            self.failUnlessEqual(data['d']['message'], "")
            self.failUnless(data['d']["isError"])
            self.failUnless("failure" in data['d'])
            self.failUnless(data['d']["failure"].check(SampleError))
            self.failUnless("whoops1" in str(data['d']["failure"]))

            # grab the third event from the log
            data = events[2]
            self.failUnless(isinstance(data, dict))
            expected_tubid = t2.tubID
            if t2.tubID is None:
                expected_tubid = "<unauth>"
            self.failUnlessEqual(data['from'], expected_tubid)
            self.failUnlessEqual(data['d']['message'], "")
            self.failUnless(data['d']["isError"])
            self.failUnless("failure" in data['d'])
            self.failUnless(data['d']["failure"].check(SampleError))
            self.failUnless("whoops2" in str(data['d']["failure"]))

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
    test_log_gatherer.timeout = 20

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
    test_log_gatherer_furlfile.timeout = 20

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
    test_log_gatherer_empty_furlfile.timeout = 20



