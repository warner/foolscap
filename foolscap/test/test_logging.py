
import os, pickle, time, bz2
from cStringIO import StringIO
from zope.interface import implements
from twisted.trial import unittest
from twisted.application import service
from twisted.internet import defer, reactor
from twisted.python import log as twisted_log
from twisted.python import failure, runtime, usage
import foolscap
from foolscap.logging import gatherer, log, tail, incident, cli, web
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
        basedir = "logging/Advanced/FileObserver"
        os.makedirs(basedir)
        l = log.FoolscapLogger()
        fn = os.path.join(basedir, "observer-log.out")
        ob = log.LogFileObserver(fn)
        l.addObserver(ob.msg)
        l.msg("one")
        l.msg("two")
        d = fireEventually()
        def _check(res):
            l.removeObserver(ob.msg)
            ob._logFile.close()
            f = open(fn, "rb")
            events = []
            while True:
                try:
                    e = pickle.load(f)
                    events.append(e)
                except EOFError:
                    break
            self.failUnlessEqual(len(events), 3)
            self.failUnlessEqual(events[0]["header"]["type"],
                                 "log-file-observer")
            self.failUnlessEqual(events[0]["header"]["threshold"],
                                 log.OPERATIONAL)
            self.failUnlessEqual(events[1]["from"], "local")
            self.failUnlessEqual(events[2]["d"]["message"], "two")
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

class SuperstitiousQualifier(incident.IncidentQualifier):
    def check_event(self, ev):
        if "thirteen" in ev.get("message", ""):
            return True
        return False

class ImpatientReporter(incident.IncidentReporter):
    TRAILING_DELAY = 1.0
    TRAILING_EVENT_LIMIT = 3

class Incidents(unittest.TestCase, PollMixin):
    def test_basic(self):
        l = log.FoolscapLogger()
        self.failUnlessEqual(l.incidents_declared, 0)
        # no qualifiers are run until a logdir is provided
        l.msg("one", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 0)
        l.setLogDir("logging/Incidents/basic")
        got_logdir = l.logdir
        self.failUnlessEqual(got_logdir,
                             os.path.abspath("logging/Incidents/basic"))
        # qualifiers should be run now
        l.msg("two")
        l.msg("3-trigger", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 1)
        self.failUnlessEqual(len(l.active_incident_reporters), 1)
        # at this point, the uncompressed logfile should be present, and it
        # should contain all the events up to and including the trigger
        files = os.listdir(got_logdir)
        self.failUnlessEqual(len(files), 2)
        # the uncompressed one will sort earlier, since it lacks the .bz2
        # extension
        files.sort()
        self.failUnlessEqual(files[0] + ".bz2.tmp", files[1])
        # unix systems let us look inside the uncompressed file while it's
        # still being written to by the recorder
        if runtime.platformType == "posix":
            events = self._read_logfile(os.path.join(got_logdir, files[0]))
            self.failUnlessEqual(len(events), 1+3)
            header = events[0]
            self.failUnless("header" in events[0])
            self.failUnlessEqual(events[0]["header"]["trigger"]["message"],
                                 "3-trigger")
            self.failUnlessEqual(events[3]["d"]["message"], "3-trigger")

        l.msg("4-trailing")
        # this will take 5 seconds to finish trailing events
        d = self.poll(lambda: bool(l.incidents_recorded), 1.0)
        def _check(res):
            self.failUnlessEqual(len(l.recent_recorded_incidents), 1)
            fn = l.recent_recorded_incidents[0]
            events = self._read_logfile(fn)
            self.failUnlessEqual(len(events), 1+4)
            self.failUnless("header" in events[0])
            self.failUnlessEqual(events[0]["header"]["trigger"]["message"],
                                 "3-trigger")
            self.failUnlessEqual(events[3]["d"]["message"], "3-trigger")
            self.failUnlessEqual(events[4]["d"]["message"], "4-trailing")

        d.addCallback(_check)
        return d

    def _read_logfile(self, fn):
        if fn.endswith(".bz2"):
            f = bz2.BZ2File(fn, "r")
        else:
            f = open(fn, "rb")
        events = []
        while True:
            try:
                events.append(pickle.load(f))
            except EOFError:
                break
            except ValueError:
                break
        f.close()
        return events

    def test_qualifier1(self):
        l = log.FoolscapLogger()
        l.setIncidentQualifier(SuperstitiousQualifier())
        l.setLogDir("logging/Incidents/qualifier1")
        l.msg("1", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 0)

    def test_qualifier2(self):
        l = log.FoolscapLogger()
        # call them in the other order
        l.setLogDir("logging/Incidents/qualifier2")
        l.setIncidentQualifier(SuperstitiousQualifier())
        l.msg("1", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 0)

    def test_customize(self):
        l = log.FoolscapLogger()
        l.setIncidentQualifier(SuperstitiousQualifier())
        l.setLogDir("logging/Incidents/customize")
        # you set the reporter *class*, not an instance
        bad_ir = ImpatientReporter("basedir", "logger", "tubid")
        self.failUnlessRaises((AssertionError, TypeError),
                              l.setIncidentReporterFactory, bad_ir)
        l.setIncidentReporterFactory(ImpatientReporter)
        l.msg("1", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 0)
        l.msg("2")
        l.msg("thirteen is scary")
        self.failUnlessEqual(l.incidents_declared, 1)
        l.msg("4")
        l.msg("5")
        l.msg("6") # this should hit the trailing event limit
        l.msg("7") # this should not be recorded
        d = self.poll(lambda: bool(l.incidents_recorded), 1.0)
        def _check(res):
            self.failUnlessEqual(len(l.recent_recorded_incidents), 1)
            fn = l.recent_recorded_incidents[0]
            events = self._read_logfile(fn)
            self.failUnlessEqual(len(events), 1+6)
            self.failUnlessEqual(events[-1]["d"]["message"], "6")
        d.addCallback(_check)
        return d


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
        basedir = "logging/Publish/logport_furlfile1"
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
        basedir = "logging/Publish/logport_furlfile2"
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
        basedir = "logging/Publish/logpublisher"
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
                    # twisted-8.0 has textFromEventDict, which means we get a
                    # ["message"] key from log.err . In older version of
                    # twisted, we don't.
                    if msgs[6]["message"]:
                        self.failUnless("Unhandled Error" in msgs[6]["message"])
                        self.failUnless("SampleError: err3" in msgs[6]["message"])
                    self.failUnless(msgs[6]["isError"])
                    self.failUnless("failure" in msgs[6])
                    self.failUnless(msgs[6]["failure"].check(SampleError))
                    self.failUnless("err3" in str(msgs[6]["failure"]))

                    # same
                    if msgs[7]["message"]:
                        self.failUnless("Unhandled Error" in msgs[7]["message"])
                        self.failUnless("SampleError: err4" in msgs[7]["message"])
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
        basedir = "logging/Publish/logpublisher_catchup"
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

class IncidentPublisher(unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

    def test_get_incidents(self):
        basedir = "logging/IncidentPublisher/get_incidents"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        t.logger = self.logger = log.FoolscapLogger()
        logdir = os.path.join(basedir, "logdir")
        t.logger.setLogDir(logdir)
        t.logger.setIncidentReporterFactory(incident.NonTrailingIncidentReporter)
        # dump some other files in the incident directory
        open(os.path.join(logdir, "distraction.bz2"), "w").write("stuff")
        open(os.path.join(logdir, "noise"), "w").write("stuff")
        # fill the buffers with some messages
        t.logger.msg("one")
        t.logger.msg("two")
        # and trigger an incident
        t.logger.msg("three", level=log.WEIRD)
        # the NonTrailingIncidentReporter needs a turn before it will have
        # finished recording the event: the getReference() call will suffice.

        # now set up a Tub to connect to the logport
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()
        logport_furl2 = open(furlfile, "r").read().strip()
        self.failUnlessEqual(logport_furl, logport_furl2)

        t2 = GoodEnoughTub()
        t2.setServiceParent(self.parent)

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            d = logport.callRemote("list_incidents")
            d.addCallback(self._check_listed)
            d.addCallback(lambda res:
                          logport.callRemote("get_incident", self.i_name))
            d.addCallback(self._check_incident)
            def _decompress(res):
                # now we manually decompress the logfile for that incident,
                # to exercise the code that provides access to incidents that
                # did not finish their trailing-gather by the time the
                # application was shut down
                fn1 = os.path.join(logdir, self.i_name)
                assert fn1.endswith(".bz2")
                fn2 = fn1[:-len(".bz2")]
                f1 = bz2.BZ2File(fn1, "r")
                f2 = open(fn2, "wb")
                f2.write(f1.read())
                f2.close()
                f1.close()
                os.unlink(fn1)
            d.addCallback(_decompress)
            # and do it again
            d.addCallback(lambda res: logport.callRemote("list_incidents"))
            d.addCallback(self._check_listed)
            d.addCallback(lambda res:
                          logport.callRemote("get_incident", self.i_name))
            d.addCallback(self._check_incident)
            return d
        d.addCallback(_got_logport)
        return d

    def _check_listed(self, incidents):
        self.failUnless(isinstance(incidents, dict))
        self.failUnlessEqual(len(incidents), 1)
        self.i_name = i_name = incidents.keys()[0]
        (tubid_s, incarnation, trigger) = incidents[i_name]
        self.failUnlessEqual(tubid_s, "local")
        self.failUnlessEqual(incarnation, self.logger.incarnation)
        self.failUnlessEqual(trigger["message"], "three")
    def _check_incident(self, (header, events) ):
        self.failUnlessEqual(header["type"], "incident")
        self.failUnlessEqual(header["trigger"]["message"], "three")
        self.failUnlessEqual(len(events), 3)
        self.failUnlessEqual(events[0]["message"], "one")

class Gatherer(PollMixin, unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        log.setTwistedLogBridge(None) # disable any bridge still in place
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
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
            self.failUnlessEqual(len(events), 4)

            # header
            data = events.pop(0)
            self.failUnless(isinstance(data, dict))
            self.failUnless("header" in data)
            self.failUnlessEqual(data["header"]["type"], "gatherer")
            self.failUnlessEqual(data["header"]["start"], 123.456)

            # grab the first event from the log
            data = events.pop(0)
            self.failUnless(isinstance(data, dict))
            expected_tubid = t2.tubID
            if t2.tubID is None:
                expected_tubid = "<unauth>"
            self.failUnlessEqual(data['from'], expected_tubid)
            self.failUnlessEqual(data['d']['message'], "gathered message here")

            # grab the second event from the log
            data = events.pop(0)
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
            data = events.pop(0)
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
        basedir = "logging/Gatherer/log_gatherer"
        os.makedirs(basedir)

        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        gatherer = MyGatherer()
        gatherer.d = defer.Deferred()
        fn = os.path.join(basedir, "logs.pickle")
        gatherer._open_savefile(123.456, fn)
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
        basedir = "logging/Gatherer/log_gatherer_furlfile"
        os.makedirs(basedir)

        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        gatherer = MyGatherer()
        gatherer.d = defer.Deferred()
        fn = os.path.join(basedir, "logs.pickle")
        gatherer._open_savefile(123.456, fn)
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
        basedir = "logging/Gatherer/log_gatherer_empty_furlfile"
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


class Tail(unittest.TestCase):
    def test_logprinter(self):
        target_tubid_s = "jiijpvbge2e3c3botuzzz7la3utpl67v"
        options1 = {"save-to": None,
                   "verbose": None}
        out = StringIO()
        lp = tail.LogPrinter(options1, target_tubid_s[:8], out)
        lp.remote_msg({"time": 1207005906.527782,
                       "level": 25,
                       "num": 123,
                       "message": "howdy",
                       })
        outmsg = out.getvalue()
        # this contains a localtime string, so don't check the hour
        self.failUnless(":25:06.527 L25 []#123 howdy" in outmsg)

        lp.remote_msg({"time": 1207005907.527782,
                       "level": 25,
                       "num": 124,
                       "format": "howdy %(there)s",
                       "there": "pardner",
                       })
        outmsg = out.getvalue()
        # this contains a localtime string, so don't check the hour
        self.failUnless(":25:07.527 L25 []#124 howdy pardner" in outmsg)

        try:
            raise RuntimeError("fake error")
        except RuntimeError:
            f = failure.Failure()

        lp.remote_msg({"time": 1207005950.002,
                       "level": 30,
                       "num": 125,
                       "message": "oops",
                       "failure": f,
                       })
        outmsg = out.getvalue()

        self.failUnless(":25:50.002 L30 []#125 oops\n FAILURE:\n" in outmsg,
                        outmsg)
        self.failUnless("exceptions.RuntimeError" in outmsg, outmsg)
        self.failUnless(": fake error" in outmsg, outmsg)
        self.failUnless("--- <exception caught here> ---\n" in outmsg, outmsg)

    def test_logprinter_verbose(self):
        target_tubid_s = "jiijpvbge2e3c3botuzzz7la3utpl67v"
        options1 = {"save-to": None,
                   "verbose": True}
        out = StringIO()
        lp = tail.LogPrinter(options1, target_tubid_s[:8], out)
        lp.remote_msg({"time": 1207005906.527782,
                       "level": 25,
                       "num": 123,
                       "message": "howdy",
                       })
        outmsg = out.getvalue()
        self.failUnless("'message': 'howdy'" in outmsg, outmsg)
        self.failUnless("'time': 1207005906.527782" in outmsg, outmsg)
        self.failUnless("'level': 25" in outmsg, outmsg)
        self.failUnless("{" in outmsg, outmsg)

    def test_logprinter_saveto(self):
        target_tubid_s = "jiijpvbge2e3c3botuzzz7la3utpl67v"
        saveto_filename = "test_logprinter_saveto.flog"
        options = {"save-to": saveto_filename,
                   "verbose": False}
        out = StringIO()
        lp = tail.LogPrinter(options, target_tubid_s[:8], out)
        lp.remote_msg({"time": 1207005906.527782,
                       "level": 25,
                       "num": 123,
                       "message": "howdy",
                       })
        outmsg = out.getvalue()
        lp.saver.disconnected() # cause the file to be closed
        f = open(saveto_filename, "rb")
        data = pickle.load(f) # header
        self.failUnlessEqual(data["header"]["type"], "tail")
        data = pickle.load(f) # event
        self.failUnlessEqual(data["from"], "jiijpvbg")
        self.failUnlessEqual(data["d"]["message"], "howdy")
        self.failUnlessEqual(data["d"]["num"], 123)

    def test_options(self):
        basedir = "logging/Tail/options"
        os.makedirs(basedir)
        fn = os.path.join(basedir, "foo")
        f = open(fn, "w")
        f.write("pretend this is a furl")
        f.close()
        f = open(os.path.join(basedir, "logport.furl"), "w")
        f.write("this too")
        f.close()

        to = tail.TailOptions()
        to.parseOptions(["pb:pretend-furl"])
        self.failIf(to["verbose"])
        self.failIf(to["catch-up"])
        self.failUnlessEqual(to.target_furl, "pb:pretend-furl")

        to = tail.TailOptions()
        to.parseOptions(["--verbose", "--catch-up", basedir])
        self.failUnless(to["verbose"])
        self.failUnless(to["catch-up"])
        self.failUnlessEqual(to.target_furl, "this too")

        to = tail.TailOptions()
        to.parseOptions(["--save-to", "save.flog", fn])
        self.failIf(to["verbose"])
        self.failIf(to["catch-up"])
        self.failUnlessEqual(to["save-to"], "save.flog")
        self.failUnlessEqual(to.target_furl, "pretend this is a furl")

        to = tail.TailOptions()
        self.failUnlessRaises(RuntimeError, to.parseOptions, ["bogus.txt"])

# applications that provide a command-line tool may find it useful to include
# a "flogtool" subcommand, using something like this:
class WrapperOptions(usage.Options):
    synopsis = "Usage: wrapper flogtool <command>"
    subCommands = [("flogtool", None, cli.Options, "foolscap log tool")]

def run_wrapper(argv):
    config = WrapperOptions()
    config.parseOptions(argv)
    command = config.subCommand
    if command == "flogtool":
        so = config.subOptions
        return cli.run_flogtool(argv[1:])

class CLI(unittest.TestCase):
    def test_create_gatherer(self):
        basedir = "logging/CLI/create_gatherer"
        argv = ["flogtool", "create-gatherer", "--quiet", basedir]
        cli.run_flogtool(argv[1:], run_by_human=False)
        self.failUnless(os.path.exists(basedir))

    def test_create_gatherer_badly(self):
        basedir = "logging/CLI/create_gatherer"
        argv = ["flogtool", "create-gatherer", "--bogus-arg"]
        self.failUnlessRaises(usage.UsageError,
                              cli.run_flogtool, argv[1:], run_by_human=False)

    def test_wrapper(self):
        basedir = "logging/CLI/wrapper"
        argv = ["wrapper", "flogtool", "create-gatherer", "--quiet", basedir]
        run_wrapper(argv[1:])
        self.failUnless(os.path.exists(basedir))

class Web(unittest.TestCase):
    def setUp(self):
        self.viewer = None
    def tearDown(self):
        d = defer.maybeDeferred(unittest.TestCase.tearDown, self)
        if self.viewer:
            d.addCallback(lambda res: self.viewer.serv.stopService())
        return d

    def test_basic(self):
        from twisted.web import client
        basedir = "logging/Web/basic"
        os.makedirs(basedir)
        l = log.FoolscapLogger()
        fn = os.path.join(basedir, "flog.out")
        ob = log.LogFileObserver(fn)
        l.addObserver(ob.msg)
        l.msg("one")
        lp = l.msg("two")
        l.msg("three", parent=lp, failure=failure.Failure(RuntimeError("yo")))
        l.msg("four", level=log.UNUSUAL)
        d = fireEventually()
        def _created(res):
            l.removeObserver(ob.msg)
            ob._stop()
            argv = ["-p", "tcp:0:interface=127.0.0.1",
                    "--quiet",
                    fn]
            options = web.WebViewerOptions()
            options.parseOptions(argv)
            self.viewer = web.WebViewer()
            self.url = self.viewer.start(options)
            self.baseurl = self.url[:self.url.rfind("/")] + "/"

        d.addCallback(_created)
        d.addCallback(lambda res: client.getPage(self.url))
        def _check_welcome(page):
            self.failUnless("4 events covering" in page)
            self.failUnless('href="summary/0-20">3 events</a> at level 20'
                            in page)
        d.addCallback(_check_welcome)
        d.addCallback(lambda res:
                      client.getPage(self.baseurl + "summary/0-20"))
        def _check_summary(page):
            self.failUnless("Events at level 20" in page)
            self.failUnless(": two" in page)
            self.failIf("four" in page)
        d.addCallback(_check_summary)
        d.addCallback(lambda res: client.getPage(self.baseurl + "all-events"))
        def _check_all_events(page):
            self.failUnless("3 root events" in page)
            self.failUnless(": one</span>" in page)
            self.failUnless(": two</span>" in page)
            self.failUnless(": three FAILURE:" in page)
            self.failUnless(": UNUSUAL four</span>" in page)
        d.addCallback(_check_all_events)
        d.addCallback(lambda res:
                      client.getPage(self.baseurl + "all-events?sort=number"))
        d.addCallback(_check_all_events)
        d.addCallback(lambda res:
                      client.getPage(self.baseurl + "all-events?sort=time"))
        d.addCallback(_check_all_events)
        return d

