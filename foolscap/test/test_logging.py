
import os, pickle, time, bz2
from cStringIO import StringIO
from zope.interface import implements
from twisted.trial import unittest
from twisted.application import service
from twisted.internet import defer
from twisted.python import log as twisted_log
from twisted.python import failure, runtime, usage
import foolscap
from foolscap.logging import gatherer, log, tail, incident, cli, web, \
     publish, dumper
from foolscap.logging.interfaces import RILogObserver
from foolscap.eventual import fireEventually, flushEventualQueue
from foolscap.tokens import NoLocationError
from foolscap.test.common import PollMixin, StallMixin, GoodEnoughTub
from foolscap.api import RemoteException, Referenceable


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

    def testFailure(self):
        l = log.FoolscapLogger()
        f1 = failure.Failure(ValueError("bad value"))
        l.msg("failure1", failure=f1)
        # real RemoteExceptions always wrap CopiedFailure, so this is not
        # really accurate. However, it's a nuisance to create a real
        # CopiedFailure: look in
        # test_call.ExamineFailuresMixin._examine_raise for test code that
        # exercises this properly.
        f2 = failure.Failure(RemoteException(f1))
        l.msg("failure2", failure=f2)

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

class NoFollowUpReporter(incident.IncidentReporter):
    TRAILING_DELAY = None

class LogfileReaderMixin:
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

class Incidents(unittest.TestCase, PollMixin, LogfileReaderMixin):
    def test_basic(self):
        l = log.FoolscapLogger()
        self.failUnlessEqual(l.incidents_declared, 0)
        # no qualifiers are run until a logdir is provided
        l.msg("one", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 0)
        l.setLogDir("logging/Incidents/basic")
        l.setLogDir("logging/Incidents/basic") # this should be idempotent
        got_logdir = l.logdir
        self.failUnlessEqual(got_logdir,
                             os.path.abspath("logging/Incidents/basic"))
        # qualifiers should be run now
        l.msg("two")
        l.msg("3-trigger", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 1)
        self.failUnless(l.get_active_incident_reporter())
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
            #header = events[0]
            self.failUnless("header" in events[0])
            self.failUnlessEqual(events[0]["header"]["trigger"]["message"],
                                 "3-trigger")
            self.failUnlessEqual(events[0]["header"]["versions"]["foolscap"],
                                 foolscap.__version__)
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
            self.failUnlessEqual(events[0]["header"]["versions"]["foolscap"],
                                 foolscap.__version__)
            self.failUnlessEqual(events[3]["d"]["message"], "3-trigger")
            self.failUnlessEqual(events[4]["d"]["message"], "4-trailing")

        d.addCallback(_check)
        return d

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

    def test_overlapping(self):
        l = log.FoolscapLogger()
        l.setLogDir("logging/Incidents/overlapping")
        got_logdir = l.logdir
        self.failUnlessEqual(got_logdir,
                             os.path.abspath("logging/Incidents/overlapping"))
        d = defer.Deferred()
        def _go(name, trigger):
            d.callback( (name, trigger) )
        l.addImmediateIncidentObserver(_go)
        l.setIncidentReporterFactory(ImpatientReporter)
        l.msg("1")
        l.msg("2-trigger", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 1)
        self.failUnless(l.get_active_incident_reporter())
        l.msg("3-trigger", level=log.BAD)
        self.failUnlessEqual(l.incidents_declared, 2)
        self.failUnless(l.get_active_incident_reporter())

        def _check(res):
            self.failUnlessEqual(l.incidents_recorded, 1)
            self.failUnlessEqual(len(l.recent_recorded_incidents), 1)
            # at this point, the logfile should be present, and it should
            # contain all the events up to and including both triggers

            files = os.listdir(got_logdir)
            self.failUnlessEqual(len(files), 1)
            events = self._read_logfile(os.path.join(got_logdir, files[0]))

            self.failUnlessEqual(len(events), 1+3)
            self.failUnlessEqual(events[0]["header"]["trigger"]["message"],
                                 "2-trigger")
            self.failUnlessEqual(events[1]["d"]["message"], "1")
            self.failUnlessEqual(events[2]["d"]["message"], "2-trigger")
            self.failUnlessEqual(events[3]["d"]["message"], "3-trigger")
        d.addCallback(_check)

        return d

    def test_classify(self):
        l = log.FoolscapLogger()
        l.setIncidentReporterFactory(incident.NonTrailingIncidentReporter)
        l.setLogDir("logging/Incidents/classify")
        got_logdir = l.logdir
        l.msg("foom", level=log.BAD, failure=failure.Failure(RuntimeError()))
        d = fireEventually()
        def _check(res):
            files = [fn for fn in os.listdir(got_logdir) if fn.endswith(".bz2")]
            self.failUnlessEqual(len(files), 1)

            ic = incident.IncidentClassifier()
            def classify_foom(trigger):
                if "foom" in trigger.get("message",""):
                    return "foom"
            ic.add_classifier(classify_foom)
            options = incident.ClassifyOptions()
            options.parseOptions([os.path.join(got_logdir, fn) for fn in files])
            options.stdout = StringIO()
            ic.run(options)
            out = options.stdout.getvalue()
            self.failUnless(out.strip().endswith(": foom"), out)

            ic2 = incident.IncidentClassifier()
            options = incident.ClassifyOptions()
            options.parseOptions(["--verbose"] +
                                 [os.path.join(got_logdir, fn) for fn in files])
            options.stdout = StringIO()
            ic2.run(options)
            out = options.stdout.getvalue()
            self.failUnless(".flog.bz2: unknown\n" in out, out)
            # this should have a pprinted trigger dictionary
            self.failUnless("'message': 'foom'," in out, out)
            self.failUnless("'num': 0," in out, out)
            self.failUnless("RuntimeError" in out, out)

        d.addCallback(_check)
        return d

class Observer(Referenceable):
    implements(RILogObserver)
    def __init__(self):
        self.messages = []
        self.incidents = []
        self.done_with_incidents = False
        self.last_received = time.time()
    def remote_msg(self, d):
        self.messages.append(d)
        self.last_received = time.time()

    def remote_new_incident(self, name, trigger):
        self.incidents.append( (name, trigger) )
    def remote_done_with_incident_catchup(self):
        self.done_with_incidents = True

class MyGatherer(gatherer.GathererService):
    verbose = False

    def remote_logport(self, nodeid, publisher):
        d = gatherer.GathererService.remote_logport(self, nodeid, publisher)
        d.addBoth(lambda res: self.d.callback(publisher))

class SampleError(Exception):
    """a sample error"""

class Publish(PollMixin, unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()
        # make the MAX_QUEUE_SIZE smaller to speed up the test, and restore
        # it when we're done. The normal value is 2000, chosen to bound the
        # queue to perhaps 1MB. Lowering the size from 2000 to 500 speeds up
        # the test from about 10s to 5s.
        self.saved_queue_size = publish.Subscription.MAX_QUEUE_SIZE
        publish.Subscription.MAX_QUEUE_SIZE = 500

    def tearDown(self):
        publish.Subscription.MAX_QUEUE_SIZE = self.saved_queue_size
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

    def test_logport_furlfile1(self):
        basedir = "logging/Publish/logport_furlfile1"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        # setOption before setServiceParent
        t.setOption("logport-furlfile", furlfile)
        t.setServiceParent(self.parent)
        self.failUnlessRaises(NoLocationError, t.getLogPort)
        self.failUnlessRaises(NoLocationError, t.getLogPortFURL)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        self.failIf(os.path.exists(furlfile))
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        logport_furl = open(furlfile, "r").read().strip()
        self.failUnlessEqual(logport_furl, t.getLogPortFURL())

    def test_logport_furlfile2(self):
        basedir = "logging/Publish/logport_furlfile2"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        # setServiceParent before setOption
        t.setServiceParent(self.parent)
        self.failUnlessRaises(NoLocationError, t.getLogPort)
        self.failUnlessRaises(NoLocationError, t.getLogPortFURL)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setOption("logport-furlfile", furlfile)
        self.failIf(os.path.exists(furlfile))
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        logport_furl = open(furlfile, "r").read().strip()
        self.failUnlessEqual(logport_furl, t.getLogPortFURL())

    def test_logpublisher(self):
        basedir = "logging/Publish/logpublisher"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        self.failUnlessRaises(NoLocationError, t.getLogPort)
        self.failUnlessRaises(NoLocationError, t.getLogPortFURL)

        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()
        logport_furl2 = open(furlfile, "r").read().strip()
        self.failUnlessEqual(logport_furl, logport_furl2)
        tw_log = twisted_log.LogPublisher()
        tlb = t.setOption("bridge-twisted-logs", tw_log)

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
            # note: catch_up=False, so this message won't be sent
            log.msg("message 0 here, before your time")
            d.addCallback(lambda res:
                          logport.callRemote("subscribe_to_all", ob))
            def _emit(subscription):
                self._subscription = subscription
                ob.last_received = time.time()
                log.msg("message 1 here")
                tw_log.msg("message 2 here")

                # switch to generic (no tubid) bridge
                tw_log.removeObserver(tlb.observer)
                log.bridgeLogsFromTwisted(None, tw_log)

                tw_log.msg("message 3 here")
                tw_log.msg(format="%(foo)s is foo", foo="foo")
                log.err(failure.Failure(SampleError("err1")))
                log.err(SampleError("err2"))
                # simulate twisted.python.log.err, which is unfortunately
                # not a method of LogPublisher
                def err(_stuff=None, _why=None):
                    if isinstance(_stuff, Exception):
                        tw_log.msg(failure=failure.Failure(_stuff),
                                   isError=1, why=_why)
                    else:
                        tw_log.msg(failure=_stuff, isError=1, why=_why)
                err(failure.Failure(SampleError("err3")))
                err(SampleError("err4"))
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
                self.failUnlessEqual(len(msgs), 8)
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

    def test_logpublisher_overload(self):
        basedir = "logging/Publish/logpublisher_overload"
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

        t2 = GoodEnoughTub()
        t2.setServiceParent(self.parent)
        ob = Observer()

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            d = logport.callRemote("subscribe_to_all", ob)
            def _emit(subscription):
                self._subscription = subscription
                ob.last_received = time.time()
                for i in range(10000):
                    log.msg("message %d here" % i)
            d.addCallback(_emit)
            # now we wait until the observer has seen nothing for a full
            # second. I'd prefer something faster and more deterministic, but
            # this ought to handle the normal slow-host cases.
            expected = publish.Subscription.MAX_QUEUE_SIZE
            def _check_f():
                return bool(len(ob.messages) >= expected)
            d.addCallback(lambda res: self.poll(_check_f, 0.2))
            # TODO: I'm not content with that polling, and would prefer to do
            # something faster and more deterministic
            #d.addCallback(fireEventually)
            #d.addCallback(fireEventually)
            def _check_observer(res):
                msgs = ob.messages
                self.failUnlessEqual(len(msgs), expected)
                # since we discard new messages during overload (and preserve
                # old ones), we should see 0..MAX_QUEUE_SIZE-1.
                got = []
                for m in msgs:
                    ignored1, number_s, ignored2 = m["message"].split()
                    number = int(number_s)
                    got.append(number)
                self.failUnlessEqual(got, sorted(got))
                self.failUnlessEqual(got, range(expected))

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
            def _check_versions(versions):
                self.failUnlessEqual(versions["foolscap"],
                                     foolscap.__version__)
            d.addCallback(_check_versions)
            d.addCallback(lambda res: logport.callRemote("get_pid"))
            def _check_pid(pid):
                self.failUnlessEqual(pid, os.getpid())
            d.addCallback(_check_pid)
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
            # wait until we've received the later message
            def _check_f():
                for m in ob.messages:
                    if m.get("message") == "this is a later message":
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

class IncidentPublisher(PollMixin, unittest.TestCase):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

    def _write_to(self, logdir, fn, data="stuff"):
        f = open(os.path.join(logdir, fn), "w")
        f.write(data)
        f.close()

    def test_list_incident_names(self):
        basedir = "logging/IncidentPublisher/list_incident_names"
        os.makedirs(basedir)
        t = GoodEnoughTub()
        t.setLocation("127.0.0.1:1234")
        t.logger = self.logger = log.FoolscapLogger()
        logdir = os.path.join(basedir, "logdir")
        t.logger.setLogDir(logdir)
        p = t.getLogPort()

        # dump some other files in the incident directory
        self._write_to(logdir, "distraction.bz2")
        self._write_to(logdir, "noise")
        # and a few real-looking incidents
        I1 = "incident-2008-07-29-204211-aspkxoi"
        I2 = "incident-2008-07-30-112233-wodaei"
        I1_abs = os.path.abspath(os.path.join(logdir, I1 + ".flog"))
        I2_abs = os.path.abspath(os.path.join(logdir, I2 + ".flog.bz2"))
        self._write_to(logdir, I1 + ".flog")
        self._write_to(logdir, I2 + ".flog.bz2")

        all = list(p.list_incident_names())
        self.failUnlessEqual(set([name for (name,fn) in all]), set([I1, I2]))
        imap = dict(all)
        self.failUnlessEqual(imap[I1], I1_abs)
        self.failUnlessEqual(imap[I2], I2_abs)

        new = list(p.list_incident_names(since=I1))
        self.failUnlessEqual(set([name for (name,fn) in new]), set([I2]))


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
                assert not self.i_name.endswith(".bz2")
                fn1 = os.path.join(logdir, self.i_name) + ".flog.bz2"
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
        self.failUnless(i_name.startswith("incident"))
        self.failIf(i_name.endswith(".flog") or i_name.endswith(".bz2"))
        trigger = incidents[i_name]
        self.failUnlessEqual(trigger["message"], "three")
    def _check_incident(self, (header, events) ):
        self.failUnlessEqual(header["type"], "incident")
        self.failUnlessEqual(header["trigger"]["message"], "three")
        self.failUnlessEqual(len(events), 3)
        self.failUnlessEqual(events[0]["message"], "one")

    def test_subscribe(self):
        basedir = "logging/IncidentPublisher/subscribe"
        os.makedirs(basedir)
        t = GoodEnoughTub()
        t.logger = self.logger = log.FoolscapLogger()
        logdir = os.path.join(basedir, "logdir")
        t.logger.setLogDir(logdir)
        t.logger.setIncidentReporterFactory(incident.NonTrailingIncidentReporter)

        # fill the buffers with some messages
        t.logger.msg("boring")
        t.logger.msg("blah")
        # and trigger the first incident
        t.logger.msg("one", level=log.WEIRD)
        # the NonTrailingIncidentReporter needs a turn before it will have
        # finished recording the event: the getReference() call will suffice.

        # now set up a Tub to connect to the logport
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        logport_furl = t.getLogPortFURL()

        ob = Observer()
        t2 = GoodEnoughTub()
        t2.setServiceParent(self.parent)

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            self._logport = logport
            d2 = logport.callRemote("subscribe_to_incidents", ob) # no catchup
            return d2
        d.addCallback(_got_logport)
        def _subscribed(subscription):
            self._subscription = subscription
        d.addCallback(_subscribed)
        # pause long enough for the incident names to change
        d.addCallback(lambda res: time.sleep(2))
        d.addCallback(lambda res: t.logger.msg("two", level=log.WEIRD))
        d.addCallback(lambda res:
                      self.poll(lambda: bool(ob.incidents), 0.1))
        def _triggerof(incident):
            (name, trigger) = incident
            return trigger["message"]
        def _check_new(res):
            self.failUnlessEqual(len(ob.incidents), 1)
            self.failUnlessEqual(_triggerof(ob.incidents[0]), "two")
        d.addCallback(_check_new)
        d.addCallback(lambda res: self._subscription.callRemote("unsubscribe"))

        # now subscribe and catch up on all incidents
        ob2 = Observer()
        d.addCallback(lambda res:
                      self._logport.callRemote("subscribe_to_incidents", ob2,
                                               True, ""))
        d.addCallback(_subscribed)
        d.addCallback(lambda res:
                      self.poll(lambda: ob2.done_with_incidents, 0.1))
        def _check_all(res):
            self.failUnlessEqual(len(ob2.incidents), 2)
            self.failUnlessEqual(_triggerof(ob2.incidents[0]), "one")
            self.failUnlessEqual(_triggerof(ob2.incidents[1]), "two")
        d.addCallback(_check_all)

        d.addCallback(lambda res: time.sleep(2))
        d.addCallback(lambda res: t.logger.msg("three", level=log.WEIRD))
        d.addCallback(lambda res:
                      self.poll(lambda: len(ob2.incidents) >= 3, 0.1))
        def _check_all2(res):
            self.failUnlessEqual(len(ob2.incidents), 3)
            self.failUnlessEqual(_triggerof(ob2.incidents[0]), "one")
            self.failUnlessEqual(_triggerof(ob2.incidents[1]), "two")
            self.failUnlessEqual(_triggerof(ob2.incidents[2]), "three")
        d.addCallback(_check_all2)
        d.addCallback(lambda res: self._subscription.callRemote("unsubscribe"))

        # test the since= argument, setting it equal to the name of the
        # second incident. This should give us the third incident.
        ob3 = Observer()
        d.addCallback(lambda res:
                      self._logport.callRemote("subscribe_to_incidents", ob3,
                                               True, ob2.incidents[1][0]))
        d.addCallback(_subscribed)
        d.addCallback(lambda res:
                      self.poll(lambda: ob3.done_with_incidents, 0.1))
        def _check_since(res):
            self.failUnlessEqual(len(ob3.incidents), 1)
            self.failUnlessEqual(_triggerof(ob3.incidents[0]), "three")
        d.addCallback(_check_since)
        d.addCallback(lambda res: time.sleep(2))
        d.addCallback(lambda res: t.logger.msg("four", level=log.WEIRD))
        d.addCallback(lambda res:
                      self.poll(lambda: len(ob3.incidents) >= 2, 0.1))
        def _check_since2(res):
            self.failUnlessEqual(len(ob3.incidents), 2)
            self.failUnlessEqual(_triggerof(ob3.incidents[0]), "three")
            self.failUnlessEqual(_triggerof(ob3.incidents[1]), "four")
        d.addCallback(_check_since2)
        d.addCallback(lambda res: self._subscription.callRemote("unsubscribe"))

        return d
    test_subscribe.timeout = 20

class MyIncidentGathererService(gatherer.IncidentGathererService):
    verbose = False
    cb_new_incident = None

    def remote_logport(self, nodeid, publisher):
        d = gatherer.IncidentGathererService.remote_logport(self,
                                                            nodeid, publisher)
        d.addCallback(lambda res: self.d.callback(publisher))
        return d

    def new_incident(self, abs_fn, rel_fn, nodeid_s, incident):
        gatherer.IncidentGathererService.new_incident(self, abs_fn, rel_fn,
                                                      nodeid_s, incident)
        if self.cb_new_incident:
            self.cb_new_incident((abs_fn, rel_fn))

class IncidentGatherer(unittest.TestCase,
                       PollMixin, StallMixin, LogfileReaderMixin):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()
        self.logger = log.FoolscapLogger()
        self.logger.setIncidentReporterFactory(NoFollowUpReporter)

    def tearDown(self):
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d

    def create_incident_gatherer(self, basedir, classifiers=[]):
        # create an incident gatherer, which will make its own Tub
        ig_basedir = os.path.join(basedir, "ig")
        null = StringIO()
        ig = MyIncidentGathererService(classifiers=classifiers,
                                       basedir=ig_basedir, stdout=null)
        ig.tub_class = GoodEnoughTub
        ig.d = defer.Deferred()
        return ig

    def create_connected_tub(self, ig):
        t = GoodEnoughTub()
        t.logger = self.logger
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        t.setOption("log-gatherer-furl", ig.my_furl)

    def test_connect(self):
        basedir = "logging/IncidentGatherer/connect"
        os.makedirs(basedir)
        self.logger.setLogDir(basedir)

        ig = self.create_incident_gatherer(basedir)
        ig.setServiceParent(self.parent)
        self.create_connected_tub(ig)

        d = ig.d
        # give the call to remote_logport a chance to retire
        d.addCallback(self.stall, 0.5)
        return d

    def test_emit(self):
        basedir = "logging/IncidentGatherer/emit"
        os.makedirs(basedir)
        self.logger.setLogDir(basedir)

        ig = self.create_incident_gatherer(basedir)
        ig.setServiceParent(self.parent)
        incident_d = defer.Deferred()
        ig.cb_new_incident = incident_d.callback
        self.create_connected_tub(ig)

        d = ig.d

        d.addCallback(lambda res: self.logger.msg("boom", level=log.WEIRD))
        d.addCallback(lambda res: incident_d)
        def _new_incident((abs_fn, rel_fn)):
            events = self._read_logfile(abs_fn)
            header = events[0]["header"]
            self.failUnless("trigger" in header)
            self.failUnlessEqual(header["trigger"]["message"], "boom")
            e = events[1]["d"]
            self.failUnlessEqual(e["message"], "boom")

            # it should have been classified as "unknown"
            unknowns_fn = os.path.join(ig.basedir, "classified", "unknown")
            unknowns = [fn.strip() for fn in open(unknowns_fn,"r").readlines()]
            self.failUnlessEqual(len(unknowns), 1)
            self.failUnlessEqual(unknowns[0], rel_fn)
        d.addCallback(_new_incident)

        # now shut down the gatherer, create a new one with the same basedir
        # (with some classifier functions), remove the existing
        # classifications, and start it up. It should reclassify everything
        # at startup.

        d.addCallback(lambda res: ig.disownServiceParent())

        def classify_boom(trigger):
            if "boom" in trigger.get("message",""):
                return "boom"
        def classify_foom(trigger):
            if "foom" in trigger.get("message",""):
                return "foom"

        incident_d2 = defer.Deferred()
        def _update_classifiers(res):
            self.remove_classified_incidents(ig)
            ig2 = self.create_incident_gatherer(basedir, [classify_boom])
            ##ig2.add_classifier(classify_foom)
            # we add classify_foom by writing it into a file, to exercise the
            # look-for-classifier-files code
            foomfile = os.path.join(ig2.basedir, "classify_foom.py")
            f = open(foomfile, "w")
            f.write('''
def classify_incident(trigger):
    if "foom" in trigger.get("message",""):
        return "foom"
''')
            f.close()
            ig2.setServiceParent(self.parent)
            # now that it's been read, delete it to avoid affecting later
            # runs
            os.unlink(foomfile)
            self.ig2 = ig2

            # incidents should be classified in startService
            unknowns_fn = os.path.join(ig.basedir, "classified", "unknown")
            self.failIf(os.path.exists(unknowns_fn))
            booms_fn = os.path.join(ig.basedir, "classified", "boom")
            booms = [fn.strip() for fn in open(booms_fn,"r").readlines()]
            self.failUnlessEqual(len(booms), 1)
            fooms_fn = os.path.join(ig.basedir, "classified", "foom")
            self.failIf(os.path.exists(fooms_fn))

            ig2.cb_new_incident = incident_d2.callback

            return ig2.d
        d.addCallback(_update_classifiers)
        d.addCallback(lambda res: self.logger.msg("foom", level=log.WEIRD))
        d.addCallback(lambda res: incident_d2)
        def _new_incident2((abs_fn, rel_fn)):
            # this one should be classified as "foom"

            # it should have been classified as "unknown"
            fooms_fn = os.path.join(ig.basedir, "classified", "foom")
            fooms = [fn.strip() for fn in open(fooms_fn,"r").readlines()]
            self.failUnlessEqual(len(fooms), 1)
            self.failUnlessEqual(fooms[0], rel_fn)
            unknowns_fn = os.path.join(ig.basedir, "classified", "unknown")
            self.failIf(os.path.exists(unknowns_fn))
        d.addCallback(_new_incident2)
        d.addCallback(lambda res: self.ig2.disownServiceParent())

        # if we remove just classified/boom, then those incidents should be
        # reclassified

        def _remove_boom_incidents(res):
            booms_fn = os.path.join(ig.basedir, "classified", "boom")
            os.remove(booms_fn)

            ig2a = self.create_incident_gatherer(basedir, [classify_boom,
                                                           classify_foom])
            ig2a.setServiceParent(self.parent)
            self.ig2a = ig2a

            # now classified/boom should be back, and the other files should
            # have been left untouched
            booms = [fn.strip() for fn in open(booms_fn,"r").readlines()]
            self.failUnlessEqual(len(booms), 1)
        d.addCallback(_remove_boom_incidents)
        d.addCallback(lambda res: self.ig2a.disownServiceParent())

        # and if we remove the classification functions (but do *not* remove
        # the classified incidents), the new gatherer should not reclassify
        # anything

        def _update_classifiers_again(res):
            ig3 = self.create_incident_gatherer(basedir)
            ig3.setServiceParent(self.parent)
            self.ig3 = ig3

            unknowns_fn = os.path.join(ig.basedir, "classified", "unknown")
            self.failIf(os.path.exists(unknowns_fn))
            booms_fn = os.path.join(ig.basedir, "classified", "boom")
            booms = [fn.strip() for fn in open(booms_fn,"r").readlines()]
            self.failUnlessEqual(len(booms), 1)
            fooms_fn = os.path.join(ig.basedir, "classified", "foom")
            fooms = [fn.strip() for fn in open(fooms_fn,"r").readlines()]
            self.failUnlessEqual(len(fooms), 1)
            return ig3.d
        d.addCallback(_update_classifiers_again)

        d.addCallback(lambda res: self.ig3.disownServiceParent())

        # and if we remove all the stored incidents (and the 'latest'
        # record), the gatherer will grab everything. This exercises the
        # only-grab-one-at-a-time code. I verified this manually, by adding a
        # print to the avoid-duplicate clause of
        # IncidentObserver.maybe_fetch_incident .

        def _create_ig4(res):
            ig4 = self.create_incident_gatherer(basedir)
            for nodeid in os.listdir(os.path.join(ig4.basedir, "incidents")):
                nodedir = os.path.join(ig4.basedir, "incidents", nodeid)
                for fn in os.listdir(nodedir):
                    os.unlink(os.path.join(nodedir, fn))
                os.rmdir(nodedir)
            ig4.setServiceParent(self.parent)
            self.ig4 = ig4
        d.addCallback(_create_ig4)
        d.addCallback(lambda res:
                      self.poll(lambda : self.ig4.incidents_received == 2))

        return d

    def remove_classified_incidents(self, ig):
        classified = os.path.join(ig.basedir, "classified")
        for category in os.listdir(classified):
            os.remove(os.path.join(classified, category))
        os.rmdir(classified)

class Gatherer(unittest.TestCase, LogfileReaderMixin, StallMixin, PollMixin):
    def setUp(self):
        self.parent = service.MultiService()
        self.parent.startService()

    def tearDown(self):
        d = defer.succeed(None)
        d.addCallback(lambda res: self.parent.stopService())
        d.addCallback(flushEventualQueue)
        return d


    def _emit_messages_and_flush(self, res, t):
        log.msg("gathered message here")
        try:
            raise SampleError("whoops1")
        except:
            log.err()
        try:
            raise SampleError("whoops2")
        except SampleError:
            log.err(failure.Failure())
        d = self.stall(None, 1.0)
        d.addCallback(lambda res: t.disownServiceParent())
        # that will disconnect from the gatherer, which will flush the logfile
        d.addCallback(self.stall, 1.0)
        return d

    def _check_gatherer(self, fn, starting_timestamp, expected_tubid):
        events = []
        for e in self._read_logfile(fn):
            # discard internal foolscap events, like connection
            # negotiation
            if "d" in e and "foolscap" in e["d"].get("facility", ""):
                pass
            else:
                events.append(e)

        if len(events) != 4:
            from pprint import pprint
            pprint(events)
        self.failUnlessEqual(len(events), 4)

        # header
        data = events.pop(0)
        self.failUnless(isinstance(data, dict))
        self.failUnless("header" in data)
        self.failUnlessEqual(data["header"]["type"], "gatherer")
        self.failUnlessEqual(data["header"]["start"], starting_timestamp)

        # grab the first event from the log
        data = events.pop(0)
        self.failUnless(isinstance(data, dict))
        self.failUnlessEqual(data['from'], expected_tubid)
        self.failUnlessEqual(data['d']['message'], "gathered message here")

        # grab the second event from the log
        data = events.pop(0)
        self.failUnless(isinstance(data, dict))
        self.failUnlessEqual(data['from'], expected_tubid)
        self.failUnlessEqual(data['d']['message'], "")
        self.failUnless(data['d']["isError"])
        self.failUnless("failure" in data['d'])
        self.failUnless(data['d']["failure"].check(SampleError))
        self.failUnless("whoops1" in str(data['d']["failure"]))

        # grab the third event from the log
        data = events.pop(0)
        self.failUnless(isinstance(data, dict))
        self.failUnlessEqual(data['from'], expected_tubid)
        self.failUnlessEqual(data['d']['message'], "")
        self.failUnless(data['d']["isError"])
        self.failUnless("failure" in data['d'])
        self.failUnless(data['d']["failure"].check(SampleError))
        self.failUnless("whoops2" in str(data['d']["failure"]))

    def test_wrongdir(self):
        basedir = "logging/Gatherer/wrongdir"
        os.makedirs(basedir)

        # create a LogGatherer with an unspecified basedir: it should look
        # for a .tac file in the current directory, not see it, and complain
        e = self.failUnlessRaises(RuntimeError,
                                  MyGatherer, None, True, None)
        self.failUnless("running in the wrong directory" in str(e))

    def test_log_gatherer(self):
        # setLocation, then set log-gatherer-furl. Also, use bzip=True for
        # this one test.
        basedir = "logging/Gatherer/log_gatherer"
        os.makedirs(basedir)

        # create a gatherer, which will create its own Tub
        gatherer = MyGatherer(None, True, basedir)
        gatherer.tub_class = GoodEnoughTub
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furl = gatherer.my_furl
        starting_timestamp = gatherer._starting_timestamp

        t = GoodEnoughTub()
        expected_tubid = t.tubID
        if t.tubID is None:
            expected_tubid = "<unauth>"
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        t.setOption("log-gatherer-furl", gatherer_furl)

        # about now, the node will be contacting the Gatherer and
        # offering its logport.

        # gatherer.d will be fired when subscribe_to_all() has finished
        d = gatherer.d
        d.addCallback(self._emit_messages_and_flush, t)
        d.addCallback(lambda res: gatherer.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp, expected_tubid)
        return d
    test_log_gatherer.timeout = 20

    def test_log_gatherer2(self):
        # set log-gatherer-furl, then setLocation. Also, use a timed rotator.
        basedir = "logging/Gatherer/log_gatherer2"
        os.makedirs(basedir)

        # create a gatherer, which will create its own Tub
        gatherer = MyGatherer(3600, False, basedir)
        gatherer.tub_class = GoodEnoughTub
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furl = gatherer.my_furl
        starting_timestamp = gatherer._starting_timestamp

        t = GoodEnoughTub()
        expected_tubid = t.tubID
        if t.tubID is None:
            expected_tubid = "<unauth>"
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setOption("log-gatherer-furl", gatherer_furl)
        t.setLocation("127.0.0.1:%d" % l.getPortnum())

        d = gatherer.d
        d.addCallback(self._emit_messages_and_flush, t)
        d.addCallback(lambda res: gatherer.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp, expected_tubid)
        return d
    test_log_gatherer2.timeout = 20

    def test_log_gatherer_furlfile(self):
        # setLocation, then set log-gatherer-furlfile
        basedir = "logging/Gatherer/log_gatherer_furlfile"
        os.makedirs(basedir)

        # create a gatherer, which will create its own Tub
        gatherer = MyGatherer(None, False, basedir)
        gatherer.tub_class = GoodEnoughTub
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furlfile = os.path.join(basedir, gatherer.furlFile)
        starting_timestamp = gatherer._starting_timestamp

        t = GoodEnoughTub()
        expected_tubid = t.tubID
        if t.tubID is None:
            expected_tubid = "<unauth>"
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        t.setOption("log-gatherer-furlfile", gatherer_furlfile)

        d = gatherer.d
        d.addCallback(self._emit_messages_and_flush, t)
        d.addCallback(lambda res: gatherer.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp, expected_tubid)
        return d
    test_log_gatherer_furlfile.timeout = 20

    def test_log_gatherer_furlfile2(self):
        # set log-gatherer-furlfile, then setLocation
        basedir = "logging/Gatherer/log_gatherer_furlfile2"
        os.makedirs(basedir)

        # create a gatherer, which will create its own Tub
        gatherer = MyGatherer(None, False, basedir)
        gatherer.tub_class = GoodEnoughTub
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furlfile = os.path.join(basedir, gatherer.furlFile)
        starting_timestamp = gatherer._starting_timestamp

        t = GoodEnoughTub()
        expected_tubid = t.tubID
        if t.tubID is None:
            expected_tubid = "<unauth>"
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setOption("log-gatherer-furlfile", gatherer_furlfile)
        # one bug we had was that the log-gatherer was contacted before
        # setLocation had occurred, so exercise that case
        d = self.stall(None, 1.0)
        def _start(res):
            t.setLocation("127.0.0.1:%d" % l.getPortnum())
            return gatherer.d
        d.addCallback(_start)
        d.addCallback(self._emit_messages_and_flush, t)
        d.addCallback(lambda res: gatherer.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp, expected_tubid)
        return d
    test_log_gatherer_furlfile2.timeout = 20

    def test_log_gatherer_furlfile_multiple(self):
        basedir = "logging/Gatherer/log_gatherer_furlfile_multiple"
        os.makedirs(basedir)

        gatherer1_basedir = os.path.join(basedir, "gatherer1")
        os.makedirs(gatherer1_basedir)
        gatherer1 = MyGatherer(None, False, gatherer1_basedir)
        gatherer1.tub_class = GoodEnoughTub
        gatherer1.d = defer.Deferred()
        gatherer1.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer1_furl = gatherer1.my_furl
        starting_timestamp1 = gatherer1._starting_timestamp

        gatherer2_basedir = os.path.join(basedir, "gatherer2")
        os.makedirs(gatherer2_basedir)
        gatherer2 = MyGatherer(None, False, gatherer2_basedir)
        gatherer2.tub_class = GoodEnoughTub
        gatherer2.d = defer.Deferred()
        gatherer2.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer2_furl = gatherer2.my_furl
        starting_timestamp2 = gatherer2._starting_timestamp

        gatherer3_basedir = os.path.join(basedir, "gatherer3")
        os.makedirs(gatherer3_basedir)
        gatherer3 = MyGatherer(None, False, gatherer3_basedir)
        gatherer3.tub_class = GoodEnoughTub
        gatherer3.d = defer.Deferred()
        gatherer3.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer3_furl = gatherer3.my_furl
        starting_timestamp3 = gatherer3._starting_timestamp

        gatherer_furlfile = os.path.join(basedir, "log_gatherer.furl")
        f = open(gatherer_furlfile, "w")
        f.write(gatherer1_furl + "\n")
        f.write(gatherer2_furl + "\n")
        f.close()

        t = GoodEnoughTub()
        expected_tubid = t.tubID
        if t.tubID is None:
            expected_tubid = "<unauth>"
        t.setOption("log-gatherer-furl", gatherer3_furl)
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        t.setOption("log-gatherer-furlfile", gatherer_furlfile)
        # now both log gatherer connections will be being established

        d = defer.DeferredList([gatherer1.d, gatherer2.d, gatherer3.d],
                               fireOnOneErrback=True)
        d.addCallback(self._emit_messages_and_flush, t)
        d.addCallback(lambda res: gatherer1.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp1, expected_tubid)
        d.addCallback(lambda res: gatherer2.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp2, expected_tubid)
        d.addCallback(lambda res: gatherer3.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp3, expected_tubid)
        return d
    test_log_gatherer_furlfile_multiple.timeout = 20

    def test_log_gatherer_empty_furlfile(self):
        basedir = "logging/Gatherer/log_gatherer_empty_furlfile"
        os.makedirs(basedir)

        gatherer_fn = os.path.join(basedir, "lg.furl")
        open(gatherer_fn, "w").close()
        # leave the furlfile empty: use no gatherer

        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        t.setOption("log-gatherer-furlfile", gatherer_fn)

        lp_furl = t.getLogPortFURL()
        del lp_furl
        t.log("this message shouldn't make anything explode")
    test_log_gatherer_empty_furlfile.timeout = 20

    def test_log_gatherer_missing_furlfile(self):
        basedir = "logging/Gatherer/log_gatherer_missing_furlfile"
        os.makedirs(basedir)

        gatherer_fn = os.path.join(basedir, "missing_lg.furl")
        open(gatherer_fn, "w").close()
        # leave the furlfile missing: use no gatherer

        t = GoodEnoughTub()
        t.setServiceParent(self.parent)
        l = t.listenOn("tcp:0:interface=127.0.0.1")
        t.setLocation("127.0.0.1:%d" % l.getPortnum())
        t.setOption("log-gatherer-furlfile", gatherer_fn)

        lp_furl = t.getLogPortFURL()
        del lp_furl
        t.log("this message shouldn't make anything explode")
    test_log_gatherer_missing_furlfile.timeout = 20


class Tail(unittest.TestCase):
    def test_logprinter(self):
        target_tubid_s = "jiijpvbge2e3c3botuzzz7la3utpl67v"
        options1 = {"save-to": None,
                   "verbose": None}
        out = StringIO()
        lp = tail.LogPrinter(options1, target_tubid_s[:8], out)
        lp.got_versions({})
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
        lp.got_versions({})
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
        lp.got_versions({})
        lp.remote_msg({"time": 1207005906.527782,
                       "level": 25,
                       "num": 123,
                       "message": "howdy",
                       })
        outmsg = out.getvalue()
        del outmsg
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
        return cli.run_flogtool(argv[1:])

class CLI(unittest.TestCase):
    def test_create_gatherer(self):
        basedir = "logging/CLI/create_gatherer"
        argv = ["flogtool", "create-gatherer", "--quiet", basedir]
        cli.run_flogtool(argv[1:], run_by_human=False)
        self.failUnless(os.path.exists(basedir))

        basedir = "logging/CLI/create_gatherer2"
        argv = ["flogtool", "create-gatherer", "--rotate", "3600",
                "--quiet", basedir]
        cli.run_flogtool(argv[1:], run_by_human=False)
        self.failUnless(os.path.exists(basedir))

        basedir = "logging/CLI/create_gatherer3"
        argv = ["flogtool", "create-gatherer", basedir]
        (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
        self.failUnless(os.path.exists(basedir))
        self.failUnless(("Gatherer created in directory %s" % basedir)
                        in out, out)
        self.failUnless("Now run" in out, out)
        self.failUnless("to launch the daemon" in out, out)

    def test_create_gatherer_badly(self):
        #basedir = "logging/CLI/create_gatherer"
        argv = ["flogtool", "create-gatherer", "--bogus-arg"]
        self.failUnlessRaises(usage.UsageError,
                              cli.run_flogtool, argv[1:], run_by_human=False)

    def test_wrapper(self):
        basedir = "logging/CLI/wrapper"
        argv = ["wrapper", "flogtool", "create-gatherer", "--quiet", basedir]
        run_wrapper(argv[1:])
        self.failUnless(os.path.exists(basedir))

    def test_create_incident_gatherer(self):
        basedir = "logging/CLI/create_incident_gatherer"
        argv = ["flogtool", "create-incident-gatherer", "--quiet", basedir]
        cli.run_flogtool(argv[1:], run_by_human=False)
        self.failUnless(os.path.exists(basedir))

        basedir = "logging/CLI/create_incident_gatherer2"
        argv = ["flogtool", "create-incident-gatherer", basedir]
        (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
        self.failUnless(os.path.exists(basedir))
        self.failUnless(("Incident Gatherer created in directory %s" % basedir)
                        in out, out)
        self.failUnless("Now run" in out, out)
        self.failUnless("to launch the daemon" in out, out)

class LogfileWriterMixin:

    def create_logfile(self):
        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir)
        fn = os.path.join(self.basedir, "dump.flog")
        l = log.FoolscapLogger()
        lfo = log.LogFileObserver(fn, level=0)
        l.addObserver(lfo.msg)
        l.msg("one", facility="big.facility")
        time.sleep(0.2) # give filter --after something to work with
        l.msg("two", level=log.OPERATIONAL-1)
        try:
            raise SampleError("whoops1")
        except:
            l.err(message="three")
        l.msg("four")
        d = fireEventually()
        def _done(res):
            lfo._stop()
            #events = self._read_logfile(fn)
            #self.failUnlessEqual(len(events), 1+3)
            return fn
        d.addCallback(_done)
        return d

    def create_incident(self):
        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir)
        l = log.FoolscapLogger()
        l.setLogDir(self.basedir)
        l.setIncidentReporterFactory(NoFollowUpReporter)

        d = defer.Deferred()
        def _done(name, trigger):
            d.callback( (name,trigger) )
        l.addImmediateIncidentObserver(_done)

        l.msg("one")
        l.msg("two")
        l.msg("boom", level=log.WEIRD)
        l.msg("four")

        d.addCallback(lambda (name,trigger):
                      os.path.join(self.basedir, name+".flog.bz2"))

        return d

class Dumper(unittest.TestCase, LogfileWriterMixin, LogfileReaderMixin):
    # create a logfile, then dump it, and examine the output to make sure it
    # worked right.

    def test_dump(self):
        self.basedir = "logging/Dumper/dump"
        d = self.create_logfile()
        def _check(fn):
            events = self._read_logfile(fn)

            d = dumper.LogDumper()
            # initialize the LogDumper() timestamp mode
            d.options = dumper.DumpOptions()
            d.options.parseOptions([fn])

            argv = ["flogtool", "dump", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnlessEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.failUnless(lines[0].strip().startswith("Application versions"),
                            lines[0])
            mypid = os.getpid()
            self.failUnlessEqual(lines[3].strip(), "PID: %s" % mypid, lines[3])
            lines = lines[5:]
            line0 = "local#%d %s: one" % (events[1]["d"]["num"],
                                          d.format_time(events[1]["d"]["time"]))
            self.failUnlessEqual(lines[0].strip(), line0)
            self.failUnless("FAILURE:" in lines[3])
            self.failUnless("test_logging.SampleError: whoops1" in lines[-3])
            self.failUnless(lines[-1].startswith("local#3 "))

            argv = ["flogtool", "dump", "--just-numbers", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnlessEqual(err, "")
            lines = list(StringIO(out).readlines())
            line0 = "%s %d" % (d.format_time(events[1]["d"]["time"]),
                               events[1]["d"]["num"])
            self.failUnlessEqual(lines[0].strip(), line0)
            self.failUnless(lines[1].strip().endswith(" 1"))
            self.failUnless(lines[-1].strip().endswith(" 3"))
            # failures are not dumped in --just-numbers
            self.failUnlessEqual(len(lines), 1+3)

            argv = ["flogtool", "dump", "--rx-time", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnlessEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.failUnless(lines[0].strip().startswith("Application versions"),
                            lines[0])
            mypid = os.getpid()
            self.failUnlessEqual(lines[3].strip(), "PID: %s" % mypid, lines[3])
            lines = lines[5:]
            line0 = "local#%d rx(%s) emit(%s): one" % \
                    (events[1]["d"]["num"],
                     d.format_time(events[1]["rx_time"]),
                     d.format_time(events[1]["d"]["time"]))
            self.failUnlessEqual(lines[0].strip(), line0)
            self.failUnless(lines[-1].strip().endswith(" four"))

            argv = ["flogtool", "dump", "--verbose", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnlessEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.failUnless("header" in lines[0])
            self.failUnless("'message': 'one'" in lines[1])
            self.failUnless("'level': 20" in lines[1])
            self.failUnless(": four: {" in lines[-1])

        d.addCallback(_check)
        return d

    def test_incident(self):
        self.basedir = "logging/Dumper/incident"
        d = self.create_incident()
        def _check(fn):
            events = self._read_logfile(fn)
            # for sanity, make sure we created the incident correctly
            assert events[0]["header"]["type"] == "incident"
            assert events[0]["header"]["trigger"]["num"] == 2

            argv = ["flogtool", "dump", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnlessEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.failUnlessEqual(len(lines), 8)
            self.failUnlessEqual(lines[0].strip(),
                                 "Application versions (embedded in logfile):")
            self.failUnless(lines[1].strip().startswith("foolscap:"), lines[1])
            self.failUnless(lines[2].strip().startswith("twisted:"), lines[2])
            mypid = os.getpid()
            self.failUnlessEqual(lines[3].strip(), "PID: %s" % mypid, lines[3])
            self.failUnlessEqual(lines[4].strip(), "")
            self.failIf("[INCIDENT-TRIGGER]" in lines[5])
            self.failIf("[INCIDENT-TRIGGER]" in lines[6])
            self.failUnless(lines[7].strip().endswith(": boom [INCIDENT-TRIGGER]"))
        d.addCallback(_check)
        return d

class Filter(unittest.TestCase, LogfileWriterMixin, LogfileReaderMixin):

    def compare_events(self, a, b):
        # cmp(a,b) won't quite work, because two instances of CopiedFailure
        # loaded from the same pickle don't compare as equal
        self.failUnlessEqual(len(a), len(b))
        for i in range(len(a)):
            a1,b1 = a[i],b[i]
            self.failUnlessEqual(set(a1.keys()), set(b1.keys()))
            for k in a1:
                if k == "d":
                    self.failUnlessEqual(set(a1["d"].keys()),
                                         set(b1["d"].keys()))
                    for k2 in a1["d"]:
                        if k2 == "failure":
                            f1 = a1["d"][k2]
                            f2 = b1["d"][k2]
                            self.failUnlessEqual(f1.value, f2.value)
                            self.failUnlessEqual(f1.getTraceback(),
                                                 f2.getTraceback())
                        else:
                            self.failUnlessEqual(a1["d"][k2], b1["d"][k2])
                else:
                    self.failUnlessEqual(a1[k], b1[k])


    def test_basic(self):
        self.basedir = "logging/Filter/basic"
        d = self.create_logfile()
        def _check(fn):
            events = self._read_logfile(fn)
            count = len(events)
            assert count == 5

            dirname,filename = os.path.split(fn)
            fn2 = os.path.join(dirname, "filtered-" + filename)

            # pass-through
            argv = ["flogtool", "filter", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("copied 5 of 5 events into new file" in out, out)
            self.compare_events(events, self._read_logfile(fn2))

            # convert to .bz2 while we're at it
            fn2bz2 = fn2 + ".bz2"
            argv = ["flogtool", "filter", fn, fn2bz2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("copied 5 of 5 events into new file" in out, out)
            self.compare_events(events, self._read_logfile(fn2bz2))

            # modify the file in place
            argv = ["flogtool", "filter", "--above", "20", fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("modifying event file in place" in out, out)
            self.failUnless("--above: removing events below level 20" in out, out)
            self.failUnless("copied 4 of 5 events into new file" in out, out)
            self.compare_events([events[0], events[1], events[3], events[4]],
                                self._read_logfile(fn2))

            # modify the file in place, two-argument version
            argv = ["flogtool", "filter", fn2, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("modifying event file in place" in out, out)
            self.failUnless("copied 4 of 4 events into new file" in out, out)
            self.compare_events([events[0], events[1], events[3], events[4]],
                                self._read_logfile(fn2))

            # --above with a string argument
            argv = ["flogtool", "filter", "--above", "OPERATIONAL", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("--above: removing events below level 20" in out, out)
            self.failUnless("copied 4 of 5 events into new file" in out, out)
            self.compare_events([events[0], events[1], events[3], events[4]],
                                self._read_logfile(fn2))

            t_one = events[1]["d"]["time"]
            # we can only pass integers into --before and --after, so we'll
            # just test that we get all or nothing
            argv = ["flogtool", "filter", "--before", str(int(t_one - 10)),
                    fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("copied 1 of 5 events into new file" in out, out)
            # we always get the header, so it's 1 instead of 0
            self.compare_events(events[:1], self._read_logfile(fn2))

            argv = ["flogtool", "filter", "--after", str(int(t_one + 10)),
                    fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("copied 1 of 5 events into new file" in out, out)
            self.compare_events(events[:1], self._read_logfile(fn2))

            # --facility
            argv = ["flogtool", "filter", "--strip-facility", "big", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("--strip-facility: removing events for big and children" in out, out)
            self.failUnless("copied 4 of 5 events into new file" in out, out)
            self.compare_events([events[0],events[2],events[3],events[4]],
                                self._read_logfile(fn2))

            # pass-through, --verbose, read from .bz2
            argv = ["flogtool", "filter", "--verbose", fn2bz2, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("copied 5 of 5 events into new file" in out, out)
            lines = [l.strip() for l in StringIO(out).readlines()]
            self.failUnlessEqual(lines,
                                 ["HEADER", "0", "1", "2", "3",
                                  "copied 5 of 5 events into new file"])
            self.compare_events(events, self._read_logfile(fn2))

            # --from . This normally takes a base32 tubid prefix, but the
            # things we've logged all say ["from"]="local". So just test
            # all-or-nothing.
            argv = ["flogtool", "filter", "--from", "local", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("--from: retaining events only from tubid prefix local" in out, out)
            self.failUnless("copied 5 of 5 events into new file" in out, out)
            self.compare_events(events, self._read_logfile(fn2))

            argv = ["flogtool", "filter", "--from", "NOTlocal", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.failUnless("--from: retaining events only from tubid prefix NOTlocal" in out, out)
            self.failUnless("copied 1 of 5 events into new file" in out, out)
            self.compare_events(events[:1], self._read_logfile(fn2))


        d.addCallback(_check)
        return d



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
            mypid = os.getpid()
            self.failUnless("PID %s" % mypid in page,
                            "didn't see 'PID %s' in '%s'" % (mypid, page))
            self.failUnless("Application Versions:" in page, page)
            self.failUnless("foolscap: %s" % foolscap.__version__ in page, page)
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
        d.addCallback(lambda res:
                      client.getPage(self.baseurl + "all-events?sort=nested"))
        d.addCallback(_check_all_events)
        d.addCallback(lambda res:
                      client.getPage(self.baseurl + "all-events?timestamps=local"))
        d.addCallback(_check_all_events)
        d.addCallback(lambda res:
                      client.getPage(self.baseurl + "all-events?timestamps=utc"))
        d.addCallback(_check_all_events)
        return d


class Bridge(unittest.TestCase):
    def test_foolscap_to_twisted(self):
        fl = log.FoolscapLogger()
        tw = twisted_log.LogPublisher()
        log.bridgeLogsToTwisted(None, fl, tw)
        tw_out = []
        tw.addObserver(tw_out.append)
        fl_out = []
        fl.addObserver(fl_out.append)

        fl.msg("one")
        fl.msg(format="two %(two)d", two=2)
        fl.msg("three", level=log.NOISY) # should be removed
        d = flushEventualQueue()
        def _check(res):
            self.failUnlessEqual(len(fl_out), 3)
            self.failUnlessEqual(fl_out[0]["message"], "one")
            self.failUnlessEqual(fl_out[1]["format"], "two %(two)d")
            self.failUnlessEqual(fl_out[2]["message"], "three")

            self.failUnlessEqual(len(tw_out), 2)
            self.failUnlessEqual(tw_out[0]["message"], ("one",))
            self.failUnless(tw_out[0]["from-foolscap"])
            self.failUnlessEqual(tw_out[1]["message"], ("two 2",))
            self.failUnless(tw_out[1]["from-foolscap"])

        d.addCallback(_check)
        return d

    def test_twisted_to_foolscap(self):
        fl = log.FoolscapLogger()
        tw = twisted_log.LogPublisher()
        log.bridgeLogsFromTwisted(None, tw, fl)
        tw_out = []
        tw.addObserver(tw_out.append)
        fl_out = []
        fl.addObserver(fl_out.append)

        tw.msg("one")
        tw.msg(format="two %(two)d", two=2)
        d = flushEventualQueue()
        def _check(res):
            self.failUnlessEqual(len(tw_out), 2)
            self.failUnlessEqual(tw_out[0]["message"], ("one",))
            self.failUnlessEqual(tw_out[1]["format"], "two %(two)d")
            self.failUnlessEqual(tw_out[1]["two"], 2)

            self.failUnlessEqual(len(fl_out), 2)
            self.failUnlessEqual(fl_out[0]["message"], "one")
            self.failUnless(fl_out[0]["from-twisted"])
            self.failUnlessEqual(fl_out[1]["format"], "two %(two)d")
            self.failUnless(fl_out[1]["from-twisted"])

        d.addCallback(_check)
        return d


    def test_no_loops(self):
        fl = log.FoolscapLogger()
        tw = twisted_log.LogPublisher()
        log.bridgeLogsFromTwisted(None, tw, fl)
        log.bridgeLogsToTwisted(None, fl, tw)
        tw_out = []
        tw.addObserver(tw_out.append)
        fl_out = []
        fl.addObserver(fl_out.append)

        tw.msg("one")
        fl.msg("two")

        d = flushEventualQueue()
        def _check(res):
            self.failUnlessEqual(len(tw_out), 2)
            self.failUnlessEqual(tw_out[0]["message"], ("one",))
            self.failUnlessEqual(tw_out[1]["message"], ("two",))

            self.failUnlessEqual(len(fl_out), 2)
            self.failUnlessEqual(fl_out[0]["message"], "one")
            self.failUnlessEqual(fl_out[1]["message"], "two")

        d.addCallback(_check)
        return d

