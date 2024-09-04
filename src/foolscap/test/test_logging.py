
import os, sys, json, time, bz2, base64, re
import six
from unittest import mock
from io import StringIO
from zope.interface import implementer
from twisted.trial import unittest
from twisted.application import service
from twisted.internet import defer, reactor
from twisted.internet.defer import inlineCallbacks, returnValue
try:
    from twisted import logger as twisted_logger
except ImportError:
    twisted_logger = None
from twisted.web import client
from twisted.python import log as twisted_log
from twisted.python import failure, runtime, usage
import foolscap
from foolscap.logging import gatherer, log, tail, incident, cli, web, \
     publish, dumper, flogfile
from foolscap.logging.interfaces import RILogObserver
from foolscap.util import format_time, allocate_tcp_port, ensure_dict_str
from foolscap.eventual import fireEventually, flushEventualQueue
from foolscap.tokens import NoLocationError
from foolscap.test.common import PollMixin, StallMixin
from foolscap.api import RemoteException, Referenceable, Tub


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
        t = Tub()
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
            self.assertEqual(len(out), 2)
            self.assertEqual(out[0]["message"], "one")
            self.assertEqual(out[1]["message"], "two")
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
            expected_magic = f.read(len(flogfile.MAGIC))
            self.assertEqual(expected_magic, flogfile.MAGIC)
            events = []
            for line in f:
                events.append(json.loads(line.decode("utf-8")))
            self.assertEqual(len(events), 3)
            self.assertEqual(events[0]["header"]["type"],
                                 "log-file-observer")
            self.assertEqual(events[0]["header"]["threshold"],
                                 log.OPERATIONAL)
            self.assertEqual(events[1]["from"], "local")
            self.assertEqual(events[2]["d"]["message"], "two")
        d.addCallback(_check)
        return d

    def testDisplace(self):
        l = log.FoolscapLogger()
        l.set_buffer_size(log.OPERATIONAL, 3)
        l.msg("one")
        l.msg("two")
        l.msg("three")
        items = l.buffers[None][log.OPERATIONAL]
        self.assertEqual(len(items), 3)
        l.msg("four") # should displace "one"
        self.assertEqual(len(items), 3)
        m0 = items[0]
        self.assertEqual(type(m0), dict)
        self.assertEqual(m0['message'], "two")
        self.assertEqual(items[-1]['message'], "four")

    def testFacilities(self):
        l = log.FoolscapLogger()
        l.explain_facility("ui", "This is the UI.")
        l.msg("one", facility="ui")
        l.msg("two")

        items = l.buffers["ui"][log.OPERATIONAL]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["message"], "one")

    def testOnePriority(self):
        l = log.FoolscapLogger()
        l.msg("one", level=log.NOISY)
        l.msg("two", level=log.WEIRD)
        l.msg("three", level=log.NOISY)

        items = l.buffers[None][log.NOISY]
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['message'], "one")
        self.assertEqual(items[1]['message'], "three")

        items = l.buffers[None][log.WEIRD]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['message'], "two")

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
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]['message'], "five")
        self.assertEqual(items[-1]['message'], "seven")

        items = l.buffers[None][log.WEIRD]
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['message'], "one")
        self.assertEqual(items[-1]['message'], "four")

    def testHierarchy(self):
        l = log.FoolscapLogger()

        n = l.msg("one")
        n2 = l.msg("two", parent=n)
        l.msg("three", parent=n2)

class ErrorfulQualifier(incident.IncidentQualifier):
    def __init__(self):
        self._first = True

    def check_event(self, ev):
        if self._first:
            self._first = False
            raise ValueError("oops")
        return False

class NoStdio(unittest.TestCase):
    # bug #244 is caused, in part, by Foolscap-side logging failures which
    # write an error message ("unable to serialize X") to stderr, which then
    # gets captured by twisted's logging (when run in a program under
    # twistd), then fed back into foolscap logging. Check that unserializable
    # objects don't cause anything to be written to a mock stdout/stderr
    # object.
    #
    # FoolscapLogger used stdio in two places:
    # * msg() when format_message() throws
    # * add_event() when IncidentQualifier.event() throws

    def setUp(self):
        self.fl = log.FoolscapLogger()
        self.mock_stdout = StringIO()
        self.mock_stderr = StringIO()
        self.orig_stdout = sys.stdout
        self.orig_stderr = sys.stderr
        sys.stdout = self.mock_stdout
        sys.stderr = self.mock_stderr

    def tearDown(self):
        sys.stdout = self.orig_stdout
        sys.stderr = self.orig_stderr

    def check_stdio(self):
        self.assertEqual(self.mock_stdout.getvalue(), "")
        self.assertEqual(self.mock_stderr.getvalue(), "")

    def test_unformattable(self):
        self.fl.msg(format="one=%(unformattable)s") # missing format key
        self.check_stdio()

    def test_unserializable_incident(self):
        # one #244 pathway involved an unserializable event that caused an
        # exception during IncidentReporter.incident_declared(), as it tried
        # to record all recent events. We can test the lack of stdio by using
        # a qualifier that throws an error directly.
        self.fl.setIncidentQualifier(ErrorfulQualifier())
        self.fl.activate_incident_qualifier()
        # make sure we set it up correctly
        self.assertTrue(self.fl.active_incident_qualifier)
        self.fl.msg("oops", arg=lambda : "lambdas are unserializable",
                    level=log.BAD)
        self.check_stdio()
        # The internal error will cause a new "metaevent" to be recorded. The
        # original event may or may not get recorded first, depending upon
        # the error (i.e. does it happen before or after buffer.append is
        # called). Also, get_buffered_events() is unordered. So search for
        # the right one.
        events = [e for e in self.fl.get_buffered_events()
                  if e.get("facility") == "foolscap/internal-error"]
        self.assertEqual(len(events), 1)
        m = events[0]["message"]
        expected = "internal error in log._msg, args=('oops',)"
        self.assertTrue(m.startswith(expected), m)
        self.assertIn("ValueError('oops'", m)

def ser(what):
    return json.dumps(what, cls=flogfile.ExtendedEncoder)

class Serialization(unittest.TestCase):
    def test_lazy_serialization(self):
        # Both foolscap and twisted allow (somewhat) arbitrary kwargs in the
        # log.msg() call. Twisted will either discard the event (if nobody is
        # listening), or stringify it right away.
        #
        # Foolscap does neither. It records the event (kwargs and all) in a
        # circular buffer, so a later observer can learn about them (either
        # 'flogtool tail' or a stored Incident file). And it stores the
        # arguments verbatim, leaving stringification to the future observer
        # (if they want it), so tools can filter events without using regexps
        # or parsing prematurely-flattened strings.
        #
        # Test this by logging a mutable object, modifying it, then checking
        # the buffer. We expect to see the modification.
        fl = log.FoolscapLogger()
        mutable = {"key": "old"}
        fl.msg("one", arg=mutable)
        mutable["key"] = "new"
        events = list(fl.get_buffered_events())
        self.assertTrue(events[0]["arg"]["key"], "new")

    def test_failure(self):
        try:
            raise ValueError("oops5")
        except ValueError:
            f = failure.Failure()
        out = json.loads(ser({"f": f}))["f"]
        self.assertEqual(out["@"], "Failure")
        self.assertIn("ValueError: oops5", out["repr"])
        self.assertIn("traceback", out)

    def test_unserializable(self):
        # The code that serializes log events to disk (with JSON) tries very
        # hard to get *something* recorded, even when you give log.msg()
        # something strange.
        self.assertEqual(json.loads(ser({"a": 1})), {"a": 1})
        unjsonable = [set([1,2])]
        self.assertEqual(json.loads(ser(unjsonable)),
                         [{'@': 'UnJSONable',
                           'repr': repr(set([1, 2])),
                           'message': "log.msg() was given an object that could not be encoded into JSON. I've replaced it with this UnJSONable object. The object's repr is in .repr"}])

        # if the repr() fails, we get a different message
        class Unreprable:
            def __repr__(self):
                raise ValueError("oops7")
        unrep = [Unreprable()]
        self.assertEqual(json.loads(ser(unrep)),
                         [{"@": "Unreprable",
                           "exception_repr": repr(ValueError('oops7')),
                           "message": "log.msg() was given an object that could not be encoded into JSON, and when I tried to repr() it I got an error too. I've put the repr of the exception in .exception_repr",
                           }])

        # and if repr()ing the failed repr() exception fails, we give up
        real_repr = repr
        def really_bad_repr(o):
            if isinstance(o, ValueError):
                raise TypeError("oops9")
            return real_repr(o)
        if six.PY2:
            import __builtin__
            assert __builtin__.repr is repr
            with mock.patch("__builtin__.repr", really_bad_repr):
                s = ser(unrep)
        else:
            import builtins
            assert builtins.repr is repr
            with mock.patch("builtins.repr", really_bad_repr):
                s = ser(unrep)
        self.assertEqual(json.loads(s),
                         [{"@": "ReallyUnreprable",
                           "message": "log.msg() was given an object that could not be encoded into JSON, and when I tried to repr() it I got an error too. That exception wasn't repr()able either. I give up. Good luck.",
                           }])

    def test_not_pickle(self):
        # Older versions of Foolscap used pickle to store events into the
        # Incident log, and dealt with errors by dropping the event. Newer ones
        # use JSON, and use a placeholder when errors occur. Test that
        # pickleable (but not JSON-able) objects are *not* written to the file
        # directly, but are replaced by an "unjsonable" placeholder.
        basedir = "logging/Serialization/not_pickle"
        os.makedirs(basedir)
        fl = log.FoolscapLogger()
        ir = incident.IncidentReporter(basedir, fl, "tubid")
        ir.TRAILING_DELAY = None
        fl.msg("first")
        unjsonable = [object()] # still picklable
        unserializable = [lambda: "neither pickle nor JSON can capture me"]
        # having unserializble data in the logfile should not break the rest
        fl.msg("unjsonable", arg=unjsonable)
        fl.msg("unserializable", arg=unserializable)
        fl.msg("last")
        events = list(fl.get_buffered_events())
        # if unserializable data breaks incident reporting, this
        # incident_declared() call will cause an exception
        ir.incident_declared(events[0])
        # that won't record any trailing events, but does
        # eventually(finished_Recording), so wait for that to conclude
        d = flushEventualQueue()
        def _check(_):
            files = os.listdir(basedir)
            self.assertEqual(len(files), 1)
            fn = os.path.join(basedir, files[0])
            events = list(flogfile.get_events(fn))
            self.assertEqual(events[0]["header"]["type"], "incident")
            self.assertEqual(events[1]["d"]["message"], "first")
            self.assertEqual(len(events), 5)
            # actually this should record 5 events: both unrecordable events
            # should be replaced with error messages that *are* recordable
            self.assertEqual(events[2]["d"]["message"], "unjsonable")
            self.assertEqual(events[2]["d"]["arg"][0]["@"], "UnJSONable")
            self.assertEqual(events[3]["d"]["message"], "unserializable")
            self.assertEqual(events[3]["d"]["arg"][0]["@"], "UnJSONable")
            self.assertEqual(events[4]["d"]["message"], "last")
        d.addCallback(_check)
        return d

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
        return list(flogfile.get_events(fn))

class Incidents(unittest.TestCase, PollMixin, LogfileReaderMixin):
    def test_basic(self):
        l = log.FoolscapLogger()
        self.assertEqual(l.incidents_declared, 0)
        # no qualifiers are run until a logdir is provided
        l.msg("one", level=log.BAD)
        self.assertEqual(l.incidents_declared, 0)
        l.setLogDir("logging/Incidents/basic")
        l.setLogDir("logging/Incidents/basic") # this should be idempotent
        got_logdir = l.logdir
        self.assertEqual(got_logdir,
                             os.path.abspath("logging/Incidents/basic"))
        # qualifiers should be run now
        l.msg("two")
        l.msg("3-trigger", level=log.BAD)
        self.assertEqual(l.incidents_declared, 1)
        self.assertTrue(l.get_active_incident_reporter())
        # at this point, the uncompressed logfile should be present, and it
        # should contain all the events up to and including the trigger
        files = os.listdir(got_logdir)
        self.assertEqual(len(files), 2)
        # the uncompressed one will sort earlier, since it lacks the .bz2
        # extension
        files.sort()
        self.assertEqual(files[0] + ".bz2.tmp", files[1])
        # unix systems let us look inside the uncompressed file while it's
        # still being written to by the recorder
        if runtime.platformType == "posix":
            events = self._read_logfile(os.path.join(got_logdir, files[0]))
            self.assertEqual(len(events), 1+3)
            #header = events[0]
            self.assertTrue("header" in events[0])
            self.assertEqual(events[0]["header"]["trigger"]["message"],
                                 "3-trigger")
            self.assertEqual(events[0]["header"]["versions"]["foolscap"],
                                 foolscap.__version__)
            self.assertEqual(events[3]["d"]["message"], "3-trigger")

        l.msg("4-trailing")
        # this will take 5 seconds to finish trailing events
        d = self.poll(lambda: bool(l.incidents_recorded), 1.0)
        def _check(res):
            self.assertEqual(len(l.recent_recorded_incidents), 1)
            fn = l.recent_recorded_incidents[0]
            events = self._read_logfile(fn)
            self.assertEqual(len(events), 1+4)
            self.assertTrue("header" in events[0])
            self.assertEqual(events[0]["header"]["trigger"]["message"],
                                 "3-trigger")
            self.assertEqual(events[0]["header"]["versions"]["foolscap"],
                                 foolscap.__version__)
            self.assertEqual(events[3]["d"]["message"], "3-trigger")
            self.assertEqual(events[4]["d"]["message"], "4-trailing")

        d.addCallback(_check)
        return d

    def test_qualifier1(self):
        l = log.FoolscapLogger()
        l.setIncidentQualifier(SuperstitiousQualifier())
        l.setLogDir("logging/Incidents/qualifier1")
        l.msg("1", level=log.BAD)
        self.assertEqual(l.incidents_declared, 0)

    def test_qualifier2(self):
        l = log.FoolscapLogger()
        # call them in the other order
        l.setLogDir("logging/Incidents/qualifier2")
        l.setIncidentQualifier(SuperstitiousQualifier())
        l.msg("1", level=log.BAD)
        self.assertEqual(l.incidents_declared, 0)

    def test_customize(self):
        l = log.FoolscapLogger()
        l.setIncidentQualifier(SuperstitiousQualifier())
        l.setLogDir("logging/Incidents/customize")
        # you set the reporter *class*, not an instance
        bad_ir = ImpatientReporter("basedir", "logger", "tubid")
        self.assertRaises((AssertionError, TypeError),
                              l.setIncidentReporterFactory, bad_ir)
        l.setIncidentReporterFactory(ImpatientReporter)
        l.msg("1", level=log.BAD)
        self.assertEqual(l.incidents_declared, 0)
        l.msg("2")
        l.msg("thirteen is scary")
        self.assertEqual(l.incidents_declared, 1)
        l.msg("4")
        l.msg("5")
        l.msg("6") # this should hit the trailing event limit
        l.msg("7") # this should not be recorded
        d = self.poll(lambda: bool(l.incidents_recorded), 1.0)
        def _check(res):
            self.assertEqual(len(l.recent_recorded_incidents), 1)
            fn = l.recent_recorded_incidents[0]
            events = self._read_logfile(fn)
            self.assertEqual(len(events), 1+6)
            self.assertEqual(events[-1]["d"]["message"], "6")
        d.addCallback(_check)
        return d

    def test_overlapping(self):
        l = log.FoolscapLogger()
        l.setLogDir("logging/Incidents/overlapping")
        got_logdir = l.logdir
        self.assertEqual(got_logdir,
                             os.path.abspath("logging/Incidents/overlapping"))
        d = defer.Deferred()
        def _go(name, trigger):
            d.callback( (name, trigger) )
        l.addImmediateIncidentObserver(_go)
        l.setIncidentReporterFactory(ImpatientReporter)
        l.msg("1")
        l.msg("2-trigger", level=log.BAD)
        self.assertEqual(l.incidents_declared, 1)
        self.assertTrue(l.get_active_incident_reporter())
        l.msg("3-trigger", level=log.BAD)
        self.assertEqual(l.incidents_declared, 2)
        self.assertTrue(l.get_active_incident_reporter())

        def _check(res):
            self.assertEqual(l.incidents_recorded, 1)
            self.assertEqual(len(l.recent_recorded_incidents), 1)
            # at this point, the logfile should be present, and it should
            # contain all the events up to and including both triggers

            files = os.listdir(got_logdir)
            self.assertEqual(len(files), 1)
            events = self._read_logfile(os.path.join(got_logdir, files[0]))

            self.assertEqual(len(events), 1+3)
            self.assertEqual(events[0]["header"]["trigger"]["message"],
                                 "2-trigger")
            self.assertEqual(events[1]["d"]["message"], "1")
            self.assertEqual(events[2]["d"]["message"], "2-trigger")
            self.assertEqual(events[3]["d"]["message"], "3-trigger")
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
            self.assertEqual(len(files), 1)

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
            self.assertTrue(out.strip().endswith(": foom"), out)

            ic2 = incident.IncidentClassifier()
            options = incident.ClassifyOptions()
            options.parseOptions(["--verbose"] +
                                 [os.path.join(got_logdir, fn) for fn in files])
            options.stdout = StringIO()
            ic2.run(options)
            out = options.stdout.getvalue()
            self.failUnlessIn(".flog.bz2: unknown\n", out)
            # this should have a JSON-formatted trigger dictionary
            self.assertTrue(re.search(r'u?"message": u?"foom"', out), out)
            self.failUnlessIn('"num": 0', out)
            self.failUnlessIn("RuntimeError", out)

        d.addCallback(_check)
        return d

@implementer(RILogObserver)
class Observer(Referenceable):
    def __init__(self):
        self.messages = []
        self.incidents = []
        self.done_with_incidents = False
    def remote_msg(self, d):
        self.messages.append(d)

    def remote_new_incident(self, name, trigger):
        self.incidents.append( (name, trigger) )
    def remote_done_with_incident_catchup(self):
        self.done_with_incidents = True

class MyGatherer(gatherer.GathererService):
    verbose = False

    def __init__(self, rotate, use_bzip, basedir):
        portnum = allocate_tcp_port()
        with open(os.path.join(basedir, "port"), "w") as f:
            f.write("tcp:%d\n" % portnum)
        with open(os.path.join(basedir, "location"), "w") as f:
            f.write("tcp:127.0.0.1:%d\n" % portnum)
        gatherer.GathererService.__init__(self, rotate, use_bzip, basedir)

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
        t = Tub()
        # setOption before setServiceParent
        t.setOption("logport-furlfile", furlfile)
        t.setServiceParent(self.parent)
        self.assertRaises(NoLocationError, t.getLogPort)
        self.assertRaises(NoLocationError, t.getLogPortFURL)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        self.assertFalse(os.path.exists(furlfile))
        t.setLocation("127.0.0.1:%d" % portnum)
        logport_furl = open(furlfile, "r").read().strip()
        self.assertEqual(logport_furl, t.getLogPortFURL())

    def test_logport_furlfile2(self):
        basedir = "logging/Publish/logport_furlfile2"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = Tub()
        # setServiceParent before setOption
        t.setServiceParent(self.parent)
        self.assertRaises(NoLocationError, t.getLogPort)
        self.assertRaises(NoLocationError, t.getLogPortFURL)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setOption("logport-furlfile", furlfile)
        self.assertFalse(os.path.exists(furlfile))
        t.setLocation("127.0.0.1:%d" % portnum)
        logport_furl = open(furlfile, "r").read().strip()
        self.assertEqual(logport_furl, t.getLogPortFURL())

    def test_logpublisher(self):
        basedir = "logging/Publish/logpublisher"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = Tub()
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        self.assertRaises(NoLocationError, t.getLogPort)
        self.assertRaises(NoLocationError, t.getLogPortFURL)

        t.setLocation("127.0.0.1:%d" % portnum)
        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()
        logport_furl2 = open(furlfile, "r").read().strip()
        self.assertEqual(logport_furl, logport_furl2)
        tw_log = twisted_log.LogPublisher()
        tlb = t.setOption("bridge-twisted-logs", tw_log)

        t2 = Tub()
        t2.setServiceParent(self.parent)
        ob = Observer()

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            d = logport.callRemote("get_versions")
            def _check(versions):
                versions = ensure_dict_str(versions)
                self.assertEqual(versions["foolscap"],
                                 six.ensure_text(foolscap.__version__))
            d.addCallback(_check)
            # note: catch_up=False, so this message won't be sent
            log.msg("message 0 here, before your time")
            d.addCallback(lambda res:
                          logport.callRemote("subscribe_to_all", ob))
            def _emit(subscription):
                self._subscription = subscription
                log.msg("message 1 here")
                tw_log.msg("message 2 here")

                # switch to generic (no tubid) bridge
                log.unbridgeLogsFromTwisted(tw_log, tlb)
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
            # wait until we've seen all the messages, or the test times out
            d.addCallback(lambda res: self.poll(lambda: len(ob.messages) >= 8))
            def _check_observer(res):
                msgs = ob.messages
                self.assertEqual(len(msgs), 8)
                self.assertEqual(msgs[0]["message"], "message 1 here")
                self.assertEqual(msgs[1]["from-twisted"], True)
                self.assertEqual(msgs[1]["message"], "message 2 here")
                self.assertEqual(msgs[1]["tubID"], t.tubID)
                self.assertEqual(msgs[2]["from-twisted"], True)
                self.assertEqual(msgs[2]["message"], "message 3 here")
                self.assertEqual(msgs[2]["tubID"], None)
                self.assertEqual(msgs[3]["from-twisted"], True)
                self.assertEqual(msgs[3]["message"], "foo is foo")

                # check the errors
                self.assertEqual(msgs[4]["message"], "")
                self.assertTrue(msgs[4]["isError"])
                self.assertTrue("failure" in msgs[4])
                self.assertTrue(msgs[4]["failure"].check(SampleError))
                self.assertTrue("err1" in str(msgs[4]["failure"]))
                self.assertEqual(msgs[5]["message"], "")
                self.assertTrue(msgs[5]["isError"])
                self.assertTrue("failure" in msgs[5])
                self.assertTrue(msgs[5]["failure"].check(SampleError))
                self.assertTrue("err2" in str(msgs[5]["failure"]))

                # errors coming from twisted are stringified
                self.assertEqual(msgs[6]["from-twisted"], True)
                self.assertTrue("Unhandled Error" in msgs[6]["message"])
                self.assertTrue("SampleError: err3" in msgs[6]["message"])
                self.assertTrue(msgs[6]["isError"])

                self.assertEqual(msgs[7]["from-twisted"], True)
                self.assertTrue("Unhandled Error" in msgs[7]["message"])
                self.assertTrue("SampleError: err4" in msgs[7]["message"])
                self.assertTrue(msgs[7]["isError"])

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
        t = Tub()
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)

        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()
        logport_furl2 = open(furlfile, "r").read().strip()
        self.assertEqual(logport_furl, logport_furl2)

        t2 = Tub()
        t2.setServiceParent(self.parent)
        ob = Observer()

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            d = logport.callRemote("subscribe_to_all", ob)
            def _emit(subscription):
                self._subscription = subscription
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
                self.assertEqual(len(msgs), expected)
                # since we discard new messages during overload (and preserve
                # old ones), we should see 0..MAX_QUEUE_SIZE-1.
                got = []
                for m in msgs:
                    ignored1, number_s, ignored2 = m["message"].split()
                    number = int(number_s)
                    got.append(number)
                self.assertEqual(got, sorted(got))
                self.assertEqual(got, list(range(expected)))

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
        t = Tub()
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)

        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()

        t2 = Tub()
        t2.setServiceParent(self.parent)
        ob = Observer()

        d = t2.getReference(logport_furl)
        def _got_logport(logport):
            d = logport.callRemote("get_versions")
            def _check_versions(versions):
                versions = ensure_dict_str(versions)
                self.assertEqual(versions["foolscap"],
                                 six.ensure_text(foolscap.__version__))
            d.addCallback(_check_versions)
            d.addCallback(lambda res: logport.callRemote("get_pid"))
            def _check_pid(pid):
                self.assertEqual(pid, os.getpid())
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
                self.assertTrue(len(msgs) >= 2, len(msgs))
                first = None
                second = None
                for i,m in enumerate(msgs):
                    if m.get("message") == "this is an early message":
                        first = i
                    if m.get("message") == "this is a later message":
                        second = i
                self.assertTrue(first is not None)
                self.assertTrue(second is not None)
                self.assertTrue(first < second,
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
        t = Tub()
        t.setLocation("127.0.0.1:1234")
        t.logger = self.logger = log.FoolscapLogger()
        logdir = os.path.join(basedir, "logdir")
        t.logger.setLogDir(logdir)
        p = t.getLogPort()

        # dump some other files in the incident directory
        self._write_to(logdir, "distraction.bz2")
        self._write_to(logdir, "noise")

        os.remove(os.path.join(logdir,"distraction.bz2"))
        os.remove(os.path.join(logdir, "noise"))

        # and a few real-looking incidents
        I1 = "incident-2008-07-29-204211-aspkxoi"
        I2 = "incident-2008-07-30-112233-wodaei"
        I1_abs = os.path.abspath(os.path.join(logdir, I1 + ".flog"))
        I2_abs = os.path.abspath(os.path.join(logdir, I2 + ".flog.bz2"))
        self._write_to(logdir, I1 + ".flog")
        self._write_to(logdir, I2 + ".flog.bz2")

        all = list(p.list_incident_names())
        self.assertEqual(set([name for (name,fn) in all]), set([I1, I2]))
        imap = dict(all)
        self.assertEqual(imap[I1], I1_abs)
        self.assertEqual(imap[I2], I2_abs)

        new = list(p.list_incident_names(since=I1))
        self.assertEqual(set([name for (name,fn) in new]), set([I2]))

        os.remove(os.path.join(logdir, I1 + ".flog"))
        os.remove(os.path.join(logdir, I2 + ".flog.bz2"))


    def test_get_incidents(self):
        basedir = "logging/IncidentPublisher/get_incidents"
        os.makedirs(basedir)
        furlfile = os.path.join(basedir, "logport.furl")
        t = Tub()
        t.logger = self.logger = log.FoolscapLogger()
        logdir = os.path.join(basedir, "logdir")
        t.logger.setLogDir(logdir)
        t.logger.setIncidentReporterFactory(incident.NonTrailingIncidentReporter)
        # dump some other files in the incident directory
        f = open(os.path.join(logdir, "distraction.bz2"), "w")
        f.write("stuff")
        f.close()
        f = open(os.path.join(logdir, "noise"), "w")
        f.write("stuff")
        f.close()

        os.remove(os.path.join(logdir, "distraction.bz2"))

        # fill the buffers with some messages
        t.logger.msg("one")
        t.logger.msg("two")
        # and trigger an incident
        t.logger.msg("three", level=log.WEIRD)
        # the NonTrailingIncidentReporter needs a turn before it will have
        # finished recording the event: the getReference() call will suffice.

        # now set up a Tub to connect to the logport
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)

        t.setOption("logport-furlfile", furlfile)
        logport_furl = t.getLogPortFURL()
        logport_furl2 = open(furlfile, "r").read().strip()
        self.assertEqual(logport_furl, logport_furl2)

        t2 = Tub()
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
        self.assertTrue(isinstance(incidents, dict))
        self.assertEqual(len(incidents), 1)
        self.i_name = i_name = list(incidents.keys())[0]
        self.assertTrue(i_name.startswith("incident"))
        self.assertFalse(i_name.endswith(".flog") or i_name.endswith(".bz2"))
        trigger = incidents[i_name]
        self.assertEqual(trigger["message"], "three")
    def _check_incident(self, xxx_todo_changeme2 ):
        (header, events) = xxx_todo_changeme2
        self.assertEqual(header["type"], "incident")
        self.assertEqual(header["trigger"]["message"], "three")
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["message"], "one")

    def test_subscribe(self):
        basedir = "logging/IncidentPublisher/subscribe"
        os.makedirs(basedir)
        t = Tub()
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
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
        logport_furl = t.getLogPortFURL()

        ob = Observer()
        t2 = Tub()
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
            self.assertEqual(len(ob.incidents), 1)
            self.assertEqual(_triggerof(ob.incidents[0]), "two")
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
            self.assertEqual(len(ob2.incidents), 2)
            self.assertEqual(_triggerof(ob2.incidents[0]), "one")
            self.assertEqual(_triggerof(ob2.incidents[1]), "two")
        d.addCallback(_check_all)

        d.addCallback(lambda res: time.sleep(2))
        d.addCallback(lambda res: t.logger.msg("three", level=log.WEIRD))
        d.addCallback(lambda res:
                      self.poll(lambda: len(ob2.incidents) >= 3, 0.1))
        def _check_all2(res):
            self.assertEqual(len(ob2.incidents), 3)
            self.assertEqual(_triggerof(ob2.incidents[0]), "one")
            self.assertEqual(_triggerof(ob2.incidents[1]), "two")
            self.assertEqual(_triggerof(ob2.incidents[2]), "three")
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
            self.assertEqual(len(ob3.incidents), 1)
            self.assertEqual(_triggerof(ob3.incidents[0]), "three")
        d.addCallback(_check_since)
        d.addCallback(lambda res: time.sleep(2))
        d.addCallback(lambda res: t.logger.msg("four", level=log.WEIRD))
        d.addCallback(lambda res:
                      self.poll(lambda: len(ob3.incidents) >= 2, 0.1))
        def _check_since2(res):
            self.assertEqual(len(ob3.incidents), 2)
            self.assertEqual(_triggerof(ob3.incidents[0]), "three")
            self.assertEqual(_triggerof(ob3.incidents[1]), "four")
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
        if not os.path.isdir(ig_basedir):
            os.mkdir(ig_basedir)
            portnum = allocate_tcp_port()
            with open(os.path.join(ig_basedir, "port"), "w") as f:
                f.write("tcp:%d\n" % portnum)
            with open(os.path.join(ig_basedir, "location"), "w") as f:
                f.write("tcp:127.0.0.1:%d\n" % portnum)
        null = StringIO()
        ig = MyIncidentGathererService(classifiers=classifiers,
                                       basedir=ig_basedir, stdout=null)
        ig.d = defer.Deferred()
        return ig

    def create_connected_tub(self, ig):
        t = Tub()
        t.logger = self.logger
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
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
        def _new_incident(xxx_todo_changeme):
            (abs_fn, rel_fn) = xxx_todo_changeme
            events = self._read_logfile(abs_fn)
            header = events[0]["header"]
            self.assertTrue("trigger" in header)
            self.assertEqual(header["trigger"]["message"], "boom")
            e = events[1]["d"]
            self.assertEqual(e["message"], "boom")

            # it should have been classified as "unknown"
            unknowns_fn = os.path.join(ig.basedir, "classified", "unknown")
            unknowns = [fn.strip() for fn in open(unknowns_fn,"r").readlines()]
            self.assertEqual(len(unknowns), 1)
            self.assertEqual(unknowns[0], rel_fn)
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
            self.assertFalse(os.path.exists(unknowns_fn))
            booms_fn = os.path.join(ig.basedir, "classified", "boom")
            booms = [fn.strip() for fn in open(booms_fn,"r").readlines()]
            self.assertEqual(len(booms), 1)
            fooms_fn = os.path.join(ig.basedir, "classified", "foom")
            self.assertFalse(os.path.exists(fooms_fn))

            ig2.cb_new_incident = incident_d2.callback

            return ig2.d
        d.addCallback(_update_classifiers)
        d.addCallback(lambda res: self.logger.msg("foom", level=log.WEIRD))
        d.addCallback(lambda res: incident_d2)
        def _new_incident2(xxx_todo_changeme1):
            # this one should be classified as "foom"

            # it should have been classified as "unknown"
            (abs_fn, rel_fn) = xxx_todo_changeme1
            fooms_fn = os.path.join(ig.basedir, "classified", "foom")
            fooms = [fn.strip() for fn in open(fooms_fn,"r").readlines()]
            self.assertEqual(len(fooms), 1)
            self.assertEqual(fooms[0], rel_fn)
            unknowns_fn = os.path.join(ig.basedir, "classified", "unknown")
            self.assertFalse(os.path.exists(unknowns_fn))
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
            self.assertEqual(len(booms), 1)
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
            self.assertFalse(os.path.exists(unknowns_fn))
            booms_fn = os.path.join(ig.basedir, "classified", "boom")
            booms = [fn.strip() for fn in open(booms_fn,"r").readlines()]
            self.assertEqual(len(booms), 1)
            fooms_fn = os.path.join(ig.basedir, "classified", "foom")
            fooms = [fn.strip() for fn in open(fooms_fn,"r").readlines()]
            self.assertEqual(len(fooms), 1)
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
        self.assertEqual(len(events), 4)

        # header
        data = events.pop(0)
        self.assertTrue(isinstance(data, dict))
        self.assertTrue("header" in data)
        self.assertEqual(data["header"]["type"], "gatherer")
        self.assertEqual(data["header"]["start"], starting_timestamp)

        # grab the first event from the log
        data = events.pop(0)
        self.assertTrue(isinstance(data, dict))
        self.assertEqual(data['from'], expected_tubid)
        self.assertEqual(data['d']['message'], "gathered message here")

        # grab the second event from the log
        data = events.pop(0)
        self.assertTrue(isinstance(data, dict))
        self.assertEqual(data['from'], expected_tubid)
        self.assertEqual(data['d']['message'], "")
        self.assertTrue(data['d']["isError"])
        self.assertTrue("failure" in data['d'])
        self.failUnlessIn("SampleError", data['d']["failure"]["repr"])
        self.failUnlessIn("whoops1", data['d']["failure"]["repr"])

        # grab the third event from the log
        data = events.pop(0)
        self.assertTrue(isinstance(data, dict))
        self.assertEqual(data['from'], expected_tubid)
        self.assertEqual(data['d']['message'], "")
        self.assertTrue(data['d']["isError"])
        self.assertTrue("failure" in data['d'])
        self.failUnlessIn("SampleError", data['d']["failure"]["repr"])
        self.failUnlessIn("whoops2", data['d']["failure"]["repr"])

    def test_wrongdir(self):
        basedir = "logging/Gatherer/wrongdir"
        os.makedirs(basedir)

        # create a LogGatherer with an unspecified basedir: it should look
        # for a .tac file in the current directory, not see it, and complain
        e = self.assertRaises(RuntimeError,
                                  gatherer.GathererService, None, True, None)
        self.assertTrue("running in the wrong directory" in str(e))

    def test_log_gatherer(self):
        # setLocation, then set log-gatherer-furl. Also, use bzip=True for
        # this one test.
        basedir = "logging/Gatherer/log_gatherer"
        os.makedirs(basedir)

        # create a gatherer, which will create its own Tub
        gatherer = MyGatherer(None, True, basedir)
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furl = gatherer.my_furl
        starting_timestamp = gatherer._starting_timestamp

        t = Tub()
        expected_tubid = t.tubID
        assert t.tubID is not None
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
        t.setOption("log-gatherer-furl", gatherer_furl)

        # about now, the node will be contacting the Gatherer and
        # offering its logport.

        # gatherer.d will be fired when subscribe_to_all() has finished
        d = gatherer.d
        d.addCallback(self._emit_messages_and_flush, t)
        # We use do_rotate() to force logfile rotation before checking
        # contents of the file, so we know it's been written out to disk
        d.addCallback(lambda res: gatherer.do_rotate())
        d.addCallback(self._check_gatherer, starting_timestamp, expected_tubid)
        return d
    test_log_gatherer.timeout = 20

    def test_log_gatherer_multiple(self):
        # setLocation, then set log-gatherer-furl.
        basedir = "logging/Gatherer/log_gatherer_multiple"
        os.makedirs(basedir)

        # create a gatherer, which will create its own Tub
        gatherer1_basedir = os.path.join(basedir, "gatherer1")
        os.makedirs(gatherer1_basedir)
        gatherer1 = MyGatherer(None, False, gatherer1_basedir)
        gatherer1.d = defer.Deferred()
        gatherer1.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer1_furl = gatherer1.my_furl
        starting_timestamp1 = gatherer1._starting_timestamp

        # create a second one
        gatherer2_basedir = os.path.join(basedir, "gatherer2")
        os.makedirs(gatherer2_basedir)
        gatherer2 = MyGatherer(None, False, gatherer2_basedir)
        gatherer2.d = defer.Deferred()
        gatherer2.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer2_furl = gatherer2.my_furl
        starting_timestamp2 = gatherer2._starting_timestamp

        t = Tub()
        expected_tubid = t.tubID
        assert t.tubID is not None
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
        t.setOption("log-gatherer-furl", (gatherer1_furl, gatherer2_furl))

        # about now, the node will be contacting the Gatherers and
        # offering its logport.

        # gatherer.d and gatherer2.d will be fired when subscribe_to_all()
        # has finished
        dl = defer.DeferredList([gatherer1.d, gatherer2.d])
        dl.addCallback(self._emit_messages_and_flush, t)
        dl.addCallback(lambda res: gatherer1.do_rotate())
        dl.addCallback(self._check_gatherer, starting_timestamp1, expected_tubid)
        dl.addCallback(lambda res: gatherer2.do_rotate())
        dl.addCallback(self._check_gatherer, starting_timestamp2, expected_tubid)
        return dl
    test_log_gatherer_multiple.timeout = 40

    def test_log_gatherer2(self):
        # set log-gatherer-furl, then setLocation. Also, use a timed rotator.
        basedir = "logging/Gatherer/log_gatherer2"
        os.makedirs(basedir)

        # create a gatherer, which will create its own Tub
        gatherer = MyGatherer(3600, False, basedir)
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furl = gatherer.my_furl
        starting_timestamp = gatherer._starting_timestamp

        t = Tub()
        expected_tubid = t.tubID
        assert t.tubID is not None
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setOption("log-gatherer-furl", gatherer_furl)
        t.setLocation("127.0.0.1:%d" % portnum)

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
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furlfile = os.path.join(basedir, gatherer.furlFile)
        starting_timestamp = gatherer._starting_timestamp

        t = Tub()
        expected_tubid = t.tubID
        assert t.tubID is not None
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
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
        gatherer.d = defer.Deferred()
        gatherer.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer_furlfile = os.path.join(basedir, gatherer.furlFile)
        starting_timestamp = gatherer._starting_timestamp

        t = Tub()
        expected_tubid = t.tubID
        assert t.tubID is not None
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setOption("log-gatherer-furlfile", gatherer_furlfile)
        # one bug we had was that the log-gatherer was contacted before
        # setLocation had occurred, so exercise that case
        d = self.stall(None, 1.0)
        def _start(res):
            t.setLocation("127.0.0.1:%d" % portnum)
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
        gatherer1.d = defer.Deferred()
        gatherer1.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer1_furl = gatherer1.my_furl
        starting_timestamp1 = gatherer1._starting_timestamp

        gatherer2_basedir = os.path.join(basedir, "gatherer2")
        os.makedirs(gatherer2_basedir)
        gatherer2 = MyGatherer(None, False, gatherer2_basedir)
        gatherer2.d = defer.Deferred()
        gatherer2.setServiceParent(self.parent)
        # that will start the gatherer
        gatherer2_furl = gatherer2.my_furl
        starting_timestamp2 = gatherer2._starting_timestamp

        gatherer3_basedir = os.path.join(basedir, "gatherer3")
        os.makedirs(gatherer3_basedir)
        gatherer3 = MyGatherer(None, False, gatherer3_basedir)
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

        t = Tub()
        expected_tubid = t.tubID
        assert t.tubID is not None
        t.setOption("log-gatherer-furl", gatherer3_furl)
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
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

        t = Tub()
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
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

        t = Tub()
        t.setServiceParent(self.parent)
        portnum = allocate_tcp_port()
        t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        t.setLocation("127.0.0.1:%d" % portnum)
        t.setOption("log-gatherer-furlfile", gatherer_fn)

        lp_furl = t.getLogPortFURL()
        del lp_furl
        t.log("this message shouldn't make anything explode")
    test_log_gatherer_missing_furlfile.timeout = 20


class Tail(unittest.TestCase):
    def test_logprinter(self):
        target_tubid_s = "jiijpvbge2e3c3botuzzz7la3utpl67v"
        options1 = {"save-to": None,
                   "verbose": None,
                   "timestamps": "short-local"}
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
        self.assertTrue(":06.527 L25 []#123 howdy" in outmsg)

        lp.remote_msg({"time": 1207005907.527782,
                       "level": 25,
                       "num": 124,
                       "format": "howdy %(there)s",
                       "there": "pardner",
                       })
        outmsg = out.getvalue()
        # this contains a localtime string, so don't check the hour
        self.assertTrue(":07.527 L25 []#124 howdy pardner" in outmsg)

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

        self.assertTrue(":50.002 L30 []#125 oops\n FAILURE:\n" in outmsg,
                        outmsg)
        self.assertTrue("RuntimeError" in outmsg, outmsg)
        self.assertTrue(": fake error" in outmsg, outmsg)
        self.assertTrue("test_logging.py" in outmsg, outmsg)

    def test_logprinter_verbose(self):
        target_tubid_s = "jiijpvbge2e3c3botuzzz7la3utpl67v"
        options1 = {"save-to": None,
                   "verbose": True,
                   "timestamps": "short-local"}
        out = StringIO()
        lp = tail.LogPrinter(options1, target_tubid_s[:8], out)
        lp.got_versions({})
        lp.remote_msg({"time": 1207005906.527782,
                       "level": 25,
                       "num": 123,
                       "message": "howdy",
                       })
        outmsg = out.getvalue()
        self.assertTrue("'message': 'howdy'" in outmsg, outmsg)
        self.assertTrue("'time': 1207005906.527782" in outmsg, outmsg)
        self.assertTrue("'level': 25" in outmsg, outmsg)
        self.assertTrue("{" in outmsg, outmsg)

    def test_logprinter_saveto(self):
        target_tubid_s = "jiijpvbge2e3c3botuzzz7la3utpl67v"
        saveto_filename = "test_logprinter_saveto.flog"
        options = {"save-to": saveto_filename,
                   "verbose": False,
                   "timestamps": "short-local"}
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
        expected_magic = f.read(len(flogfile.MAGIC))
        self.assertEqual(expected_magic, flogfile.MAGIC)
        data = json.loads(f.readline().decode("utf-8")) # header
        self.assertEqual(data["header"]["type"], "tail")
        data = json.loads(f.readline().decode("utf-8")) # event
        self.assertEqual(data["from"], "jiijpvbg")
        self.assertEqual(data["d"]["message"], "howdy")
        self.assertEqual(data["d"]["num"], 123)
        os.remove(saveto_filename)

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
        self.assertFalse(to["verbose"])
        self.assertFalse(to["catch-up"])
        self.assertEqual(to.target_furl, "pb:pretend-furl")

        to = tail.TailOptions()
        to.parseOptions(["--verbose", "--catch-up", basedir])
        self.assertTrue(to["verbose"])
        self.assertTrue(to["catch-up"])
        self.assertEqual(to.target_furl, "this too")

        to = tail.TailOptions()
        to.parseOptions(["--save-to", "save.flog", fn])
        self.assertFalse(to["verbose"])
        self.assertFalse(to["catch-up"])
        self.assertEqual(to["save-to"], "save.flog")
        self.assertEqual(to.target_furl, "pretend this is a furl")

        to = tail.TailOptions()
        self.assertRaises(RuntimeError, to.parseOptions, ["bogus.txt"])

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
        return cli.run_flogtool(argv[1:], run_by_human=False)

class CLI(unittest.TestCase):
    def test_create_gatherer(self):
        basedir = "logging/CLI/create_gatherer"
        argv = ["flogtool", "create-gatherer",
                "--port", "tcp:3117", "--location", "tcp:localhost:3117",
                "--quiet", basedir]
        cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertTrue(os.path.exists(basedir))

        basedir = "logging/CLI/create_gatherer2"
        argv = ["flogtool", "create-gatherer", "--rotate", "3600",
                "--port", "tcp:3117", "--location", "tcp:localhost:3117",
                "--quiet", basedir]
        cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertTrue(os.path.exists(basedir))

        basedir = "logging/CLI/create_gatherer3"
        argv = ["flogtool", "create-gatherer",
                "--port", "tcp:3117", "--location", "tcp:localhost:3117",
                basedir]
        (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertTrue(os.path.exists(basedir))
        self.assertTrue(("Gatherer created in directory %s" % basedir)
                        in out, out)
        self.assertTrue("Now run" in out, out)
        self.assertTrue("to launch the daemon" in out, out)

    def test_create_gatherer_badly(self):
        #basedir = "logging/CLI/create_gatherer"
        argv = ["flogtool", "create-gatherer", "--bogus-arg"]
        self.assertRaises(usage.UsageError,
                              cli.run_flogtool, argv[1:], run_by_human=False)

    def test_create_gatherer_no_location(self):
        basedir = "logging/CLI/create_gatherer_no_location"
        argv = ["flogtool", "create-gatherer", basedir]
        e = self.assertRaises(usage.UsageError,
                                  cli.run_flogtool, argv[1:],
                                  run_by_human=False)
        self.failUnlessIn("--location= is mandatory", str(e))

    def test_wrapper(self):
        basedir = "logging/CLI/wrapper"
        argv = ["wrapper", "flogtool", "create-gatherer",
                "--port", "tcp:3117", "--location", "tcp:localhost:3117",
                "--quiet", basedir]
        run_wrapper(argv[1:])
        self.assertTrue(os.path.exists(basedir))

    def test_create_incident_gatherer(self):
        basedir = "logging/CLI/create_incident_gatherer"
        argv = ["flogtool", "create-incident-gatherer",
                "--port", "tcp:3118", "--location", "tcp:localhost:3118",
                "--quiet", basedir]
        cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertTrue(os.path.exists(basedir))

        basedir = "logging/CLI/create_incident_gatherer2"
        argv = ["flogtool", "create-incident-gatherer",
                "--port", "tcp:3118", "--location", "tcp:localhost:3118",
                basedir]
        (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertTrue(os.path.exists(basedir))
        self.assertTrue(("Incident Gatherer created in directory %s" % basedir)
                        in out, out)
        self.assertTrue("Now run" in out, out)
        self.assertTrue("to launch the daemon" in out, out)

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

        d.addCallback(lambda name_trigger:
                      os.path.join(self.basedir, name_trigger[0]+".flog.bz2"))

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
            tmode = d.options["timestamps"]

            argv = ["flogtool", "dump", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.assertTrue(lines[0].strip().startswith("Application versions"),
                            lines[0])
            mypid = os.getpid()
            self.assertEqual(lines[3].strip(), "PID: %s" % mypid, lines[3])
            lines = lines[5:]
            line0 = "local#%d %s: one" % (events[1]["d"]["num"],
                                          format_time(events[1]["d"]["time"],
                                                      tmode))
            self.assertEqual(lines[0].strip(), line0)
            self.assertTrue("FAILURE:" in lines[3])
            self.failUnlessIn("test_logging.SampleError", lines[4])
            self.failUnlessIn(": whoops1", lines[4])
            self.assertTrue(lines[-1].startswith("local#3 "))

            argv = ["flogtool", "dump", "--just-numbers", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertEqual(err, "")
            lines = list(StringIO(out).readlines())
            line0 = "%s %d" % (format_time(events[1]["d"]["time"], tmode),
                               events[1]["d"]["num"])
            self.assertEqual(lines[0].strip(), line0)
            self.assertTrue(lines[1].strip().endswith(" 1"))
            self.assertTrue(lines[-1].strip().endswith(" 3"))
            # failures are not dumped in --just-numbers
            self.assertEqual(len(lines), 1+3)

            argv = ["flogtool", "dump", "--rx-time", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.assertTrue(lines[0].strip().startswith("Application versions"),
                            lines[0])
            mypid = os.getpid()
            self.assertEqual(lines[3].strip(), "PID: %s" % mypid, lines[3])
            lines = lines[5:]
            line0 = "local#%d rx(%s) emit(%s): one" % \
                    (events[1]["d"]["num"],
                     format_time(events[1]["rx_time"], tmode),
                     format_time(events[1]["d"]["time"], tmode))
            self.assertEqual(lines[0].strip(), line0)
            self.assertTrue(lines[-1].strip().endswith(" four"))

            argv = ["flogtool", "dump", "--verbose", fn]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.assertTrue("header" in lines[0])
            self.assertTrue(re.search(r"u?'message': u?'one'", lines[1]), lines[1])
            self.assertTrue("'level': 20" in lines[1])
            self.assertTrue(": four: {" in lines[-1])

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
            self.assertEqual(err, "")
            lines = list(StringIO(out).readlines())
            self.assertEqual(len(lines), 8)
            self.assertEqual(lines[0].strip(),
                                 "Application versions (embedded in logfile):")
            self.assertTrue(lines[1].strip().startswith("foolscap:"), lines[1])
            self.assertTrue(lines[2].strip().startswith("twisted:"), lines[2])
            mypid = os.getpid()
            self.assertEqual(lines[3].strip(), "PID: %s" % mypid, lines[3])
            self.assertEqual(lines[4].strip(), "")
            self.assertFalse("[INCIDENT-TRIGGER]" in lines[5])
            self.assertFalse("[INCIDENT-TRIGGER]" in lines[6])
            self.assertTrue(lines[7].strip().endswith(": boom [INCIDENT-TRIGGER]"))
        d.addCallback(_check)
        return d

    def test_oops_furl(self):
        self.basedir = os.path.join("logging", "Dumper", "oops_furl")
        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir)
        fn = os.path.join(self.basedir, "logport.furl")
        f = open(fn, "w")
        f.write("pb://TUBID@HINTS/SWISSNUM\n")
        f.close()

        d = dumper.LogDumper()
        # initialize the LogDumper() timestamp mode
        d.options = dumper.DumpOptions()
        d.options.parseOptions([fn])
        argv = ["flogtool", "dump", fn]
        (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertEqual(err, "Error: %s appears to be a FURL file.\nPerhaps you meant to run 'flogtool tail' instead of 'flogtool dump'?\n" % fn)

PICKLE_DUMPFILE_B64 = """
KGRwMApTJ2hlYWRlcicKcDEKKGRwMgpTJ3RocmVzaG9sZCcKcDMKSTAKc1MncGlkJwpwNA
pJMTg3MjgKc1MndHlwZScKcDUKUydsb2ctZmlsZS1vYnNlcnZlcicKcDYKc1MndmVyc2lv
bnMnCnA3CihkcDgKUydmb29sc2NhcCcKcDkKUycwLjkuMSsyMi5nNzhlNWEzZC5kaXJ0eS
cKcDEwCnNTJ3R3aXN0ZWQnCnAxMQpTJzE1LjUuMCcKcDEyCnNzcy6AAn1xAChVBGZyb21x
AVUFbG9jYWxxAlUHcnhfdGltZXEDR0HVmqGrUXpjVQFkcQR9cQUoVQVsZXZlbHEGSxRVC2
luY2FybmF0aW9ucQdVCMZQLsaodzvDcQhOhnEJVQhmYWNpbGl0eXEKVQxiaWcuZmFjaWxp
dHlxC1UDbnVtcQxLAFUEdGltZXENR0HVmqGrRFtbVQdtZXNzYWdlcQ5VA29uZXEPdXUugA
J9cQAoVQRmcm9tcQFVBWxvY2FscQJVB3J4X3RpbWVxA0dB1Zqhq1F+s1UBZHEEfXEFKFUH
bWVzc2FnZXEGVQN0d29xB1UDbnVtcQhLAVUEdGltZXEJR0HVmqGrUU6cVQtpbmNhcm5hdG
lvbnEKVQjGUC7GqHc7w3ELToZxDFUFbGV2ZWxxDUsTdXUugAJ9cQAoVQRmcm9tcQFVBWxv
Y2FscQJVB3J4X3RpbWVxA0dB1Zqhq1GAiFUBZHEEfXEFKFUFbGV2ZWxxBksUVQtpbmNhcm
5hdGlvbnEHVQjGUC7GqHc7w3EIToZxCVUDd2h5cQpOVQdmYWlsdXJlcQsoY2Zvb2xzY2Fw
LmNhbGwKQ29waWVkRmFpbHVyZQpxDG9xDX1xDyhVAnRicRBOVQl0cmFjZWJhY2txEVSBAw
AAVHJhY2ViYWNrIChtb3N0IHJlY2VudCBjYWxsIGxhc3QpOgogIEZpbGUgIi9Vc2Vycy93
YXJuZXIvc3R1ZmYvcHl0aG9uL2Zvb2xzY2FwL3ZlL2xpYi9weXRob24yLjcvc2l0ZS1wYW
NrYWdlcy90d2lzdGVkL3RyaWFsL19hc3luY3Rlc3QucHkiLCBsaW5lIDExMiwgaW4gX3J1
bgogICAgdXRpbHMucnVuV2l0aFdhcm5pbmdzU3VwcHJlc3NlZCwgc2VsZi5fZ2V0U3VwcH
Jlc3MoKSwgbWV0aG9kKQogIEZpbGUgIi9Vc2Vycy93YXJuZXIvc3R1ZmYvcHl0aG9uL2Zv
b2xzY2FwL3ZlL2xpYi9weXRob24yLjcvc2l0ZS1wYWNrYWdlcy90d2lzdGVkL2ludGVybm
V0L2RlZmVyLnB5IiwgbGluZSAxNTAsIGluIG1heWJlRGVmZXJyZWQKICAgIHJlc3VsdCA9
IGYoKmFyZ3MsICoqa3cpCiAgRmlsZSAiL1VzZXJzL3dhcm5lci9zdHVmZi9weXRob24vZm
9vbHNjYXAvdmUvbGliL3B5dGhvbjIuNy9zaXRlLXBhY2thZ2VzL3R3aXN0ZWQvaW50ZXJu
ZXQvdXRpbHMucHkiLCBsaW5lIDE5NywgaW4gcnVuV2l0aFdhcm5pbmdzU3VwcHJlc3NlZA
ogICAgcmVzdWx0ID0gZigqYSwgKiprdykKICBGaWxlICIvVXNlcnMvd2FybmVyL3N0dWZm
L3B5dGhvbi9mb29sc2NhcC9mb29sc2NhcC90ZXN0L3Rlc3RfbG9nZ2luZy5weSIsIGxpbm
UgMTg4MywgaW4gdGVzdF9kdW1wCiAgICBkID0gc2VsZi5jcmVhdGVfbG9nZmlsZSgpCi0t
LSA8ZXhjZXB0aW9uIGNhdWdodCBoZXJlPiAtLS0KICBGaWxlICIvVXNlcnMvd2FybmVyL3
N0dWZmL3B5dGhvbi9mb29sc2NhcC9mb29sc2NhcC90ZXN0L3Rlc3RfbG9nZ2luZy5weSIs
IGxpbmUgMTg0MiwgaW4gY3JlYXRlX2xvZ2ZpbGUKICAgIHJhaXNlIFNhbXBsZUVycm9yKC
J3aG9vcHMxIikKZm9vbHNjYXAudGVzdC50ZXN0X2xvZ2dpbmcuU2FtcGxlRXJyb3I6IHdo
b29wczEKcRJVBXZhbHVlcRNVB3dob29wczFxFFUHcGFyZW50c3EVXXEWKFUmZm9vbHNjYX
AudGVzdC50ZXN0X2xvZ2dpbmcuU2FtcGxlRXJyb3JxF1UUZXhjZXB0aW9ucy5FeGNlcHRp
b25xGFUYZXhjZXB0aW9ucy5CYXNlRXhjZXB0aW9ucRlVEl9fYnVpbHRpbl9fLm9iamVjdH
EaZVUGZnJhbWVzcRtdcRxVBHR5cGVxHVUmZm9vbHNjYXAudGVzdC50ZXN0X2xvZ2dpbmcu
U2FtcGxlRXJyb3JxHlUFc3RhY2txH11xIHViVQNudW1xIUsCVQR0aW1lcSJHQdWaoatRVt
JVB21lc3NhZ2VxI1UFdGhyZWVxJFUHaXNFcnJvcnElSwF1dS6AAn1xAChVBGZyb21xAVUF
bG9jYWxxAlUHcnhfdGltZXEDR0HVmqGrUYXkVQFkcQR9cQUoVQdtZXNzYWdlcQZVBGZvdX
JxB1UDbnVtcQhLA1UEdGltZXEJR0HVmqGrUXU2VQtpbmNhcm5hdGlvbnEKVQjGUC7GqHc7
w3ELToZxDFUFbGV2ZWxxDUsUdXUu
"""

PICKLE_INCIDENT_B64 = """
QlpoOTFBWSZTWUOW3hEAAHjfgAAQAcl/4QkhCAS/59/iQAGdWS2BJRTNNQ2oB6gGgPU9T1
BoEkintKGIABiAAaAwANGhowjJoNGmgMCpJDSaNGqbSMnqGhoaAP1S5rw5GxrNlUoxLXu2
sZ5TYy2rVCVNHMKgeDE97TBiw1hXtCfdSCISDpSlL61KFiacqWj9apY80J2PIpO7mde+vd
Jz18Myu4+djYU10JPMGU5vFAcUmmyk0kmcGUSMIDUJcKkog4W2EyyQStwwSYUEohGpr6Wm
F4KU7qccsjPJf8dTIv3ydZM5hpkW41JjJ8j0PETxlRRVFSeZYsqFU+hufU3n5O3hmYASDC
DhWMHFPJE7nXCYRsz5BGjktwUQCu6d4cixrgmGYLYA7JVCM7UqkMDVD9EMaclrFuayYGBR
xMIwXxM9pjeUuZVv2ceR5E6FSWpVRKKD98ObK5wmGmU9vqNBKqjp0wwqZlZ3x3nA4n+LTS
rmhbVjNyWeh/xdyRThQkEOW3hE
"""

class OldPickleDumper(unittest.TestCase):
    def test_dump(self):
        self.basedir = "logging/OldPickleDumper/dump"
        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir)
        fn = os.path.join(self.basedir, "dump.flog")
        with open(fn, "wb") as f:
            f.write(base64.b64decode(PICKLE_DUMPFILE_B64))

        argv = ["flogtool", "dump", fn]
        (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertEqual(out, "")
        self.failUnlessIn("which cannot be loaded safely", err)

    def test_incident(self):
        self.basedir = "logging/OldPickleDumper/incident"
        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir)
        fn = os.path.join(self.basedir,
                          "incident-2015-12-11--08-18-28Z-uqyuiea.flog.bz2")
        with open(fn, "wb") as f:
            f.write(base64.b64decode(PICKLE_INCIDENT_B64))

        argv = ["flogtool", "dump", fn]
        (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
        self.assertEqual(out, "")
        self.failUnlessIn("which cannot be loaded safely", err)

class Filter(unittest.TestCase, LogfileWriterMixin, LogfileReaderMixin):

    def compare_events(self, a, b):
        ## # cmp(a,b) won't quite work, because two instances of CopiedFailure
        ## # loaded from the same pickle don't compare as equal

        # in fact we no longer create CopiedFailure instances in logs, so a
        # simple failUnlessEqual will now suffice
        self.assertEqual(a, b)


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
            self.assertTrue("copied 5 of 5 events into new file" in out, out)
            self.compare_events(events, self._read_logfile(fn2))

            # convert to .bz2 while we're at it
            fn2bz2 = fn2 + ".bz2"
            argv = ["flogtool", "filter", fn, fn2bz2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("copied 5 of 5 events into new file" in out, out)
            self.compare_events(events, self._read_logfile(fn2bz2))

            # modify the file in place
            argv = ["flogtool", "filter", "--above", "20", fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("modifying event file in place" in out, out)
            self.assertTrue("--above: removing events below level 20" in out, out)
            self.assertTrue("copied 4 of 5 events into new file" in out, out)
            self.compare_events([events[0], events[1], events[3], events[4]],
                                self._read_logfile(fn2))

            # modify the file in place, two-argument version
            argv = ["flogtool", "filter", fn2, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("modifying event file in place" in out, out)
            self.assertTrue("copied 4 of 4 events into new file" in out, out)
            self.compare_events([events[0], events[1], events[3], events[4]],
                                self._read_logfile(fn2))

            # --above with a string argument
            argv = ["flogtool", "filter", "--above", "OPERATIONAL", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("--above: removing events below level 20" in out, out)
            self.assertTrue("copied 4 of 5 events into new file" in out, out)
            self.compare_events([events[0], events[1], events[3], events[4]],
                                self._read_logfile(fn2))

            t_one = events[1]["d"]["time"]
            # we can only pass integers into --before and --after, so we'll
            # just test that we get all or nothing
            argv = ["flogtool", "filter", "--before", str(int(t_one - 10)),
                    fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("copied 1 of 5 events into new file" in out, out)
            # we always get the header, so it's 1 instead of 0
            self.compare_events(events[:1], self._read_logfile(fn2))

            argv = ["flogtool", "filter", "--after", str(int(t_one + 10)),
                    fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("copied 1 of 5 events into new file" in out, out)
            self.compare_events(events[:1], self._read_logfile(fn2))

            # --facility
            argv = ["flogtool", "filter", "--strip-facility", "big", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("--strip-facility: removing events for big and children" in out, out)
            self.assertTrue("copied 4 of 5 events into new file" in out, out)
            self.compare_events([events[0],events[2],events[3],events[4]],
                                self._read_logfile(fn2))

            # pass-through, --verbose, read from .bz2
            argv = ["flogtool", "filter", "--verbose", fn2bz2, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("copied 5 of 5 events into new file" in out, out)
            lines = [l.strip() for l in StringIO(out).readlines()]
            self.assertEqual(lines,
                                 ["HEADER", "0", "1", "2", "3",
                                  "copied 5 of 5 events into new file"])
            self.compare_events(events, self._read_logfile(fn2))

            # --from . This normally takes a base32 tubid prefix, but the
            # things we've logged all say ["from"]="local". So just test
            # all-or-nothing.
            argv = ["flogtool", "filter", "--from", "local", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("--from: retaining events only from tubid prefix local" in out, out)
            self.assertTrue("copied 5 of 5 events into new file" in out, out)
            self.compare_events(events, self._read_logfile(fn2))

            argv = ["flogtool", "filter", "--from", "NOTlocal", fn, fn2]
            (out,err) = cli.run_flogtool(argv[1:], run_by_human=False)
            self.assertTrue("--from: retaining events only from tubid prefix NOTlocal" in out, out)
            self.assertTrue("copied 1 of 5 events into new file" in out, out)
            self.compare_events(events[:1], self._read_logfile(fn2))


        d.addCallback(_check)
        return d


@inlineCallbacks
def getPage(url):
    a = client.Agent(reactor)
    response = yield a.request(b"GET", six.ensure_binary(url))
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # Twisted can emit a spurious internal warning here ("Using readBody
        # with a transport that does not have an abortConnection method")
        # which seems to be https://twistedmatrix.com/trac/ticket/8227
        page = yield client.readBody(response)
    if response.code != 200:
        raise ValueError("request failed (%d), page contents were: %s" % (
            response.code, six.ensure_str(page)))
    returnValue(page)

class Web(unittest.TestCase):
    def setUp(self):
        self.viewer = None
    def tearDown(self):
        d = defer.maybeDeferred(unittest.TestCase.tearDown, self)
        if self.viewer:
            d.addCallback(lambda res: self.viewer.stop())
        return d

    @inlineCallbacks
    def test_basic(self):
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
        yield fireEventually()
        l.removeObserver(ob.msg)
        ob._stop()

        portnum = allocate_tcp_port()
        argv = ["-p", "tcp:%d:interface=127.0.0.1" % portnum,
                "--quiet",
                fn]
        options = web.WebViewerOptions()
        options.parseOptions(argv)
        self.viewer = web.WebViewer()
        self.url = yield self.viewer.start(options)
        self.baseurl = self.url[:self.url.rfind("/")] + "/"

        page = yield getPage(self.url)
        page = six.ensure_str(page)
        mypid = os.getpid()
        self.assertTrue("PID %s" % mypid in page,
                        "didn't see 'PID %s' in '%s'" % (mypid, page))
        self.assertTrue("Application Versions:" in page, page)
        self.assertTrue("foolscap: %s" % foolscap.__version__ in page, page)
        self.assertTrue("4 events covering" in page)
        self.assertTrue('href="summary/0-20">3 events</a> at level 20'
                        in page)

        page = yield getPage(self.baseurl + "summary/0-20")
        page = six.ensure_str(page)
        self.assertTrue("Events at level 20" in page)
        self.assertTrue(": two" in page)
        self.assertFalse("four" in page)

        def check_all_events(page):
            page = six.ensure_str(page)
            self.assertTrue("3 root events" in page)
            self.assertTrue(": one</span>" in page)
            self.assertTrue(": two</span>" in page)
            self.assertTrue(": three FAILURE:" in page)
            self.assertTrue(": UNUSUAL four</span>" in page)

        page = yield getPage(self.baseurl + "all-events")
        check_all_events(page)

        page = yield getPage(self.baseurl + "all-events?sort=number")
        check_all_events(page)

        page = yield getPage(self.baseurl + "all-events?sort=time")
        check_all_events(page)

        page = yield getPage(self.baseurl + "all-events?sort=nested")
        check_all_events(page)

        page = yield getPage(self.baseurl + "all-events?timestamps=short-local")
        check_all_events(page)

        page = yield getPage(self.baseurl + "all-events?timestamps=utc")
        check_all_events(page)



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
            self.assertEqual(len(fl_out), 3)
            self.assertEqual(fl_out[0]["message"], "one")
            self.assertEqual(fl_out[1]["format"], "two %(two)d")
            self.assertEqual(fl_out[2]["message"], "three")

            self.assertEqual(len(tw_out), 2)
            self.assertEqual(tw_out[0]["message"], ("one",))
            self.assertTrue(tw_out[0]["from-foolscap"])
            self.assertEqual(tw_out[1]["message"], ("two 2",))
            self.assertTrue(tw_out[1]["from-foolscap"])

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
        # twisted now has places (e.g. Factory.doStart) where the new
        # Logger.info() is called with arbitrary (unserializable) kwargs for
        # string formatting, which are passed into the old LogPublisher(),
        # from which they arrive in foolscap. Make sure we can tolerate that.
        # The rule is that foolscap immediately stringifies all events it
        # gets from twisted (with log.textFromEventDict), and doesn't store
        # the additional arguments. So it's ok to put an *unserializable*
        # argument into the log.msg() call, as long as it's still
        # *stringifyable*.
        unserializable = lambda: "unserializable"
        tw.msg(format="three is %(evil)s", evil=unserializable)

        d = flushEventualQueue()
        def _check(res):
            self.assertEqual(len(tw_out), 3)
            self.assertEqual(tw_out[0]["message"], ("one",))
            self.assertEqual(tw_out[1]["format"], "two %(two)d")
            self.assertEqual(tw_out[1]["two"], 2)
            self.assertEqual(tw_out[2]["format"], "three is %(evil)s")
            self.assertEqual(tw_out[2]["evil"], unserializable)
            self.assertEqual(len(fl_out), 3)
            self.assertEqual(fl_out[0]["message"], "one")
            self.assertTrue(fl_out[0]["from-twisted"])
            self.assertEqual(fl_out[1]["message"], "two 2")
            self.assertTrue(fl_out[1]["from-twisted"])
            # str(unserializable) is like "<function <lambda> at 0xblahblah>"
            self.assertEqual(fl_out[2]["message"],
                                 "three is " + str(unserializable))
            self.assertTrue(fl_out[2]["from-twisted"])

        d.addCallback(_check)
        return d

    def test_twisted_logger_to_foolscap(self):
        if not twisted_logger:
            raise unittest.SkipTest("needs twisted.logger from Twisted>=15.2.0")
        new_pub = twisted_logger.LogPublisher()
        old_pub = twisted_log.LogPublisher(observerPublisher=new_pub,
                                           publishPublisher=new_pub)
        fl = log.FoolscapLogger()
        log.bridgeLogsFromTwisted(None, old_pub, fl)
        tw_out = []
        old_pub.addObserver(tw_out.append)
        fl_out = []
        fl.addObserver(fl_out.append)

        tl = twisted_logger.Logger(observer=new_pub)
        tl.info("one")
        # note: new twisted logger wants PEP3101 format strings, {} not %
        tl.info(format="two {two}", two=2)
        # twisted's new Logger.info() takes arbitrary (unserializable) kwargs
        # for string formatting, and passes them into the old LogPublisher(),
        # so make sure we can tolerate that. The rule is that foolscap
        # stringifies all events it gets from twisted, and doesn't store the
        # additional arguments.
        unserializable = lambda: "unserializable"
        tl.info("three is {evil!s}", evil=unserializable)

        d = flushEventualQueue()
        def _check(res):
            self.assertEqual(len(fl_out), 3)
            self.assertEqual(fl_out[0]["message"], "one")
            self.assertTrue(fl_out[0]["from-twisted"])
            self.assertEqual(fl_out[1]["message"], "two 2")
            self.assertFalse("two" in fl_out[1])
            self.assertTrue(fl_out[1]["from-twisted"])
            # str(unserializable) is like "<function <lambda> at 0xblahblah>"
            self.assertEqual(fl_out[2]["message"],
                                 "three is " + str(unserializable))
            self.assertTrue(fl_out[2]["from-twisted"])

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
            self.assertEqual(len(tw_out), 2)
            self.assertEqual(tw_out[0]["message"], ("one",))
            self.assertEqual(tw_out[1]["message"], ("two",))

            self.assertEqual(len(fl_out), 2)
            self.assertEqual(fl_out[0]["message"], "one")
            self.assertEqual(fl_out[1]["message"], "two")

        d.addCallback(_check)
        return d

