# -*- test-case-name: foolscap.test.test_pb -*-

import re, time
from zope.interface import implements, implementsOnly, implementedBy, Interface
from twisted.python import log
from twisted.internet import defer, reactor, task
from foolscap import broker
from foolscap.api import Referenceable, RemoteInterface, \
     eventually, fireEventually, flushEventualQueue
from foolscap.remoteinterface import getRemoteInterface, RemoteMethodSchema, \
     UnconstrainedMethod
from foolscap.schema import Any, SetOf, DictOf, ListOf, TupleOf, \
     NumberConstraint, ByteStringConstraint, IntegerConstraint, \
     UnicodeConstraint, ChoiceOf
from foolscap.referenceable import TubRef

from twisted.python import failure
from twisted.internet.main import CONNECTION_DONE

def getRemoteInterfaceName(obj):
    i = getRemoteInterface(obj)
    return i.__remote_name__

class Loopback:
    # The transport's promise is that write() can be treated as a
    # synchronous, isolated function call: specifically, the Protocol's
    # dataReceived() and connectionLost() methods shall not be called during
    # a call to write().

    connected = True
    def write(self, data):
        eventually(self._write, data)

    def _write(self, data):
        if not self.connected:
            return
        try:
            # isolate exceptions: if one occurred on a regular TCP transport,
            # they would hang up, so duplicate that here.
            self.peer.dataReceived(data)
        except:
            f = failure.Failure()
            log.err(f)
            print "Loopback.write exception:", f
            self.loseConnection(f)

    def loseConnection(self, why=failure.Failure(CONNECTION_DONE)):
        assert isinstance(why, failure.Failure), why
        if self.connected:
            self.connected = False
            # this one is slightly weird because 'why' is a Failure
            eventually(self._loseConnection, why)

    def _loseConnection(self, why):
        assert isinstance(why, failure.Failure), why
        self.protocol.connectionLost(why)
        self.peer.connectionLost(why)

    def flush(self):
        self.connected = False
        return fireEventually()

    def getPeer(self):
        return broker.LoopbackAddress()
    def getHost(self):
        return broker.LoopbackAddress()

Digits = re.compile("\d*")
MegaSchema1 = DictOf(str,
                     ListOf(TupleOf(SetOf(int, maxLength=10, mutable=True),
                                    str, bool, int, long, float, None,
                                    UnicodeConstraint(),
                                    ByteStringConstraint(),
                                    Any(), NumberConstraint(),
                                    IntegerConstraint(),
                                    ByteStringConstraint(maxLength=100,
                                                         minLength=90,
                                                         regexp="\w+"),
                                    ByteStringConstraint(regexp=Digits),
                                    ),
                            maxLength=20),
                     maxKeys=5)
# containers should convert their arguments into schemas
MegaSchema2 = TupleOf(SetOf(int),
                      ListOf(int),
                      DictOf(int, str),
                      )
MegaSchema3 = ListOf(TupleOf(int,int))


class RIHelper(RemoteInterface):
    def set(obj=Any()): return bool
    def set2(obj1=Any(), obj2=Any()): return bool
    def append(obj=Any()): return Any()
    def get(): return Any()
    def echo(obj=Any()): return Any()
    def defer(obj=Any()): return Any()
    def hang(): return Any()
    # test one of everything
    def megaschema(obj1=MegaSchema1, obj2=MegaSchema2): return None
    def mega3(obj1=MegaSchema3): return None
    def choice1(obj1=ChoiceOf(ByteStringConstraint(2000), int)): return None

class HelperTarget(Referenceable):
    implements(RIHelper)
    d = None
    def __init__(self, name="unnamed"):
        self.name = name
    def __repr__(self):
        return "<HelperTarget %s>" % self.name
    def waitfor(self):
        self.d = defer.Deferred()
        return self.d

    def remote_set(self, obj):
        self.obj = obj
        if self.d:
            self.d.callback(obj)
        return True
    def remote_set2(self, obj1, obj2):
        self.obj1 = obj1
        self.obj2 = obj2
        return True

    def remote_append(self, obj):
        self.calls.append(obj)

    def remote_get(self):
        return self.obj

    def remote_echo(self, obj):
        self.obj = obj
        return obj

    def remote_defer(self, obj):
        return fireEventually(obj)

    def remote_hang(self):
        self.d = defer.Deferred()
        return self.d

    def remote_megaschema(self, obj1, obj2):
        self.obj1 = obj1
        self.obj2 = obj2
        return None

    def remote_mega3(self, obj):
        self.obj = obj
        return None

    def remote_choice1(self, obj):
        self.obj = obj
        return None

class TimeoutError(Exception):
    pass

class PollComplete(Exception):
    pass

class PollMixin:

    def poll(self, check_f, pollinterval=0.01, timeout=None):
        # Return a Deferred, then call check_f periodically until it returns
        # True, at which point the Deferred will fire.. If check_f raises an
        # exception, the Deferred will errback. If the check_f does not
        # indicate success within timeout= seconds, the Deferred will
        # errback. If timeout=None, no timeout will be enforced, and the loop
        # will poll forever (or really until Trial times out).
        cutoff = None
        if timeout is not None:
            cutoff = time.time() + timeout
        lc = task.LoopingCall(self._poll, check_f, cutoff)
        d = lc.start(pollinterval)
        def _convert_done(f):
            f.trap(PollComplete)
            return None
        d.addErrback(_convert_done)
        return d

    def _poll(self, check_f, cutoff):
        if cutoff is not None and time.time() > cutoff:
            raise TimeoutError()
        if check_f():
            raise PollComplete()

class StallMixin:
    def stall(self, res, timeout):
        d = defer.Deferred()
        reactor.callLater(timeout, d.callback, res)
        return d

class TargetMixin(PollMixin, StallMixin):

    def setUp(self):
        self.loopbacks = []

    def setupBrokers(self):

        self.targetBroker = broker.Broker(TubRef("targetBroker"))
        self.callingBroker = broker.Broker(TubRef("callingBroker"))

        t1 = Loopback()
        t1.peer = self.callingBroker
        t1.protocol = self.targetBroker
        self.targetBroker.transport = t1
        self.loopbacks.append(t1)

        t2 = Loopback()
        t2.peer = self.targetBroker
        t2.protocol = self.callingBroker
        self.callingBroker.transport = t2
        self.loopbacks.append(t2)

        self.targetBroker.connectionMade()
        self.callingBroker.connectionMade()

    def tearDown(self):
        # returns a Deferred which fires when the Loopbacks are drained
        dl = [l.flush() for l in self.loopbacks]
        d = defer.DeferredList(dl)
        d.addCallback(flushEventualQueue)
        return d

    def setupTarget(self, target, txInterfaces=False):
        # txInterfaces controls what interfaces the sender uses
        #  False: sender doesn't know about any interfaces
        #  True: sender gets the actual interface list from the target
        #  (list): sender uses an artificial interface list
        puid = target.processUniqueID()
        tracker = self.targetBroker.getTrackerForMyReference(puid, target)
        tracker.send()
        clid = tracker.clid
        if txInterfaces:
            iname = getRemoteInterfaceName(target)
        else:
            iname = None
        rtracker = self.callingBroker.getTrackerForYourReference(clid, iname)
        rr = rtracker.getRef()
        return rr, target



class RIMyTarget(RemoteInterface):
    # method constraints can be declared directly:
    add1 = RemoteMethodSchema(_response=int, a=int, b=int)
    free = UnconstrainedMethod()

    # or through their function definitions:
    def add(a=int, b=int): return int
    #add = schema.callable(add) # the metaclass makes this unnecessary
    # but it could be used for adding options or something
    def join(a=str, b=str, c=int): return str
    def getName(): return str
    disputed = RemoteMethodSchema(_response=int, a=int)
    def fail(): return str  # actually raises an exception
    def failstring(): return str # raises a string exception

class RIMyTarget2(RemoteInterface):
    __remote_name__ = "RIMyTargetInterface2"
    sub = RemoteMethodSchema(_response=int, a=int, b=int)

# For some tests, we want the two sides of the connection to disagree about
# the contents of the RemoteInterface they are using. This is remarkably
# difficult to accomplish within a single process. We do it by creating
# something that behaves just barely enough like a RemoteInterface to work.
class FakeTarget(dict):
    pass
RIMyTarget3 = FakeTarget()
RIMyTarget3.__remote_name__ = RIMyTarget.__remote_name__

RIMyTarget3['disputed'] = RemoteMethodSchema(_response=int, a=str)
RIMyTarget3['disputed'].name = "disputed"
RIMyTarget3['disputed'].interface = RIMyTarget3

RIMyTarget3['disputed2'] = RemoteMethodSchema(_response=str, a=int)
RIMyTarget3['disputed2'].name = "disputed"
RIMyTarget3['disputed2'].interface = RIMyTarget3

RIMyTarget3['sub'] = RemoteMethodSchema(_response=int, a=int, b=int)
RIMyTarget3['sub'].name = "sub"
RIMyTarget3['sub'].interface = RIMyTarget3

class Target(Referenceable):
    implements(RIMyTarget)

    def __init__(self, name=None):
        self.calls = []
        self.name = name
    def getMethodSchema(self, methodname):
        return None
    def remote_add(self, a, b):
        self.calls.append((a,b))
        return a+b
    remote_add1 = remote_add
    def remote_free(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return "bird"
    def remote_getName(self):
        return self.name
    def remote_disputed(self, a):
        return 24
    def remote_fail(self):
        raise ValueError("you asked me to fail")
    def remote_fail_remotely(self, target):
        return target.callRemote("fail")

    def remote_failstring(self):
        raise "string exceptions are annoying"

class TargetWithoutInterfaces(Target):
    # undeclare the RIMyTarget interface
    implementsOnly(implementedBy(Referenceable))

class BrokenTarget(Referenceable):
    implements(RIMyTarget)

    def remote_add(self, a, b):
        return "error"


class IFoo(Interface):
    # non-remote Interface
    pass

class Foo(Referenceable):
    implements(IFoo)

class RIDummy(RemoteInterface):
    pass

class RITypes(RemoteInterface):
    def returns_none(work=bool): return None
    def takes_remoteinterface(a=RIDummy): return str
    def returns_remoteinterface(work=int): return RIDummy
    def takes_interface(a=IFoo): return str
    def returns_interface(work=bool): return IFoo

class DummyTarget(Referenceable):
    implements(RIDummy)

class TypesTarget(Referenceable):
    implements(RITypes)

    def remote_returns_none(self, work):
        if work:
            return None
        return "not None"

    def remote_takes_remoteinterface(self, a):
        # TODO: really, I want to just be able to say:
        #   if RIDummy.providedBy(a):
        iface = a.tracker.interface
        if iface and iface == RIDummy:
            return "good"
        raise RuntimeError("my argument (%s) should provide RIDummy, "
                           "but doesn't" % a)

    def remote_returns_remoteinterface(self, work):
        if work == 1:
            return DummyTarget()
        if work == -1:
            return TypesTarget()
        return 15

    def remote_takes_interface(self, a):
        if IFoo.providedBy(a):
            return "good"
        raise RuntimeError("my argument (%s) should provide IFoo, but doesn't" % a)

    def remote_returns_interface(self, work):
        if work:
            return Foo()
        return "not implementor of IFoo"


class ShouldFailMixin:

    def shouldFail(self, expected_failure, which, substring,
                   callable, *args, **kwargs):
        assert substring is None or isinstance(substring, str)
        d = defer.maybeDeferred(callable, *args, **kwargs)
        def done(res):
            if isinstance(res, failure.Failure):
                if not res.check(expected_failure):
                    self.fail("got failure %s, was expecting %s"
                              % (res, expected_failure))
                if substring:
                    self.failUnless(substring in str(res),
                                    "%s: substring '%s' not in '%s'"
                                    % (which, substring, str(res)))
                # make the Failure available to a subsequent callback, but
                # keep it from triggering an errback
                return [res]
            else:
                self.fail("%s was supposed to raise %s, not get '%s'" %
                          (which, expected_failure, res))
        d.addBoth(done)
        return d

from foolscap import crypto

from foolscap.api import Tub
def GoodEnoughTub(certData=None, certFile=None, options={}):
    return Tub(certData, certFile, options)
