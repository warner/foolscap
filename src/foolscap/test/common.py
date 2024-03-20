# -*- test-case-name: foolscap.test.test_pb -*-

from __future__ import print_function
import six
import time
from zope.interface import implementer, implementer_only, implementedBy, Interface
from twisted.python import log
from twisted.internet import defer, reactor, task, protocol
from twisted.application import internet
from twisted.trial import unittest
from foolscap import broker, eventual, negotiate
from foolscap.api import Tub, Referenceable, RemoteInterface, \
     eventually, fireEventually, flushEventualQueue
from foolscap.remoteinterface import getRemoteInterface, RemoteMethodSchema, \
     UnconstrainedMethod
from foolscap.schema import Any, SetOf, DictOf, ListOf, TupleOf, \
     NumberConstraint, ByteStringConstraint, IntegerConstraint, \
     UnicodeConstraint, ChoiceOf
from foolscap.referenceable import TubRef
from foolscap.util import allocate_tcp_port, long_type

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
            print("Loopback.write exception:", f)
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

MegaSchema1 = DictOf(ByteStringConstraint(),
                     ListOf(TupleOf(SetOf(int, maxLength=10, mutable=True),
                                    six.binary_type, bool, int, long_type, float, None,
                                    UnicodeConstraint(),
                                    ByteStringConstraint(),
                                    Any(), NumberConstraint(),
                                    IntegerConstraint(),
                                    ByteStringConstraint(maxLength=100,
                                                         minLength=90),
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

@implementer(RIHelper)
class HelperTarget(Referenceable):
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
    def join(a=bytes, b=bytes, c=int): return bytes
    def getName(): return bytes
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

@implementer(RIMyTarget)
class Target(Referenceable):
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

    def remote_with_f(self, f):
        return f

@implementer_only(implementedBy(Referenceable))
class TargetWithoutInterfaces(Target):
    # undeclare the RIMyTarget interface
    pass

@implementer(RIMyTarget)
class BrokenTarget(Referenceable):
    def remote_add(self, a, b):
        return "error"


class IFoo(Interface):
    # non-remote Interface
    pass

@implementer(IFoo)
class Foo(Referenceable):
    pass

class RIDummy(RemoteInterface):
    pass

class RITypes(RemoteInterface):
    def returns_none(work=bool): return None
    def takes_remoteinterface(a=RIDummy): return str
    def returns_remoteinterface(work=int): return RIDummy
    def takes_interface(a=IFoo): return str
    def returns_interface(work=bool): return IFoo

@implementer(RIDummy)
class DummyTarget(Referenceable):
    pass

@implementer(RITypes)
class TypesTarget(Referenceable):
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
                    self.assertTrue(substring in str(res),
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

tubid_low = "3hemthez7rvgvyhjx2n5kdj7mcyar3yt"
certData_low = \
"""-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIULiWIK/eoHGJ3wqKnDZfCutVx8DMwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjAxMjYwNjQzNTZaFw0yMzAx
MjEwNjQzNTZaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDp5L0V99sbjqxzWprhvn8Z27lk+mkInW3I8AolwAp1
GJ7EVVzCgqnqNBvjfHaAfLai5rT1iRAs3byxg7iZQBTyg3qtkcRh+ezIaIZmqr07
P3LTLez+ih3W10EqIt2VEvsyQoiIAtyZLPqADFn8aR8bfWAh2Gy+RwAdbpRogqLD
ijYPbjQkgRQEC2b7+8P08v0qTEmmOgGf6L/iTVlHXYKpoUvCVeu3dYuOA0DcgkyR
qes1QuzjPFSEc7DXoXpveAd80TP51GNPfmX1YJ9O+v+4JLeodLzE5CcOmr9p51ca
XBzAzMPT8GPwQSFgVpl6o2IidYA6dorRSljbn23rapk3AgMBAAGjUzBRMB0GA1Ud
DgQWBBQNGkPKQvZ71GwaCJyw+6l9hcn2bDAfBgNVHSMEGDAWgBQNGkPKQvZ71Gwa
CJyw+6l9hcn2bDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBN
6Q9bI0jBvtubzGUp55yl/b8MCuOre3wXVJPBDlHchk9QRZbyVQV5oenbiDSVmQI8
9K34xAYv2U24QnMDO1Yd3WE/jT4ndQEIGUUv51Wl4/BiBGOQGY0YHTTWsIzWMJ6/
qElKyVk1O3Oc0AdDlkxmx6BQ7pZ3rwSoaAkWTHetAjEub6veWWveBqukgBNuM7k3
qgYtfDT1Qa+uVSpe15UyiE5s+3FLvxBOeil9dxnYcNO4/pRMAMifuXKVmgvDG7Fp
hs22brC2Oaspgvkd+Nnh+cmpCo2WjM0LitQgqogN4dRBaylIDfTrhMYD2vl2ZxMn
y2gaNZYEqvhEQ1kh9BZf
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA6eS9FffbG46sc1qa4b5/Gdu5ZPppCJ1tyPAKJcAKdRiexFVc
woKp6jQb43x2gHy2oua09YkQLN28sYO4mUAU8oN6rZHEYfnsyGiGZqq9Oz9y0y3s
/ood1tdBKiLdlRL7MkKIiALcmSz6gAxZ/GkfG31gIdhsvkcAHW6UaIKiw4o2D240
JIEUBAtm+/vD9PL9KkxJpjoBn+i/4k1ZR12CqaFLwlXrt3WLjgNA3IJMkanrNULs
4zxUhHOw16F6b3gHfNEz+dRjT35l9WCfTvr/uCS3qHS8xOQnDpq/aedXGlwcwMzD
0/Bj8EEhYFaZeqNiInWAOnaK0UpY259t62qZNwIDAQABAoIBAQDbGqUrPCmscgYI
dbsbeAm23oeZGZ9lK5zZnEvVO0ZQlUS9pT2lFSQ5OqFZhJG6IZoxli+0x7Y4YWvP
WxaFsWsuF47HpAK0yZxPzOMCsDVemDxnqeEWPapgRPtNjqXGbaaVWZBu4Udn0qPD
ak6tzogOh2+TpRuRUA/CgoFSOfZhd4Ay2eXHnu1CUEY7VK7hWp25o0L6ZQBEH6Ig
iVWqkEA+D4DSk2TOsWZKOWvU0pLNRq4iilj5fLuz/tCKabnW5IIaVSSc1zCqUafm
IMqbPUB0u1BD71mF35o6vSmf9P3HBqaO5pErXih0qja/1B+XjKMUANMqvi00UuO1
sWdhOMrhAoGBAPu/oDxBulIZD8IGB0oMHD3q5X/c3dk61xOdsOYzYW7JCRnidyPi
2f2v58MPqTb0utB7j3TNb0OhrthtUSBCmLfxoPo2I2Mh0HooO6scJBmRgFGsulGR
PDgruRiFBWU4eUHys061d9NnPOl1nAQC15AAX6OqsKkyX+CtxoN3Z9+HAoGBAO3X
67jF3SRL2+nmAoLVNqQTaNqZ0c2pkVPu3UxcgucFWDJEIR4DQlYDkhHDKfTIzIOD
UeehJ5nhFhjSatrUVzPTzAya3XuMw2YszmsAeOuJ2SODx5spnDtrGtgbMUGykJkB
sUtP9An4c/5uW/bBmPZv+o1umsCymfUtK9zAqQTRAoGBAOf2P0yGO4md8fkS2PCP
jA45O9G+zuNz5ez7JZ5WxXXw4uPo2WJFihrIVEJVUdODWAb1cs9q4xRsC9D7mP6i
nlkO2Qbzj1OuOov0OlaFjXXJrXSUNPEnY1dWYiyHlNsZWBE98Z2ac5hkzalHZsQD
YmAbGASUKEceVV2OgRVtllZNAoGBAM5ZhdaSPBGQiyR7/PO7viNN/6ugxoizNDXo
yDDHFn8OgP1jZIQgeb4cbO9iLpWEXQNAvJ/EjpIP2dcBP9nJXjrF54OMHNpjPuf3
ucLV7xMTTsNkQppY2IYon2qc9Pg1zwQglsxreqPn3eMBpmIIhwhQEMYCDtteWPqB
DUwCDuHxAoGAdsM+IB8vFAQH9JtwGXwZEuhGqNa1eqJ1q5l0TeP6Dswbr8oI7sV1
XThHbrF0H3pM7i+PrvWS0KFMqLW0ttf6DWxbbLDZ24fithWdtlU2HWo2NQmyHMJ4
g0mwtv2O+4UPxxpp/OlETsABvkMQJsPVwdKSLcEFvDqIer9sU16fAt4=
-----END RSA PRIVATE KEY-----
"""

tubid_high = "6cxxohyb5ysw6ftpwprbzffxrghbfopm"
certData_high = \
"""-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUdb5gm2PF95WWF0VxTbuYJuvIEeQwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjAxMjYwNjQzNTdaFw0yMzAx
MjEwNjQzNTdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCijS3kKa3qxiLBur/MhFq4haoSsQGZtEh9VGoR5Qzi
REVy7YRFpa7atFKt04hosS6z6dz9QOnF9DExqbbjHaY9zL3yx6fPc+C4vc+NlG+D
/1PEBbWWLIIBucIR6RZFn5Q8q6rzxHH450HKOOS4ZkZxYwUhbGUrgqE1x86iCqZG
3GhQJypKOEjFpgBRWeJZyHDp5Sx64TwpaJRN8msxaog+EDkSeuz5S+0uHnTDVCrG
/KWwTpXeFvFZmn4FQwt3bIhgDtFgeMkOOI2PtopggX4161CV5O5cgUttp/gZ2rzo
RS4z8zl+gv2gdT7AZvN1LvVeXduN8oVBdUm4DqXMEEJfAgMBAAGjUzBRMB0GA1Ud
DgQWBBRhlyr/xXeqpwt4AAQTcdp5vnV5ozAfBgNVHSMEGDAWgBRhlyr/xXeqpwt4
AAQTcdp5vnV5ozAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAL
blOBPO+CC3/jWOOHhpA/7Puc2FZbUS7bTOZnoCjoYkAoQrZ8YVL+0oBO34ZIVbh3
lZuBAo00ryydV+D809lj8S79x4S43IX8ubr1fOnqVgdVQLMZ26c0FfMnkAkFuWUo
53jFL/mBeOH8A4JuQXiF5NVkeaFDM8E36OgpqDIPSwFJCkjhjGZKhVlH4RxaFO8k
BCUNOKp9OgN3M2wCGqVQEqRfq2M8jbYMvlWXhf6/7XtRSRMiuRa2xda/LjhLdzYr
88MIsMPcR3gkBSqxOabjez5dVGOtPMxyp2g4XNjSbPf5icGP/Ed+1NFwvkaztNts
IM15aJDB57nP4O+BfmLT
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoo0t5Cmt6sYiwbq/zIRauIWqErEBmbRIfVRqEeUM4kRFcu2E
RaWu2rRSrdOIaLEus+nc/UDpxfQxMam24x2mPcy98senz3PguL3PjZRvg/9TxAW1
liyCAbnCEekWRZ+UPKuq88Rx+OdByjjkuGZGcWMFIWxlK4KhNcfOogqmRtxoUCcq
SjhIxaYAUVniWchw6eUseuE8KWiUTfJrMWqIPhA5Enrs+UvtLh50w1QqxvylsE6V
3hbxWZp+BUMLd2yIYA7RYHjJDjiNj7aKYIF+NetQleTuXIFLbaf4Gdq86EUuM/M5
foL9oHU+wGbzdS71Xl3bjfKFQXVJuA6lzBBCXwIDAQABAoIBAH4QU4jhshmjtAze
0iTAeMMmFnIMiJs1sApSzzg1lTpdjCbHgY+qIONIed6JcP8QepHZSyO1lheJfCVx
435b3jOLd7yzjrdavOtJeY/pkFqkR8h8TQm8Vs8TyyisxjMUwZgT4q7OqT1JzEIS
wX8pAnSpQK9dK1EFLBVTcjNFYxMMXAMptSIH4hZmsgE9eIDKrFPD1YSDe8dmXdYn
O6fU+n3TcLe4XzePAaKJfPScn0mbhbQGZTaP1MGzdeJGkORJrfczO4ouuud+s4Dp
tNhui1r9FvgIh2jRLoNGCxC1GirtsU163iMsYC6lRdmRq3ROIn3j26q7Dl4Zj+CM
CTadnNECgYEAzmLpX+s0xEfk83DXfuA6NgOqWEBiKFnI1Bc39fCkwqxNaCCHY5wP
/nJayb5OrAgT49jSYArPgwGksXvWJ6SO3GQJjD4DVZqdXLmgjxuM2r8mvyh0hXqe
yOHKeSh4vwGQiXRQGM86KtmNLTZa7s2kzTk5msI9T3h8uhErqMPRBoUCgYEAyaCn
P9ctKUDa97PgPEHNbRVvDdj/y9IciUJ/vXSB3TVBcDudK8fsHRBtWZ1OU98UhTN3
cwR7tM+IUkPVsx+p/jiEOUVXnhyxfRhiVJdUlJZtR9q9cfjW6ysV4ta/VEgy0GQ6
iRt2THsbBKk0+3esDOfuyOWfoH+vm71Z6ITktJMCgYB6fihHHsFtscIIXrP4ALtr
7Zb/1A6uJkPU5Yb4OICBbmRu5ceVbj3r5hFOZd4pqo2rkLej+yaYebQ3BunfE4Ma
+WDVVMUD3MWDEEVkSpS6C/PCRw+JXXK6hZB3gnbP3uzbOCaF4xCB+Ccba4Ri8bjb
eRhgauKatUdJ5AEGpFn+RQKBgCxffc9P9LFqg4YWARhhxurl163tfsYFdKBEkUZJ
mLbtHHytsfZLpkvzLI2XUACnTKXP4M7gQrVVIwQvx50HL+sx1u+fshuq5ujH8AP7
1fJpdJ1mp2CoyeuxbLyiVDMhPIWeOT+pWoyUXyrUbkOVX7jrZiKyXkH9N9GHh3zj
mk2fAoGBALPGDVJ4643B3z3XUgjbfRDpgY4Lx7HDXW86WbYJuuzGu0g0zqtmow/h
baT502XGrVzmDxOZiC2sc1zJ+heTE0U/sw0d53Hmc0XAkN5j/LrX5tDEm/+p9I9N
kDy3S5DB14xqahm5XPB3S8vMSa1BtHw8OatJPX7SVU/NL46iDY2M
-----END RSA PRIVATE KEY-----
"""


class BaseMixin(ShouldFailMixin):

    def setUp(self):
        self.connections = []
        self.servers = []
        self.services = []

    def tearDown(self):
        for c in self.connections:
            if c.transport:
                c.transport.loseConnection()
        dl = []
        for s in self.servers:
            dl.append(defer.maybeDeferred(s.stopListening))
        for s in self.services:
            dl.append(defer.maybeDeferred(s.stopService))
        d = defer.DeferredList(dl)
        d.addCallback(flushEventualQueue)
        return d

    def stall(self, res, timeout):
        d = defer.Deferred()
        reactor.callLater(timeout, d.callback, res)
        return d

    def insert_turns(self, res, count):
        d = eventual.fireEventually(res)
        for i in range(count-1):
            d.addCallback(eventual.fireEventually)
        return d

    def makeServer(self, options={}, listenerOptions={}):
        self.tub = tub = Tub(_test_options=options)
        tub.startService()
        self.services.append(tub)
        portnum = allocate_tcp_port()
        tub.listenOn("tcp:%d:interface=127.0.0.1" % portnum,
                     _test_options=listenerOptions)
        tub.setLocation("127.0.0.1:%d" % portnum)
        self.target = Target()
        return tub.registerReference(self.target), portnum

    def makeSpecificServer(self, certData,
                           negotiationClass=negotiate.Negotiation):
        self.tub = tub = Tub(certData=certData)
        tub.negotiationClass = negotiationClass
        tub.startService()
        self.services.append(tub)
        portnum = allocate_tcp_port()
        tub.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        tub.setLocation("127.0.0.1:%d" % portnum)
        self.target = Target()
        return tub.registerReference(self.target), portnum

    def createSpecificServer(self, certData,
                             negotiationClass=negotiate.Negotiation):
        tub = Tub(certData=certData)
        tub.negotiationClass = negotiationClass
        tub.startService()
        self.services.append(tub)
        portnum = allocate_tcp_port()
        tub.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
        tub.setLocation("127.0.0.1:%d" % portnum)
        target = Target()
        return tub, target, tub.registerReference(target), portnum

    def makeNullServer(self):
        f = protocol.Factory()
        f.protocol = protocol.Protocol # discards everything
        s = internet.TCPServer(0, f)
        s.startService()
        self.services.append(s)
        portnum = s._port.getHost().port
        return portnum

    def makeHTTPServer(self):
        try:
            from twisted.web import server, resource, static
        except ImportError:
            raise unittest.SkipTest('this test needs twisted.web')
        root = resource.Resource()
        root.putChild(b"", static.Data("hello\n", "text/plain"))
        s = internet.TCPServer(0, server.Site(root))
        s.startService()
        self.services.append(s)
        portnum = s._port.getHost().port
        return portnum

    def connectClient(self, portnum):
        tub = Tub()
        tub.startService()
        self.services.append(tub)
        d = tub.getReference("pb://127.0.0.1:%d/hello" % portnum)
        return d

class MakeTubsMixin:
    def makeTubs(self, numTubs, mangleLocation=None, start=True):
        self.services = []
        self.tub_ports = []
        for i in range(numTubs):
            t = Tub()
            if start:
                t.startService()
            self.services.append(t)
            portnum = allocate_tcp_port()
            self.tub_ports.append(portnum)
            t.listenOn("tcp:%d:interface=127.0.0.1" % portnum)
            location = "tcp:127.0.0.1:%d" % portnum
            if mangleLocation:
                location = mangleLocation(portnum)
            t.setLocation(location)
        return self.services
