# -*- test-case-name: foolscap.test.test_sturdyref -*-

# this module is responsible for sending and receiving OnlyReferenceable and
# Referenceable (callable) objects. All details of actually invoking methods
# live in call.py

import weakref
from functools import total_ordering
import six
from zope.interface import interface
from zope.interface import implementer
from twisted.python.components import registerAdapter
Interface = interface.Interface
from twisted.internet import defer
from twisted.python import failure, log

from foolscap import ipb, slicer, tokens, call
BananaError = tokens.BananaError
Violation = tokens.Violation
from foolscap.constraint import IConstraint, ByteStringConstraint
from foolscap.remoteinterface import getRemoteInterface, \
     getRemoteInterfaceByName, RemoteInterfaceConstraint
from foolscap.schema import constraintMap
from foolscap.copyable import Copyable, RemoteCopy
from foolscap.eventual import eventually, fireEventually
from foolscap.furl import decode_furl

@implementer(ipb.IReferenceable)
class OnlyReferenceable(object):
    def processUniqueID(self):
        return id(self)

@implementer(ipb.IReferenceable, ipb.IRemotelyCallable)
class Referenceable(OnlyReferenceable):
    _interface = None
    _interfaceName = None

    # TODO: this code wants to be in an adapter, not a base class. Also, it
    # would be nice to cache this across the class: if every instance has the
    # same interfaces, they will have the same values of _interface and
    # _interfaceName, and it feels silly to store this data separately for
    # each instance. Perhaps we could compare the instance's interface list
    # with that of the class and only recompute this stuff if they differ.

    def getInterface(self):
        if not self._interface:
            self._interface = getRemoteInterface(self)
            if self._interface:
                self._interfaceName = self._interface.__remote_name__
            else:
                self._interfaceName = None
        return self._interface

    def getInterfaceName(self):
        self.getInterface()
        return self._interfaceName

    def doRemoteCall(self, methodname, args, kwargs):
        meth = getattr(self, "remote_%s" % methodname)
        res = meth(*args, **kwargs)
        return res

constraintMap[Referenceable] = RemoteInterfaceConstraint(None)

class ReferenceableTracker(object):
    """I hold the data which tracks a local Referenceable that is in used by
    a remote Broker.

    @ivar obj: the actual object
    @ivar refcount: the number of times this reference has been sent to the
                    remote end, minus the number of DECREF messages which it
                    has sent back. When it goes to zero, the remote end has
                    forgotten the RemoteReference, and is prepared to forget
                    the RemoteReferenceData as soon as the DECREF message is
                    acknowledged.
    @ivar clid: the connection-local ID used to represent this object on the
                wire.
    """

    def __init__(self, tub, obj, puid, clid):
        self.tub = tub
        self.obj = obj
        self.clid = clid
        self.puid = puid
        self.refcount = 0

    def send(self):
        """Increment the refcount.
        @return: True if this is the first transmission of the reference.
        """
        self.refcount += 1
        if self.refcount == 1:
            return True

    def getURL(self):
        if self.tub:
            return self.tub.getOrCreateURLForReference(self.obj)
        return None

    def decref(self, count):
        """Call this in response to a DECREF message from the other end.
        @return: True if the refcount went to zero, meaning this clid should
        be retired.
        """
        assert self.refcount >= count, "decref(%d) but refcount was %d" % (count, self.refcount)
        self.refcount -= count
        if self.refcount == 0:
            return True
        return False

# TODO: rather than subclassing Referenceable, ReferenceableSlicer should be
# registered to use for anything which provides any RemoteInterface

class ReferenceableSlicer(slicer.BaseSlicer):
    """I handle pb.Referenceable objects (things with remotely invokable
    methods, which are copied by reference).
    """
    opentype = ('my-reference',)

    def slice(self, streamable, protocol):
        broker = self.requireBroker(protocol)
        puid = ipb.IReferenceable(self.obj).processUniqueID()
        tracker = broker.getTrackerForMyReference(puid, self.obj)
        if broker.remote_broker:
            # emit a my-reference sequence
            yield b'my-reference'
            yield tracker.clid
            firstTime = tracker.send()
            if firstTime:
                # this is the first time the Referenceable has crossed this
                # wire. In addition to the clid, send the interface name (if
                # any), and any URL this reference might be known by
                iname = ipb.IRemotelyCallable(self.obj).getInterfaceName() or ""
                yield six.ensure_binary(iname)
                url = tracker.getURL()
                if url:
                    yield six.ensure_binary(url)
        else:
            # when we're serializing to data, rather than to a live
            # connection, all of my Referenceables are turned into
            # their-reference sequences, to prompt the eventual recipient to
            # create a new connection for this object.

            # a big note on object lifetimes: obviously, the data cannot keep
            # the Referenceable alive. Use tub.registerReference() on any
            # Referenceable that you want to include in the serialized data,
            # and take steps to make sure that later incarnations of this Tub
            # will do the same.
            yield b'their-reference'
            yield 0 # giftID==0 tells the recipient to not try to ack it
            yield six.ensure_binary(tracker.getURL())


registerAdapter(ReferenceableSlicer, Referenceable, ipb.ISlicer)

class CallableSlicer(slicer.BaseSlicer):
    """Bound methods are serialized as my-reference sequences with negative
    clid values."""
    opentype = ('my-reference',)

    def sliceBody(self, streamable, protocol):
        broker = self.requireBroker(protocol)
        # TODO: consider this requirement, maybe based upon a Tub flag
        # assert ipb.ISlicer(self.obj.im_self)
        # or maybe even isinstance(self.obj.im_self, Referenceable)
        puid = id(self.obj)
        tracker = broker.getTrackerForMyCall(puid, self.obj)
        yield tracker.clid
        firstTime = tracker.send()
        if firstTime:
            # this is the first time the Call has crossed this wire. In
            # addition to the clid, send the schema name and any URL this
            # reference might be known by
            schema = self.getSchema() or ""
            yield six.ensure_binary(schema)
            url = tracker.getURL()
            if url:
                yield six.ensure_binary(url)

    def getSchema(self):
        return None # TODO: not quite ready yet
        # callables which are actually bound methods of a pb.Referenceable
        # can use the schema from that
        s = ipb.IReferenceable(self.obj.im_self, None)
        if s:
            return s.getSchemaForMethodNamed(self.obj.im_func.__name__)
        # both bound methods and raw callables can also use a .schema
        # attribute
        return getattr(self.obj, "schema", None)


# The CallableSlicer is activated through PBRootSlicer.slicerTable, because a
# StorageBanana might want to stick with the old MethodSlicer/FunctionSlicer
# for these types
#registerAdapter(CallableSlicer, types.MethodType, ipb.ISlicer)


class ReferenceUnslicer(slicer.BaseUnslicer):
    """I turn an incoming 'my-reference' sequence into a RemoteReference or a
    RemoteMethodReference."""
    state = 0
    clid = None
    interfaceName = None
    url = None
    inameConstraint = ByteStringConstraint() # TODO: only known RI names?
    urlConstraint = ByteStringConstraint()

    def checkToken(self, typebyte, size):
        if self.state == 0:
            if typebyte not in (tokens.INT, tokens.NEG):
                raise BananaError("reference ID must be an INT or NEG")
        elif self.state == 1:
            self.inameConstraint.checkToken(typebyte, size)
        elif self.state == 2:
            self.urlConstraint.checkToken(typebyte, size)
        else:
            raise Violation("too many parameters in my-reference")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, defer.Deferred)
        assert ready_deferred is None
        if self.state == 0:
            self.clid = obj
            self.state = 1
        elif self.state == 1:
            # must be the interface name
            self.interfaceName = six.ensure_str(obj) or None
            self.state = 2
        elif self.state == 2:
            # URL
            self.url = six.ensure_str(obj)
            self.state = 3
        else:
            raise BananaError("Too many my-reference parameters")

    def receiveClose(self):
        if self.clid is None:
            raise BananaError("sequence ended too early")
        tracker = self.broker.getTrackerForYourReference(self.clid,
                                                         self.interfaceName,
                                                         self.url)
        return tracker.getRef(), None

    def describe(self):
        if self.clid is None:
            return "<ref-?>"
        return "<ref-%s>" % self.clid



class RemoteReferenceTracker(object):
    """I hold the data necessary to locate (or create) a RemoteReference.

    @ivar url: the target Referenceable's global URL
    @ivar broker: the Broker which holds this RemoteReference
    @ivar clid: for that Broker, the your-reference CLID for the
                RemoteReference
    @ivar interfaceName: the name of a RemoteInterface object that the
                         RemoteReference claims to implement
    @ivar interface: our version of a RemoteInterface object that corresponds
                     to interfaceName
    @ivar received_count: the number of times the remote end has send us this
                          object. We must send back decref() calls to match.
    @ivar ref: a weakref to the RemoteReference itself
    """

    def __init__(self, parent, clid, url, interfaceName):
        self.broker = parent
        self.clid = clid
        # TODO: the remote end sends us a global URL, when really it should
        # probably send us a per-Tub name, which can can then concatenate to
        # their TubID if/when we pass it on to others. By accepting a full
        # URL, we give them the ability to sort-of spoof others. For now, we
        # check that their URL uses the same tubid as our broker is
        # expecting, but the Right Way is to just not have them send the base
        # part in the first place. I haven't yet made this change because I'm
        # not yet positive it would work.. how exactly does the base url get
        # sent, anyway? What about Tubs visible through multiple names?
        self.url = url
        if url is not None:
            # unit tests frequently set url=None
            assert self.broker.remote_tubref
            expected_tubid = self.broker.remote_tubref.getTubID()
            url_tubid = SturdyRef(url).getTubRef().getTubID()
            if expected_tubid != url_tubid:
                raise BananaError("inbound reference claims bad tubid, %s vs %s"
                                  % (expected_tubid, url_tubid))
        self.interfaceName = interfaceName
        self.interface = getRemoteInterfaceByName(interfaceName)
        self.received_count = 0
        self.ref = None

    def __repr__(self):
        s = "<RemoteReferenceTracker(clid=%d,url=%s)>" % (self.clid, self.url)
        return s

    def getURL(self):
        return self.url

    def getRef(self):
        """Return the actual RemoteReference that we hold, creating it if
        necessary. This is called when we receive a my-reference sequence
        from the remote end, so we must increment our received_count."""
        # self.ref might be None (if we haven't created it yet), or it might
        # be a dead weakref (if it has been released but our _handleRefLost
        # hasn't fired yet). In either case we need to make a new
        # RemoteReference.
        if self.ref is None or self.ref() is None:
            ref = RemoteReference(self)
            self.ref = weakref.ref(ref, self._refLost)
        self.received_count += 1
        return self.ref()

    def _refLost(self, wref):
        # don't do anything right now, we could be in the middle of all sorts
        # of weird code. both __del__ and weakref callbacks can fire at any
        # time. Almost as bad as threads..

        # instead, do stuff later.
        eventually(self._handleRefLost)

    def _handleRefLost(self):
        if self.ref is None or self.ref() is None:
            count, self.received_count = self.received_count, 0
            if count == 0:
                return
            self.broker.freeYourReference(self, count)
        # otherwise our RemoteReference is actually still alive, resurrected
        # between the call to _refLost and the eventual call to
        # _handleRefLost. In this case, don't decref anything.


@implementer(ipb.IRemoteReference)
class RemoteReferenceOnly(object):
    def __init__(self, tracker):
        """@param tracker: the RemoteReferenceTracker which points to us"""
        self.tracker = tracker

    def getSturdyRef(self):
        return SturdyRef(self.tracker.getURL())
    def getRemoteTubID(self):
        rt = self.tracker.broker.remote_tubref
        assert rt
        return rt.getTubID()

    def getPeer(self):
        """Return an IAddress-providing object that describes the remote
        peer. If we've connected to ourselves, this will be a
        foolscap.broker.LoopbackAddress instance. If we've connected to
        someone else, this will be a twisted.internet.address.IPv4Address
        instance, with .host and .port attributes."""
        transport = self.tracker.broker.transport
        return transport.getPeer()

    def isConnected(self):
        """Return False if this reference is known to be dead."""
        return not self.tracker.broker.disconnected
    def getLocationHints(self):
        return SturdyRef(self.tracker.url).locationHints
    def getConnectionInfo(self):
        return self.tracker.broker.getConnectionInfo()

    def getDataLastReceivedAt(self):
        """If keepalives are enabled, this returns seconds-since-epoch when
        we last received any data from the remote side. This is
        connection-wide, not specific to this particular object. If
        keepalives are disabled (the default), it returns None."""
        return self.tracker.broker.getDataLastReceivedAt()

    def notifyOnDisconnect(self, callback, *args, **kwargs):
        """Register a callback to run when we lose this connection.

        The callback will be invoked with whatever extra arguments you
        provide to this function. For example::

         def my_callback(name, number):
             print name, number+4
         cookie = rref.notifyOnDisconnect(my_callback, 'bob', number=3)

        This function returns an opaque cookie. If you want to cancel the
        notification, pass this same cookie back to dontNotifyOnDisconnect::

         rref.dontNotifyOnDisconnect(cookie)

        Note that if the Tub is shutdown (via stopService), all
        notifyOnDisconnect handlers are cancelled.
        """

        # return a cookie (really the (cb,args,kwargs) tuple) that they must
        # use to deregister
        marker = self.tracker.broker.notifyOnDisconnect(callback,
                                                        *args, **kwargs)
        return marker
    def dontNotifyOnDisconnect(self, marker):
        self.tracker.broker.dontNotifyOnDisconnect(marker)

    def __repr__(self):
        r = "<%s at 0x%x" % (self.__class__.__name__, abs(id(self)))
        if self.tracker.url:
            r += " [%s]" % self.tracker.url
        r += ">"
        return r

class RemoteReference(RemoteReferenceOnly):
    def callRemote(self, _name, *args, **kwargs):
        # Note: for consistency, *all* failures are reported asynchronously.
        return defer.maybeDeferred(self._callRemote, _name, False,
                                   args, kwargs)

    def callRemoteOnly(self, _name, *args, **kwargs):
        # the remote end will not send us a response. The only error cases
        # are arguments that don't match the schema, or broken invariants. In
        # particular, DeadReferenceError will be silently consumed.
        d = defer.maybeDeferred(self._callRemote, _name, True,
                                args, kwargs)
        del d
        return None

    def _callRemote(self, _name, callOnly, args, kwargs):
        req = None
        broker = self.tracker.broker
        _name = six.ensure_str(_name)

        # remember that "none" is not a valid constraint, so we use it to
        # mean "not set by the caller", which means we fall back to whatever
        # the RemoteInterface says. Using None would mean an AnyConstraint,
        # which is not the same thing.
        methodConstraintOverride = kwargs.get("_methodConstraint", "none")
        resultConstraint = kwargs.get("_resultConstraint", "none")
        useSchema = kwargs.get("_useSchema", True)

        if "_methodConstraint" in kwargs:
            del kwargs["_methodConstraint"]
        if "_resultConstraint" in kwargs:
            del kwargs["_resultConstraint"]
        if "_useSchema" in kwargs:
            del kwargs["_useSchema"]

        if callOnly:
            if broker.disconnected:
                # DeadReferenceError is silently consumed
                return
            reqID = 0
        else:
            # newRequestID() could fail with a DeadReferenceError
            reqID = broker.newRequestID()

        # in this section, we validate the outbound arguments against our
        # notion of what the other end will accept (the RemoteInterface)

        # first, figure out which method they want to invoke
        (interfaceName,
         methodName,
         methodSchema) = self._getMethodInfo(_name)
        methodName = six.ensure_str(methodName)

        req = call.PendingRequest(reqID, self, interfaceName, methodName)
        # TODO: consider adding a stringified stack trace to that
        # PendingRequest creation, so that DeadReferenceError can emit even
        # more information about the call which failed

        # for debugging: these are put into the messages emitted when
        # logRemoteFailures is turned on
        req.interfaceName = interfaceName
        req.methodName = methodName

        if methodConstraintOverride != "none":
            methodSchema = methodConstraintOverride

        if useSchema and methodSchema:
            # check args against the arg constraint. This could fail if
            # any arguments are of the wrong type
            try:
                methodSchema.checkAllArgs(args, kwargs, False)
            except Violation as v:
                v.setLocation("%s.%s(%s)" % (interfaceName, methodName,
                                             v.getLocation()))
                raise

            # the Interface gets to constraint the return value too, so
            # make a note of it to use later
            req.setConstraint(methodSchema.getResponseConstraint())

        # if the caller specified a _resultConstraint, that overrides
        # the schema's one
        if resultConstraint != "none":
            # overrides schema
            req.setConstraint(IConstraint(resultConstraint))

        clid = self.tracker.clid
        slicer = call.CallSlicer(reqID, clid, methodName, args, kwargs)

        # up to this point, we are not committed to sending anything to the
        # far end. The various phases of commitment are:

        #  1: once we tell our broker about the PendingRequest, we must
        #  promise to retire it eventually. Specifically, if we encounter an
        #  error before we give responsibility to the connection, we must
        #  retire it ourselves.

        #  2: once we start sending the CallSlicer to the other end (in
        #  particular, once they receive the reqID), they might send us a
        #  response, so we must be prepared to handle that. Giving the
        #  PendingRequest to the broker arranges for this to happen.

        # So all failures which occur before these commitment events are
        # entirely local: stale broker, bad method name, bad arguments. If
        # anything raises an exception before this point, the PendingRequest
        # is abandoned, and our maybeDeferred wrapper returns a failing
        # Deferred.

        # commitment point 1. We assume that if this call raises an
        # exception, the broker will be sure to not track the dead
        # PendingRequest
        if not callOnly:
            broker.addRequest(req)
            # if callOnly, the PendingRequest will never know about the
            # broker, and will therefore never ask to be removed from it

        # TODO: there is a decidability problem here: if the reqID made
        # it through, the other end will send us an answer (possibly an
        # error if the remaining slices were aborted). If not, we will
        # not get an answer. To decide whether we should remove our
        # broker.waitingForAnswers[] entry, we need to know how far the
        # slicing process made it.

        try:
            # commitment point 2
            d = broker.send(slicer)
            # d will fire when the last argument has been serialized. It will
            # errback if the arguments (or any of their children) could not
            # be serialized. We need to catch this case and errback the
            # caller.

            # if we got here, we have been able to start serializing the
            # arguments. If serialization fails, the PendingRequest needs to
            # be flunked (because we aren't guaranteed that the far end will
            # do it).

            d.addErrback(req.fail)

        except:
            req.fail(failure.Failure())

        # the remote end could send back an error response for many reasons:
        #  bad method name
        #  bad argument types (violated their schema)
        #  exception during method execution
        #  method result violated the results schema
        # something else could occur to cause an errback:
        #  connection lost before response completely received
        #  exception during deserialization of the response
        #   [but only if it occurs after the reqID is received]
        #  method result violated our results schema
        # if none of those occurred, the callback will be run

        return req.deferred

    def _getMethodInfo(self, name):
        assert type(name) is str
        interfaceName = None
        methodName = name
        methodSchema = None

        iface = self.tracker.interface
        if iface:
            interfaceName = iface.__remote_name__
            try:
                methodSchema = iface[name]
            except KeyError:
                raise Violation("%s(%s) does not offer %s" % \
                                (interfaceName, self, name))
        return interfaceName, methodName, methodSchema


class RemoteMethodReferenceTracker(RemoteReferenceTracker):
    def getRef(self):
        if self.ref is None:
            ref = RemoteMethodReference(self)
            self.ref = weakref.ref(ref, self._refLost)
        self.received_count += 1
        return self.ref()

class RemoteMethodReference(RemoteReference):
    def callRemote(self, *args, **kwargs):
        # TODO: I suspect it would safer to use something other than
        # 'callRemote' here.
        # TODO: this probably needs a very different implementation

        # there is no schema support yet, so we can't convert positional args
        # into keyword args
        assert args == ()
        return RemoteReference.callRemote(self, "", *args, **kwargs)

    def _getMethodInfo(self, name):
        interfaceName = None
        methodName = ""
        methodSchema = None
        return interfaceName, methodName, methodSchema

@implementer(ipb.IRemoteReference)
class LocalReferenceable(object):
    def __init__(self, original):
        self.original = original

    def notifyOnDisconnect(self, callback, *args, **kwargs):
        # local objects never disconnect
        return None
    def dontNotifyOnDisconnect(self, marker):
        pass

    def callRemote(self, methname, *args, **kwargs):
        def _try(ignored):
            meth = getattr(self.original, "remote_" + methname)
            return meth(*args, **kwargs)
        d = fireEventually()
        d.addCallback(_try)
        return d

    def callRemoteOnly(self, methname, *args, **kwargs):
        d = self.callRemote(methname, *args, **kwargs)
        d.addErrback(lambda f: None)
        return None

registerAdapter(LocalReferenceable, ipb.IReferenceable, ipb.IRemoteReference)



class YourReferenceSlicer(slicer.BaseSlicer):
    """I handle pb.RemoteReference objects (being sent back home to the
    original pb.Referenceable-holder)
    """

    def slice(self, streamable, protocol):
        broker = self.requireBroker(protocol)
        self.streamable = streamable
        tracker = self.obj.tracker
        if tracker.broker == broker:
            # sending back to home broker
            yield b'your-reference'
            yield tracker.clid
        else:
            # sending somewhere else
            furl = tracker.getURL()
            if furl is None:
                log.msg("gift has no FURL, host Tub is unreachable, sending ''")
                furl = ""
            assert isinstance(furl, str)
            giftID = broker.makeGift(self.obj)
            yield b'their-reference'
            yield giftID
            yield six.ensure_binary(furl)

    def describe(self):
        return "<your-ref-%s>" % self.obj.tracker.clid

registerAdapter(YourReferenceSlicer, RemoteReference, ipb.ISlicer)

class YourReferenceUnslicer(slicer.LeafUnslicer):
    """I accept incoming (integer) your-reference sequences and try to turn
    them back into the original Referenceable. I also accept (string)
    your-reference sequences and try to turn them into a published
    Referenceable that they did not have access to before."""
    clid = None

    def checkToken(self, typebyte, size):
        if typebyte != tokens.INT:
            raise BananaError("your-reference ID must be an INT")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, defer.Deferred)
        assert ready_deferred is None
        self.clid = obj

    def receiveClose(self):
        if self.clid is None:
            raise BananaError("sequence ended too early")
        obj = self.broker.getMyReferenceByCLID(self.clid)
        if not obj:
            raise Violation("unknown clid '%s'" % self.clid)
        return obj, None

    def describe(self):
        return "<your-ref-%s>" % self.obj.refID


class TheirReferenceUnslicer(slicer.LeafUnslicer):
    """I accept gifts of third-party references. This is turned into a live
    reference upon receipt."""
    # (their-reference, giftID, URL)
    state = 0
    giftID = None
    url = None
    urlConstraint = ByteStringConstraint()

    def checkToken(self, typebyte, size):
        if self.state == 0:
            if typebyte != tokens.INT:
                raise BananaError("their-reference giftID must be an INT")
        elif self.state == 1:
            self.urlConstraint.checkToken(typebyte, size)
        else:
            raise Violation("too many parameters in their-reference")

    def receiveChild(self, obj, ready_deferred=None):
        assert not isinstance(obj, defer.Deferred)
        assert ready_deferred is None
        if self.state == 0:
            self.giftID = obj
            self.state = 1
        elif self.state == 1:
            # URL
            self.url = six.ensure_str(obj)
            self.state = 2
        else:
            raise BananaError("Too many their-reference parameters")

    def receiveClose(self):
        if self.giftID is None or self.url is None:
            raise BananaError("sequence ended too early")
        if self.broker.tub.accept_gifts:
            d = self.broker.tub.getReference(self.url)
            d.addBoth(self.ackGift)
        else:
            d = defer.fail(Violation("gifts are prohibited in this Tub"))

        # we return a Deferred that will fire with the RemoteReference when
        # it becomes available. The RemoteReference is not even referenceable
        # until then. In addition, we provide a ready_deferred, since any
        # mutable container which holds the gift will be referenceable early
        # but the message delivery must still wait for the getReference to
        # complete. See to it that we fire the object deferred before we fire
        # the ready_deferred.

        obj_deferred = defer.Deferred()
        ready_deferred = defer.Deferred()

        def _ready(rref):
            obj_deferred.callback(rref)
            ready_deferred.callback(rref)
        def _failed(f):
            # if an error in getReference() occurs, log it locally (with
            # priority UNUSUAL), because this end might need to diagnose some
            # connection or networking problems.
            log.msg("gift (%s) failed to resolve: %s" % (self.url, f))
            # deliver a placeholder object to the container, but signal the
            # ready_deferred that we've failed. This will bubble up to the
            # enclosing InboundDelivery, and when it gets to the top of the
            # queue, it will be flunked.
            obj_deferred.callback("Place holder for a Gift which failed to "
                                  "resolve: %s" % f)
            ready_deferred.errback(f)
        d.addCallbacks(_ready, _failed)

        return obj_deferred, ready_deferred

    def ackGift(self, rref):
        # giftID==0 means they aren't doing reference counting
        if self.giftID != 0:
            rb = self.broker.remote_broker
            # if we lose the connection, they'll decref the gift anyway
            rb.callRemoteOnly("decgift", giftID=self.giftID, count=1)
        return rref

    def describe(self):
        if self.giftID is None:
            return "<gift-?>"
        return "<gift-%s>" % self.giftID


@total_ordering
class SturdyRef(Copyable, RemoteCopy):
    """I am a pointer to a Referenceable that lives in some (probably remote)
    Tub. This pointer is long-lived, however you cannot send messages with it
    directly. To use it, you must ask your Tub to turn it into a
    RemoteReference with tub.getReference(sturdyref).

    The SturdyRef is associated with a URL: you can create a SturdyRef out of
    a URL that you obtain from some other source, and you can ask the
    SturdyRef for its URL.

    SturdyRefs are serialized by copying their URL, and create an identical
    SturdyRef on the receiving side."""

    typeToCopy = copytype = "foolscap.SturdyRef"

    tubID = None
    name = None

    def __init__(self, url=None):
        self.locationHints = [] # list of strings
        self.url = url
        if url:
            self.url = six.ensure_str(self.url)
            self.tubID, self.locationHints, self.name = decode_furl(url)

    def getTubRef(self):
        return TubRef(self.tubID, self.locationHints)


    def getURL(self):
        return self.url

    def __str__(self):
        return str(self.url)

    def _distinguishers(self):
        """Two SturdyRefs are equivalent if they point to the same object.
        SturdyRefs pay attention only to the TubID and the reference name.
        This method makes it easier to compare a pair of SturdyRefs."""
        return (True, self.tubID, self.name)

    def __hash__(self):
        return hash(self._distinguishers())

    def __lt__(self, them):
        return self._distinguishers() < them._distinguishers()
    def __eq__(self, them):
        return (type(self) is type(them) and
                self.__class__ == them.__class__ and
                self._distinguishers() == them._distinguishers())
    def __ne__(self, them):
        return not self == them

@total_ordering
class TubRef(object):
    """This is a little helper class which provides a comparable identifier
    for Tubs. TubRefs can be used as keys in dictionaries that track
    connections to remote Tubs."""

    def __init__(self, tubID, locationHints=None):
        if locationHints is None:
            locationHints = []
        assert isinstance(locationHints, list), locationHints
        assert all([isinstance(hint, str) for hint in locationHints]), \
               locationHints
        self.tubID = tubID and six.ensure_str(tubID)
        self.locationHints = locationHints

    def getLocations(self):
        return self.locationHints

    def getTubID(self):
        return self.tubID
    def getShortTubID(self):
        return self.tubID[:4]

    def __str__(self):
        return "pb://" + self.tubID

    def _distinguishers(self):
        """This serves the same purpose as SturdyRef._distinguishers."""
        return (self.tubID,)

    def __hash__(self):
        return hash(self._distinguishers())

    def __lt__(self, them):
        return self._distinguishers() < them._distinguishers()
    def __eq__(self, them):
        return (type(self) is type(them) and
                self.__class__ == them.__class__ and
                self._distinguishers() == them._distinguishers())
    def __ne__(self, them):
        return not self == them
