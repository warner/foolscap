
from twisted.python import failure, reflect
from twisted.internet import defer

from foolscap import copyable, slicer, tokens
from foolscap.copyable import AttributeDictConstraint
from foolscap.constraint import ByteStringConstraint
from foolscap.slicers.list import ListConstraint
from tokens import BananaError, Violation
from foolscap.util import AsyncAND
from foolscap.logging import log

def wrap_remote_failure(f):
    return failure.Failure(tokens.RemoteException(f))

class FailureConstraint(AttributeDictConstraint):
    opentypes = [("copyable", "twisted.python.failure.Failure")]
    name = "FailureConstraint"
    klass = failure.Failure

    def __init__(self):
        attrs = [('type', ByteStringConstraint(200)),
                 ('value', ByteStringConstraint(1000)),
                 ('traceback', ByteStringConstraint(2000)),
                 ('parents', ListConstraint(ByteStringConstraint(200))),
                 ]
        AttributeDictConstraint.__init__(self, *attrs)

    def checkObject(self, obj, inbound):
        if not isinstance(obj, self.klass):
            raise Violation("is not an instance of %s" % self.klass)


class PendingRequest(object):
    # this object is a local representation of a message we have sent to
    # someone else, that will be executed on their end.
    active = True

    def __init__(self, reqID, rref, interface_name, method_name):
        self.reqID = reqID
        self.rref = rref # keep it alive
        self.broker = None # if set, the broker knows about us
        self.deferred = defer.Deferred()
        self.constraint = None # this constrains the results
        self.failure = None
        self.interface_name = interface_name # for error messages
        self.method_name = method_name # same

    def setConstraint(self, constraint):
        self.constraint = constraint

    def getMethodNameInfo(self):
        return (self.interface_name, self.method_name)

    def complete(self, res):
        if self.broker:
            self.broker.removeRequest(self)
        if self.active:
            self.active = False
            self.deferred.callback(res)
        else:
            log.msg("PendingRequest.complete called on an inactive request")

    def fail(self, why):
        if self.active:
            if self.broker:
                self.broker.removeRequest(self)
            self.active = False
            self.failure = why
            if (self.broker and
                self.broker.tub and
                self.broker.tub.logRemoteFailures):

                my_short_tubid = "??"
                if self.broker.tub: # for tests
                    my_short_tubid = self.broker.tub.getShortTubID()
                their_short_tubid = self.broker.remote_tubref.getShortTubID()

                lp = log.msg("an outbound callRemote (that we [%s] sent to "
                             "someone else [%s]) failed on the far end"
                             % (my_short_tubid, their_short_tubid),
                             level=log.UNUSUAL)
                methname = ".".join([self.interfaceName or "?",
                                     self.methodName or "?"])
                log.msg(" reqID=%d, rref=%s, methname=%s"
                        % (self.reqID, self.rref, methname),
                        level=log.NOISY, parent=lp)
                #stack = why.getTraceback()
                # TODO: include the first few letters of the remote tubID in
                # this REMOTE tag
                #stack = "REMOTE: " + stack.replace("\n", "\nREMOTE: ")
                log.msg(" the REMOTE failure was:", failure=why,
                        level=log.NOISY, parent=lp)
                #log.msg(stack, level=log.NOISY, parent=lp)
            self.deferred.errback(why)
        else:
            log.msg("WEIRD: fail() on an inactive request", traceback=True)
            if self.failure:
                log.msg("multiple failures")
                log.msg("first one was:", self.failure)
                log.msg("this one was:", why)
                log.err("multiple failures indicate a problem")

class ArgumentSlicer(slicer.ScopedSlicer):
    opentype = ('arguments',)

    def __init__(self, args, kwargs, methodname="?"):
        slicer.ScopedSlicer.__init__(self, None)
        self.args = args
        self.kwargs = kwargs
        self.which = ""
        self.methodname = methodname

    def sliceBody(self, streamable, banana):
        yield len(self.args)
        for i,arg in enumerate(self.args):
            self.which = "arg[%d]-of-%s" % (i, self.methodname)
            yield arg
        keys = self.kwargs.keys()
        keys.sort()
        for argname in keys:
            self.which = "arg[%s]-of-%s" % (argname, self.methodname)
            yield argname
            yield self.kwargs[argname]

    def describe(self):
        return "<%s>" % self.which


class CallSlicer(slicer.ScopedSlicer):
    opentype = ('call',)

    def __init__(self, reqID, clid, methodname, args, kwargs):
        slicer.ScopedSlicer.__init__(self, None)
        self.reqID = reqID
        self.clid = clid
        self.methodname = methodname
        self.args = args
        self.kwargs = kwargs

    def sliceBody(self, streamable, banana):
        yield self.reqID
        yield self.clid
        yield self.methodname
        yield ArgumentSlicer(self.args, self.kwargs, self.methodname)

    def describe(self):
        return "<call-%s-%s-%s>" % (self.reqID, self.clid, self.methodname)

class InboundDelivery(object):
    """An inbound message that has not yet been delivered.

    This is created when a 'call' sequence has finished being received. The
    Broker will add it to a queue. The delivery at the head of the queue is
    serviced when all of its arguments have been resolved.

    The only way that the arguments might not all be available is if one of
    the Unslicers which created them has provided a 'ready_deferred' along
    with the prospective object. The only standard Unslicer which does this
    is the TheirReferenceUnslicer, which handles introductions. (custom
    Unslicers might also provide a ready_deferred, for example a URL
    slicer/unslicer pair for which the receiving end fetches the target of
    the URL as its value, or a UnixFD slicer/unslicer that had to wait for a
    side-channel unix-domain socket to finish transferring control over the
    FD to the recipient before being ready).

    Most Unslicers refuse to accept unready objects as their children (most
    implementations of receiveChild() do 'assert ready_deferred is None').
    The CallUnslicer is fairly unique in not rejecting such objects.

    We do require, however, that all of the arguments be at least
    referenceable. This is not generally a problem: the only time an
    unslicer's receiveChild() can get a non-referenceable object (represented
    by a Deferred) is if that unslicer is participating in a reference cycle
    that has not yet completed, and CallUnslicers only live at the top level,
    above any cycles.
    """

    def __init__(self, broker, reqID, obj,
                 interface, methodname, methodSchema,
                 allargs):
        self.broker = broker
        self.reqID = reqID
        self.obj = obj
        self.interface = interface
        self.methodname = methodname
        self.methodSchema = methodSchema
        self.allargs = allargs

    def logFailure(self, f):
        # called if tub.logLocalFailures is True
        my_short_tubid = "??"
        if self.broker.tub: # for tests
            my_short_tubid = self.broker.tub.getShortTubID()
        their_short_tubid = "<unauth>"
        if self.broker.remote_tubref:
            their_short_tubid = self.broker.remote_tubref.getShortTubID()
        lp = log.msg("an inbound callRemote that we [%s] executed (on behalf "
                     "of someone else, TubID %s) failed"
                     % (my_short_tubid, their_short_tubid),
                     level=log.UNUSUAL)
        if self.interface:
            methname = self.interface.getName() + "." + self.methodname
        else:
            methname = self.methodname
        log.msg(" reqID=%d, rref=%s, methname=%s" %
                (self.reqID, self.obj, methname),
                level=log.NOISY, parent=lp)
        log.msg(" args=%s" % (self.allargs.args,), level=log.NOISY, parent=lp)
        log.msg(" kwargs=%s" % (self.allargs.kwargs,),
                level=log.NOISY, parent=lp)
        #if isinstance(f.type, str):
        #    stack = "getTraceback() not available for string exceptions\n"
        #else:
        #    stack = f.getTraceback()
        # TODO: trim stack to everything below Broker._doCall
        #stack = "LOCAL: " + stack.replace("\n", "\nLOCAL: ")
        log.msg(" the LOCAL failure was:", failure=f,
                level=log.NOISY, parent=lp)
        #log.msg(stack, level=log.NOISY, parent=lp)

class ArgumentUnslicer(slicer.ScopedUnslicer):
    methodSchema = None
    debug = False

    def setConstraint(self, methodSchema):
        self.methodSchema = methodSchema

    def start(self, count):
        if self.debug:
            log.msg("%s.start: %s" % (self, count))
        self.numargs = None
        self.args = []
        self.kwargs = {}
        self.argname = None
        self.argConstraint = None
        self.num_unreferenceable_children = 0
        self._all_children_are_referenceable_d = None
        self._ready_deferreds = []
        self.closed = False

    def checkToken(self, typebyte, size):
        if self.numargs is None:
            # waiting for positional-arg count
            if typebyte != tokens.INT:
                raise BananaError("posarg count must be an INT")
            return
        if len(self.args) < self.numargs:
            # waiting for a positional arg
            if self.argConstraint:
                self.argConstraint.checkToken(typebyte, size)
            return
        if self.argname is None:
            # waiting for the name of a keyword arg
            if typebyte not in (tokens.STRING, tokens.VOCAB):
                raise BananaError("kwarg name must be a STRING")
            # TODO: limit to longest argument name of the method?
            return
        # waiting for the value of a kwarg
        if self.argConstraint:
            self.argConstraint.checkToken(typebyte, size)

    def doOpen(self, opentype):
        if self.argConstraint:
            self.argConstraint.checkOpentype(opentype)
        unslicer = self.open(opentype)
        if unslicer:
            if self.argConstraint:
                unslicer.setConstraint(self.argConstraint)
        return unslicer

    def receiveChild(self, token, ready_deferred=None):
        if self.debug:
            log.msg("%s.receiveChild: %s %s %s %s %s args=%s kwargs=%s" %
                    (self, self.closed, self.num_unreferenceable_children,
                     len(self._ready_deferreds), token, ready_deferred,
                     self.args, self.kwargs))
        if self.numargs is None:
            # this token is the number of positional arguments
            assert isinstance(token, int)
            assert ready_deferred is None
            self.numargs = token
            if self.numargs:
                ms = self.methodSchema
                if ms:
                    accept, self.argConstraint = \
                            ms.getPositionalArgConstraint(0)
                    assert accept
            return

        if len(self.args) < self.numargs:
            # this token is a positional argument
            argvalue = token
            argpos = len(self.args)
            self.args.append(argvalue)
            if isinstance(argvalue, defer.Deferred):
                # this may occur if the child is a gift which has not
                # resolved yet.
                self.num_unreferenceable_children += 1
                argvalue.addCallback(self.updateChild, argpos)
            if ready_deferred:
                if self.debug:
                    log.msg("%s.receiveChild got an unready posarg" % self)
                self._ready_deferreds.append(ready_deferred)
            if len(self.args) < self.numargs:
                # more to come
                ms = self.methodSchema
                if ms:
                    nextargnum = len(self.args)
                    accept, self.argConstraint = \
                            ms.getPositionalArgConstraint(nextargnum)
                    assert accept
            return

        if self.argname is None:
            # this token is the name of a keyword argument
            assert ready_deferred is None
            self.argname = token
            # if the argname is invalid, this may raise Violation
            ms = self.methodSchema
            if ms:
                accept, self.argConstraint = \
                        ms.getKeywordArgConstraint(self.argname,
                                                   self.numargs,
                                                   self.kwargs.keys())
                assert accept
            return

        # this token is the value of a keyword argument
        argvalue = token
        self.kwargs[self.argname] = argvalue
        if isinstance(argvalue, defer.Deferred):
            self.num_unreferenceable_children += 1
            argvalue.addCallback(self.updateChild, self.argname)
        if ready_deferred:
            if self.debug:
                log.msg("%s.receiveChild got an unready kwarg" % self)
            self._ready_deferreds.append(ready_deferred)
        self.argname = None
        return

    def updateChild(self, obj, which):
        # one of our arguments has just now become referenceable. Normal
        # types can't trigger this (since the arguments to a method form a
        # top-level serialization domain), but special Unslicers might. For
        # example, the Gift unslicer will eventually provide us with a
        # RemoteReference, but for now all we get is a Deferred as a
        # placeholder.

        if self.debug:
            log.msg("%s.updateChild, [%s] became referenceable: %s" %
                    (self, which, obj))
        if isinstance(which, int):
            self.args[which] = obj
        else:
            self.kwargs[which] = obj
        self.num_unreferenceable_children -= 1
        if self.num_unreferenceable_children == 0:
            if self._all_children_are_referenceable_d:
                self._all_children_are_referenceable_d.callback(None)
        return obj


    def receiveClose(self):
        if self.debug:
            log.msg("%s.receiveClose: %s %s %s" %
                    (self, self.closed, self.num_unreferenceable_children,
                     len(self._ready_deferreds)))
        if (self.numargs is None or
            len(self.args) < self.numargs or
            self.argname is not None):
            raise BananaError("'arguments' sequence ended too early")
        self.closed = True
        dl = []
        if self.num_unreferenceable_children:
            d = self._all_children_are_referenceable_d = defer.Deferred()
            dl.append(d)
        dl.extend(self._ready_deferreds)
        ready_deferred = None
        if dl:
            ready_deferred = AsyncAND(dl)
        return self, ready_deferred

    def describe(self):
        s = "<arguments"
        if self.numargs is not None:
            if len(self.args) < self.numargs:
                s += " arg[%d]" % len(self.args)
            else:
                if self.argname is not None:
                    s += " arg[%s]" % self.argname
                else:
                    s += " arg[?]"
        if self.closed:
            s += " closed"
            # TODO: it would be nice to indicate if we still have unready
            # children
        s += ">"
        return s


class CallUnslicer(slicer.ScopedUnslicer):

    debug = False

    def start(self, count):
        # start=0:reqID, 1:objID, 2:methodname, 3: arguments
        self.stage = 0
        self.reqID = None
        self.obj = None
        self.interface = None
        self.methodname = None
        self.methodSchema = None # will be a MethodArgumentsConstraint
        self._ready_deferreds = []

    def checkToken(self, typebyte, size):
        # TODO: limit strings by returning a number instead of None
        if self.stage == 0:
            if typebyte != tokens.INT:
                raise BananaError("request ID must be an INT")
        elif self.stage == 1:
            if typebyte not in (tokens.INT, tokens.NEG):
                raise BananaError("object ID must be an INT/NEG")
        elif self.stage == 2:
            if typebyte not in (tokens.STRING, tokens.VOCAB):
                raise BananaError("method name must be a STRING")
            # TODO: limit to longest method name of self.obj in the interface
        elif self.stage == 3:
            if typebyte != tokens.OPEN:
                raise BananaError("arguments must be an 'arguments' sequence")
        else:
            raise BananaError("too many objects given to CallUnslicer")

    def doOpen(self, opentype):
        # checkToken insures that this can only happen when we're receiving
        # an arguments object, so we don't have to bother checking self.stage
        assert self.stage == 3
        unslicer = self.open(opentype)
        if self.methodSchema:
            unslicer.setConstraint(self.methodSchema)
        return unslicer

    def reportViolation(self, f):
        # if the Violation is because we received an ABORT, then we know
        # that the sender knows there was a problem, so don't respond.
        if f.value.args[0] == "ABORT received":
            return f

        # if the Violation was raised after we know the reqID, we can send
        # back an Error.
        if self.stage > 0:
            self.broker.callFailed(f, self.reqID)
        return f # give up our sequence

    def receiveChild(self, token, ready_deferred=None):
        assert not isinstance(token, defer.Deferred)
        if self.debug:
            log.msg("%s.receiveChild [s%d]: %s" %
                    (self, self.stage, repr(token)))

        if self.stage == 0: # reqID
            # we don't yet know which reqID to send any failure to
            assert ready_deferred is None
            self.reqID = token
            self.stage = 1
            if self.reqID != 0:
                assert self.reqID not in self.broker.activeLocalCalls
                self.broker.activeLocalCalls[self.reqID] = self
            return

        if self.stage == 1: # objID
            # this might raise an exception if objID is invalid
            assert ready_deferred is None
            self.objID = token
            try:
                self.obj = self.broker.getMyReferenceByCLID(token)
            except KeyError:
                raise Violation("unknown CLID %d" % (token,))
            #iface = self.broker.getRemoteInterfaceByName(token)
            if self.objID < 0:
                self.interface = None
            else:
                self.interface = self.obj.getInterface()
            self.stage = 2
            return

        if self.stage == 2: # methodname
            # validate the methodname, get the schema. This may raise an
            # exception for unknown methods

            # must find the schema, using the interfaces

            # TODO: getSchema should probably be in an adapter instead of in
            # a pb.Referenceable base class. Old-style (unconstrained)
            # flavors.Referenceable should be adapted to something which
            # always returns None

            # TODO: make this faster. A likely optimization is to take a
            # tuple of components.getInterfaces(obj) and use it as a cache
            # key. It would be even faster to use obj.__class__, but that
            # would probably violate the expectation that instances can
            # define their own __implements__ (independently from their
            # class). If this expectation were to go away, a quick
            # obj.__class__ -> RemoteReferenceSchema cache could be built.

            assert ready_deferred is None
            self.stage = 3

            if self.objID < 0:
                # the target is a bound method, ignore the methodname
                self.methodSchema = getattr(self.obj, "methodSchema", None)
                self.methodname = None # TODO: give it something useful
                if self.broker.requireSchema and not self.methodSchema:
                    why = "This broker does not accept unconstrained " + \
                          "method calls"
                    raise Violation(why)
                return

            self.methodname = token

            if self.interface:
                # they are calling an interface+method pair
                ms = self.interface.get(self.methodname)
                if not ms:
                    why = "method '%s' not defined in %s" % \
                          (self.methodname, self.interface.__remote_name__)
                    raise Violation(why)
                self.methodSchema = ms

            return

        if self.stage == 3: # arguments
            assert isinstance(token, ArgumentUnslicer)
            self.allargs = token
            # queue the message. It will not be executed until all the
            # arguments are ready. The .args list and .kwargs dict may change
            # before then.
            if ready_deferred:
                self._ready_deferreds.append(ready_deferred)
            self.stage = 4
            return

    def receiveClose(self):
        if self.stage != 4:
            raise BananaError("'call' sequence ended too early")
        # time to create the InboundDelivery object so we can queue it
        delivery = InboundDelivery(self.broker, self.reqID, self.obj,
                                   self.interface, self.methodname,
                                   self.methodSchema,
                                   self.allargs)
        ready_deferred = None
        if self._ready_deferreds:
            ready_deferred = AsyncAND(self._ready_deferreds)
        return delivery, ready_deferred

    def describe(self):
        s = "<methodcall"
        if self.stage == 0:
            pass
        if self.stage >= 1:
            s += " reqID=%d" % self.reqID
        if self.stage >= 2:
            s += " obj=%s" % (self.obj,)
            ifacename = "[none]"
            if self.interface:
                ifacename = self.interface.__remote_name__
            s += " iface=%s" % ifacename
        if self.stage >= 3:
            s += " methodname=%s" % self.methodname
        s += ">"
        return s


class AnswerSlicer(slicer.ScopedSlicer):
    opentype = ('answer',)

    def __init__(self, reqID, results, methodname="?"):
        assert reqID != 0
        slicer.ScopedSlicer.__init__(self, None)
        self.reqID = reqID
        self.results = results
        self.methodname = methodname

    def sliceBody(self, streamable, banana):
        yield self.reqID
        yield self.results

    def describe(self):
        return "<answer-%s-to-%s>" % (self.reqID, self.methodname)

class AnswerUnslicer(slicer.ScopedUnslicer):
    request = None
    resultConstraint = None
    haveResults = False

    def start(self, count):
        slicer.ScopedUnslicer.start(self, count)
        self._ready_deferreds = []
        self._child_deferred = None

    def checkToken(self, typebyte, size):
        if self.request is None:
            if typebyte != tokens.INT:
                raise BananaError("request ID must be an INT")
        elif not self.haveResults:
            if self.resultConstraint:
                try:
                    self.resultConstraint.checkToken(typebyte, size)
                except Violation, v:
                    # improve the error message
                    if v.args:
                        # this += gives me a TypeError "object doesn't
                        # support item assignment", which confuses me
                        #v.args[0] += " in inbound method results"
                        why = v.args[0] + " in inbound method results"
                        v.args = why,
                    else:
                        v.args = ("in inbound method results",)
                    raise # this will errback the request
        else:
            raise BananaError("stop sending me stuff!")

    def doOpen(self, opentype):
        if self.resultConstraint:
            self.resultConstraint.checkOpentype(opentype)
            # TODO: improve the error message
        unslicer = self.open(opentype)
        if unslicer:
            if self.resultConstraint:
                unslicer.setConstraint(self.resultConstraint)
        return unslicer

    def receiveChild(self, token, ready_deferred=None):
        if self.request == None:
            assert not isinstance(token, defer.Deferred)
            assert ready_deferred is None
            reqID = token
            # may raise Violation for bad reqIDs
            self.request = self.broker.getRequest(reqID)
            self.resultConstraint = self.request.constraint
        else:
            if isinstance(token, defer.Deferred):
                self._child_deferred = token
            else:
                self._child_deferred = defer.succeed(token)
            if ready_deferred:
                self._ready_deferreds.append(ready_deferred)
            self.haveResults = True

    def reportViolation(self, f):
        # if the Violation was received after we got the reqID, we can tell
        # the broker it was an error
        if self.request != None:
            self.request.fail(f) # local violation
        return f # give up our sequence

    def receiveClose(self):
        # three things must happen before our request is complete:
        #   receiveClose has occurred
        #   the receiveChild object deferred (if any) has fired
        #   ready_deferred has finished
        # If ready_deferred errbacks, provide its failure object to the
        # request. If not, provide the request with whatever receiveChild
        # got.

        if not self._child_deferred:
            raise BananaError("Answer didn't include an answer")

        if self._ready_deferreds:
            d = AsyncAND(self._ready_deferreds)
        else:
            d = defer.succeed(None)

        def _ready(res):
            return self._child_deferred
        d.addCallback(_ready)

        def _done(res):
            self.request.complete(res)
        def _fail(f):
            # we hit here if any of the _ready_deferreds fail (i.e a Gift
            # failed to resolve), or if the _child_deferred fails (not sure
            # how this could happen). I think it's ok to return a local
            # exception (instead of a RemoteException) for both.
            self.request.fail(f)
        d.addCallbacks(_done, _fail)

        return None, None

    def describe(self):
        if self.request:
            return "Answer(req=%s)" % self.request.reqID
        return "Answer(req=?)"



class ErrorSlicer(slicer.ScopedSlicer):
    opentype = ('error',)

    def __init__(self, reqID, f):
        slicer.ScopedSlicer.__init__(self, None)
        assert isinstance(f, failure.Failure)
        self.reqID = reqID
        self.f = f

    def sliceBody(self, streamable, banana):
        yield self.reqID
        yield self.f

    def describe(self):
        return "<error-%s>" % self.reqID

class ErrorUnslicer(slicer.ScopedUnslicer):
    request = None
    fConstraint = FailureConstraint()
    gotFailure = False

    def checkToken(self, typebyte, size):
        if self.request == None:
            if typebyte != tokens.INT:
                raise BananaError("request ID must be an INT")
        elif not self.gotFailure:
            self.fConstraint.checkToken(typebyte, size)
        else:
            raise BananaError("stop sending me stuff!")

    def doOpen(self, opentype):
        self.fConstraint.checkOpentype(opentype)
        unslicer = self.open(opentype)
        if unslicer:
            unslicer.setConstraint(self.fConstraint)
        return unslicer

    def reportViolation(self, f):
        # a failure while receiving the failure. A bit daft, really.
        if self.request != None:
            self.request.fail(f)
        return f # give up our sequence

    def receiveChild(self, token, ready_deferred=None):
        assert not isinstance(token, defer.Deferred)
        assert ready_deferred is None
        if self.request == None:
            reqID = token
            # may raise BananaError for bad reqIDs
            self.request = self.broker.getRequest(reqID)
        else:
            self.failure = token
            self.gotFailure = True

    def receiveClose(self):
        f = self.failure
        if not self.broker._expose_remote_exception_types:
            f = wrap_remote_failure(f)
        self.request.fail(f)
        return None, None

    def describe(self):
        if self.request is None:
            return "<error-?>"
        return "<error-%s>" % self.request.reqID


def truncate(s, limit):
    assert limit > 3
    if s and len(s) > limit:
        s = s[:limit-3] + ".."
    return s

# failures are sent as Copyables
class FailureSlicer(slicer.BaseSlicer):
    slices = failure.Failure
    classname = "twisted.python.failure.Failure"

    def slice(self, streamable, banana):
        self.streamable = streamable
        yield 'copyable'
        yield self.classname
        state = self.getStateToCopy(self.obj, banana)
        for k,v in state.iteritems():
            yield k
            yield v
    def describe(self):
        return "<%s>" % self.classname

    def getStateToCopy(self, obj, broker):
        #state = obj.__dict__.copy()
        #state['tb'] = None
        #state['frames'] = []
        #state['stack'] = []

        state = {}
        # string exceptions show up as obj.value == None and
        # isinstance(obj.type, str). Normal exceptions show up as obj.value
        # == text and obj.type == exception class. We need to make sure we
        # can handle both.
        if isinstance(obj.value, failure.Failure):
            # TODO: how can this happen? I got rid of failure2Copyable, so
            # if this case is possible, something needs to replace it
            raise RuntimeError("not implemented yet")
            #state['value'] = failure2Copyable(obj.value, banana.unsafeTracebacks)
        elif isinstance(obj.type, str):
            state['value'] = str(obj.value)
            state['type'] = obj.type # a string
        else:
            state['value'] = str(obj.value) # Exception instance
            state['type'] = reflect.qual(obj.type) # Exception class
        # TODO: I suspect that f.value may be getting a copy of the
        # traceback, because I've seen it be 1819 bytes at one point. I had
        # assumed that it was just the exception name plus args: whatever
        # Exception.__repr__ returns.
        state['value'] = truncate(state['value'], 1000)
        state['type'] = truncate(state['type'], 200)

        if broker.unsafeTracebacks:
            if isinstance(obj.type, str):
                stack = "getTraceback() not available for string exceptions\n"
            else:
                stack = obj.getTraceback()
            state['traceback'] = stack
            # TODO: provide something with globals and locals and HTML and
            # all that cool stuff
        else:
            state['traceback'] = 'Traceback unavailable\n'

        # The last few lines are often the most interesting. If we need to
        # truncate this, grab the first few lines and then as much of the
        # tail as we can get.
        if len(state['traceback']) > 1900:
            state['traceback'] = (state['traceback'][:700] +
                                  "\n\n-- TRACEBACK ELIDED --\n\n"
                                  + state['traceback'][-1200:])

        parents = obj.parents[:]
        if parents:
            for i,value in enumerate(parents):
                parents[i] = truncate(value, 200)
        state['parents'] = parents

        return state

class CopiedFailure(failure.Failure, copyable.RemoteCopyOldStyle):
    # this is a RemoteCopyOldStyle because you can't raise new-style
    # instances as exceptions.

    """I am a shadow of some remote Failure instance. I contain less
    information than the original did.

    You can still extract a (brief) printable traceback from me. My .parents
    attribute is a list of strings describing the class of the exception
    that I contain, just like the real Failure had, so my trap() and check()
    methods work fine. My .type and .value attributes are string
    representations of the original exception class and exception instance,
    respectively. The most significant effect is that you cannot access
    f.value.args, and should instead just use f.value .

    My .frames and .stack attributes are empty, although this may change in
    the future (and with the cooperation of the sender).
    """

    nonCyclic = True
    stateSchema = FailureConstraint()

    def __init__(self):
        copyable.RemoteCopyOldStyle.__init__(self)

    def __getstate__(self):
        s = failure.Failure.__getstate__(self)
        # the ExceptionLikeString we use in self.type is not pickleable, so
        # replace it with the same sort of string that we use in the wire
        # protocol.
        if not isinstance(self.type, str):
            s['type'] = reflect.qual(self.type)
        return s

    def __setstate__(self, state):
        self.setCopyableState(state)

    def setCopyableState(self, state):
        #self.__dict__.update(state)
        self.__dict__ = state
        # state includes: type, value, traceback, parents
        #self.type = state['type']
        #self.value = state['value']
        #self.traceback = state['traceback']
        #self.parents = state['parents']
        self.tb = None
        self.frames = []
        self.stack = []

        # MAYBE: for native exception types, be willing to wire up a
        # reference to the real exception class. For other exception types,
        # our .type attribute will be a string, which (from a Failure's point
        # of view) looks as if someone raised an old-style string exception.
        # This is here so that trial will properly render a CopiedFailure
        # that comes out of a test case (since it unconditionally does
        # reflect.qual(f.type)

        # ACTUALLY: replace self.type with a class that looks a lot like the
        # original exception class (meaning that reflect.qual() will return
        # the same string for this as for the original). If someone calls our
        # .trap method, resulting in a new Failure with contents copied from
        # this one, then the new Failure.printTraceback will attempt to use
        # reflect.qual() on our self.type, so it needs to be a class instead
        # of a string.

        assert isinstance(self.type, str)
        typepieces = self.type.split(".")
        class ExceptionLikeString:
            pass
        self.type = ExceptionLikeString
        self.type.__module__ = ".".join(typepieces[:-1])
        self.type.__name__ = typepieces[-1]

    def __str__(self):
        return "[CopiedFailure instance: %s]" % self.getBriefTraceback()

    pickled = 1
    def printTraceback(self, file=None, elideFrameworkCode=0,
                       detail='default'):
        if file is None: file = log.logerr
        file.write("Traceback from remote host -- ")
        file.write(self.traceback)

copyable.registerRemoteCopy(FailureSlicer.classname, CopiedFailure)

class CopiedFailureSlicer(FailureSlicer):
    # A calls B. B calls C. C fails and sends a Failure to B. B gets a
    # CopiedFailure and sends it to A. A should get a CopiedFailure too. This
    # class lives on B and slices the CopiedFailure as it is sent to A.
    slices = CopiedFailure

    def getStateToCopy(self, obj, broker):
        state = {}
        for k in ('value', 'type', 'parents'):
            state[k] = getattr(obj, k)
        if broker.unsafeTracebacks:
            state['traceback'] = obj.traceback
        else:
            state['traceback'] = "Traceback unavailable\n"
        if not isinstance(state['type'], str):
            state['type'] = reflect.qual(state['type']) # Exception class
        return state
