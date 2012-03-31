
import struct, time

from twisted.internet import protocol, defer
from twisted.python.failure import Failure
from twisted.python import log

# make sure to import allslicers, so they all get registered. Even if the
# need for RootSlicer/etc goes away, do the import here anyway.
from foolscap.slicers.allslicers import RootSlicer, RootUnslicer
from foolscap.slicers.allslicers import ReplaceVocabSlicer, AddVocabSlicer

import stringchain
import tokens
from tokens import SIZE_LIMIT, STRING, LIST, INT, NEG, \
     LONGINT, LONGNEG, VOCAB, FLOAT, OPEN, CLOSE, ABORT, ERROR, \
     PING, PONG, \
     BananaError, BananaFailure, Violation

EPSILON = 0.1

def int2b128(integer, stream):
    if integer == 0:
        stream(chr(0))
        return
    assert integer > 0, "can only encode positive integers"
    while integer:
        stream(chr(integer & 0x7f))
        integer = integer >> 7

def b1282int(st):
    # NOTE that this is little-endian
    oneHundredAndTwentyEight = 128
    i = 0
    place = 0
    for char in st:
        num = ord(char)
        i = i + (num * (oneHundredAndTwentyEight ** place))
        place = place + 1
    return i

# long_to_bytes and bytes_to_long taken from PyCrypto: Crypto/Util/number.py

def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of
    the byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\000':
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    # add back some pad bytes. this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * '\000' + s
    return s

def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = '\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

HIGH_BIT_SET = chr(0x80)



# Banana is a big class. It is split up into three sections: sending,
# receiving, and connection setup. These used to be separate classes, but
# the __init__ functions got too weird.

class Banana(protocol.Protocol):

    def __init__(self, features={}):
        """
        @param features: a dictionary of negotiated connection features
        """
        self.initSend()
        self.initReceive()

    def populateVocabTable(self, vocabStrings):
        """
        I expect a list of strings. I will populate my initial vocab
        table (both inbound and outbound) with this list.

        It is not safe to use this method once anything has been serialized
        onto the wire. This method can only be used to set up the initial
        vocab table based upon a negotiated set of common words. The
        'initial-vocab-table-index' parameter is used to decide upon the
        contents of this table.
        """

        out_vocabDict = dict(zip(vocabStrings, range(len(vocabStrings))))
        self.outgoingVocabTableWasReplaced(out_vocabDict)

        in_vocabDict = dict(zip(range(len(vocabStrings)), vocabStrings))
        self.replaceIncomingVocabulary(in_vocabDict)

    ### connection setup

    def connectionMade(self):
        if self.debugSend:
            print "Banana.connectionMade"
        self.initSlicer()
        self.initUnslicer()
        from twisted.internet import reactor
        
        if self.keepaliveTimeout is not None:
            self.dataLastReceivedAt = time.time()
            t = reactor.callLater(self.keepaliveTimeout + EPSILON,
                                  self.keepaliveTimerFired)
            self.keepaliveTimer = t
            self.useKeepalives = True
        if self.disconnectTimeout is not None:
            self.dataLastReceivedAt = time.time()
            t = reactor.callLater(self.disconnectTimeout + EPSILON,
                                  self.disconnectTimerFired)
            self.disconnectTimer = t
            self.useKeepalives = True
        # prime the pump
        self.produce()

    def connectionLost(self, why):
        if self.disconnectTimer:
            self.disconnectTimer.cancel()
            self.disconnectTimer = None
        if self.keepaliveTimer:
            self.keepaliveTimer.cancel()
            self.keepaliveTimer = None
        protocol.Protocol.connectionLost(self, why)

    ### SendBanana
    # called by .send()
    # calls transport.write() and transport.loseConnection()

    slicerClass = RootSlicer # this is used in connectionMade()
    paused = False
    streamable = True # this is checked at connectionMade() time
    debugSend = False

    def initSend(self):
        self.openCount = 0
        self.outgoingVocabulary = {}
        self.nextAvailableOutgoingVocabularyIndex = 0
        self.pendingVocabAdditions = set()

    def initSlicer(self):
        self.rootSlicer = self.slicerClass(self)
        self.rootSlicer.allowStreaming(self.streamable)
        assert tokens.ISlicer.providedBy(self.rootSlicer)
        assert tokens.IRootSlicer.providedBy(self.rootSlicer)

        itr = self.rootSlicer.slice()
        next = iter(itr).next
        top = (self.rootSlicer, next, None)
        self.slicerStack = [top]

    def send(self, obj):
        if self.debugSend: print "Banana.send(%s)" % obj
        return self.rootSlicer.send(obj)

    def _slice_error(self, f, s):
        log.msg("Error in Deferred returned by slicer %s: %s" % (s, f))
        self.sendFailed(f)

    def produce(self, dummy=None):
        # optimize: cache 'next' because we get many more tokens than stack
        # pushes/pops
        while self.slicerStack and not self.paused:
            if self.debugSend: print "produce.loop"
            try:
                slicer, next, openID = self.slicerStack[-1]
                obj = next()
                if self.debugSend: print " produce.obj=%s" % (obj,)
                if isinstance(obj, defer.Deferred):
                    for s,n,o in self.slicerStack:
                        if not s.streamable:
                            raise Violation("parent not streamable")
                    obj.addCallback(self.produce)
                    obj.addErrback(self._slice_error, s)
                    # this is the primary exit point
                    break
                elif type(obj) in (int, long, float, str):
                    # sendToken raises a BananaError for weird tokens
                    self.sendToken(obj)
                else:
                    # newSlicerFor raises a Violation for unsendable types
                    # pushSlicer calls .slice, which can raise Violation
                    try:
                        slicer = self.newSlicerFor(obj)
                        self.pushSlicer(slicer, obj)
                    except Violation, v:
                        # pushSlicer is arranged such that the pushing of
                        # the Slicer and the sending of the OPEN happen
                        # together: either both occur or neither occur. In
                        # addition, there is nothing past the OPEN/push
                        # which can cause an exception.

                        # Therefore, if an exception was raised, we know
                        # that the OPEN has not been sent (so we don't have
                        # to send an ABORT), and that the new Unslicer has
                        # not been pushed (so we don't have to pop one from
                        # the stack)

                        f = BananaFailure()
                        if self.debugSend:
                            print " violation in newSlicerFor:", f
                        self.handleSendViolation(f,
                                                 doPop=False, sendAbort=False)

            except StopIteration:
                if self.debugSend: print "StopIteration"
                self.popSlicer()

            except Violation, v:
                # Violations that occur because of Constraints are caught
                # before the Slicer is pushed. A Violation that is caught
                # here was raised inside .next(), or .streamable wasn't
                # obeyed. The Slicer should now be abandoned.
                if self.debugSend: print " violation in .next:", v

                f = BananaFailure()
                self.handleSendViolation(f, doPop=True, sendAbort=True)

            except:
                print "exception in produce"
                log.msg("exception in produce")
                self.sendFailed(Failure())
                # there is no point to raising this again. The Deferreds are
                # all errbacked in sendFailed(). This function was called
                # inside a Deferred which errbacks to sendFailed(), and
                # we've already called that once. The connection will be
                # dropped by sendFailed(), and the error is logged, so there
                # is nothing left to do.
                return

        assert self.slicerStack # should never be empty

    def handleSendViolation(self, f, doPop, sendAbort):
        f.value.setLocation(self.describeSend())

        while True:
            top = self.slicerStack[-1][0]

            if self.debugSend:
                print " handleSendViolation.loop, top=%s" % top

            # should we send an ABORT? Only if an OPEN has been sent, which
            # happens in pushSlicer (if at all).
            if sendAbort:
                lastOpenID = self.slicerStack[-1][2]
                if lastOpenID is not None:
                    if self.debugSend:
                        print "  sending ABORT(%s)" % lastOpenID
                    self.sendAbort(lastOpenID)

            # should we pop the Slicer? yes
            if doPop:
                if self.debugSend: print "  popping %s" % top
                self.popSlicer()
                if not self.slicerStack:
                    if self.debugSend: print "RootSlicer died!"
                    raise BananaError("Hey! You killed the RootSlicer!")
                top = self.slicerStack[-1][0]

            # now inform the parent. If they also give up, we will
            # loop, popping more Slicers off the stack until the
            # RootSlicer ignores the error

            if self.debugSend:
                print "  notifying parent", top
            f = top.childAborted(f)

            if f:
                doPop = True
                sendAbort = True
                continue
            else:
                break


        # the parent wants to forge ahead

    def newSlicerFor(self, obj):
        if tokens.ISlicer.providedBy(obj):
            return obj
        topSlicer = self.slicerStack[-1][0]
        # slicerForObject could raise a Violation, for unserializeable types
        return topSlicer.slicerForObject(obj)

    def pushSlicer(self, slicer, obj):
        if self.debugSend: print "push", slicer
        assert len(self.slicerStack) < 10000 # failsafe

        # if this method raises a Violation, it means that .slice failed,
        # and neither the OPEN nor the stack-push has occurred

        topSlicer = self.slicerStack[-1][0]
        slicer.parent = topSlicer

        # we start the Slicer (by getting its iterator) first, so that if it
        # fails we can refrain from sending the OPEN (hence we do not have
        # to send an ABORT and CLOSE, which simplifies the send logic
        # considerably). slicer.slice is the only place where a Violation
        # can be raised: it is caught and passed cleanly to the parent. If
        # it happens anywhere else, or if any other exception is raised, the
        # connection will be dropped.

        # the downside to this approach is that .slice happens before
        # .registerReference, so any late-validation being done in .slice
        # will not be able to detect the fact that this object has already
        # begun serialization. Validation performed in .next is ok.

        # also note that if .slice is a generator, any exception it raises
        # will not occur until .next is called, which happens *after* the
        # slicer has been pushed. This check is only useful for .slice
        # methods which are *not* generators.

        itr = slicer.slice(topSlicer.streamable, self)
        next = iter(itr).next

        # we are now committed to sending the OPEN token, meaning that
        # failures after this point will cause an ABORT/CLOSE to be sent

        openID = None
        if slicer.sendOpen:
            openID = self.sendOpen()
            if slicer.trackReferences:
                topSlicer.registerReference(openID, obj)
            # note that the only reason to hold on to the openID here is for
            # the debug/optional copy in the CLOSE token. Consider ripping
            # this code out if we decide to stop sending that copy.

        slicertuple = (slicer, next, openID)
        self.slicerStack.append(slicertuple)

    def popSlicer(self):
        slicer, next, openID = self.slicerStack.pop()
        if openID is not None:
            self.sendClose(openID)
        if self.debugSend: print "pop", slicer

    def describeSend(self):
        where = []
        for i in self.slicerStack:
            try:
                piece = i[0].describe()
            except:
                log.msg("Banana.describeSend")
                log.err()
                piece = "???"
            where.append(piece)
        return ".".join(where)

    def setOutgoingVocabulary(self, vocabStrings):
        """Schedule a replacement of the outbound VOCAB table.

        Higher-level code may call this at any time with a list of strings.
        Immediately after the replacement has occured, the outbound VOCAB
        table will contain all of the strings in vocabStrings and nothing
        else. This table tells the token-sending code which strings to
        abbreviate with short integers in a VOCAB token.

        This function can be called at any time (even while the protocol is
        in the middle of serializing and transmitting some other object)
        because it merely schedules a replacement to occur at some point in
        the future. A special marker (the ReplaceVocabSlicer) is placed in
        the outbound queue, and the table replacement will only happend after
        all the items ahead of that marker have been serialized. At the same
        time the table is replaced, a (set-vocab..) sequence will be
        serialized towards the far end. This insures that we set our outbound
        table at the same 'time' as the far end starts using it.
        """
        # build a VOCAB message, send it, then set our outgoingVocabulary
        # dictionary to start using the new table
        assert isinstance(vocabStrings, (list, tuple))
        for s in vocabStrings:
            assert isinstance(s, str)
        vocabDict = dict(zip(vocabStrings, range(len(vocabStrings))))
        s = ReplaceVocabSlicer(vocabDict)
        # the ReplaceVocabSlicer does some magic to insure the VOCAB message
        # does not use vocab tokens itself. This would be legal (sort of a
        # differential compression), but confusing. It accomplishes this by
        # clearing our self.outgoingVocabulary dict when it begins to be
        # serialized.
        self.send(s)

        # likewise, when it finishes, the ReplaceVocabSlicer replaces our
        # self.outgoingVocabulary dict when it has finished sending the
        # strings. It is important that this occur in the serialization code,
        # or somewhen very close to it, because otherwise there could be a
        # race condition that could result in some strings being vocabized
        # with the wrong keys.

    def addToOutgoingVocabulary(self, value):
        """Schedule 'value' for addition to the outbound VOCAB table.

        This may be called at any time. If the string is already scheduled
        for addition, or if it is already in the VOCAB table, it will be
        ignored. (TODO: does this introduce an annoying-but-not-fatal race
        condition?) The string will not actually be added to the table until
        the outbound serialization queue has been serviced.
        """
        assert isinstance(value, str)
        if value in self.outgoingVocabulary:
            return
        if value in self.pendingVocabAdditions:
            return
        self.pendingVocabAdditions.add(str)
        s = AddVocabSlicer(value)
        self.send(s)

    def outgoingVocabTableWasReplaced(self, newTable):
        # this is called by the ReplaceVocabSlicer to manipulate our table.
        # It must certainly *not* be called by higher-level user code.
        self.outgoingVocabulary = newTable
        if newTable:
            maxIndex = max(newTable.values()) + 1
            self.nextAvailableOutgoingVocabularyIndex = maxIndex
        else:
            self.nextAvailableOutgoingVocabularyIndex = 0

    def allocateEntryInOutgoingVocabTable(self, string):
        assert string not in self.outgoingVocabulary
        # TODO: a softer failure more for this assert is to re-send the
        # existing key. To make sure that really happens, though, we have to
        # remove it from the vocab table, otherwise we'll tokenize the
        # string. If we can insure that, then this failure mode would waste
        # time and network but would otherwise be harmless.
        #
        # return self.outgoingVocabulary[string]

        self.pendingVocabAdditions.remove(self.value)
        index = self.nextAvailableOutgoingVocabularyIndex
        self.nextAvailableOutgoingVocabularyIndex = index + 1
        return index

    def outgoingVocabTableWasAmended(self, index, string):
        self.outgoingVocabulary[string] = index

    # these methods define how we emit low-level tokens

    def sendPING(self, number=0):
        if number:
            int2b128(number, self.transport.write)
        self.transport.write(PING)

    def sendPONG(self, number):
        if number:
            int2b128(number, self.transport.write)
        self.transport.write(PONG)

    def sendOpen(self):
        openID = self.openCount
        self.openCount += 1
        int2b128(openID, self.transport.write)
        self.transport.write(OPEN)
        return openID

    def sendToken(self, obj):
        write = self.transport.write
        if isinstance(obj, (int, long)):
            if obj >= 2**31:
                s = long_to_bytes(obj)
                int2b128(len(s), write)
                write(LONGINT)
                write(s)
            elif obj >= 0:
                int2b128(obj, write)
                write(INT)
            elif -obj > 2**31: # NEG is [-2**31, 0)
                s = long_to_bytes(-obj)
                int2b128(len(s), write)
                write(LONGNEG)
                write(s)
            else:
                int2b128(-obj, write)
                write(NEG)
        elif isinstance(obj, float):
            write(FLOAT)
            write(struct.pack("!d", obj))
        elif isinstance(obj, str):
            if self.outgoingVocabulary.has_key(obj):
                symbolID = self.outgoingVocabulary[obj]
                int2b128(symbolID, write)
                write(VOCAB)
            else:
                self.maybeVocabizeString(obj)
                int2b128(len(obj), write)
                write(STRING)
                write(obj)
        else:
            raise BananaError, "could not send object: %s" % repr(obj)

    def maybeVocabizeString(self, string):
        # TODO: keep track of the last 30 strings we've send in full. If this
        # string appears more than 3 times on that list, create a vocab item
        # for it. Make sure we don't start using the vocab number until the
        # ADDVOCAB token has been queued.
        if False:
            self.addToOutgoingVocabulary(string)

    def sendClose(self, openID):
        int2b128(openID, self.transport.write)
        self.transport.write(CLOSE)

    def sendAbort(self, count=0):
        int2b128(count, self.transport.write)
        self.transport.write(ABORT)

    def sendError(self, msg):
        if not self.transport:
            return
        if len(msg) > SIZE_LIMIT:
            msg = msg[:SIZE_LIMIT-10] + "..."
        int2b128(len(msg), self.transport.write)
        self.transport.write(ERROR)
        self.transport.write(msg)
        # now you should drop the connection
        self.transport.loseConnection()

    def sendFailed(self, f):
        # call this if an exception is raised in transmission. The Failure
        # will be logged and the connection will be dropped. This is
        # suitable for use as an errback handler.
        print "SendBanana.sendFailed:", f
        log.msg("Sendfailed.sendfailed")
        log.err(f)
        try:
            if self.transport:
                self.transport.loseConnection()
        except:
            print "exception during transport.loseConnection"
            log.err()
        try:
            self.rootSlicer.connectionLost(f)
        except:
            print "exception during rootSlicer.connectionLost"
            log.err()

    ### ReceiveBanana
    # called with dataReceived()
    # calls self.receivedObject()

    unslicerClass = RootUnslicer
    debugReceive = False
    logViolations = False
    logReceiveErrors = True
    useKeepalives = False
    keepaliveTimeout = None
    keepaliveTimer = None
    disconnectTimeout = None
    disconnectTimer = None

    def initReceive(self):
        self.inOpen = False # set during the Index Phase of an OPEN sequence
        self.opentype = [] # accumulates Index Tokens

        # to pre-negotiate, set the negotiation parameters and set
        # self.negotiated to True. It might instead make sense to fill
        # self.buffer with the inbound negotiation block.
        self.negotiated = False
        self.connectionAbandoned = False
        self.buffer = stringchain.StringChain()

        self.incomingVocabulary = {}
        self.skipBytes = 0 # used to discard a single long token
        self.discardCount = 0 # used to discard non-primitive objects
        self.exploded = None # last-ditch error catcher

    def initUnslicer(self):
        self.rootUnslicer = self.unslicerClass(self)
        self.receiveStack = [self.rootUnslicer]
        self.objectCounter = 0
        self.objects = {}

    def printStack(self, verbose=0):
        print "STACK:"
        for s in self.receiveStack:
            if verbose:
                d = s.__dict__.copy()
                del d['protocol']
                print " %s: %s" % (s, d)
            else:
                print " %s" % s

    def setObject(self, count, obj):
        for i in range(len(self.receiveStack)-1, -1, -1):
            self.receiveStack[i].setObject(count, obj)

    def getObject(self, count):
        for i in range(len(self.receiveStack)-1, -1, -1):
            obj = self.receiveStack[i].getObject(count)
            if obj is not None:
                return obj
        raise ValueError, "dangling reference '%d'" % count


    def replaceIncomingVocabulary(self, vocabDict):
        # maps small integer to string, should be called in response to a
        # OPEN(set-vocab) sequence.
        self.incomingVocabulary = vocabDict

    def addIncomingVocabulary(self, key, value):
        # called in response to an OPEN(add-vocab) sequence
        self.incomingVocabulary[key] = value

    def dataReceived(self, chunk):
        if self.connectionAbandoned:
            return
        if self.useKeepalives:
            self.dataLastReceivedAt = time.time()
        try:
            self.handleData(chunk)
        except Exception, e:
            if isinstance(e, BananaError):
                # only reveal the reason if it is a protocol error
                e.where = self.describeReceive()
                msg = str(e) # send them the text of the error
            else:
                msg = ("exception while processing data, more "
                       "information in the logfiles")
                if not self.logReceiveErrors:
                    msg += ", except that self.logReceiveErrors=False"
                    msg += ", sucks to be you"
            self.sendError(msg)
            self.connectionAbandoned = True
            self.reportReceiveError(Failure())

    def keepaliveTimerFired(self):
        self.keepaliveTimer = None
        age = time.time() - self.dataLastReceivedAt
        if age > self.keepaliveTimeout:
            # the connection looks idle, so let's provoke a response
            self.sendPING()
            
        from twisted.internet import reactor
        # we restart the timer in either case
        t = reactor.callLater(self.keepaliveTimeout + EPSILON,
                              self.keepaliveTimerFired)
        self.keepaliveTimer = t

    def disconnectTimerFired(self):
        self.disconnectTimer = None
        age = time.time() - self.dataLastReceivedAt
        if age > self.disconnectTimeout:
            # the connection looks dead, so drop it
            log.msg("disconnectTimeout, no data for %d seconds" % age)
            self.connectionTimedOut()
            # we assume that connectionTimedOut() will actually drop the
            # connection, so we don't restart the timer. TODO: this might not
            # be the right thing to do, perhaps we should restart it
            # unconditionally.
        else:
            from twisted.internet import reactor
            # we're still ok, so restart the timer
            t = reactor.callLater(self.disconnectTimeout + EPSILON,
                                  self.disconnectTimerFired)
            self.disconnectTimer = t

    def getDataLastReceivedAt(self):
        """If keepalives are enabled, this returns the seconds-since-epoch
        when the most recent data was received on this connection. If
        keepalives are disabled (which is the detault), it returns None."""

        if self.useKeepalives:
            return self.dataLastReceivedAt
        return None

    def connectionTimedOut(self):
        # this is to be implemented by higher-level code. It ought to log a
        # suitable message and then drop the connection.
        pass

    def reportReceiveError(self, f):
        # tests can override this to stash the failure somewhere else. Tests
        # which intentionally cause an error set self.logReceiveErrors=False
        # so that the log.err doesn't flunk the test.
        log.msg("Banana.reportReceiveError: an error occured during receive")
        if self.logReceiveErrors:
            log.err(f)
        if self.debugReceive:
            # trial watches log.err and treats it as a failure, so log the
            # exception in a way that doesn't make trial flunk the test
            log.msg(f.getBriefTraceback())


    def handleData(self, chunk):
        # buffer, assemble into tokens
        # call self.receiveToken(token) with each
        if self.skipBytes:
            if len(chunk) <= self.skipBytes:
                # skip the whole chunk
                self.skipBytes -= len(chunk)
                return
            # skip part of the chunk, and stop skipping
            chunk = chunk[self.skipBytes:]
            self.skipBytes = 0
        self.buffer.append(chunk)

        # Loop through the available input data, extracting one token per
        # pass.

        while len(self.buffer):
            first65 = self.buffer.popleft(65)
            pos = 0
            for ch in first65:
                if ch >= HIGH_BIT_SET:
                    break
                pos = pos + 1
                if pos > 64:
                    # drop the connection. We log more of the buffer, but not
                    # all of it, to make it harder for someone to spam our
                    # logs.
                    s = first65 + self.buffer.popleft(200)
                    raise BananaError("token prefix is limited to 64 bytes: "
                                      "but got %r" % s)
            else:
                # we've run out of buffer without seeing the high bit, which
                # means we're still waiting for header to finish
                self.buffer.appendleft(first65)
                return
            assert pos <= 64

            # At this point, the header and type byte have been received.
            # The body may or may not be complete.

            typebyte = first65[pos]
            if pos:
                header = b1282int(first65[:pos])
            else:
                header = 0

            # rejected is set as soon as a violation is detected. It
            # indicates that this single token will be rejected.

            rejected = False
            if self.discardCount:
                rejected = True

            wasInOpen = self.inOpen
            if typebyte == OPEN:
                self.inboundObjectCount = self.objectCounter
                self.objectCounter += 1
                if self.inOpen:
                    raise BananaError("OPEN token followed by OPEN")
                self.inOpen = True
                # the inOpen flag is set as soon as the OPEN token is
                # witnessed (even it it gets rejected later), because it
                # means that there is a new sequence starting that must be
                # handled somehow (either discarded or given to a new
                # Unslicer).

                # The inOpen flag is cleared when the Index Phase ends. There
                # are two possibilities: 1) a new Unslicer is pushed, and
                # tokens are delivered to it normally. 2) a Violation was
                # raised, and the tokens must be discarded
                # (self.discardCount++). *any* rejection-caused True->False
                # transition of self.inOpen must be accompanied by exactly
                # one increment of self.discardCount

            # determine if this token will be accepted, and if so, how large
            # it is allowed to be (for STRING and LONGINT/LONGNEG)

            if ((not rejected) and
                (typebyte not in (PING, PONG, ABORT, CLOSE, ERROR))):
                # PING, PONG, ABORT, CLOSE, and ERROR are always legal. All
                # others (including OPEN) can be rejected by the schema: for
                # example, a list of integers would reject STRING, VOCAB, and
                # OPEN because none of those will produce integers. If the
                # unslicer's .checkToken rejects the tokentype, its
                # .receiveChild will immediately get an Failure
                try:
                    # the purpose here is to limit the memory consumed by
                    # the body of a STRING, OPEN, LONGINT, or LONGNEG token
                    # (i.e., the size of a primitive type). If the sender
                    # wants to feed us more data than we want to accept, the
                    # checkToken() method should raise a Violation. This
                    # will never be called with ABORT or CLOSE types.
                    top = self.receiveStack[-1]
                    if wasInOpen:
                        top.openerCheckToken(typebyte, header, self.opentype)
                    else:
                        top.checkToken(typebyte, header)
                except Violation:
                    rejected = True
                    f = BananaFailure()
                    if wasInOpen:
                        methname = "openerCheckToken"
                    else:
                        methname = "checkToken"
                    self.handleViolation(f, methname, inOpen=self.inOpen)
                    self.inOpen = False

            if typebyte == ERROR and header > SIZE_LIMIT:
                # someone is trying to spam us with an ERROR token. Drop
                # them with extreme prejudice.
                raise BananaError("oversized ERROR token")

            self.buffer.appendleft(first65[pos+1:])

            # determine what kind of token it is. Each clause finishes in
            # one of four ways:
            #
            #  raise BananaError: the protocol was violated so badly there is
            #                     nothing to do for it but hang up abruptly
            #
            #  return: if the token is not yet complete (need more data)
            #
            #  continue: if the token is complete but no object (for
            #            handleToken) was produced, e.g. OPEN, CLOSE, ABORT
            #
            #  obj=foo: the token is complete and an object was produced
            #
            # note that if rejected==True, the object is dropped instead of
            # being passed up to the current Unslicer

            if typebyte == OPEN:
                self.inboundOpenCount = header
                if rejected:
                    if self.debugReceive:
                        print "DROP (OPEN)"
                    if self.inOpen:
                        # we are discarding everything at the old level, so
                        # discard everything in the new level too
                        self.discardCount += 1
                        if self.debugReceive:
                            print "++discardCount (OPEN), now %d" \
                                  % self.discardCount
                        self.inOpen = False
                    else:
                        # the checkToken handleViolation has already started
                        # discarding this new sequence, we don't have to
                        pass
                else:
                    self.inOpen = True
                    self.opentype = []
                continue

            elif typebyte == CLOSE:
                count = header
                if self.discardCount:
                    self.discardCount -= 1
                    if self.debugReceive:
                        print "--discardCount (CLOSE), now %d" \
                              % self.discardCount
                else:
                    self.handleClose(count)
                continue

            elif typebyte == ABORT:
                count = header
                # TODO: this isn't really a Violation, but we need something
                # to describe it. It does behave identically to what happens
                # when receiveChild raises a Violation. The .handleViolation
                # will pop the now-useless Unslicer and start discarding
                # tokens just as if the Unslicer had made the decision.
                if rejected:
                    if self.debugReceive:
                        print "DROP (ABORT)"
                    # I'm ignoring you, LALALALALA.
                    #
                    # In particular, do not deliver a second Violation
                    # because of the ABORT that we're supposed to be
                    # ignoring because of a first Violation that happened
                    # earlier.
                    continue
                try:
                    # slightly silly way to do it, but nice and uniform
                    raise Violation("ABORT received")
                except Violation:
                    f = BananaFailure()
                    self.handleViolation(f, "receive-abort")
                continue

            elif typebyte == ERROR:
                strlen = header
                if len(self.buffer) >= strlen:
                    # the whole string is available
                    obj = self.buffer.popleft(strlen)
                    # handleError must drop the connection
                    self.handleError(obj)
                    return
                else:
                    self.buffer.appendleft(first65[:pos+1])
                    return # there is more to come

            elif typebyte == LIST:
                raise BananaError("oldbanana peer detected, " +
                                  "compatibility code not yet written")
                #listStack.append((header, []))

            elif typebyte == STRING:
                strlen = header
                if len(self.buffer) >= strlen:
                    # the whole string is available
                    obj = self.buffer.popleft(strlen)
                    # although it might be rejected
                else:
                    # there is more to come
                    if rejected:
                        # drop all we have and note how much more should be
                        # dropped
                        if self.debugReceive:
                            print "DROPPED some string bits"
                        self.skipBytes = strlen - len(self.buffer)
                        self.buffer.clear()
                    else:
                        self.buffer.appendleft(first65[:pos+1])
                    return

            elif typebyte == INT:
                obj = int(header)
            elif typebyte == NEG:
                # -2**31 is too large for a positive int, so go through
                # LongType first
                obj = int(-long(header))
            elif typebyte == LONGINT or typebyte == LONGNEG:
                strlen = header
                if len(self.buffer) >= strlen:
                    # the whole number is available
                    obj = bytes_to_long(self.buffer.popleft(strlen))
                    if typebyte == LONGNEG:
                        obj = -obj
                    # although it might be rejected
                else:
                    # there is more to come
                    if rejected:
                        # drop all we have and note how much more should be
                        # dropped
                        self.skipBytes = strlen - len(self.buffer)
                        self.buffer.clear()
                    else:
                        self.buffer.appendleft(first65[:pos+1])
                    return

            elif typebyte == VOCAB:
                obj = self.incomingVocabulary[header]
                # TODO: bail if expanded string is too big
                # this actually means doing self.checkToken(VOCAB, len(obj))
                # but we have to make sure we handle the rejection properly

            elif typebyte == FLOAT:
                if len(self.buffer) >= 8:
                    obj = struct.unpack("!d", self.buffer.popleft(8))[0]
                else:
                    # this case is easier than STRING, because it is only 8
                    # bytes. We don't bother skipping anything.
                    self.buffer.appendleft(first65[:pos+1])
                    return

            elif typebyte == PING:
                self.sendPONG(header)
                continue # otherwise ignored

            elif typebyte == PONG:
                continue # otherwise ignored

            else:
                raise BananaError("Invalid Type Byte 0x%x" % ord(typebyte))

            if not rejected:
                if self.inOpen:
                    self.handleOpen(self.inboundOpenCount,
                                    self.inboundObjectCount,
                                    obj)
                    # handleOpen might push a new unslicer and clear
                    # .inOpen, or leave .inOpen true and append the object
                    # to .indexOpen
                else:
                    self.handleToken(obj)
            else:
                if self.debugReceive:
                    print "DROP", type(obj), obj
                pass # drop the object

            # while loop ends here

        # note: this is redundant, as there are no 'break' statements in that
        # loop, and the loop exit condition is 'while len(self.buffer)'
        self.buffer.clear()


    def handleOpen(self, openCount, objectCount, indexToken):
        self.opentype.append(indexToken)
        opentype = tuple(self.opentype)
        if self.debugReceive:
            print "handleOpen(%d,%d,%s)" % (openCount, objectCount, indexToken)
        top = self.receiveStack[-1]
        try:
            # obtain a new Unslicer to handle the object
            child = top.doOpen(opentype)
            if not child:
                if self.debugReceive:
                    print " doOpen wants more index tokens"
                return # they want more index tokens, leave .inOpen=True
            if self.debugReceive:
                print " opened[%d] with %s" % (openCount, child)
        except Violation:
            # must discard the rest of the child object. There is no new
            # unslicer pushed yet, so we don't use abandonUnslicer
            self.inOpen = False
            f = BananaFailure()
            self.handleViolation(f, "doOpen", inOpen=True)
            return

        assert tokens.IUnslicer.providedBy(child), "child is %s" % child
        self.inOpen = False
        child.protocol = self
        child.openCount = openCount
        child.parent = top
        self.receiveStack.append(child)
        try:
            child.start(objectCount)
        except Violation:
            # the child is now on top, so use abandonUnslicer to discard the
            # rest of the child
            f = BananaFailure()
            # notifies the new child
            self.handleViolation(f, "start")

    def handleToken(self, token, ready_deferred=None):
        top = self.receiveStack[-1]
        if self.debugReceive: print "handleToken(%s)" % (token,)
        if ready_deferred:
            assert isinstance(ready_deferred, defer.Deferred)
        try:
            top.receiveChild(token, ready_deferred)
        except Violation:
            # this is how the child says "I've been contaminated". We don't
            # pop them automatically: if they want that, they should return
            # back the failure in their reportViolation method.
            f = BananaFailure()
            self.handleViolation(f, "receiveChild")

    def handleClose(self, closeCount):
        if self.debugReceive:
            print "handleClose(%d)" % closeCount
        if self.receiveStack[-1].openCount != closeCount:
            raise BananaError("lost sync, got CLOSE(%d) but expecting %s" \
                              % (closeCount, self.receiveStack[-1].openCount))

        child = self.receiveStack[-1] # don't pop yet: describe() needs it

        try:
            obj, ready_deferred = child.receiveClose()
        except Violation:
            # the child is contaminated. However, they're finished, so we
            # don't have to discard anything. Just give an Failure to the
            # parent instead of the object they would have returned.
            f = BananaFailure()
            self.handleViolation(f, "receiveClose", inClose=True)
            return
        if self.debugReceive: print "receiveClose returned", obj

        try:
            child.finish()
        except Violation:
            # .finish could raise a Violation if an object that references
            # the child is just now deciding that they don't like it
            # (perhaps their TupleConstraint couldn't be asserted until the
            # tuple was complete and referenceable). In this case, the child
            # has produced a valid object, but an earlier (incomplete)
            # object is not valid. So we treat this as if this child itself
            # raised the Violation. The .where attribute will point to this
            # child, which is the node that caused somebody problems, but
            # will be marked <FINISH>, which indicates that it wasn't the
            # child itself which raised the Violation. TODO: not true
            #
            # TODO: it would be more useful if the UF could also point to
            # the completing object (the one which raised Violation).

            f = BananaFailure()
            self.handleViolation(f, "finish", inClose=True)
            return

        self.receiveStack.pop()

        # now deliver the object to the parent
        self.handleToken(obj, ready_deferred)

    def handleViolation(self, f, methname, inOpen=False, inClose=False):
        """An Unslicer has decided to give up, or we have given up on it
        (because we received an ABORT token).
        """

        where = self.describeReceive()
        f.value.setLocation(where)

        if self.debugReceive:
            print " handleViolation-%s (inOpen=%s, inClose=%s): %s" \
                  % (methname, inOpen, inClose, f)

        assert isinstance(f, BananaFailure)

        if self.logViolations:
            log.msg("Violation in %s at %s" % (methname, where))
            log.err(f)

        if inOpen:
            self.discardCount += 1
            if self.debugReceive:
                print "  ++discardCount (inOpen), now %d" % self.discardCount

        while True:
            # tell the parent that their child is dead. This is useful for
            # things like PB, which may want to errback the current request.
            if self.debugReceive:
                print " reportViolation to %s" % self.receiveStack[-1]
            f = self.receiveStack[-1].reportViolation(f)
            if not f:
                # they absorbed the failure
                if self.debugReceive:
                    print "  buck stopped, error absorbed"
                break

            # the old top wants to propagate it upwards
            if self.debugReceive:
                print "  popping %s" % self.receiveStack[-1]
            if not inClose:
                self.discardCount += 1
                if self.debugReceive:
                    print "  ++discardCount (pop, not inClose), now %d" \
                          % self.discardCount
            inClose = False

            old = self.receiveStack.pop()

            try:
                # TODO: if handleClose encountered a Violation in .finish,
                # we will end up calling it a second time
                old.finish() # ??
            except Violation:
                pass # they've already failed once

            if not self.receiveStack:
                # now there's nobody left to create new Unslicers, so we
                # must drop the connection
                why = "Oh my god, you killed the RootUnslicer! " + \
                      "You bastard!!"
                raise BananaError(why)

            # now we loop until someone absorbs the failure


    def handleError(self, msg):
        log.msg("got banana ERROR from remote side: %s" % msg)
        self.transport.loseConnection()


    def describeReceive(self):
        where = []
        for i in self.receiveStack:
            try:
                piece = i.describe()
            except:
                piece = "???"
                #raise
            where.append(piece)
        return ".".join(where)

    def receivedObject(self, obj):
        """Decoded objects are delivered here, unless you use a RootUnslicer
        variant which does something else in its .childFinished method.
        """
        raise NotImplementedError

    def reportViolation(self, why):
        return why

