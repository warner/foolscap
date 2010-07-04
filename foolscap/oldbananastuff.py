#! /usr/bin/python


class OFF:

    def receiveLength(self):
        # requirement: complete headers live in a single chunk
        b = self.bufferChunks[0]
        bo = self.bufferOffset
        pos = 0
        while pos < 64 and bo+pos < len(b):
            ch = b[bo+pos]
            if ch >= HIGH_BIT_SET:
                # found the type byte
                header = b1282int(b[bo:bo+pos])
                typebyte = ch
                self.bufferOffset += pos+1
                self.receiveTypeByte(header, typebyte) # puts us in WANT_BODY
                return False
        if pos >= 64:
            # drop the connection
            raise BananaError("token prefix is limited to 64 bytes: "
                              "but got %r" % (str(b[bo:bo+pos])))
        # we need more data to continue. Trim out the part we've used
        if self.bufferOffset == 0:
            pass
        elif self.bufferOffset >= len(self.bufferChunks[0]):
            self.bufferChunks.pop(0)
        else:
            self.bufferChunks[0] = self.bufferChunks[0][self.bufferOffset:]
        self.bufferSize -= self.bufferOffset
        self.bufferOffset = 0
        return True

    def updateOffsets(self, chunknum, offset, consumed):
        if chunknum > 0:
            self.bufferChunks = self.bufferChunks[chunknum:]
        self.bufferOffset = offset
        # see if the first chunk is exhausted
        if self.bufferChunks:
            if self.bufferOffset >= len(self.bufferChunks[0]):
                self.bufferChunks.pop(0)
                self.bufferOffset = 0
        self.bufferSize -= consumed

    def receiveLength2(self):
        header_bytes = []
        for chunknum,chunk in enumerate(self.bufferChunks):
            start = 0
            if chunknum == 0:
                start = self.bufferOffset
            for i in range(start, len(chunk)):
                ch = chunk[i]
                if ch >= HIGH_BIT_SET:
                    # found the type byte
                    header = b1282int(header_bytes)
                    typebyte = ch
                    self.updateOffsets(chunknum, i+1, len(header_bytes)+1)
                    # handle the typebyte
                    self.receiveTypeByte(header, typebyte)
                    return False
                # still looking, but maybe we've looked too far
                header_bytes.append(ch)
                if len(header_bytes) > 64:
                    # drop the connection
                    got = "".join(header_bytes)
                    raise BananaError("token prefix is limited to 64 bytes:"
                                      " but got %r" % got)
                # still looking
        return True

    def OLD_handleData(self, chunk):
        # buffer, assemble into tokens
        # call self.receiveToken(token) with each
        if self.skipBytes:
            if len(chunk) < self.skipBytes:
                # skip the whole chunk
                self.skipBytes -= len(chunk)
                return
            # skip part of the chunk, and stop skipping
            chunk = chunk[self.skipBytes:]
            self.skipBytes = 0
        buffer = self.buffer + chunk

        # Loop through the available input data, extracting one token per
        # pass.

        while buffer:
            assert self.buffer != buffer, \
                   ("Banana.handleData: no progress made: %s %s" %
                    (repr(buffer),))
            self.buffer = buffer
            pos = 0

            for ch in buffer:
                if ch >= HIGH_BIT_SET:
                    break
                pos = pos + 1
                if pos > 64:
                    # drop the connection. We log more of the buffer, but not
                    # all of it, to make it harder for someone to spam our
                    # logs.
                    raise BananaError("token prefix is limited to 64 bytes: "
                                      "but got %r" % (buffer[:200],))
            else:
                # we've run out of buffer without seeing the high bit, which
                # means we're still waiting for header to finish
                return
            assert pos <= 64

            # At this point, the header and type byte have been received.
            # The body may or may not be complete.

            typebyte = buffer[pos]
            if pos:
                header = b1282int(buffer[:pos])
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

            rest = buffer[pos+1:]

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
                buffer = rest
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
                buffer = rest
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
                buffer = rest
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
                if len(rest) >= strlen:
                    # the whole string is available
                    buffer = rest[strlen:]
                    obj = rest[:strlen]
                    # handleError must drop the connection
                    self.handleError(obj)
                    return
                else:
                    return # there is more to come

            elif typebyte == LIST:
                raise BananaError("oldbanana peer detected, " +
                                  "compatibility code not yet written")
                #listStack.append((header, []))
                #buffer = rest

            elif typebyte == STRING:
                strlen = header
                if len(rest) >= strlen:
                    # the whole string is available
                    buffer = rest[strlen:]
                    obj = rest[:strlen]
                    # although it might be rejected
                else:
                    # there is more to come
                    if rejected:
                        # drop all we have and note how much more should be
                        # dropped
                        if self.debugReceive:
                            print "DROPPED some string bits"
                        self.skipBytes = strlen - len(rest)
                        self.buffer = ""
                    return

            elif typebyte == INT:
                buffer = rest
                obj = int(header)
            elif typebyte == NEG:
                buffer = rest
                # -2**31 is too large for a positive int, so go through
                # LongType first
                obj = int(-long(header))
            elif typebyte == LONGINT or typebyte == LONGNEG:
                strlen = header
                if len(rest) >= strlen:
                    # the whole number is available
                    buffer = rest[strlen:]
                    obj = bytes_to_long(rest[:strlen])
                    if typebyte == LONGNEG:
                        obj = -obj
                    # although it might be rejected
                else:
                    # there is more to come
                    if rejected:
                        # drop all we have and note how much more should be
                        # dropped
                        self.skipBytes = strlen - len(rest)
                        self.buffer = ""
                    return

            elif typebyte == VOCAB:
                buffer = rest
                obj = self.incomingVocabulary[header]
                # TODO: bail if expanded string is too big
                # this actually means doing self.checkToken(VOCAB, len(obj))
                # but we have to make sure we handle the rejection properly

            elif typebyte == FLOAT:
                if len(rest) >= 8:
                    buffer = rest[8:]
                    obj = struct.unpack("!d", rest[:8])[0]
                else:
                    # this case is easier than STRING, because it is only 8
                    # bytes. We don't bother skipping anything.
                    return

            elif typebyte == PING:
                buffer = rest
                self.sendPONG(header)
                continue # otherwise ignored

            elif typebyte == PONG:
                buffer = rest
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

        self.buffer = ''
