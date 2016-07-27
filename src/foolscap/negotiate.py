# -*- test-case-name: foolscap.test.test_negotiate -*-

import time
from twisted.python.failure import Failure
from twisted.internet import protocol, reactor
from twisted.internet.error import ConnectionDone

from foolscap import broker, referenceable, vocab
from foolscap.eventual import eventually
from foolscap.tokens import (SIZE_LIMIT, ERROR,
                             BananaError, NegotiationError,
                             RemoteNegotiationError, DuplicateConnection)
from foolscap.ipb import DeadReferenceError
from foolscap.banana import int2b128
from foolscap.logging import log
from foolscap.logging.log import NOISY, OPERATIONAL, WEIRD, UNUSUAL, CURIOUS
from foolscap.util import isSubstring
from foolscap import crypto

def best_overlap(my_min, my_max, your_min, your_max, name):
    """Find the highest integer which is in both ranges (inclusive).
    Raise NegotiationError (using 'name' in the error message) if there
    is no overlap."""
    best = min(my_max, your_max)
    if best < my_min:
        raise NegotiationError("I can't handle %s %d" % (name, best))
    if best < your_min:
        raise NegotiationError("You can't handle %s %d" % (name, best))
    return best

def check_inrange(my_min, my_max, decision, name):
    if decision < my_min or decision > my_max:
        raise NegotiationError("I can't handle %s %d" % (name, decision))

# negotiation phases
PLAINTEXT, ENCRYPTED, DECIDING, BANANA, ABANDONED = range(5)


# version number history:
#  1 (0.1.0): offer includes initial-vocab-table-range,
#             decision includes initial-vocab-table-index
#  2 (0.1.1): no changes to offer or decision
#             reqID=0 was commandeered for use by callRemoteOnly()
#  3 (0.1.3): added PING and PONG tokens

class Negotiation(protocol.Protocol):
    """This is the first protocol to speak over the wire. It is responsible
    for negotiating the connection parameters, then switching the connection
    over to the actual Banana protocol. This removes all the details of
    negotiation from Banana, and makes it easier to use a more complex scheme
    (including a STARTTLS transition) in PB.

    Negotiation consists of three phases. In the PLAINTEXT phase, the client
    side (i.e. the one which initiated the connection) sends an
    HTTP-compatible GET request for the target Tub ID. This request includes
    an Connection: Upgrade header. The GET request serves a couple of
    purposes: if a PB client is accidentally pointed at an HTTP server, it
    will trigger a sensible 404 Error instead of getting confused. A regular
    HTTP server can be used to send back a 303 Redirect, allowing Apache (or
    whatever) to be used as a redirection server.

    After sending the GET request, the client waits for the server to send a
    101 Switching Protocols command, then starts the TLS session. It may also
    receive a 303 Redirect command, in which case it drops the connection and
    tries again with the new target.

    In the PLAINTEXT phase, the server side (i.e. the one which accepted the
    connection) waits for the client's GET request, extracts the TubID from
    the first line, consults the local Listener object to locate the
    appropriate Tub (and its certificate), sends back a 101 Switching
    Protocols response, then starts the TLS session with the Tub's
    certificate. If the Listener reports that the requested Tub is listening
    elsewhere, the server sends back a 303 Redirect instead, and then drops
    the connection.

    By the end of the PLAINTEXT phase, both ends know which Tub they are
    using (self.tub has been set).

    Both sides send a Hello Block upon entering the ENCRYPTED phase, which in
    practice means just after starting the TLS session. The Hello block
    contains the negotiation offer, as a series of Key: Value lines separated
    by \\r\\n delimiters and terminated by a blank line. Upon receiving the
    other end's Hello block, each side switches to the DECIDING phase, and
    then evaluates the received Hello message.

    Each side compares TubIDs, and the side with the lexicographically higher
    value becomes the Master. (If, for some reason, one side does not claim a
    TubID, its value is treated as None, which always compares *less* than
    any actual TubID, so the non-TubID side will probably not be the Master.
    Any possible ties are resolved by having the server side be the master).
    Both sides know the other's TubID, so both sides know whether they are
    the Master or not.

    The Master has two jobs to do. The first is that it compares the
    negotiation offer against its own capabilities, and comes to a decision
    about what the connection parameters shall be. It may decide that the two
    sides are not compatible, in which case it will abandon the connection.
    The second job is to decide whether to continue to use the connection at
    all: if the Master already has a connection to the other Tub, it will
    drop this new one. This decision must be made by the Master (as opposed
    to the Server) because it is possible for both Tubs to connect to each
    other simultaneously, and this design avoids a race condition that could
    otherwise drop *both* connections.

    If the Master decides to continue with the connection, it sends the
    Decision block to the non-master side. It then swaps out the Negotiation
    protocol for a new Banana protocol instance that has been created with
    the same parameters that were used to create the Decision block.

    The non-master side is waiting in the DECIDING phase for this block. Upon
    receiving it, the non-master side evaluates the connection parameters and
    either drops the connection or swaps in a new Banana protocol instance
    with the same parameters. At this point, negotiation is complete and the
    Negotiation instances are dropped.


    @ivar negotationOffer: a dict which describes what we will offer to the
    far side. Each key/value pair will be put into a rfc822-style header and
    sent from the client to the server when the connection is established. On
    the server side, handleNegotiation() uses negotationOffer to indicate
    what we are locally capable of.

    Subclasses may influence the negotiation process by modifying this
    dictionary before connectionMade() is called.

    @ivar negotiationResults: a dict which describes what the two ends have
    agreed upon. This is computed by the server, stored locally, and sent
    down to the client. The client receives it and stores it without
    modification (server chooses).

    In general, the negotiationResults are the same on both sides of the same
    connection. However there may be certain parameters which are sent as
    part of the negotiation block (the PB TubID, for example) which will not.

    """

    myTubID = None
    tub = None
    theirTubID = None

    receive_phase = PLAINTEXT # we are expecting this
    send_phase = PLAINTEXT # the other end is expecting this

    doNegotiation = True
    debugNegotiation = False
    forceNegotiation = None

    minVersion = 3
    maxVersion = 3

    brokerClass = broker.Broker

    initialVocabTableRange = vocab.getVocabRange()

    SERVER_TIMEOUT = 120 # You have 2 minutes to complete negotiation, or
                         # else. The only reason this isn't closer to 10s is
                         # that Tor/I2P connection establishment might
                         # include spinning up a local Tor/I2P daemon, which
                         # can take 30-50 seconds from a cold start.
    negotiationTimer = None

    def __init__(self, logparent=None):
        self._logparent = log.msg("Negotiation started", parent=logparent,
                                  facility="foolscap.negotiation")
        for i in range(self.minVersion, self.maxVersion+1):
            assert hasattr(self, "evaluateNegotiationVersion%d" % i), i
            assert hasattr(self, "acceptDecisionVersion%d" % i), i
        assert isinstance(self.initialVocabTableRange, tuple)
        self.negotiationOffer = {
            "banana-negotiation-range": "%d %d" % (self.minVersion,
                                                   self.maxVersion),
            "initial-vocab-table-range": "%d %d" % self.initialVocabTableRange,
            }
        # TODO: for testing purposes, it might be useful to be able to add
        # some keys to this offer
        if self.forceNegotiation is not None:
            # TODO: decide how forcing should work. Maybe forceNegotiation
            # should be a dict of keys or something. distinguish between
            # offer and decision.
            self.negotiationOffer['negotiation-forced'] = "True"
        self.buffer = ""
        self._test_options = {}
        # to trigger specific race conditions during unit tests, it is useful
        # to allow certain operations to be stalled for a moment.
        # self._test_options will contain a key like
        # debug_slow_connectionMade to indicate that there should be a 1
        # second delay between the real connectionMade and the time our
        # self.connectionMade() method is invoked. To support this, the first
        # time connectionMade() is invoked,
        # self.debugTimers['connectionMade'] is set to a 1s DelayedCall,
        # which fires self.debug_fireTimer('connectionMade', callable,
        # *args). That will set self.debugTimers['connectionMade'] to None,
        # so the condition is not fired again, then invoke the actual
        # connectionMade method. When the connection is lost, all remaining
        # timers will be canceled.
        self.debugTimers = {}

        # if anything goes wrong during negotiation (version mismatch,
        # malformed headers, assertion checks), we stash the Failure in this
        # attribute and then drop the connection. For client-side
        # connections, we notify our parent TubConnector when the
        # connectionLost() message is finally delivered.
        self.failureReason = None

    def log(self, *args, **kwargs):
        # we log as NOISY by default, because nobody should hear about
        # negotiation unless it goes wrong.
        if 'parent' not in kwargs:
            kwargs['parent'] = self._logparent
        if 'facility' not in kwargs:
            kwargs['facility'] = "foolscap.negotiation"
        if 'level' not in kwargs:
            kwargs['level'] = log.NOISY
        return log.msg(*args, **kwargs)

    def initClient(self, connector, targetHost):
        # clients do connectTCP and speak first with a GET
        self.log("initClient: to target %s" % connector.target,
                 target=connector.target.getTubID())
        self.isClient = True
        self.tub = connector.tub
        self.brokerClass = self.tub.brokerClass
        self.myTubID = self.tub.tubID
        self.connector = connector
        self.target = connector.target
        self.targetHost = targetHost
        self._test_options = self.tub._test_options.copy()
        tubID = self.target.getTubID()
        slave_record = self.tub.slave_table.get(tubID, ("none",0))
        assert isinstance(slave_record, tuple), slave_record
        self.negotiationOffer['last-connection'] = "%s %s" % slave_record

    def initServer(self, listener):
        # servers do listenTCP and respond to the GET
        self.log("initServer", listener=repr(listener))
        self.isClient = False
        self.listener = listener
        self._test_options = self.listener._test_options.copy()
        # the broker class is set when we find out which Tub we should use

    def parseLines(self, header):
        lines = header.split("\r\n")
        block = {}
        for line in lines:
            colon = line.index(":")
            key = line[:colon].lower()
            value = line[colon+1:].lstrip()
            block[key] = value
        return block

    def sendBlock(self, block):
        keys = block.keys()
        keys.sort()
        for k in keys:
            self.transport.write("%s: %s\r\n" % (k.lower(), block[k]))
        self.transport.write("\r\n") # end block

    def debug_doTimer(self, name, timeout, call, *args):
        if (self._test_options.has_key("debug_slow_%s" % name) and
            not self.debugTimers.has_key(name)):
            self.log("debug_doTimer(%s)" % name)
            t = reactor.callLater(timeout, self.debug_fireTimer, name)
            self.debugTimers[name] = (t, [(call, args)])
            cb = self._test_options["debug_slow_%s" % name]
            if cb is not None and cb is not True:
                cb()
            return True
        return False

    def debug_addTimerCallback(self, name, call, *args):
        if self.debugTimers.get(name):
            self.debugTimers[name][1].append((call, args))
            return True
        return False

    def debug_forceTimer(self, name):
        if self.debugTimers.get(name):
            self.debugTimers[name][0].cancel()
            self.debug_fireTimer(name)

    def debug_forceAllTimers(self):
        for name in self.debugTimers:
            if self.debugTimers.get(name):
                self.debugTimers[name][0].cancel()
                self.debug_fireTimer(name)

    def debug_cancelAllTimers(self):
        for name in self.debugTimers:
            if self.debugTimers.get(name):
                self.debugTimers[name][0].cancel()
                self.debugTimers[name] = None

    def debug_fireTimer(self, name):
        calls = self.debugTimers[name][1]
        self.debugTimers[name] = None
        for call,args in calls:
            call(*args)

    def connectionMade(self):
        # once connected, this Negotiation instance must either invoke
        # self.switchToBanana or self.negotiationFailed, to insure that the
        # TubConnector (if any) gets told about the results of the connection
        # attempt.

        if self.doNegotiation:
            if self.isClient:
                self.connectionMadeClient()
            else:
                self.connectionMadeServer()
        else:
            self.switchToBanana({})

    def connectionMadeClient(self):
        assert self.receive_phase == PLAINTEXT
        # the client needs to send the HTTP-compatible tubid GET,
        # along with the TLS upgrade request
        self.sendPlaintextClient()
        # now we wait for the TLS Upgrade acceptance to come back

    def sendPlaintextClient(self):
        req = []
        self.log("sendPlaintextClient: GET for tubID %s" %
                 self.target.tubID)
        req.append("GET /id/%s HTTP/1.1" % self.target.tubID)
        req.append("Host: %s" % self.targetHost)
        self.log("sendPlaintextClient: wantEncryption=True")
        req.append("Upgrade: TLS/1.0")
        req.append("Connection: Upgrade")
        self.transport.write("\r\n".join(req))
        self.transport.write("\r\n\r\n")
        # the next thing the other end expects to see is the encrypted phase
        self.send_phase = ENCRYPTED

    def connectionMadeServer(self):
        # the server just waits for the GET message to arrive, but set up the
        # server timeout first
        if self.debug_doTimer("connectionMade", 1, self.connectionMade):
            return
        timeout = self._test_options.get('server_timeout', self.SERVER_TIMEOUT)
        if timeout:
            # oldpb clients will hit this case.
            self.negotiationTimer = reactor.callLater(timeout,
                                                      self.negotiationTimedOut)

    def sendError(self, why):
        pass # TODO

    def negotiationTimedOut(self):
        del self.negotiationTimer
        why = Failure(NegotiationError("negotiation timeout"))
        self.sendError(why)
        self.failureReason = why
        self.transport.loseConnection()

    def stopNegotiationTimer(self):
        if self.negotiationTimer:
            self.negotiationTimer.cancel()
            del self.negotiationTimer

    def dataReceived(self, chunk):
        self.log("dataReceived(isClient=%s,phase=%s,options=%s): %r"
                 % (self.isClient, self.receive_phase, self._test_options,
                    chunk),
                 level=NOISY)
        if self.receive_phase == ABANDONED:
            return

        self.buffer += chunk

        if self.debug_addTimerCallback("connectionMade",
                                       self.dataReceived, ''):
            return

        try:
            # we accumulate a header block for each phase
            if len(self.buffer) > 4096:
                raise BananaError("Header too long")
            eoh = self.buffer.find('\r\n\r\n')
            if eoh == -1:
                return
            header, self.buffer = self.buffer[:eoh], self.buffer[eoh+4:]
            if self.receive_phase == PLAINTEXT:
                if self.isClient:
                    self.handlePLAINTEXTClient(header)
                else:
                    self.handlePLAINTEXTServer(header)
            elif self.receive_phase == ENCRYPTED:
                self.handleENCRYPTED(header)
            elif self.receive_phase == DECIDING:
                self.handleDECIDING(header)
            else:
                assert 0, "should not get here"
            # there might be some leftover data for the next phase.
            # self.buffer will be emptied when we switchToBanana, so in that
            # case we won't call the wrong dataReceived.
            if self.buffer:
                self.dataReceived("")

        except Exception, e:
            why = Failure()
            if isinstance(e, RemoteNegotiationError):
                pass # they've already hung up
            else:
                # there's a chance we can provide a little bit more information
                # to the other end before we hang up on them
                if isinstance(e, NegotiationError):
                    errmsg = str(e)
                else:
                    self.log("negotiation had internal error:", failure=why,
                             level=UNUSUAL)
                    errmsg = "internal server error, see logs"
                errmsg = errmsg.replace("\n", " ").replace("\r", " ")
                if self.send_phase == PLAINTEXT:
                    resp = ("HTTP/1.1 500 Internal Server Error: %s\r\n\r\n"
                            % errmsg)
                    self.transport.write(resp)
                elif self.send_phase in (ENCRYPTED, DECIDING):
                    block = {'banana-decision-version': 1,
                             'error': errmsg,
                             }
                    self.sendBlock(block)
                elif self.send_phase == BANANA:
                    self.sendBananaError(errmsg)

            self.failureReason = why
            self.transport.loseConnection()
            return

    def sendBananaError(self, msg):
        if len(msg) > SIZE_LIMIT:
            msg = msg[:SIZE_LIMIT-10] + "..."
        int2b128(len(msg), self.transport.write)
        self.transport.write(ERROR)
        self.transport.write(msg)
        # now you should drop the connection

    def connectionLost(self, reason):
        # force connectionMade to happen, so connectionLost can occur
        # normally
        self.debug_forceTimer("connectionMade")
        # cancel the other slowdown timers, since they all involve sending
        # data, and the connection is no longer available
        self.debug_cancelAllTimers()
        for k,t in self.debugTimers.items():
            if t:
                t[0].cancel()
                self.debugTimers[k] = None
        if self.isClient:
            l = self.tub._test_options.get("debug_gatherPhases")
            if l is not None:
                l.append(self.receive_phase)
        if not self.failureReason:
            self.failureReason = reason
        self.negotiationFailed()

    def handlePLAINTEXTServer(self, header):
        # the client sends us a GET message
        lines = header.split("\r\n")
        if not lines[0].startswith("GET "):
            raise BananaError("not right")
        command, url, version = lines[0].split()
        if not url.startswith("/id/"):
            # probably a web browser
            raise BananaError("not right")
        targetTubID = url[4:]
        self.log("handlePLAINTEXTServer: targetTubID='%s'" % targetTubID,
                 level=NOISY)
        if targetTubID == "":
            # they're asking for an old UnauthenticatedTub. Refuse.
            raise NegotiationError("secure Tubs require encryption")
        if isSubstring("Upgrade: TLS/1.0\r\n", header):
            wantEncrypted = True
        else:
            wantEncrypted = False
        self.log("handlePLAINTEXTServer: wantEncrypted=%s" % wantEncrypted,
                 level=NOISY)
        # we ignore the rest of the lines

        # now that we know which Tub the client wants to connect to, either
        # send a Redirect, or start the ENCRYPTED phase

        tub, redirect = self.listener.lookupTubID(targetTubID)
        if tub:
            self.tub = tub # our tub
            self._test_options.update(self.tub._test_options)
            self.brokerClass = self.tub.brokerClass
            self.myTubID = tub.tubID
            self.sendPlaintextServerAndStartENCRYPTED()
        elif redirect:
            self.sendRedirect(redirect)
        else:
            raise NegotiationError("unknown TubID %s" % targetTubID)

    def sendPlaintextServerAndStartENCRYPTED(self):
        # this is invoked on the server side
        if self.debug_doTimer("sendPlaintextServer", 1,
                              self.sendPlaintextServerAndStartENCRYPTED):
            return
        resp = "\r\n".join(["HTTP/1.1 101 Switching Protocols",
                            "Upgrade: TLS/1.0, PB/1.0",
                            "Connection: Upgrade",
                            ])
        self.transport.write(resp)
        self.transport.write("\r\n\r\n")
        # the next thing they expect is the encrypted block
        self.send_phase = ENCRYPTED
        self.startENCRYPTED()

    def sendRedirect(self, redirect):
        # this is invoked on the server side
        # send the redirect message, then close the connection. make sure the
        # data gets flushed, though.
        raise NotImplementedError # TODO

    def handlePLAINTEXTClient(self, header):
        self.log("handlePLAINTEXTClient: header='%s'" % header)
        lines = header.split("\r\n")
        tokens = lines[0].split()
        # TODO: accept a 303 redirect
        if tokens[1] != "101":
            raise BananaError("not right, got '%s', "
                              "expected 101 Switching Protocols"
                              % lines[0])
        if not isSubstring("Upgrade: TLS/1.0", header):
            raise BananaError("header didn't contain TLS upgrade: %r" % (header,))
        # we ignore everything else

        # now we upgrade to TLS
        self.startENCRYPTED()
        # and wait for their Hello to arrive

    def startENCRYPTED(self):
        # this is invoked on both sides. We move to the "ENCRYPTED" phase,
        # which involves a TLS-encrypted session.
        self.log("startENCRYPTED(isClient=%s)" % (self.isClient,))
        self.startTLS(self.tub.myCertificate)
        # TODO: can startTLS trigger dataReceived?
        self.receive_phase = ENCRYPTED
        self.sendHello()

    def sendHello(self):
        """This is called on both sides as soon as the encrypted connection
        is established. This causes a negotiation block to be sent to the
        other side as an offer."""
        if self.debug_doTimer("sendHello", 1, self.sendHello):
            return

        hello = self.negotiationOffer.copy()

        assert self.myTubID
        # This indicates which identity we wish to claim. This is the hash of
        # the certificate we're using.
        hello['my-tub-id'] = self.myTubID

        if self.tub:
            IR = self.tub.getIncarnationString()
            hello['my-incarnation'] = IR

        self.log("Negotiate.sendHello (isClient=%s): %s" %
                 (self.isClient, hello))
        self.sendBlock(hello)


    def handleENCRYPTED(self, header):
        # both ends have sent a Hello message
        if self.debug_addTimerCallback("sendHello",
                                       self.handleENCRYPTED, header):
            return
        self.theirCertificate = None
        # We should be encrypted now. Get the peer's certificate.
        them = crypto.peerFromTransport(self.transport)
        if them and them.original:
            self.theirCertificate = them

        hello = self.parseLines(header)
        if hello.has_key("error"):
            raise RemoteNegotiationError(hello["error"])
        self.evaluateHello(hello)

    def evaluateHello(self, offer):
        """Evaluate the HELLO message sent by the other side. We compare
        TubIDs, and the higher value becomes the 'master' and makes the
        negotiation decisions.

        This method returns a tuple of DECISION,PARAMS. There are a few
        different possibilities::

            - We are the master, we make a negotiation decision: DECISION is
            the block of data to send back to the non-master side, PARAMS are
            the connection parameters we will use ourselves.

            - We are the master, we can't accomodate their request: raise
            NegotiationError

            - We are not the master: DECISION is None
        """

        self.log("evaluateHello(isClient=%s): offer=%s" %
                 (self.isClient, offer))
        if not offer.has_key('banana-negotiation-range'):
            if offer.has_key('banana-negotiation-version'):
                msg = ("Peer is speaking foolscap-0.0.5 or earlier, "
                       "which is not compatible with this version. "
                       "Please upgrade the peer.")
                raise NegotiationError(msg)
            raise NegotiationError("No valid banana-negotiation sequence seen")
        min_s, max_s = offer['banana-negotiation-range'].split()
        theirMinVer = int(min_s)
        theirMaxVer = int(max_s)
        # best_overlap() might raise a NegotiationError
        best = best_overlap(self.minVersion, self.maxVersion,
                            theirMinVer, theirMaxVer,
                            "banana version")

        negfunc = getattr(self, "evaluateNegotiationVersion%d" % best)
        self.decision_version = best
        return negfunc(offer)

    def evaluateNegotiationVersion1(self, offer):
        forced = False
        f = offer.get('negotiation-forced', None)
        if f and f.lower() == "true":
            forced = True
        # 'forced' means the client is on a one-way link (or is really
        # stubborn) and has already made up its mind about the connection
        # parameters. If we are unable to handle exactly what they have
        # offered, we must hang up.
        assert not forced # TODO: implement


        # glyph says: look at Juice, it does rfc822 parsing, startTLS,
        # switch-to-other-protocol, etc. grep for retrieveConnection in q2q.

        # TODO: oh, if we see an HTTP client, send a good HTTP error like
        # "protocol not supported", or maybe even an HTML page that explains
        # what a PB server is

        # there are four distinct dicts here:
        #  self.negotiationOffer: what we want
        #  clientOffer: what they sent to us, the client's requests.
        #  serverOffer: what we send to them, the server's decision
        #  self.negotiationResults: the negotiated settings
        #
        # [my-tub-id] is not present in self.negotiationResults
        # the server's tubID is in [my-tub-id] for both self.negotiationOffer
        # and serverOffer
        # the client's tubID is in [my-tub-id] for clientOffer

        myTubID = self.myTubID

        theirTubID = offer.get("my-tub-id")
        if self.theirCertificate is None:
            # no client certificate
            if theirTubID is not None:
                # this is where a poor MitM attack is detected, one which
                # doesn't even pretend to encrypt the connection
                raise BananaError("you must use a certificate to claim a "
                                  "TubID")
        else:
            # verify that their claimed TubID matches their SSL certificate.
            # TODO: handle chains
            digest = crypto.digest32(self.theirCertificate.digest("sha1"))
            if digest != theirTubID:
                # this is where a good MitM attack is detected, one which
                # encrypts the connection but which of course uses the wrong
                # certificate
                raise BananaError("TubID mismatch")

        assert theirTubID
        theirTubRef = referenceable.TubRef(theirTubID)
        self.theirTubRef = theirTubRef # for use by non-master side, later

        if self.isClient:
            # verify that we connected to the Tub we expected to.
            if theirTubRef != self.target:
                # TODO: how (if at all) should this error message be
                # communicated to the other side?
                raise BananaError("connected to the wrong Tub")

        if myTubID is None and theirTubID is None:
            iAmTheMaster = not self.isClient
        elif myTubID is None:
            iAmTheMaster = False
        elif theirTubID is None:
            iAmTheMaster = True
        else:
            # this is the most common case
            iAmTheMaster = myTubID > theirTubID

        self.log(format="iAmTheMaster: %(master)s", master=iAmTheMaster)

        decision, params = None, None

        if iAmTheMaster:
            # we get to decide everything. The other side is now waiting for
            # a decision block.
            self.send_phase = DECIDING
            decision = {}
            params = {}
            # combine their 'offer' and our own self.negotiationOffer to come
            # up with a 'decision' to be sent back to the other end, and the
            # 'params' to be used on our connection

            # first, do we continue with this connection? we might have an
            # existing connection for this particular tub

            if theirTubRef and theirTubRef in self.tub.brokers:
                # there is an existing connection.. we might want to prefer
                # this new offer, because the old connection might be stale
                # (NAT boxes and laptops that disconnect abruptly are two
                # ways for a single process to disappear silently and then
                # reappear with a different IP address).
                lp = self.log("got offer for an existing connection",
                              level=UNUSUAL)
                existing = self.tub.brokers[theirTubRef]
                acceptOffer = self.compareOfferAndExisting(offer, existing, lp)
                if acceptOffer:
                    # drop the old one
                    self.log("accepting new offer, dropping existing connection",
                             parent=lp)
                    err = DeadReferenceError("[%s] replaced by a new connection"
                                             % theirTubRef.getShortTubID())
                    why = Failure(err)
                    existing.shutdown(why)
                else:
                    # reject the new one
                    self.log("rejecting the offer: we already have one",
                             parent=lp)
                    raise DuplicateConnection("Duplicate connection")

            if theirTubRef:
                # generate a new seqnum, one higher than the last one we've
                # used.
                old_seqnum = self.tub.master_table.get(theirTubRef.getTubID(),
                                                       0)
                new_seqnum = old_seqnum + 1
                new_slave_IR = offer.get('my-incarnation', None)
                self.tub.master_table[theirTubRef.getTubID()] = new_seqnum
                my_IR = self.tub.getIncarnationString()
                decision['current-connection'] = "%s %s" % (my_IR, new_seqnum)
                # these params will be copied into the Broker where we can
                # retrieve them later, when we need to compare it against a new
                # offer.
                params['current-slave-IR'] = new_slave_IR
                params['current-seqnum'] = new_seqnum

            # what initial vocab set should we use?
            theirVocabRange_s = offer.get("initial-vocab-table-range", "0 0")
            theirVocabRange = theirVocabRange_s.split()
            theirVocabMin = int(theirVocabRange[0])
            theirVocabMax = int(theirVocabRange[1])
            vocab_index = best_overlap(
                self.initialVocabTableRange[0],
                self.initialVocabTableRange[1],
                theirVocabMin, theirVocabMax,
                "initial vocab set")
            vocab_hash = vocab.hashVocabTable(vocab_index)
            decision['initial-vocab-table-index'] = "%d %s" % (vocab_index,
                                                               vocab_hash)
            decision['banana-decision-version'] = str(self.decision_version)

            # v1: handle vocab table index
            params['banana-decision-version'] = self.decision_version
            params['initial-vocab-table-index'] = vocab_index

        else:
            # otherwise, the other side gets to decide. The next thing they
            # expect to hear from us is banana.
            self.send_phase = BANANA


        if iAmTheMaster:
            # I am the master, so I send the decision
            self.log("Negotiation.sendDecision: %s" % decision,
                     level=OPERATIONAL)
            # now we send the decision and switch to Banana. they might hang
            # up.
            self.sendDecision(decision, params)
        else:
            # I am not the master, I receive the decision
            self.receive_phase = DECIDING

    def evaluateNegotiationVersion2(self, offer):
        # version 2 changes the meaning of reqID=0 in a 'call' sequence, to
        # support the implementation of callRemoteOnly. No other protocol
        # changes were made, and no changes were made to the offer or
        # decision blocks.
        return self.evaluateNegotiationVersion1(offer)

    def evaluateNegotiationVersion3(self, offer):
        # version 3 adds PING and PONG tokens, to enable keepalives and
        # idle-disconnect. No other protocol changes were made, and no
        # changes were made to the offer or decision blocks.
        return self.evaluateNegotiationVersion1(offer)

    def compareOfferAndExisting(self, offer, existing, lp):
        """Compare the new offer against the existing connection, and
        decide which to keep.

        @return: True to accept the new offer, False to stick with the
                 existing connection.
        """

        def log(*args, **kwargs):
            if 'parent' not in kwargs:
                kwargs['parent'] = lp
            return self.log(*args, **kwargs)

        existing_slave_IR = existing.current_slave_IR
        existing_seqnum = existing.current_seqnum

        log(format="existing connection has slave_IR=%(slave_IR)s, seqnum=%(seqnum)s",
            slave_IR=existing_slave_IR, seqnum=existing_seqnum)

        # TESTING: force handle-old stuff
        #lp2 = log("TESTING: forcing use of handle-old logic")
        #return self.handle_old(offer, existing, 60, lp2)

        # step one: does the inbound offer have a my-incarnation header? If
        # not, this is an older peer (<foolscap-0.1.7). We use
        # offer.get("my-incarnation") instead of "my-incarnation" in offer
        # so that unit tests can cause a client to send an empty string to
        # simulate the earlier version.
        if not offer.get("my-incarnation") or "last-connection" not in offer:
            # TODO: new servers send my-incarnation but not last-connection

            # this is an old peer (foolscap 0.1.7 or earlier), which won't
            # give us enough information to make some of the decisions below.
            # We reject the offer to avoid connection flap, and the
            # situtation won't be worse than it was in 0.1.7 .
            lp2 = log("pre-0.2.0 peer detected (no my-incarnation"
                      " or last-connection)", level=CURIOUS)
            if self.tub._handle_old_duplicate_connections is not False:
                # but if we've been configured to do better (with the
                # 60-second age heuristic), do that.
                self.log("using handle-old-duplicate-connections", parent=lp2)
                threshold = self.tub._handle_old_duplicate_connections
                return self.handle_old(offer, existing, threshold, lp2)
            return False # reject the offer

        if offer["my-incarnation"] != existing_slave_IR:
            # this offer is from a different invocation of the peer than we
            # think we're currently talking to. That means the slave has
            # restarted since we made our connection, so clearly our
            # connection is stale. Accept the offer.
            log("offer is from different peer incarnation than existing")
            return True # accept

        pieces = offer['last-connection'].split()
        offer_master_IR = pieces[0]
        offer_master_seqnum = int(pieces[1])

        if offer_master_IR == "none":
            # the peer doesn't remember talking to anybody: they don't think
            # they've ever been connected to us. We disagree, and we remember
            # their incarnation record. So they must have made an initial
            # attempt to connect to us (their first), we accepted their
            # connection, and the decision message got lost or hasn't arrived
            # yet. The most likely situation is that this is one of the
            # parallel connections (one per hint), for which we want to
            # reject their offer. The less likely situation is that they
            # heard our initial connection setup but the decision message got
            # lost, in which case we entry the "no reconnects until TCP gives
            # up" state.
            log("peer doesn't remember talking to us")
            return False # reject

        if offer_master_IR != self.tub.getIncarnationString():
            # the peer doesn't remember talking to us specifically, but they
            # remember talking to one of our past lives. That means our last
            # decision message didn't make it to them, and the last
            # connection they *did* hear about was from one of our previous
            # runs. Therefore our existing connection isn't viable, and we
            # should accept their offer.
            #
            log("peer remembers talking to our past life")
            return True # accept

        # at this point, the offer's IR matches our own, so the seqnum is
        # worth comparing
        if offer_master_seqnum == existing_seqnum:
            # the offer demonstrates that the client knows about the same
            # connection that we do, and they made a new connection anyways.
            # From this we can conclude that our connection is stale, so we
            # should accept the offer.
            log("peer knows about existing seqnum")
            return True

        if offer_master_seqnum < existing_seqnum:
            # Possible ways to get here, most likely first
            #  1: simultaneous parallel connections (multiple hints),
            #     from a client who used to have an established connection
            #     with us (so they're sending the right offer_master_IR).
            #     Reject the offer to avoid connection flap.
            #  2: client connected, but our decision got lost, they're still
            #     living in the past. Reject the offer, we'll enter the
            #     no-reconnect-until-TCP-gives-up state
            #  3: crazy stalled message case, again we wait for TCP to expire

            # more details on #2: the client connects successfully, then the
            # client thinks the connection has been lost (but the server
            # thinks it's still good), so the client reconnects, and this
            # connection gets as far as the master making a decision, but the
            # decision message is lost before it gets to the client. Then the
            # client connects a third time, and now we're considering the
            # third offer: the IRs are all the same, the attempt_id is
            # different than our existing (2nd) connection, but the seqnum is
            # older. In this case, we want to accept the new offer.


            # more details on #3 (more rare): the client connects and loses
            # the connection (as before), then the client connects a second
            # time and gets as far as sending the offer when they time out,
            # cancelling the negotiation already in progress (sending a FIN
            # after the offer message) and triggering a third connection. The
            # third connection somehow races ahead and completes negotiation
            # before the 2nd-connection offer+FIN make it to the server. Now,
            # finally, the offer arrives: we're now evaluating an
            # out-of-order offer on a socket that's about to be closed.
            # Ideally we'd like to reject this offer.

            log("peer knows about old seqnum")
            return False # reject

        # offer_master_seqnum > existing_seqnum indicates something really
        # weird has taken place.
        log(format="offer_master_seqnum %(offer)d > existing_seqnum %(existing)d",
            offer=offer_master_seqnum, existing=existing_seqnum, level=WEIRD)
        return False # reject weirdness

    def handle_old(self, offer, existing, threshold, lp):
        # determine the age of the existing broker
        age = time.time() - existing.creation_timestamp
        if age < threshold:
            self.log("the existing broker is too new (%d<%d), rejecting offer"
                     % (age, threshold),
                     parent=lp)
            return False # reject the offer
        self.log("the existing broker is old enough to replace", parent=lp)
        return True # accept the offer

    def sendDecision(self, decision, params):
        if self.debug_doTimer("sendDecision", 1,
                              self.sendDecision, decision, params):
            return
        if self.debug_addTimerCallback("sendHello",
                                       self.sendDecision, decision, params):
            return
        self.sendBlock(decision)
        self.send_phase = BANANA
        self.switchToBanana(params)

    def handleDECIDING(self, header):
        # this gets called on the non-master side
        self.log("handleDECIDING(isClient=%s): %s" % (self.isClient, header),
                 level=NOISY)
        if self.debug_doTimer("handleDECIDING", 1,
                              self.handleDECIDING, header):
            # for testing purposes, wait a moment before accepting the
            # decision. This insures that we trigger the "Duplicate
            # Broker" condition. NOTE: This will interact badly with the
            # "there might be some leftover data for the next phase" call
            # in dataReceived
            return
        decision = self.parseLines(header)
        params = self.acceptDecision(decision)
        self.switchToBanana(params)

    def acceptDecision(self, decision):
        """This is called on the client end when it receives the results of
        the negotiation from the server. The client must accept this decision
        (and return the connection parameters dict), or raise
        NegotiationError to hang up.negotiationResults."""
        self.log("Banana.acceptDecision: got %s" % decision, level=OPERATIONAL)

        version = decision.get('banana-decision-version')
        if not version:
            raise NegotiationError("No banana-decision-version value")
        acceptfunc = getattr(self, "acceptDecisionVersion%d" % int(version))
        if not acceptfunc:
            raise NegotiationError("I cannot handle banana-decision-version "
                                   "value of %d" % int(version))
        return acceptfunc(decision)

    def acceptDecisionVersion1(self, decision):
        if decision.has_key("error"):
            error = decision["error"]
            raise RemoteNegotiationError("Banana negotiation failed: %s"
                                         % error)

        # parse the decision here, create the connection parameters dict
        ver = int(decision['banana-decision-version'])
        vocab_index_string = decision.get('initial-vocab-table-index')
        if vocab_index_string:
            vocab_index, vocab_hash = vocab_index_string.split()
            vocab_index = int(vocab_index)
        else:
            vocab_index = 0
        check_inrange(self.initialVocabTableRange[0],
                      self.initialVocabTableRange[1],
                      vocab_index, "initial vocab table index")
        our_hash = vocab.hashVocabTable(vocab_index)
        if vocab_index > 0 and our_hash != vocab_hash:
            msg = ("Our hash for vocab-table-index %d (%s) does not match "
                   "your hash (%s)" % (vocab_index, our_hash, vocab_hash))
            raise NegotiationError(msg)

        if self.theirTubRef in self.tub.brokers:
            # we're the slave, so we need to drop our existing connection and
            # use the one picked by the master
            self.log("master told us to use a new connection, "
                     "so we must drop the existing one", level=UNUSUAL)
            err = DeadReferenceError("replaced by a new connection")
            why = Failure(err)
            self.tub.brokers[self.theirTubRef].shutdown(why)

        current_connection = decision.get('current-connection')
        if current_connection:
            tubID = self.theirTubRef.getTubID()
            self.tub.slave_table[tubID] = tuple(current_connection.split())
        else:
            self.log("no current-connection in decision from %s" %
                     self.theirTubRef, level=UNUSUAL)

        params = { 'banana-decision-version': ver,
                   'initial-vocab-table-index': vocab_index,
                   }
        return params

    def acceptDecisionVersion2(self, decision):
        # this only affects the interpretation of reqID=0, so we can use the
        # same accept function
        return self.acceptDecisionVersion1(decision)

    def acceptDecisionVersion3(self, decision):
        # this adds PING and PONG tokens, so we can use the same accept
        # function
        return self.acceptDecisionVersion1(decision)

    def loopbackDecision(self):
        # if we were talking to ourselves, what negotiation decision would we
        # reach? This is used for loopback connections
        max_vocab = self.initialVocabTableRange[1]
        params = { 'banana-decision-version': self.maxVersion,
                   'initial-vocab-table-index': max_vocab,
                   }
        return params

    def startTLS(self, cert):
        # the TLS connection (according to glyph) is "ready" immediately, but
        # really the negotiation is going on behind the scenes (OpenSSL is
        # trying a little too hard to be transparent). I think you have to
        # write some bytes to trigger the negotiation. getPeerCertificate()
        # can't be called until you receive some bytes, so grab it when a
        # negotiation block arrives that claims to have an authenticated
        # TubID.

        # Instead of this:
        #  opts = self.tub.myCertificate.options()
        # We use the MyOptions class to fix up the verify stuff: we request a
        # certificate from the client, but do not verify it against a list of
        # root CAs
        self.log("startTLS, client=%s" % self.isClient)
        kwargs = {}
        if cert:
            kwargs['privateKey'] = cert.privateKey.original
            kwargs['certificate'] = cert.original
        ctxFactory = crypto.FoolscapContextFactory(**kwargs)

        self.transport.startTLS(ctxFactory)

    def switchToBanana(self, params):
        # switch over to the new protocol (a Broker instance). This
        # Negotiation protocol goes away after this point.

        lp = self.log("Negotiate.switchToBanana(isClient=%s)" % self.isClient,
                      level=NOISY)
        self.log("params: %s" % (params,), parent=lp)

        self.stopNegotiationTimer()

        if self.isClient:
            theirTubRef = self.target
        else:
            theirTubRef = self.theirTubRef

        b = self.brokerClass(theirTubRef, params,
                             self.tub.keepaliveTimeout,
                             self.tub.disconnectTimeout,
                             )
        b.factory = self.factory # not used for PB code
        b.setTub(self.tub)
        # we leave ourselves as the protocol, but redirect incoming messages
        # (from the transport) to the broker
        #self.transport.protocol = b
        self.dataReceived = b.dataReceived
        self.connectionLost = b.connectionLost

        b.makeConnection(self.transport)
        buf, self.buffer = self.buffer, "" # empty our buffer, just in case
        b.dataReceived(buf) # and hand it to the new protocol

        # if we were created as a client, we'll have a TubConnector. Let them
        # know that this connection has succeeded, so they can stop any other
        # connection attempts still in progress.
        if self.isClient:
            self.connector.negotiationComplete(self)

        # finally let our Tub know that they can start using the new Broker.
        # This will wake up anyone who initiated an outbound connection.
        self.tub.brokerAttached(theirTubRef, b, self.isClient)

    def negotiationFailed(self):
        reason = self.failureReason
        self.stopNegotiationTimer()
        if self.receive_phase != ABANDONED and self.isClient:
            eventually(self.connector.negotiationFailed, self, reason)
        self.receive_phase = ABANDONED
        cb = self._test_options.get("debug_negotiationFailed_cb")
        if cb:
            # note that this gets called with a NegotiationError, not a
            # Failure. ACTUALLY: not true, gets a Failure
            eventually(cb, reason)

        # Negotiations fail all the time, for benign reasons, so limit how
        # much we log (the full Failure and traceback is frequently useless
        # and noisy). Parallel connection-hints cause the slower connection
        # to be rejected as a duplicate, as do full-mesh applications (like
        # Tahoe) that construct cross-linked connections.
        if reason.check(DuplicateConnection):
            # this happens when we reject a connection during negotiation
            self.log("negotiationFailed: DuplicateConnection",
                     level=NOISY, umid="XRFlRA")
        elif reason.check(ConnectionDone):
            # this happens to our other losing parallel connection attempts
            self.log("negotiationFailed: ConnectionDone",
                     level=NOISY, umid="9khFxA")
        elif reason.check(RemoteNegotiationError):
            # and this is how the remote side tells us they rejected or
            # abandoned a connection. Sometimes it's due to a duplicate
            # connection, sometimes due to code problems. In either case, the
            # traceback would only show local code, and is unhelpful.
            self.log("negotiationFailed: remote: %s" % reason.value.args[0],
                     level=NOISY, umid="yAsbmA")
        else:
            # This shouldn't happen very often.
            self.log("negotiationFailed", failure=reason,
                     level=OPERATIONAL, umid="pm2kjg")

# TODO: make sure code that examines self.receive_phase handles ABANDONED
