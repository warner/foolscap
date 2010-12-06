
from referenceable import Referenceable

# wow there are a lot of classes here.

# The two main actors are Sam and Bob. Sam is the publically-visible
# "server", who runs the RelayService. Bob is running the target server, but
# lives behind a NAT box. (there is also Alice, who is a client that wants to
# talk to Bob, who gets a FURL that has Bob's tubid and Sam's connection
# hints). We also talk about Bob2, who is another NAT-bound server, and
# Alice2, who is a second client.

# Sam runs a single RelayService on each of his Listeners. The RelayService
# gets a FURL, which is provided to Bob so he can take advantage of the
# relay.

# Bob starts using the relay by setting up a RelayListener(tub, relay_furl)
# and then asking it for rl.getConnectionHints(). The RelayListener talks to
# Sam's RelayService, causing Sam to create a RelayClientHandler (which is
# specific to Bob: i.e. Bob2 will get a different RelayClientHandler). The
# RelayClientHandler retains a reference to Bob's RelayService.

# Then, when Alice connects to Sam,...


class RelayService(Referenceable):
    # I am remotely available to the client (who lives behind a NAT box).
    def __init__(self, listener):
        self.listener = listener

    def remote_relay_for_me(self, tubid, relay_client):
        # um, need to validate tubid. Really, they shouldn't get to provide
        # it at all. relay_client is an object on their end. We could use
        # relay_client.remote_tubid, but they could pass in a Gift, causing
        # us to send data for the 3rd-party Tub to an object of the 2nd
        # party's choosing (although the object would have to live on the 3rd
        # tub, it might not be a real RelayClient, which could be a
        # vulnerability).
        s = OneRelayService(relay_client)
        self.listener.addRelay(tubid, s)
        return XXX.getConnectionHints()

class OneRelayService(Referenceable):
    # I am locally passed to the server-side Negotiation object when its
    # Listener says it provides service for the given tubid.
    def __init__(self, remote_client):
        self.remote = remote_client

class RelayClient(Referenceable):
    def remote_new_connection(self, plaintext, remote):
        return RelayConnection(plaintext, remote)

class RelayClientProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.connectionMade(self)
    def send(self, data):
        self.transport.write(data)
    def dataReceived(self, data):
        self.factory.dataReceived(data)
    def connectionLost(self, why):
        self.factory.connectionLost(why)

class RelayConnection(Referenceable, ClientFactory):
    protocol = RelayClientProtocol
    def __init__(self, plaintext, remote, local_host, local_port):
        self.remote = remote
        self.remote.notifyOnDisconnect(self.disconnected)
        self.inbound_data = plaintext
        self.local = None
        reactor.connectTCP(local_host, local_port, self)

    def connectionMade(self, proto):
        self.local = proto
        self.local.send(self.inbound_data)
        del self.inbound_data
    def remote_receive_data(self, data):
        if self.local:
            self.local.send(data)
        else:
            self.inbound_data += data
    def dataReceived(self, data):
        self.remote.callRemoteOnly("send_data", data)
    def connectionLost(self, why):
        self.remote.callRemoteOnly("disconnect")
        # now this object goes away
        del self.remote
        del self.local
    def disconnected(self):
        self.transport.loseConnection()



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

    """

    myTubID = None
    tub = None
    theirTubID = None

    receive_phase = PLAINTEXT # we are expecting this
    send_phase = PLAINTEXT # the other end is expecting this

    SERVER_TIMEOUT = 60 # you have 60 seconds to complete negotiation, or else
    negotiationTimer = None

    def __init__(self, logparent=None):
        self._logparent = log.msg("Negotiation started", parent=logparent,
                                  facility="foolscap.negotiation")
        self.buffer = ""
        

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

    def initServer(self, listener):
        # servers do listenTCP and respond to the GET
        self.log("initServer", listener=repr(listener))
        self.isClient = False
        self.listener = listener
        self.options = self.listener.options.copy()
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

    def connectionMade(self):
        # once connected, this Negotiation instance must either invoke
        # self.switchToBanana or self.negotiationFailed, to insure that the
        # TubConnector (if any) gets told about the results of the connection
        # attempt.

        self.connectionMadeServer()

    def connectionMadeServer(self):
        # the server just waits for the GET message to arrive, but set up the
        # server timeout first
        timeout = self.options.get('server_timeout', self.SERVER_TIMEOUT)
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
                 % (self.isClient, self.receive_phase, self.options, chunk),
                 level=NOISY)
        if self.receive_phase == ABANDONED:
            return

        self.buffer += chunk

        try:
            # we accumulate a header block for each phase
            if len(self.buffer) > 4096:
                raise BananaError("Header too long")
            eoh = self.buffer.find('\r\n\r\n')
            if eoh == -1:
                return
            header, self.buffer = self.buffer[:eoh], self.buffer[eoh+4:]
            if self.receive_phase == PLAINTEXT:
                self.handlePLAINTEXTServer(header)
            else:
                assert 0, "should not get here"
            # there might be some leftover data for the next phase.
            # self.buffer will be emptied when we switchToBanana, so in that
            # case we won't call the wrong dataReceived.
            if self.buffer:
                self.dataReceived("")

        except Exception, e:
            why = Failure()
            self.log("negotiation had exception", failure=why)
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
            l = self.tub.options.get("debug_gatherPhases")
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
            targetTubID = None
        if isSubstring("Upgrade: TLS/1.0\r\n", header):
            wantEncrypted = True
        else:
            wantEncrypted = False
        self.log("handlePLAINTEXTServer: wantEncrypted=%s" % wantEncrypted,
                 level=NOISY)
        # we ignore the rest of the lines

        if wantEncrypted and not crypto_available:
            # this is a confused client, or a bad URL: if we don't have
            # crypto, we couldn't have created a pb:// URL.
            self.log("Negotiate.handlePLAINTEXTServer: client wants "
                     "encryption for TubID=%s but we have no crypto, "
                     "hanging up on them" % targetTubID,
                     level=UNUSUAL)
            # we could just not offer the encryption, but they won't be happy
            # with the results, since they wanted to connect to a specific
            # TubID.
            raise NegotiationError("crypto not available")

        if wantEncrypted and targetTubID is None:
            # we wouldn't know which certificate to use, so don't use
            # encryption at all, even though the client wants to. TODO: if it
            # is possible to do startTLS on the server side without a server
            # certificate, do that. It might be possible to do some sort of
            # ephemeral non-signed certificate.
            wantEncrypted = False

        if targetTubID is not None and not wantEncrypted:
            raise NegotiationError("secure Tubs require encryption")

        # now that we know which Tub the client wants to connect to, either
        # send a Redirect, or start the ENCRYPTED phase

        tub, redirect = self.listener.lookupTubID(targetTubID)
        if tub:
            self.tub = tub # our tub
            self.options.update(self.tub.options)
            self.brokerClass = self.tub.brokerClass
            self.myTubID = tub.tubID
            self.sendPlaintextServerAndStartENCRYPTED(wantEncrypted)
        elif redirect:
            self.sendRedirect(redirect)
        else:
            raise NegotiationError("unknown TubID %s" % targetTubID)

    def sendPlaintextServerAndStartENCRYPTED(self, encrypted):
        # this is invoked on the server side
        if self.debug_doTimer("sendPlaintextServer", 1,
                              self.sendPlaintextServerAndStartENCRYPTED,
                              encrypted):
            return
        if encrypted:
            resp = "\r\n".join(["HTTP/1.1 101 Switching Protocols",
                                "Upgrade: TLS/1.0, PB/1.0",
                                "Connection: Upgrade",
                                ])
        else:
            # TODO: see if this makes sense, I haven't read the HTTP spec
            resp = "\r\n".join(["HTTP/1.1 101 Switching Protocols",
                                "Upgrade: PB/1.0",
                                "Connection: Upgrade",
                                ])
        self.transport.write(resp)
        self.transport.write("\r\n\r\n")
        # the next thing they expect is the encrypted block
        self.send_phase = ENCRYPTED
        self.startENCRYPTED(encrypted)

    def sendRedirect(self, redirect):
        # this is invoked on the server side
        # send the redirect message, then close the connection. make sure the
        # data gets flushed, though.
        raise NotImplementedError # TODO
