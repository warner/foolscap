from zope.interface import implementer
from twisted.trial import unittest
from twisted.internet import defer, protocol, reactor
from twisted.internet.error import ConnectionRefusedError
from foolscap.api import RemoteInterface, Referenceable, flushEventualQueue, \
     BananaError, Tub
from foolscap.util import allocate_tcp_port
from foolscap.referenceable import RemoteReference
from foolscap.furl import encode_furl, decode_furl
from foolscap.test.common import (HelperTarget, RIHelper, ShouldFailMixin,
                                  MakeTubsMixin)
from foolscap.tokens import NegotiationError, Violation

class RIConstrainedHelper(RemoteInterface):
    def set(obj=RIHelper): return None


@implementer(RIConstrainedHelper)
class ConstrainedHelper(Referenceable):
    def __init__(self, name="unnamed"):
        self.name = name

    def remote_set(self, obj):
        self.obj = obj

class Base(ShouldFailMixin, MakeTubsMixin):

    debug = False

    def setUp(self):
        self.tubA, self.tubB, self.tubC, self.tubD = self.makeTubs(4)

    def tearDown(self):
        d = defer.DeferredList([s.stopService() for s in self.services])
        d.addCallback(flushEventualQueue)
        return d

    def createCharacters(self):
        self.alice = HelperTarget("alice")
        self.bob = HelperTarget("bob")
        self.bob_url = self.tubB.registerReference(self.bob, "bob")
        self.carol = HelperTarget("carol")
        self.carol_url = self.tubC.registerReference(self.carol, "carol")
        # cindy is Carol's little sister. She doesn't have a phone, but
        # Carol might talk about her anyway.
        self.cindy = HelperTarget("cindy")
        # more sisters. Alice knows them, and she introduces Bob to them.
        self.charlene = HelperTarget("charlene")
        self.christine = HelperTarget("christine")
        self.clarisse = HelperTarget("clarisse")
        self.colette = HelperTarget("colette")
        self.courtney = HelperTarget("courtney")
        self.dave = HelperTarget("dave")
        self.dave_url = self.tubD.registerReference(self.dave, "dave")

    def createInitialReferences(self):
        # we must start by giving Alice a reference to both Bob and Carol.
        if self.debug: print("Alice gets Bob")
        d = self.tubA.getReference(self.bob_url)
        def _aliceGotBob(abob):
            if self.debug: print("Alice got bob")
            self.abob = abob # Alice's reference to Bob
            if self.debug: print("Alice gets carol")
            d = self.tubA.getReference(self.carol_url)
            return d
        d.addCallback(_aliceGotBob)
        def _aliceGotCarol(acarol):
            if self.debug: print("Alice got carol")
            self.acarol = acarol # Alice's reference to Carol
            d = self.tubB.getReference(self.dave_url)
            return d
        d.addCallback(_aliceGotCarol)
        def _bobGotDave(bdave):
            self.bdave = bdave
        d.addCallback(_bobGotDave)
        return d

    def createMoreReferences(self):
        # give Alice references to Carol's sisters
        dl = []

        url = self.tubC.registerReference(self.charlene, "charlene")
        d = self.tubA.getReference(url)
        def _got_charlene(rref):
            self.acharlene = rref
        d.addCallback(_got_charlene)
        dl.append(d)

        url = self.tubC.registerReference(self.christine, "christine")
        d = self.tubA.getReference(url)
        def _got_christine(rref):
            self.achristine = rref
        d.addCallback(_got_christine)
        dl.append(d)

        url = self.tubC.registerReference(self.clarisse, "clarisse")
        d = self.tubA.getReference(url)
        def _got_clarisse(rref):
            self.aclarisse = rref
        d.addCallback(_got_clarisse)
        dl.append(d)

        url = self.tubC.registerReference(self.colette, "colette")
        d = self.tubA.getReference(url)
        def _got_colette(rref):
            self.acolette = rref
        d.addCallback(_got_colette)
        dl.append(d)

        url = self.tubC.registerReference(self.courtney, "courtney")
        d = self.tubA.getReference(url)
        def _got_courtney(rref):
            self.acourtney = rref
        d.addCallback(_got_courtney)
        dl.append(d)

        return defer.DeferredList(dl)

class Gifts(Base, unittest.TestCase):
    # Here we test the three-party introduction process as depicted in the
    # classic Granovetter diagram. Alice has a reference to Bob and another
    # one to Carol. Alice wants to give her Carol-reference to Bob, by
    # including it as the argument to a method she invokes on her
    # Bob-reference.

    def testGift(self):
        #defer.setDebugging(True)
        self.createCharacters()
        d = self.createInitialReferences()
        def _introduce(res):
            d2 = self.bob.waitfor()
            if self.debug: print("Alice introduces Carol to Bob")
            # send the gift. This might not get acked by the time the test is
            # done and everything is torn down, so we use callRemoteOnly
            self.abob.callRemoteOnly("set", obj=(self.alice, self.acarol))
            return d2 # this fires with the gift that bob got
        d.addCallback(_introduce)
        def _bobGotCarol(xxx_todo_changeme):
            (balice,bcarol) = xxx_todo_changeme
            if self.debug: print("Bob got Carol")
            self.bcarol = bcarol
            if self.debug: print("Bob says something to Carol")
            d2 = self.carol.waitfor()
            # handle ConnectionDone as described before
            self.bcarol.callRemoteOnly("set", obj=12)
            return d2
        d.addCallback(_bobGotCarol)
        def _carolCalled(res):
            if self.debug: print("Carol heard from Bob")
            self.assertEqual(res, 12)
        d.addCallback(_carolCalled)
        return d
    testGift.timeout = 10

    def testImplicitGift(self):
        # in this test, Carol was registered in her Tub (using
        # registerReference), but Cindy was not. Alice is given a reference
        # to Carol, then uses that to get a reference to Cindy. Then Alice
        # sends a message to Bob and includes a reference to Cindy. The test
        # here is that we can make gifts out of references that were not
        # passed to registerReference explicitly.

        #defer.setDebugging(True)
        self.createCharacters()
        # the message from Alice to Bob will include a reference to Cindy
        d = self.createInitialReferences()
        def _tell_alice_about_cindy(res):
            self.carol.obj = self.cindy
            cindy_d = self.acarol.callRemote("get")
            return cindy_d
        d.addCallback(_tell_alice_about_cindy)
        def _introduce(a_cindy):
            # alice now has references to carol (self.acarol) and cindy
            # (a_cindy). She sends both of them (plus a reference to herself)
            # to bob.
            d2 = self.bob.waitfor()
            if self.debug: print("Alice introduces Carol to Bob")
            # send the gift. This might not get acked by the time the test is
            # done and everything is torn down, so explicitly silence any
            # ConnectionDone error that might result. When we get
            # callRemoteOnly(), use that instead.
            self.abob.callRemoteOnly("set", obj=(self.alice,
                                                 self.acarol,
                                                 a_cindy))
            return d2 # this fires with the gift that bob got
        d.addCallback(_introduce)
        def _bobGotCarol(xxx_todo_changeme1):
            (b_alice,b_carol,b_cindy) = xxx_todo_changeme1
            if self.debug: print("Bob got Carol")
            self.assertTrue(b_alice)
            self.assertTrue(b_carol)
            self.assertTrue(b_cindy)
            self.bcarol = b_carol
            if self.debug: print("Bob says something to Carol")
            d2 = self.carol.waitfor()
            if self.debug: print("Bob says something to Cindy")
            d3 = self.cindy.waitfor()

            # handle ConnectionDone as described before
            b_carol.callRemoteOnly("set", obj=4)
            b_cindy.callRemoteOnly("set", obj=5)
            return defer.DeferredList([d2,d3])
        d.addCallback(_bobGotCarol)
        def _carolAndCindyCalled(res):
            if self.debug: print("Carol heard from Bob")
            ((carol_s, carol_result), (cindy_s, cindy_result)) = res
            self.assertTrue(carol_s)
            self.assertTrue(cindy_s)
            self.assertEqual(carol_result, 4)
            self.assertEqual(cindy_result, 5)
        d.addCallback(_carolAndCindyCalled)
        return d

    # test gifts in return values too

    def testReturn(self):
        self.createCharacters()
        d = self.createInitialReferences()
        def _introduce(res):
            self.bob.obj = self.bdave
            return self.abob.callRemote("get")
        d.addCallback(_introduce)
        def _check(adave):
            # this ought to be a RemoteReference to dave, usable by alice
            self.assertTrue(isinstance(adave, RemoteReference))
            return adave.callRemote("set", 12)
        d.addCallback(_check)
        def _check2(res):
            self.assertEqual(self.dave.obj, 12)
        d.addCallback(_check2)
        return d

    def testReturnInContainer(self):
        self.createCharacters()
        d = self.createInitialReferences()
        def _introduce(res):
            self.bob.obj = {"foo": [(set([self.bdave]),)]}
            return self.abob.callRemote("get")
        d.addCallback(_introduce)
        def _check(obj):
            adave = list(obj["foo"][0][0])[0]
            # this ought to be a RemoteReference to dave, usable by alice
            self.assertTrue(isinstance(adave, RemoteReference))
            return adave.callRemote("set", 12)
        d.addCallback(_check)
        def _check2(res):
            self.assertEqual(self.dave.obj, 12)
        d.addCallback(_check2)
        return d

    def testOrdering(self):
        self.createCharacters()
        self.bob.calls = []
        d = self.createInitialReferences()
        def _introduce(res):
            # we send three messages to Bob. The second one contains the
            # reference to Carol.
            dl = []
            dl.append(self.abob.callRemote("append", obj=1))
            dl.append(self.abob.callRemote("append", obj=self.acarol))
            dl.append(self.abob.callRemote("append", obj=3))
            return defer.DeferredList(dl)
        d.addCallback(_introduce)
        def _checkBob(res):
            # this runs after all three messages have been acked by Bob
            self.assertEqual(len(self.bob.calls), 3)
            self.assertEqual(self.bob.calls[0], 1)
            self.assertTrue(isinstance(self.bob.calls[1], RemoteReference))
            self.assertEqual(self.bob.calls[2], 3)
        d.addCallback(_checkBob)
        return d

    def testContainers(self):
        self.createCharacters()
        self.bob.calls = []
        d = self.createInitialReferences()
        d.addCallback(lambda res: self.createMoreReferences())
        def _introduce(res):
            # we send several messages to Bob, each of which has a container
            # with a gift inside it. This exercises the ready_deferred
            # handling inside containers.
            dl = []
            cr = self.abob.callRemote
            dl.append(cr("append", set([self.acharlene])))
            dl.append(cr("append", frozenset([self.achristine])))
            dl.append(cr("append", [self.aclarisse]))
            dl.append(cr("append", obj=(self.acolette,)))
            dl.append(cr("append", {'a': self.acourtney}))
            # TODO: pass a gift as an attribute of a Copyable
            return defer.DeferredList(dl)
        d.addCallback(_introduce)
        def _checkBob(res):
            # this runs after all three messages have been acked by Bob
            self.assertEqual(len(self.bob.calls), 5)

            bcharlene = self.bob.calls.pop(0)
            self.assertTrue(isinstance(bcharlene, set))
            self.assertEqual(len(bcharlene), 1)
            self.assertTrue(isinstance(list(bcharlene)[0], RemoteReference))

            bchristine = self.bob.calls.pop(0)
            self.assertTrue(isinstance(bchristine, frozenset))
            self.assertEqual(len(bchristine), 1)
            self.assertTrue(isinstance(list(bchristine)[0], RemoteReference))

            bclarisse = self.bob.calls.pop(0)
            self.assertTrue(isinstance(bclarisse, list))
            self.assertEqual(len(bclarisse), 1)
            self.assertTrue(isinstance(bclarisse[0], RemoteReference))

            bcolette = self.bob.calls.pop(0)
            self.assertTrue(isinstance(bcolette, tuple))
            self.assertEqual(len(bcolette), 1)
            self.assertTrue(isinstance(bcolette[0], RemoteReference))

            bcourtney = self.bob.calls.pop(0)
            self.assertTrue(isinstance(bcourtney, dict))
            self.assertEqual(len(bcourtney), 1)
            self.assertTrue(isinstance(bcourtney['a'], RemoteReference))

        d.addCallback(_checkBob)
        return d

    def create_constrained_characters(self):
        self.alice = HelperTarget("alice")
        self.bob = ConstrainedHelper("bob")
        self.bob_url = self.tubB.registerReference(self.bob, "bob")
        self.carol = HelperTarget("carol")
        self.carol_url = self.tubC.registerReference(self.carol, "carol")
        self.dave = HelperTarget("dave")
        self.dave_url = self.tubD.registerReference(self.dave, "dave")

    def test_constraint(self):
        self.create_constrained_characters()
        self.bob.calls = []
        d = self.createInitialReferences()
        def _introduce(res):
            return self.abob.callRemote("set", self.acarol)
        d.addCallback(_introduce)
        def _checkBob(res):
            self.assertTrue(isinstance(self.bob.obj, RemoteReference))
        d.addCallback(_checkBob)
        return d



    # this was used to alice's reference to carol (self.acarol) appeared in
    # alice's gift table at the right time, to make sure that the
    # RemoteReference is kept alive while the gift is in transit. The whole
    # introduction pattern is going to change soon, so it has been disabled
    # until I figure out what the new scheme ought to be asserting.

    def OFF_bobGotCarol(self, xxx_todo_changeme4):
        (balice,bcarol) = xxx_todo_changeme4
        if self.debug: print("Bob got Carol")
        # Bob has received the gift
        self.bcarol = bcarol

        # wait for alice to receive bob's 'decgift' sequence, which was sent
        # by now (it is sent after bob receives the gift but before the
        # gift-bearing message is delivered). To make sure alice has received
        # it, send a message back along the same path.
        def _check_alice(res):
            if self.debug: print("Alice should have the decgift")
            # alice's gift table should be empty
            brokerAB = self.abob.tracker.broker
            self.assertEqual(brokerAB.myGifts, {})
            self.assertEqual(brokerAB.myGiftsByGiftID, {})
        d1 = self.alice.waitfor()
        d1.addCallback(_check_alice)
        # the ack from this message doesn't always make it back by the time
        # we end the test and hang up the connection. That connectionLost
        # causes the deferred that this returns to errback, triggering an
        # error, so we must be sure to discard any error from it. TODO: turn
        # this into balice.callRemoteOnly("set", 39), which will have the
        # same semantics from our point of view (but in addition it will tell
        # the recipient to not bother sending a response).
        balice.callRemote("set", 39).addErrback(lambda ignored: None)

        if self.debug: print("Bob says something to Carol")
        d2 = self.carol.waitfor()
        d = self.bcarol.callRemote("set", obj=12)
        d.addCallback(lambda res: d2)
        d.addCallback(self._carolCalled)
        d.addCallback(lambda res: d1)
        return d


class Bad(Base, unittest.TestCase):

    # if the recipient cannot claim their gift, the caller should see an
    # errback.

    def setUp(self):
        Base.setUp(self)

    def test_swissnum(self):
        self.createCharacters()
        d = self.createInitialReferences()
        d.addCallback(lambda res: self.tubA.getReference(self.dave_url))
        def _introduce(adave):
            # now break the gift to insure that Bob is unable to claim it.
            # The first way to do this is to simple mangle the swissnum,
            # which will result in a failure in remote_getReferenceByName.
            # NOTE: this will have to change when we modify the way gifts are
            # referenced, since tracker.url is scheduled to go away.
            adave.tracker.url = adave.tracker.url + ".MANGLED"
            return self.shouldFail(KeyError, "Bad.test_swissnum",
                                   "unable to find reference for name starting with 'da'",
                                   self.acarol.callRemote, "set", adave)
        d.addCallback(_introduce)
        # make sure we can still talk to Carol, though
        d.addCallback(lambda res: self.acarol.callRemote("set", 14))
        d.addCallback(lambda res: self.assertEqual(self.carol.obj, 14))
        return d

    def test_tubid(self):
        self.createCharacters()
        d = self.createInitialReferences()
        d.addCallback(lambda res: self.tubA.getReference(self.dave_url))
        def _introduce(adave):
            # The second way is to mangle the tubid, which will result in a
            # failure during negotiation. We mangle it by reversing the
            # characters: this makes it syntactically valid but highly
            # unlikely to remain the same. NOTE: this will have to change
            # when we modify the way gifts are referenced, since tracker.url
            # is scheduled to go away.
            (tubid, location_hints, name) = decode_furl(adave.tracker.url)
            tubid = "".join(reversed(tubid))
            adave.tracker.url = encode_furl(tubid, location_hints, name)
            return self.shouldFail(BananaError, "Bad.test_tubid", "unknown TubID",
                                   self.acarol.callRemote, "set", adave)
        d.addCallback(_introduce)
        return d

    def test_location(self):
        self.createCharacters()
        d = self.createInitialReferences()
        d.addCallback(lambda res: self.tubA.getReference(self.dave_url))
        def _introduce(adave):
            # The third way is to mangle the location hints, which will
            # result in a failure during negotiation as it attempts to
            # establish a TCP connection.

            (tubid, location_hints, name) = decode_furl(adave.tracker.url)
            # highly unlikely that there's anything listening on this port
            location_hints = ["tcp:127.0.0.1:2"]
            adave.tracker.url = encode_furl(tubid, location_hints, name)
            return self.shouldFail(ConnectionRefusedError, "Bad.test_location",
                                   "Connection was refused by other side",
                                   self.acarol.callRemote, "set", adave)
        d.addCallback(_introduce)
        return d

    def test_hang(self):
        f = protocol.Factory()
        f.protocol = protocol.Protocol # ignores all input
        p = reactor.listenTCP(0, f, interface="127.0.0.1")
        self.createCharacters()
        d = self.createInitialReferences()
        d.addCallback(lambda res: self.tubA.getReference(self.dave_url))
        def _introduce(adave):
            # The next form of mangling is to connect to a port which never
            # responds, which could happen if a firewall were silently
            # dropping the TCP packets. We can't accurately simulate this
            # case, but we can connect to a port which accepts the connection
            # and then stays silent. This should trigger the overall
            # connection timeout.
            (tubid, location_hints, name) = decode_furl(adave.tracker.url)
            location_hints = ["tcp:127.0.0.1:%d" % p.getHost().port]
            adave.tracker.url = encode_furl(tubid, location_hints, name)
            self.tubD._test_options['connect_timeout'] = 2
            return self.shouldFail(NegotiationError, "Bad.test_hang",
                                   "no connection established within client timeout",
                                   self.acarol.callRemote, "set", adave)
        d.addCallback(_introduce)
        def _stop_listening(res):
            d1 = p.stopListening()
            def _done_listening(x):
                return res
            d1.addCallback(_done_listening)
            return d1
        d.addBoth(_stop_listening)
        return d


    def testReturn_swissnum(self):
        self.createCharacters()
        d = self.createInitialReferences()
        def _introduce(res):
            # now break the gift to insure that Alice is unable to claim it.
            # The first way to do this is to simple mangle the swissnum,
            # which will result in a failure in remote_getReferenceByName.
            # NOTE: this will have to change when we modify the way gifts are
            # referenced, since tracker.url is scheduled to go away.
            self.bdave.tracker.url = self.bdave.tracker.url + ".MANGLED"
            self.bob.obj = self.bdave
            return self.shouldFail(KeyError, "Bad.testReturn_swissnum",
                                   "unable to find reference for name starting with 'da'",
                                   self.abob.callRemote, "get")
        d.addCallback(_introduce)
        # make sure we can still talk to Bob, though
        d.addCallback(lambda res: self.abob.callRemote("set", 14))
        d.addCallback(lambda res: self.assertEqual(self.bob.obj, 14))
        return d

class LongFURL(Base, unittest.TestCase):
    # make sure the old 200-byte limit on gift FURLs is gone
    def setUp(self):
        def mangleLocation(portnum):
            loc = "127.0.0.1:%d" % portnum
            loc = ",".join([loc]*15) # 239 bytes of location, 281 of FURL
            return loc
        (self.tubA, self.tubB,
         self.tubC, self.tubD) = self.makeTubs(4, mangleLocation)

    def testGift(self):
        self.createCharacters()
        d = self.createInitialReferences()
        def _introduce(res):
            d2 = self.bob.waitfor()
            if self.debug: print("Alice introduces Carol to Bob")
            # send the gift. This might not get acked by the time the test is
            # done and everything is torn down, so we use callRemoteOnly
            self.abob.callRemoteOnly("set", obj=(self.alice, self.acarol))
            return d2 # this fires with the gift that bob got
        d.addCallback(_introduce)
        def _bobGotCarol(xxx_todo_changeme2):
            (balice,bcarol) = xxx_todo_changeme2
            if self.debug: print("Bob got Carol")
            self.bcarol = bcarol
            if self.debug: print("Bob says something to Carol")
            d2 = self.carol.waitfor()
            # handle ConnectionDone as described before
            self.bcarol.callRemoteOnly("set", obj=12)
            return d2
        d.addCallback(_bobGotCarol)
        def _carolCalled(res):
            if self.debug: print("Carol heard from Bob")
            self.assertEqual(res, 12)
        d.addCallback(_carolCalled)
        return d

class Enabled(Base, unittest.TestCase):
    def setUp(self):
        self.services = [Tub() for i in range(4)]
        self.tubA, self.tubB, self.tubC, self.tubD = self.services
        for s in self.services:
            s.startService()
            p = allocate_tcp_port()
            s.listenOn("tcp:%d:interface=127.0.0.1" % p)
            s.setLocation("127.0.0.1:%d" % p)
        self.tubIDs = [self.tubA.getShortTubID(),
                       self.tubB.getShortTubID(),
                       self.tubC.getShortTubID(),
                       self.tubD.getShortTubID()]

    def get_connections(self, tub):
        self.assertFalse(tub.waitingForBrokers)
        return set([tr.getShortTubID() for tr in list(tub.brokers.keys())])

    def testGiftsEnabled(self):
        # enabled is the default, so this shouldn't change anything
        self.tubB.setOption("accept-gifts", True)
        self.createCharacters()
        d = self.createInitialReferences()
        def _introduce(res):
            d2 = self.bob.waitfor()
            d3 = self.abob.callRemote("set", obj=(self.alice, self.acarol))
            d3.addCallback(lambda _: d2)
            return d3 # this fires with the gift that bob got
        d.addCallback(_introduce)
        def _bobGotCarol(xxx_todo_changeme3):
            (balice,bcarol) = xxx_todo_changeme3
            A,B,C,D = self.tubIDs
            b_connections = self.get_connections(self.tubB)
            self.assertIn(C, b_connections)
            self.assertEqual(b_connections, set([A, C, D]))
        d.addCallback(_bobGotCarol)
        return d

    def testGiftsDisabled(self):
        self.tubB.setOption("accept-gifts", False)
        self.createCharacters()
        self.bob.obj = None
        d = self.createInitialReferences()
        d.addCallback(lambda _:
                      self.shouldFail(Violation, "testGiftsDisabled",
                                      "gifts are prohibited in this Tub",
                                      self.abob.callRemote,
                                      "set", obj=(self.alice, self.acarol)))
        d.addCallback(lambda _: self.assertFalse(self.bob.obj))
        def _check_tub(_):
            A,B,C,D = self.tubIDs
            b_connections = self.get_connections(self.tubB)
            self.failIfIn(C, b_connections)
            self.assertEqual(b_connections, set([A, D]))
        d.addCallback(_check_tub)
        return d

    def testGiftsDisabledReturn(self):
        self.tubA.setOption("accept-gifts", False)
        self.createCharacters()
        d = self.createInitialReferences()
        def _created(_):
            self.bob.obj = self.bdave
            return self.shouldFail(Violation, "testGiftsDisabledReturn",
                                   "gifts are prohibited in this Tub",
                                   self.abob.callRemote,
                                   "get")
        d.addCallback(_created)
        def _check_tub(_):
            A,B,C,D = self.tubIDs
            a_connections = self.get_connections(self.tubA)
            self.failIfIn(D, a_connections)
            self.assertEqual(a_connections, set([B,C]))
        return d

