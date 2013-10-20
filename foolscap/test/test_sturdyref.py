from twisted.trial import unittest

from foolscap.referenceable import SturdyRef, BadFURLError

TUB1 = "q5l37rle6pojjnllrwjyryulavpqdlq5"
TUB2 = "u5vgfpug7qhkxdtj76tcfh6bmzyo6w5s"

class URL(unittest.TestCase):
    def testURL(self):
        sr = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB1)
        self.failUnlessEqual(sr.tubID, TUB1)
        self.failUnlessEqual(sr.locationHints,
                             [ ("tcp", "127.0.0.1", 9900) ])
        self.failUnlessEqual(sr.name, "name")

    def testURLTcp(self):
        sr = SturdyRef("pb://%s@tcp:host=127.0.0.1:port=9900/name" % TUB1)
        self.failUnlessEqual(sr.tubID, TUB1)
        self.failUnlessEqual(sr.locationHints,
                             [ ("tcp", "127.0.0.1", 9900) ])
        self.failUnlessEqual(sr.name, "name")

    def testTubIDExtensions(self):
        sr = SturdyRef("pb://%s,otherstuff@127.0.0.1:9900/name" % TUB1)
        self.failUnlessEqual(sr.tubID, TUB1)
        self.failUnlessRaises(BadFURLError,
                              SturdyRef,
                              "pb://badstuff,%s@127.0.0.1:9900/name" % TUB1)

    def testLocationHintExtensions(self):
        furl = "pb://%s@127.0.0.1:9900,udp:127.0.0.1:7700/name" % TUB1
        sr = SturdyRef(furl)
        self.failUnlessEqual(sr.locationHints,
                             [ ("tcp", "127.0.0.1", 9900) ])
        self.failUnlessEqual(sr.getURL(), furl)

        furl = "pb://%s@udp:127.0.0.1:7700/name" % TUB1
        sr = SturdyRef(furl)
        self.failUnlessEqual(sr.locationHints, [])
        self.failUnlessEqual(sr.getURL(), furl)

        furl = "pb://%s@127.0.0.1:7700:postextension/name" % TUB1
        sr = SturdyRef(furl)
        self.failUnlessEqual(sr.locationHints, [])
        self.failUnlessEqual(sr.getURL(), furl)

    def testCompare(self):
        sr1 = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB1)
        sr2 = SturdyRef("pb://%s@127.0.0.1:9999/name" % TUB1)
        # only tubID and name matter
        self.failUnlessEqual(sr1, sr2)
        sr1 = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB2)
        sr2 = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB1)
        self.failIfEqual(sr1, sr2)
        sr1 = SturdyRef("pb://%s@127.0.0.1:9900/name1" % TUB1)
        sr2 = SturdyRef("pb://%s@127.0.0.1:9900/name2" % TUB1)
        self.failIfEqual(sr1, sr2)

    def testLocationHints(self):
        url = "pb://%s@127.0.0.1:9900,remote:8899/name" % TUB1
        sr = SturdyRef(url)
        self.failUnlessEqual(sr.tubID, TUB1)
        self.failUnlessEqual(sr.locationHints,
                             [ ("tcp", "127.0.0.1", 9900),
                               ("tcp", "remote", 8899) ])
        self.failUnlessEqual(sr.name, "name")

    def testBrokenHints(self):
        furl = "pb://%s@,/name" % TUB1 # empty hints are not allowed
        f = self.failUnlessRaises(BadFURLError, SturdyRef, furl)
        self.failUnless("empty string" in str(f), f)

        furl = "pb://%s@/name" % TUB1 # this is ok, and means "unrouteable"
        sr = SturdyRef(furl)
        self.failUnlessEqual(sr.locationHints, [])

        furl = "pb://%s/name" % TUB1 # this is not ok
        f = self.failUnlessRaises(ValueError, SturdyRef, furl)
        self.failUnless("unknown FURL prefix in " in str(f), f)
