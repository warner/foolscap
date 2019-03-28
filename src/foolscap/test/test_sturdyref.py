from twisted.trial import unittest

from foolscap.referenceable import SturdyRef
from foolscap.furl import BadFURLError

TUB1 = "q5l37rle6pojjnllrwjyryulavpqdlq5"
TUB2 = "u5vgfpug7qhkxdtj76tcfh6bmzyo6w5s"

class URL(unittest.TestCase):
    def testURL(self):
        sr = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB1)
        self.assertEqual(sr.tubID, TUB1)
        self.assertEqual(sr.locationHints, ["127.0.0.1:9900"])
        self.assertEqual(sr.name, "name")

    def testTubIDExtensions(self):
        sr = SturdyRef("pb://%s,otherstuff@127.0.0.1:9900/name" % TUB1)
        self.assertEqual(sr.tubID, TUB1)
        self.assertRaises(BadFURLError,
                              SturdyRef,
                              "pb://badstuff,%s@127.0.0.1:9900/name" % TUB1)

    def testCompare(self):
        sr1 = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB1)
        sr2 = SturdyRef("pb://%s@127.0.0.1:9999/name" % TUB1)
        # only tubID and name matter
        self.assertEqual(sr1, sr2)
        sr1 = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB2)
        sr2 = SturdyRef("pb://%s@127.0.0.1:9900/name" % TUB1)
        self.assertNotEqual(sr1, sr2)
        sr1 = SturdyRef("pb://%s@127.0.0.1:9900/name1" % TUB1)
        sr2 = SturdyRef("pb://%s@127.0.0.1:9900/name2" % TUB1)
        self.assertNotEqual(sr1, sr2)

    def testLocationHints(self):
        url = "pb://%s@127.0.0.1:9900,remote:8899/name" % TUB1
        sr = SturdyRef(url)
        self.assertEqual(sr.tubID, TUB1)
        self.assertEqual(sr.locationHints,
                             ["127.0.0.1:9900", "remote:8899"])
        self.assertEqual(sr.name, "name")

    def testBrokenHints(self):
        furl = "pb://%s@,/name" % TUB1 # empty hints are not allowed
        f = self.assertRaises(BadFURLError, SturdyRef, furl)
        self.assertTrue("no connection hint may be empty" in str(f), f)

        furl = "pb://%s@/name" % TUB1 # this is ok, and means "unrouteable"
        sr = SturdyRef(furl)
        self.assertEqual(sr.locationHints, [])

        furl = "pb://%s/name" % TUB1 # this is not ok
        f = self.assertRaises(ValueError, SturdyRef, furl)
        self.assertTrue("unknown FURL prefix in " in str(f), f)
