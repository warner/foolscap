# -*- test-case-name: foolscap.test.test_tub -*-

import os.path
from twisted.trial import unittest
try:
    from foolscap import crypto
except ImportError:
    crypto = None
if crypto and not crypto.available:
    crypto = None

from foolscap import Tub

class TestCertFile(unittest.TestCase):
    def test_generate(self):
        t = Tub()
        certdata = t.getCertData()
        self.failUnless("BEGIN CERTIFICATE" in certdata)
        self.failUnless("BEGIN RSA PRIVATE KEY" in certdata)

    def test_certdata(self):
        t1 = Tub()
        data1 = t1.getCertData()
        t2 = Tub(certData=data1)
        data2 = t2.getCertData()
        self.failUnless(data1 == data2)

    def test_certfile(self):
        fn = "test_tub.TestCertFile.certfile"
        t1 = Tub(certFile=fn)
        self.failUnless(os.path.exists(fn))
        data1 = t1.getCertData()

        t2 = Tub(certFile=fn)
        data2 = t2.getCertData()
        self.failUnless(data1 == data2)

if not crypto:
    del TestCertFile
