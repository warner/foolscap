
from twisted.trial import unittest
import time
import twisted
from twisted.internet import reactor
from foolscap.test.common import crypto_available

class Versions(unittest.TestCase):
    def test_required(self):
        if not crypto_available:
            return
        import OpenSSL
        ssl_ver = OpenSSL.__version__.split(".")
        tw_ver = twisted.__version__.split(".")
        # this is gross, but apps aren't supposed to care what sort of
        # reactor they're using. I use str() instead of isinstance(reactor,
        # twisted.internet.selectreactor.SelectReactor) because I want to
        # avoid importing the selectreactor when we aren't already using it.
        is_select = bool( "select" in str(reactor).lower() )
        if ( (ssl_ver >= "0.7".split("."))
             and (tw_ver <= "8.1.0".split("."))
             and is_select ):
            # twisted 8.1.0 bad, 8.0.1 bad, 8.0.0 bad, I think 2.5.0 is too
            print
            print "-------------"
            print "Warning: tests will fail (unclean reactor warnings)"
            print "when pyOpenSSL >= 0.7 is used in conjunction with"
            print "Twisted <= 8.1.0 . The workaround is to use the pollreactor"
            print "instead of the default selectreactor (trial -r poll)."
            print "This bug is fixed in Twisted trunk, and should appear"
            print "in the next release of Twisted."
            print " pyOpenSSL version:", OpenSSL.__version__
            print " Twisted version:", twisted.__version__
            print " reactor:", str(reactor)
            print "See http://foolscap.lothar.com/trac/ticket/62 for details."
            print
            print "Sleeping for 10 seconds to give you a chance to stop this"
            print "run and restart with -r poll..."
            print "-------------"

            # give them a chance to read it and re-run the tests with -r poll
            time.sleep(10)
            # but we don't flunk the test, that would be gratuitous
