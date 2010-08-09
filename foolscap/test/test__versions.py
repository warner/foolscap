
from twisted.trial import unittest
import time
import platform
import twisted
from twisted.internet import reactor
from twisted.python import log
from foolscap.test.common import crypto_available
from foolscap.api import __version__

def split_version(version_string):
    def maybe_int(s):
        try:
            return int(s)
        except ValueError:
            return s
    return tuple([maybe_int(piece) for piece in version_string.split(".")])

class Versions(unittest.TestCase):
    def test_required(self):
        if not crypto_available:
            return
        import OpenSSL
        ssl_ver = split_version(OpenSSL.__version__)
        tw_ver = split_version(twisted.__version__)
        # this is gross, but apps aren't supposed to care what sort of
        # reactor they're using. I use str() instead of isinstance(reactor,
        # twisted.internet.selectreactor.SelectReactor) because I want to
        # avoid importing the selectreactor when we aren't already using it.
        is_select = bool( "select" in str(reactor).lower() )
        if ( (ssl_ver >= split_version("0.7"))
             and (tw_ver <= split_version("8.1.0"))
             and is_select ):
            # twisted 8.1.0 bad, 8.0.1 bad, 8.0.0 bad, I think 2.5.0 is too.
            # twisted 10.1.0 ok.
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

    def test_record(self):
        log.msg("Versions:")
        log.msg("foolscap-%s" % __version__)
        log.msg("twisted-%s" % twisted.__version__)
        log.msg("python-%s" % platform.python_version())
        log.msg("platform: %s" % platform.version())
