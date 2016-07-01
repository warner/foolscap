
import re
from zope.interface import implementer
from twisted.internet import endpoints

from foolscap.ipb import IConnectionHintHandler, InvalidHintError

try:
    import txsocksx
except ImportError:
    txsocksx = None

class PluginDependencyNotLoaded(Exception):
    """
    PluginDependencyNotLoaded is raised when a plugin is instantiated
    and a dependency is missing.
    """

# This can match IPv4 IP addresses + port numbers *or* host names +
# port numbers.
DOTTED_QUAD_RESTR=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
DNS_NAME_RESTR=r"[A-Za-z.0-9\-]+"
OLD_STYLE_HINT_RE=re.compile(r"^(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                        DNS_NAME_RESTR))
NEW_STYLE_HINT_RE=re.compile(r"^tcp:(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                            DNS_NAME_RESTR))
ANY_HINT_RE=re.compile(r"^[^:]*:(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                            DNS_NAME_RESTR))

# Each location hint must start with "TYPE:" (where TYPE is alphanumeric) and
# then can contain any characters except "," and "/". These are expected to
# contain ":"-separated fields (e.g. "TYPE:stuff:morestuff" or
# "TYPE:key=value:key=value").

# For compatibility with current and older Foolscap releases, we also accept
# old-syle implicit TCP hints ("host:port"). These are caught and converted
# into new-style "tcp:HOST:PORT" hints in convert_legacy_hint() before we
# look up the handler.

# To avoid being interpreted as an old-style hint, the part after TYPE: may
# not consist of only 1-5 digits (so "type:123" will be treated as type="tcp"
# and hostname="type"). Creators of new hint types are advised to either use
# multiple colons (e.g. tor:HOST:PORT), or use key=value in the right-hand
# portion (e.g. systemd:fd=3).

# Future versions of foolscap may put hints in their FURLs which we do not
# understand. We will ignore such hints. This version understands two types
# of hints:
#
#  HOST:PORT                 (old-style implicit tcp)
#  tcp:HOST:PORT             (endpoint syntax for TCP connections)

def convert_legacy_hint(location):
    mo = OLD_STYLE_HINT_RE.search(location)
    if mo:
        host, port = mo.group(1), int(mo.group(2))
        return "tcp:%s:%d" % (host, port)
    return location

@implementer(IConnectionHintHandler)
class DefaultTCP:
    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = NEW_STYLE_HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized TCP hint")
        host, port = mo.group(1), int(mo.group(2))
        return endpoints.HostnameEndpoint(reactor, host, port), host

@implementer(IConnectionHintHandler)
class SOCKS5:
    def __init__(self, endpoint=None, proxy_endpoint_factory=None):
        if txsocksx is None:
            raise PluginDependencyNotLoaded("""SOCKS5 foolscap client transport plugin requires txsocksx.\n
If you are using a Python virtual env you can simply: pip install txsocksx;\n
Debian users can install via the APT repo: apt-get install txsocksx;\n""")
        self.proxy_endpoint_factory = proxy_endpoint_factory
        self.proxy_endpoint_desc = endpoint
        self.proxy_endpoint = None

    def hint_to_endpoint(self, hint, reactor):
        if self.proxy_endpoint_factory is not None:
            self.proxy_endpoint = self.proxy_endpoint_factory()
        else:
            if self.proxy_endpoint is None:
                self.proxy_endpoint = endpoints.clientFromString(reactor, self.proxy_endpoint_desc)

        mo = ANY_HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("Invalid SOCKS5 client connection hint")
        host, port = mo.group(1), int(mo.group(2))
        return txsocksx.client.SOCKS5ClientEndpoint(host, port, self.proxy_endpoint), host
