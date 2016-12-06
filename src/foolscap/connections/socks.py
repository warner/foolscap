import re
from zope.interface import implementer
from foolscap.ipb import IConnectionHintHandler, InvalidHintError
from .tcp import DOTTED_QUAD_RESTR, DNS_NAME_RESTR
from txsocksx.client import SOCKS5ClientEndpoint

HINT_RE = re.compile(r"^[^:]*:(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                      DNS_NAME_RESTR))

@implementer(IConnectionHintHandler)
class _SOCKS:
    """This can connect to tcp: or tor: hints through a SOCKS5 proxy."""
    def __init__(self, proxy_endpoint):
        self._proxy_endpoint = proxy_endpoint

    def hint_to_endpoint(self, hint, reactor, update_status):
        mo = HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized hint, wanted TYPE:HOST:PORT")
        host, port = mo.group(1), int(mo.group(2))
        # note: txsockx does not expose a way to provide the reactor
        ep = SOCKS5ClientEndpoint(host, port, self._proxy_endpoint)
        return ep, host

    def describe(self):
        return "socks"

def socks_endpoint(proxy_endpoint):
    return _SOCKS(proxy_endpoint)
