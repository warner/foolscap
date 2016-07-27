import re
from twisted.internet.endpoints import clientFromString
from twisted.internet.interfaces import IStreamClientEndpoint
from txi2p.sam import SAMI2PStreamClientEndpoint
from zope.interface import implementer

from foolscap.ipb import IConnectionHintHandler, InvalidHintError

HINT_RE=re.compile(r"^i2p:([A-Za-z.0-9\-]+)(:(\d+){1,5})?$")

@implementer(IConnectionHintHandler)
class _RunningI2P:
    def __init__(self, sam_endpoint):
        assert IStreamClientEndpoint.providedBy(sam_endpoint)
        self._sam_endpoint = sam_endpoint

    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized I2P hint")
        host, port = mo.group(1), int(mo.group(2)) if mo.group(2) else None
        return SAMI2PStreamClientEndpoint.new(self._sam_endpoint, host, port), host

def default_sam_port(reactor):
    """Return a handler which connects to a pre-existing I2P process on the
    default SAM port.
    """
    return _RunningI2P(clientFromString(reactor, 'tcp:127.0.0.1:7656'))

def with_sam_port(sam_endpoint):
    """Return a handler which connects to a pre-existing I2P process on the
    given SAM port.
    - sam_endpoint: a ClientEndpoint which points at the SAM API
    """
    return _RunningI2P(sam_endpoint)

def with_local_i2p(reactor, i2p_configdir=None):
    raise NotImplementedError

def launch_local_i2p(reactor, i2p_binary=None, i2p_configdir=None):
    raise NotImplementedError
