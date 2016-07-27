import os, re
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
import ipaddress
from .. import observer

from zope.interface import implementer
from ..ipb import IConnectionHintHandler, InvalidHintError
from ..util import allocate_tcp_port
import txtorcon
from .tcp import DOTTED_QUAD_RESTR, DNS_NAME_RESTR

def is_non_public_numeric_address(host):
    # for numeric hostnames, skip RFC1918 addresses, since no Tor exit
    # node will be able to reach those. Likewise ignore IPv6 addresses.
    try:
        a = ipaddress.ip_address(host.decode("ascii")) # wants unicode
    except ValueError:
        return False # non-numeric, let Tor try it
    if a.version != 4:
        return True # IPv6 gets ignored
    if (a.is_loopback or a.is_multicast or a.is_private or a.is_reserved
        or a.is_unspecified):
        return True # too weird, don't connect
    return False

HINT_RE = re.compile(r"^[^:]*:(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                      DNS_NAME_RESTR))

@implementer(IConnectionHintHandler)
class _Common:
    # subclasses must:
    #  define _connect()
    #  set self._socks_hostname, self._socks_port

    def __init__(self):
        self._connected = False
        self._when_connected = observer.OneShotObserverList()

    def _maybe_connect(self, reactor):
        if not self._connected:
            self._connected = True
            # connect
            d = self._connect()
            d.addBoth(self._when_connected.fire)
        return self._when_connected.whenFired()

    @inlineCallbacks
    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized TCP/Tor hint")
        host, port = mo.group(1), int(mo.group(2))
        if is_non_public_numeric_address(host):
            raise InvalidHintError("ignoring non-Tor-able ipaddr %s" % host)
        yield self._maybe_connect(reactor)
        # txsocksx doesn't like unicode: it concatenates some binary protocol
        # bytes with the hostname when talking to the SOCKS server, so the
        # py2 automatic unicode promotion blows up
        host = host.encode("ascii")
        ep = txtorcon.TorClientEndpoint(host, port,
                                        socks_hostname=self._socks_hostname,
                                        socks_port=self._socks_port)
        returnValue( (ep, host) )


# note: TorClientEndpoint imports 'reactor' itself, doesn't provide override

class _SocksTor(_Common):
    def __init__(self, hostname=None, port=None):
        _Common.__init__(self)
        self._connnected = True # no need to call _connect()
        self._socks_hostname = hostname
        self._socks_port = port # None means to use defaults: 9050, then 9150
    def _connect(self):
        return succeed(None)

def default_socks():
    # TorClientEndpoint knows how to cycle through a built-in set of socks
    # ports, but it doesn't know to set the hostname to localhost
    return _SocksTor("127.0.0.1")

def socks_port(port):
    return _SocksTor("127.0.0.1", port)


class _LaunchedTor(_Common):
    def __init__(self, reactor, data_directory=None, tor_binary=None):
        _Common.__init__(self)
        self._reactor = reactor
        self._data_directory = data_directory
        self._tor_binary = tor_binary

    @inlineCallbacks
    def _connect(self):
        # create a new Tor
        config = self.config = txtorcon.TorConfig()
        if self._data_directory:
            # The default is for launch_tor to create a tempdir itself, and
            # delete it when done. We only need to set a DataDirectory if we
            # want it to be persistent. This saves some startup time, because
            # we cache the descriptors from last time. On one of my hosts,
            # this reduces connect from 20s to 15s.
            if not os.path.exists(self._data_directory):
                # tor will mkdir this, but txtorcon wants to chdir to it
                # before spawning the tor process, so (for now) we need to
                # mkdir it ourselves. TODO: txtorcon should take
                # responsibility for this.
                os.mkdir(self._data_directory)
            config.DataDirectory = self._data_directory

        #config.ControlPort = allocate_tcp_port() # defaults to 9052
        config.SocksPort = allocate_tcp_port()
        self._socks_hostname = "127.0.0.1"
        self._socks_port = config.SocksPort

        #print "launching tor"
        tpp = yield txtorcon.launch_tor(config, self._reactor,
                                        tor_binary=self._tor_binary,
                                        )
        #print "launched"
        # gives a TorProcessProtocol with .tor_protocol
        self._tor_protocol = tpp.tor_protocol
        returnValue(True)

def launch(reactor, data_directory=None, tor_binary=None):
    """Return a handler which launches a new Tor process (once).
    - data_directory: a persistent directory where Tor can cache its
      descriptors. This allows subsequent invocations to start faster. If
      None, the process will use an ephemeral tempdir, deleting it when Tor
      exits.
    - tor_binary: the path to the Tor executable we should use. If None,
      search $PATH.
    """
    return _LaunchedTor(reactor, data_directory, tor_binary)


@implementer(IConnectionHintHandler)
class _ConnectedTor(_Common):
    def __init__(self, reactor, tor_control_endpoint):
        _Common.__init__(self)
        self._reactor = reactor
        assert IStreamClientEndpoint.providedBy(tor_control_endpoint)
        self._tor_control_endpoint = tor_control_endpoint

    @inlineCallbacks
    def _connect(self):
        tproto = yield txtorcon.build_tor_connection(self._tor_control_endpoint,
                                                     build_state=False)
        config = yield txtorcon.TorConfig.from_protocol(tproto)
        ports = list(config.SocksPort)
        port = ports[0]
        if port == "DEFAULT":
            port = "9050"
        port = int(port)
        self._socks_hostname = "127.0.0.1"
        self._socks_port = port


def control_endpoint(reactor, tor_control_endpoint):
    """Return a handler which connects to a pre-existing Tor process on the
    given control port.
    - control_port: a ClientEndpoint which points at the Tor control port
    """
    return _ConnectedTor(reactor, tor_control_endpoint)
