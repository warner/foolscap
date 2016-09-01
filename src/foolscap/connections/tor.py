import os, re
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.defer import inlineCallbacks, returnValue, succeed
from twisted.internet.endpoints import clientFromString
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
    #  define _connect(reactor)
    #  set self._socks_endpoint

    def __init__(self):
        self._connected = False
        self._when_connected = observer.OneShotObserverList()

    def _maybe_connect(self, reactor):
        if not self._connected:
            self._connected = True
            # connect
            d = self._connect(reactor)
            d.addBoth(self._when_connected.fire)
        return self._when_connected.whenFired()

    @inlineCallbacks
    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized TCP/Tor hint")
        host, portnum = mo.group(1), int(mo.group(2))
        if is_non_public_numeric_address(host):
            raise InvalidHintError("ignoring non-Tor-able ipaddr %s" % host)
        yield self._maybe_connect(reactor)
        # txsocksx doesn't like unicode: it concatenates some binary protocol
        # bytes with the hostname when talking to the SOCKS server, so the
        # py2 automatic unicode promotion blows up
        host = host.encode("ascii")
        ep = txtorcon.TorClientEndpoint(host, portnum, socks_endpoint=self._socks_endpoint)
        returnValue( (ep, host) )


# note: TorClientEndpoint imports 'reactor' itself, doesn't provide override.
# This will be fixed in txtorcon 1.0

class _SocksTor(_Common):
    def __init__(self, socks_endpoint=None):
        _Common.__init__(self)
        self._connnected = True # no need to call _connect()
        self._socks_endpoint = socks_endpoint
        # socks_endpoint=None means to use defaults: TCP to 127.0.0.1 with 9050, then 9150
    def _connect(self, reactor):
        return succeed(None)

def default_socks():
    # TorClientEndpoint knows how to cycle through a built-in set of socks
    # ports, but it doesn't know to set the hostname to localhost
    return _SocksTor()

def socks_endpoint(tor_socks_endpoint):
    assert IStreamClientEndpoint.providedBy(tor_socks_endpoint)
    return _SocksTor(tor_socks_endpoint)


class _LaunchedTor(_Common):
    def __init__(self, data_directory=None, tor_binary=None):
        _Common.__init__(self)
        self._data_directory = data_directory
        self._tor_binary = tor_binary

    @inlineCallbacks
    def _connect(self, reactor):
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
        socks_desc = "tcp:127.0.0.1:%s" % config.SocksPort
        self._socks_endpoint = clientFromString(reactor, socks_desc)

        #print "launching tor"
        tpp = yield txtorcon.launch_tor(config, reactor,
                                        tor_binary=self._tor_binary)
        #print "launched"
        # gives a TorProcessProtocol with .tor_protocol
        self._tor_protocol = tpp.tor_protocol
        returnValue(True)

def launch(data_directory=None, tor_binary=None):
    """Return a handler which launches a new Tor process (once).
    - data_directory: a persistent directory where Tor can cache its
      descriptors. This allows subsequent invocations to start faster. If
      None, the process will use an ephemeral tempdir, deleting it when Tor
      exits.
    - tor_binary: the path to the Tor executable we should use. If None,
      search $PATH.
    """
    return _LaunchedTor(data_directory, tor_binary)


@implementer(IConnectionHintHandler)
class _ConnectedTor(_Common):
    def __init__(self, tor_control_endpoint):
        _Common.__init__(self)
        assert IStreamClientEndpoint.providedBy(tor_control_endpoint)
        self._tor_control_endpoint = tor_control_endpoint

    @inlineCallbacks
    def _connect(self, reactor):
        tproto = yield txtorcon.build_tor_connection(self._tor_control_endpoint,
                                                     build_state=False)
        config = yield txtorcon.TorConfig.from_protocol(tproto)
        ports = list(config.SocksPort)
        # I've seen "9050", and "unix:/var/run/tor/socks WorldWritable"
        for port in ports:
            pieces = port.split()
            p = pieces[0]
            if p == txtorcon.DEFAULT_VALUE:
                p = "9050"
            try:
                portnum = int(p)
                socks_desc = "tcp:127.0.0.1:" + p
                self._socks_endpoint = clientFromString(reactor, socks_desc)
                return
            except ValueError:
                pass
        raise ValueError("could not use config.SocksPort: %r" % (ports,))


def control_endpoint(tor_control_endpoint):
    """Return a handler which connects to a pre-existing Tor process on the
    given control port.
    - tor_control_endpoint: a ClientEndpoint which points at the Tor control
      port
    """
    assert IStreamClientEndpoint.providedBy(tor_control_endpoint)
    return _ConnectedTor(tor_control_endpoint)
