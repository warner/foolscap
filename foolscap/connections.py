
class IFoolscapServerConnectionHelper:
    typename = "onion"
    def how_to_listen(listenspec):
        return IStreamServerEndpoint or str
    def what_to_advertise(IListeningPort):
        return connection_hint

class IFoolscapClientConnectionHelper:
    typename = "tor"
    def client_thing(connection_hint):
        # add client-private stuff: SOCKS port
        return IStreamClientEndpoint or str# which also does .startTLS


@implementer(IFoolscapConnectionHelper)
class TorPlugin:
    def __init__(self, socksport=None, tor_exe=None, statedir=None):
        self.socksport = socksport
        self.tor_exe =tor_exe
        self.statedir = statedir

    def client_Thing(connection_hint):
        addr,port = parse(connection_hint)
        epstr = txtorcon.makeClientEndpointString(self.socksport, self.tor_exe,
                                                  self.statedir,
                                                  addr, port)
        # that will launch tor if necessary, or use configured socks port

        # txtorcon installs a plugin to make this work
        return twisted.internet.endpoints.clientFromString(epstr)
