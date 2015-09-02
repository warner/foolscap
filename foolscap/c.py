
tub = Tub()
tub.listenOn(TorListener(externport=80, keydir=, ))
furl = tub.registerReference(ref) # has 'tor' hint


foolscap.registerConnectionPlugin(TorPlugin(socksport=X, # option 1
                                            tor_exe=X, statedir=Y, # option 2
                                            )
tub.listenOn("onion:80")
foolscap.removeAllPlugins()
foolscap.registerPlugin(TCPGoesThroughTor(..))

tub.listenOnEndpoint(ep)

tub.listenOn(endpoint_string,
             advertise="AUTO", # connection hint: tcp:host:port, tor:x:y
             # or ",".join(hints)
             # also [helper.what_to_advertise(port) if hint=="AUTO"]
             )

## server purposes
# externally-configured HS
tub.listenOn("tcp:1234:interface=127.0.0.1",
             advertise="onion:XYZ.onion:80")

# not handled: listen on Tor and also normal IP. meh.

# automatically-configured HS, external pre-launched Tor
foolscap.registerPlugin(TorPlugin(controlport=X))
tub.listenOn("onion:80")

# automatically-configured HS, automatically-launched Tor
foolscap.registerPlugin(TorPlugin(tor_exe=X, statedir=None))
tub1.listenOn("onion:80:hsdir=2") 
tub2.listenOn("onion:80:hsdir=1")

## client purposes, to handle hint="onion:XYZ.onion:80"

# external pre-launched Tor
foolscap.registerPlugin(TorPlugin(socksport=X))

# automatically-launched Tor
foolscap.registerPlugin(TorPlugin(tor_exe=X, statedir=None))



## connection hint
# HOST:PORT, tcp:HOST:PORT
# tor:HOST.onion:PORT, tor:HOST(v4):PORT (silly)
# i2p:HOST.i2p:PORT ?

## listening specification
# tcp:0, tcp:PORT, tcp:PORT:interface=IFACEADDR
# onion:, onion:PORT, onion:PORT:hsdir=DIR, onion:PORT:torexe=..:socksport=..
# i2p:


## tahoe config

# level0: no Tor at all

# level1A: use Tor for HS clients
tor.socks = socksport # tcp:X:Y, unix:NAME

# or
tor.exe=
tor.statedir=

# level1B: offer server over Tor
 # externally-configured HS
 tub.port = tcp:1234:interface=127.0.0.1
 tub.location = onion:XYZ.onion:80

 # automatically-configured HS
 tor.control = portspec
 [tor.authcookie/authcookiefile=]
 [tor.hsdir=~/.tahoe/private/tor-hs/]
 # or tor.exe=, [tor.statedir=]
 tub.port = onion:80
 #tub.location = AUTO,tcp:host:port

# level2: Tor only: no plain connections
???tor.control = 
anonymize = True  # safety flag

