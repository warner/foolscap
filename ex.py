
# client-only: no Listener
#tub.port = NONE
#tub.location = NONE
t = Tub(certFile=FILENAME)
# no t.listenOn(), t.setLocation(), or t.registerReference()
t.startService()

# localhost random-port: my testnet, unit tests
t = Tub(certFile=FILENAME)
port = allocatePort()
l = t.listenOn("tcp:%d" % port)
t.setLocation("tcp:127.0.0.1:%d" % port)
f = t.registerReference(obj)
t.startService()

# manually-configured host/port: real TCP deploys
#tub.port = tcp:PORT
#tub.location = tcp:HOST:PORT (or onion:N.onion:80 for manual tor)
t = Tub(certFile=FILENAME)
l = t.listenOn("tcp:%d" % PORT)
t.setLocation("tcp:%s:%d" % (HOST,PORT))
f = t.registerReference(obj)
t.startService()

# automatically-configured .onion HS
t = Tub(certFile=FILENAME)
l = t.listenOn("onion:80")
t.startService()
d = l.getLocation()
d.addCallback(t.setLocation)
d.addCallback(lambda _: t.registerReference(obj))
d.addCallback(print_furl)

# automatically-configured .onion HS, push all async into a setup tool
l = makeListener("onion:80")
d = l.getLocation()
d.addCallback(save_location)
# then actual runtime does:
t = Tub(certFile=FILENAME)
t.listenOn("onion:80")
t.setLocation(SAVED_LOCATION)
t.startService()
