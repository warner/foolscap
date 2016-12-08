Connection Handlers
===================

Each FURL contains 0 or more "connection hints", each of which tells the
client Tub how it might connect to the target Tub. Each hint has a "type",
and the usual value is "tcp". For example, "tcp:example.org:12345" means that
the client should make a TCP connection to "example.org", port 12345, and
then start a TLS-based Foolscap connection.

Plugins can be used to enable alternate transport mechanisms. For example, a
Foolscap Tub which lives behind a Tor "hidden service" might advertise a
connection hint of "tor:abc123.onion:80". This hint is not usable by an
unenhanced Foolscap application, since onion services cannot be reached
through normal TCP connections. But applications which have installed a
"Connection Handler" that recognizes the "tor:" hint type can make these
connections. A Tor-capable handler would probably replace the usual TCP
connection with one to a locally-configured Tor daemon's SOCKS proxy.

These handlers are given the connection hint, and are expected to return an
"Endpoint" object. Endpoints are a Twisted concept: they implement the
IStreamClientEndpoint interface, and have a "connect()" method. Handlers are
registered for specific hint types. If the handler is unable to parse the
hint it was given (or is otherwise unable to produce a suitable Endpoint), it
should raise InvalidHintError, and the Tub will ignore the hint.

Adding New Connection Handlers
------------------------------

Connection handlers can be added to the Tub with `addConnectionHintHandler`:

.. code-block:: python

    tub = Tub()
    tub.addConnectionHintHandler("tor", tor.socks_port("127.0.0.1", 9050))

Note that each Tub has a separate list of handlers, so if your application
uses multiple Tubs, you must add the handler to all of them. Handlers are
stored in a dictionary, with "tcp:" hints handled by the built-in
`tcp.default` handler.


Recommended Connection-Hint Types
---------------------------------

Connection handlers allow for arbitrary hint types, and applications can put
whatever they want into `Tub.setLocation()`, so this list is not exhaustive.
But to improve interoperability, applications are encouraged to converge on
at least the following hint types:

* `tcp:HOSTNAME:PORT` : This is the standard hint type. It indicates that
  clients should perform DNS resolution on `HOSTNAME` (if it isn't already a
  dotted-quad IPv4 address), make a simple TCP connection to the IPv4 or IPv6
  addresses that result, and perform negotiation with anything that answers.
  (in the future, this will accept `tcp:[IPv6:COLON:HEX]:PORT`, see ticket
  #155)
* (legacy) `HOSTNAME:PORT` : Older applications used this form to indicate
  standard TCP hints. If `HOSTNAME` and `PORT` are of the expected form, this
  is converted (by prepending `tcp:`) before being delivered to the `tcp:`
  handler. New applications should not emit this form.
* `tor:HOSTNAME:PORT` : This indicates the client should connect to
  `HOSTNAME:PORT` via a Tor proxy. The only meaningful reason for putting a
  `tor:` hint in your FURL is if `HOSTNAME` ends in `.onion`, indicating that
  the Tub is listening on a Tor "onion service" (aka "hidden service").
* `i2p:ADDR` : Like `tor:`, but use an I2P proxy. `i2p:ADDR:PORT` is also
  legal, although I2P services do not generally use port numbers.

Built-In Connection Handlers
----------------------------

Foolscap includes connection handlers that know how to use SOCKS5 and Tor
proxies. They live in their own modules, which must be imported separately.
These functions are not in `foolscap.api`, because they depend upon
additional libraries (`txsocksx` and `txtorcon`) which Foolscap does not
automatically depend upon. Your application can declare a dependency upon
Foolscap with "extras" to include these additional libraries, e.g. your
`setup.py` would contain `install_requires=["foolscap[tor]"]` to enable `from
foolscap.connections import tor`.

All handlers live in modules under in the `foolscap.connections` package, so
e.g.:

.. code-block:: python

    from foolscap.connections import tcp
    handler = tcp.default()
    tub.addConnectionHintHandler("tcp", handler)

Foolscap's built-in connection handlers are:

* `tcp.default()` : This is the basic TCP handler which all Tubs use for
  `tcp:` hints by default.
* `socks.socks_endpoint(proxy_endpoint)` : This routes connections to a
  SOCKS5 server at the given endpoint.
* `tor.default_socks()` : This attempts a SOCKS connection to `localhost`
  port 9050, which is the Tor default SOCKS port. If that fails, it tries
  port 9150, which is where the Tor Browser Bundle runs a SOCKS port. This
  should work if either Tor or the TBB are running on the current host.
* `tor.socks_endpoint(tor_socks_endpoint)` : This makes a SOCKS connection to
  an arbitrary endpoint. When using TCP endpoints, callers are strongly
  encouraged to use `host="localhost"`, rather than allowing traffic to
  travel off-box.
* `tor.control_endpoint(tor_control_endpoint)` : This connects to a
  pre-existing Tor daemon via it's "Control Port", which allows the handler
  to query Tor for its current SOCKS port (as well as control Tor entirely).
  On debian systems, the control port lives at `unix:/var/run/tor/control`,
  but the user must be a member of the `debian-tor` unix group to access it.
  The handler only makes one attempt to connect to the control port (when the
  first hint is processed), and uses that connection for all subsequent
  hints.
* `tor.control_endpoint_maker(tor_control_endpoint_maker)` : This is like
  `tor_control_endpoint()`, but instead of providing the endpoint directly,
  you provide a function which will return the endpoint on-demand. The
  function won't be called until a `tor:` hint is encountered, so you can
  avoid doing work until needed, and it can return a Deferred, so the handler
  won't try to connect to Tor until your function says it's ready. The
  function is given one argument: the reactor to use. This handler exists to
  support a use case where the application wants to launch Tor on it's own,
  so it can set up an onion-service listener, but wants to use the same Tor
  for outbound connections too (`tor.launch()` doesn't expose enough txtorcon
  internals to support this, and `tor.control_endpoint()` needs to know the
  endpoint too early, and also connects to Tor too early).
* `tor.launch(data_directory=None, tor_binary=None)` : This launches a new
  copy of Tor (once, when the first hint is processed). `tor_binary=` points
  to the exact executable to be run, otherwise it will search $PATH for the
  `tor` executable. If `data_directory=` is provided, it will be used for
  Tor's persistent state: this allows Tor to cache the "microdescriptor list"
  and can speed up the second invocation of the program considerably. If not
  provided, a ephemeral temporary directory is used (and deleted at
  shutdown).
* `i2p.default(reactor)` : This uses the "SAM" protocol over the default I2P
  daemon port (localhost:7656) to reach an I2P server. Most I2P daemons are
  listening on this port.
* `i2p.sam_endpoint(endpoint)` : This uses SAM on an alternate port to reach
  the I2P daemon.
* (future) `i2p.local_i2p(configdir=None)` : When implemented, this will
  contact an already-running I2P daemon by reading it's configuration to find
  a contact method.
* (future) `i2p.launch(configdir=None, binary=None)` : When implemented, this
  will launch a new I2P daemon (with arguments similar to `tor.launch`).

Applications which want to enable as many connection-hint types as possible
should simply install the `tor.default_socks()` and `i2p.default()` handlers
if they can be imported. This will Just Work(tm) if the most common
deployments of Tor/I2P are installed+running on the local machine. If not,
those connection hints will be ignored.

.. code-block:: python

    try:
        from foolscap.connections import tor
        tub.addConnectionHintHandler("tor", tor.default_socks())
    except ImportError:
        pass # we're missing txtorcon, oh well
    try:
        from foolscap.connections import i2p
        tub.addConnectionHintHandler("i2p", i2p.default(reactor))
    except ImportError:
        pass # we're missing txi2p


Configuring Endpoints for Connection Handlers
---------------------------------------------

Some of these handlers require an Endpoint to reference a proxy server. The
easiest way to obtain a Client Endpoint that reaches a TCP service is like
this:

.. code-block:: python

    from twisted.internet imports endpoints
    proxy_endpoint = endpoints.HostnameEndpoint(reactor, "localhost", 8080)

Applications can use a string from their config file to specify the Endpoint
to use. This gives end users a lot of flexibility to control the
application's behavior. Twisted's `clientFromString` function parses a string
and returns an endpoint:

.. code-block:: python

    from twisted.internet import reactor, endpoints
    config = "tcp:localhost:8080"
    proxy_endpoint = endpoints.clientFromString(reactor, config)


Disabling Built-In TCP Processing
---------------------------------

Normal "tcp" hints are handled by a built-in connection handler named
`tcp.default`. This handles "tcp:example.org:12345". It also handles the
backwards-compatible "example.org:12345" format (still in common use),
because all such hints are translated into the modern "tcp:example.org:12345"
format before the handler lookup takes place.

You might want to disable the `tcp.default` handler, for example to run a
client strictly behind Tor. In this configuration, *all* outbound connections
must be made through the Tor SOCKS proxy (since any direct TCP connections
would expose the client's IP address). Any "tcp:" hints must be routed
through a Tor-capable connection handler.

To accomplish this, you would use `Tub.removeAllConnectionHintHandlers()` to
remove the `tcp.default` handler, then you would add a Tor-aware "tcp:"
handler. You might also add a "tor:" handler, to handle hints that point at
hidden services.

.. code-block:: python

    from foolscap.connections import tor
    tub.removeAllConnectionHintHandlers()
    handler = tor.default_socks()
    tub.addConnectionHintHandler("tcp", handler)
    tub.addConnectionHintHandler("tor", handler)


Writing Handlers (IConnectionHintHandler)
-----------------------------------------

The handler is required to implement `foolscap.ipb.IConnectionHintHandler`,
and to provide a method named `hint_to_endpoint()`. This method takes three
arguments (hint, reactor, and `update_status` callable), and must return a
(endpoint, hostname) tuple. The handler will not be given hints for which it
was not registered, but if it is unable to parse the hint, it should raise
`ipb.InvalidHintError`. Also note that the handler will be given the whole
hint, including the type prefix that was used to locate the handler.

`hint_to_endpoint()` is allowed to return a Deferred that fires with the
(endpoint, hostname) tuple, instead of returning an immediate value.

The endpoint returned should implement
`twisted.internet.interfaces.IStreamClientEndpoint`, and the endpoint's final
connection object must implement `ITLSTransport` and offer the `startTLS`
method. Normal TCP sockets (`TCP4ClientEndpoint` objects) do exactly this.

The `hostname` value is used to construct an HTTP `Host:` header during
negotiation. This is currently underused, but if the connection hint has
anything hostname-shaped, put it here.

Note that these are not strictly plugins, in that the code doesn't
automatically scan the filesystem for new handlers (e.g. with twisted.plugin
or setuptools entrypoint plugins). You must explicitly install them into each
Tub to have any effect. Applications are free to use plugin-management
frameworks to discover objects that implement `IConnectionHintHandler` and
install them into each Tub, however most handlers probably need some local
configuration (e.g. which SOCKS port to use), and all need a hint_type for
the registration, so this may not be as productive as it first appears.

Status delivery: the third argument to ``hint_to_endpoint()`` will be a
one-argument callable named ``update_status()``. While the handler is trying
to produce an endpoint, it may call ``update_status(status)`` with a (native)
string argument each time the connection process has achieved some new state
(e.g. ``launching tor``, ``connecting to i2p``). This will be used by the
``ConnectionInfo`` object to provide connection status to the application.
Note that once the handler returns an endpoint (or the handler's Deferred
finally fires), the status will be replaced by ``connecting``, and the
handler should stop calling the status function.

If the handler raises an error (or yields a Deferred that errbacks), and the
exception object has a (native) string attribute named
``foolscap_connection_handler_error_suffix``, this string will be appended to
the usual connection status (a value in the
``ConnectionInfo.connectorStatuses`` dict), which is normally just the
stringified exception value. By setting this to something like ``(while
connecting to Tor)``, this can be used to distinguish between a failure to
connect to the Tor daemon, versus Tor failing to connect to the target onion
service.
