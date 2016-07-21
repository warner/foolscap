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
    tub.addConnectionHintHandler("tor", OnionThroughTor(proxyaddr))

Note that each Tub has a separate list of handlers, so if your application
uses multiple Tubs, you must add the handler to all of them. Handlers are
stored in a dictionary, with "tcp:" hints handled by the built-in
`DefaultTCP` handler.


Disabling Built-In TCP Processing
---------------------------------

Normal "tcp" hints are handled by a built-in connection handler named
DefaultTCP. This handles "tcp:example.org:12345". It also handles the
backwards-compatible "example.org:12345" format (still in common use),
because all such hints are translated into the modern "tcp:example.org:12345"
format before the handler lookup takes place.

You might want to disable the DefaultTCP handler, for example to run a client
behind Tor. In this configuration, all outbound connections must be made
through the Tor SOCKS proxy (any direct TCP connections would expose the
client's IP address). Any "tcp:" hints must be routed through a Tor-capable
connection handler.

To accomplish this, you would use `Tub.removeAllConnectionHintHandlers()` to
remove the DefaultTCP handler, then you would add a Tor-aware "tcp:" handler.
You might also add a "tor:" handler, to handle hints that point at hidden
services.

.. code-block:: python

    tub.removeAllConnectionHintHandlers()
    tub.addConnectionHintHandler("tcp", TCPThroughTor(proxyaddr))
    tub.addConnectionHintHandler("tor", OnionThroughTor(proxyaddr))

(note that neither of these handlers are included with Foolscap: they are
left as an exercise for the reader)


IConnectionHintHandler
----------------------

The handler is required to implement `foolscap.ipb.IConnectionHintHandler`,
and to provide a method named `hint_to_endpoint()`. This method takes two
arguments (hint and reactor), and must return a (endpoint, hostname) tuple.
The handler will not be given hints for which it was not registered, but if
it is unable to parse the hint, it should raise `ipb.InvalidHintError`. Also
note that the handler will be given the whole hint, including the type prefix
that was used to locate the handler.

`hint_to_endpoint()` is allowed to return a Deferred that fires with the
(endpoint, hostname) tuple, instead of returning an immediate value.

The endpoint returned should implement
`twisted.internet.interfaces.IStreamClientEndpoint`, and the endpoint's final
connection object must implement `ITLSTransport` and offer the `startTLS`
method. Normal TCP sockets (TCP4ClientEndpoint objects) do exactly this.

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
