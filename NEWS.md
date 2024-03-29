User visible changes in Foolscap

## TBD

* The I2P connection handler has been restored.
* Improved support for type checking with `mypy-zope`.

## Release 20.4.0 (12-Apr-2020)

Foolscap has finally been ported to py3 (specifically py3.5+). It currently
still works under py2.7 as well, although support may go away at any time.

Several features were removed to support the transition:

* The SOCKS connection handler has been removed: the `txsocksx` library it
  required does not yet work under py3. The `[socks]` extra has been removed.
* The I2P connection handler has been removed, as `txi2p` is still py2-only.
  The `[i2p]` extra has been removed.
* The `UnsafeBanana` utility has been removed. This worked like stdlib
  "pickle", and was just as unsafe, and nobody used it.

Most APIs now accept either bytes or text, and return native strings
(`str`/`bytes` on py2, `str`/`unicode` on py3).

To maintain wire-level compatibility between foolscap-based programs across
heterogeneous peers, you must keep careful track of the types sent as
arguments inside `callRemote` messages. Programs which casually sent native
strings (bytes) on py2 will continue to send those bytes over the wire, so a
py3 port of the same program will receive bytes, even though the same
(unmodified) code will send unicode instances to the py2 program. When
porting, I recommend first making all string types explicit (`b"for bytes"`
and `u"for text"`), and make sure a py2 version with these changes can
interoperate with the original py2 version. Then a py3 version has a stronger
chance of working. You may be stuck with these awkward `bytes` markers for a
long time.

Some features may no longer work very well. Hopefully these will be fixed
soon:

* logging: Foolscap's extensive logging system stores data in JSON "incident"
  files, and has multiple tools to deliver log events over the wire, some of
  which might rely upon implicit string conversion. Several of these may now
  display spurious `b''` wrappers around the data they display, especially if
  a py2 emitter sends events to a py3 follower
* appserver: the `flappserver` and `flappclient` tools have not been
  extensively tested following the conversion

See docs/py2-3-porting.rst for details and porting recommendations.

Other fixes:

* `callRemote()` did not accept a keyword argument named `f` (#65)
* switch release numbers to [CalVer](https://calver.org/), following the
  [Twisted](https://github.com/twisted/twisted/blob/twisted-20.3.0/docs/core/development/policy/release-process.rst#version-numbers)
  standard of YY.MM.patch


## Release 0.13.2 (22-Dec-2019)

NOTE: This is the last release to support Python-2.x. The Python3 porting
effort is underway, and the next release will only support Python3.

As the official end-of-life date for Python 2.7 is January 1st 2020, you have
nine days to use this release. Enjoy!

Other fixes:

Allow connection attempts to take up to 120s, since some connectors (Tor/I2P)
require spinning up a daemon and letting it connect to the network first.

Tolerate the latest Twisted and txtorcon dependencies.

The `flappserver --help` command now recommends the correct syntax for the
`--location` option (`tcp:example.org:3116` rather than `example.org:3116`).


## Release 0.13.1 (20-Nov-2017)

This release adds a minor feature to "flappclient": it now pays attention to
a pair of environment variables named $FOOLSCAP_TOR_CONTROL_PORT and
$FOOLSCAP_TOR_SOCKS_PORT. If set, the client will install a connection
handler that routes "tor:" -type FURLs through a Tor daemon at the given
ports (both of which are endpoint descriptors, e.g. "tcp:localhost:9050").

To use this, install the "tor" extra, like "pip install foolscap[tor]". If
this extra was not installed (e.g. "txtorcon" is not importable), the
environment variables will be ignored.

This release also improves the reliability of the unit test suite
(specifically test_reconnector) on slower systems.


## Release 0.13.0 (20-Nov-2017)

This release fixes compatibility with the latest Twisted-17.9.0 and changes
the way logfiles are encoded.

Foolscap's "flogtool" event-logging system can be configured to serialize log
events into "Incident Files". In previous versions, these were serialized
with the stdlib "pickle" module. However a recent change to Twisted's
"Failure" class made them unpickleable, causing Foolscap's unit test suite to
fail, and also affect applications which foolscap.logging.log.msg() with
Failures as arguments. And untrusted pickles were unsafe to load anyways.

This release replaces pickle with JSON, making it safe to use "flogtool"
utilities on untrusted incident files. All new incident files created by this
version will use JSON, and all tools (e.g. "flogtool dump") can only handle
JSON-based files.  #247

This also resolves a problem with tox-2.9.0, which caused tests to not run at
all because nothing was installed into the test environment.


## Release 0.12.7 (26-Jul-2017)

This is a minor bugfix release to help Tahoe-LAFS.

It depends upon a newer version of I2P, which should handle Tahoe storage
servers that listen on I2P sockets (the Tahoe executable makes an outbound
connection to the local I2P daemon, however it then accepts inbound TLS
connections on that same socket, which confuses the TLS negotiation because
both sides appear to be "clients", and TLS requires exactly one "client" and
one "server").

It also fixes a minor Tub shutdown behavior to let unit tests work more
reliably.  #274


## Release 0.12.6 (12-Jan-2017)

This is a minor release to improve compatibility with Twisted and I2P.

In this release, the Foolscap test suite no longer uses several deprecated
and/or internal Twisted attributes, so it should pass cleanly on the next
release of Twisted (which will probably be named Twisted-17.0.0).

In addition, the I2P connection handler was enhanced to let applications pass
arbitrary kwargs through to the underlying "SAM" API.

Finally connection-status error messages should be slightly cleaner and
provide more useful information in the face of unrecogized exceptions.


## Release 0.12.5 (07-Dec-2016)

### Connection Status Reporting

This release adds an object named `ConnectionInfo`, which encapsulates
information about a connection (both progress while being established, and
the outcome once connected). This includes which connection hint was
successful, what happened with the other hints, which handlers were used for
each, and when the connection was made or lost. To get one of these, use
`tub.getConnectionInfoForFURL(furl)` any time after `getReference()` is
called, or `rref.getConnectionInfo()` after it resolves.  #267

It also adds `ReconnectionInfo`, a similar object for Reconnectors. These
capture the state of reconnection process (trying, established, waiting), and
will provide a `ConnectionInfo` for the most recent (possibly successful)
connection attempt. The API is `reconnector.getReconnectionInfo()`.  #268

For details, see "Connection Progress/Status" and "Reconnector Status" in
`doc/using-foolscap.rst`.

### Connection Handler API Changes

To support `ConnectionInfo`, the Connection Handler API was changed.

The one backwards-incompatible change was that the `hint_to_endpoint()`
method now takes a third argument, to update the status as the handler makes
progress. External handler functions will need to be modified to accept this
new argument, and applications which use them should declare a dependency
upon the latest Foolscap version, to avoid runtime breakage.

Several backwards-compatible changes were made too: handlers can provide a
`describe()` method (which feeds `ConnectionInfo.connectionHandlers`), and
they can now set a special attribute on any exception they raise, to further
influence the status string.

In addition, the `tor.control_endpoint_maker()` handler now accepts an
optional second argument, which causes the maker function to be called with a
additional `update_status` argument. This backwards-compatible change allows
the maker function to influence the `ConnectionInfo` status too.

The Tor connection handler was enhanced to report distinct statuses for the
different phases of connection: launching a new copy of Tor, connecting to an
existing Tor daemon, etc.

### Minor Fixes

Foolscap-0.12.0 broke `flappserver create`, causing the command to hang
rather than exiting cleanly (although the flappserver directory itself was
probably created properly). This release finally fixes it.  #271


## Release 0.12.4 (27-Sep-2016)

### Improvements

The TCP connection-hint handler can now accept square-bracket-wrapped IPv6
addresses in colon-hex format. You can produce FURLs with such hints by doing
this:

    tub.setLocation("tcp:[2001:0DB8:f00e:eb00::1]:9900")

Foolscap Tubs have been using the IPv6-capable `HostnameEndpoint` since
0.11.0, so this completes the IPv6 support. Note that there are no provisions
for automatically detecting the host's IPv6 addresses: applications that wish
to use addresses (instead of hostnames) must discover those addresses on
their own. #155

A new `tor.control_endpoint_maker()` handler function was added, which is
just like `tor.control_endpoint()` but accepts a callable function, which
will be invoked only when a `tor:` hint is encountered. The function can
return a Deferred which yields the control endpoint. This allows lazy
launching of a Tor daemon, which can also be shared with other application
needs, such as listening on an Onion service.  #270


## Release 0.12.3 (01-Sep-2016)

### Improvements

The `tor.socks_port()` handler was replaced by `tor.socks_endpoint()`, which
takes an Endpoint object (just like `tor.control_endpoint()` does). This
enables applications to speak SOCKS to the Tor daemon over e.g. a Unix-domain
socket. The `tor.socks_port()` API was removed, so applications using it must
upgrade. #265

The `allocate_tcp_port()` utility function would occasionally return ports
that were in use by other applications, when those applications bound their
own port to the loopback interface (127.0.0.1). allocate_tcp_port should no
longer do this.


## Release 0.12.2 (28-Aug-2016)

### Improved Tor Connection Handler

The `tor.control_endpoint` connection handler now properly handles the
config.SocksPort response provided by the debian Tor daemon (and possibly
others), which included a confusing unix-domain socket in its response.

The `tor.socks_port` handler was changed to accept both hostname and port
number. Using anything but "localhost" or "127.0.0.1" is highly discouraged,
as it would reveal your IP address to (possibly hostile) external hosts. This
change was made to support applications (e.g. Tahoe-LAFS) which accept
endpoint strings to configure socks_port, but then parse them and reject
anything but TCP endpoints (to match Foolscap's current limitations). Such
applications ought to warn their users to use only localhost.


## Release 0.12.1 (20-Aug-2016)

### Connection Handlers for SOCKS, Tor, I2P

Foolscap now includes importable connection handlers for SOCKS(5a), Tor, and
I2P. #242, #246, #261

These handlers require additional supporting libraries, so they must be
imported separately, and a setuptools "extra feature" declaration must be
used to ask for the supporting libs. For example, applications which want to
use `tor:` hints (on a host with a Tor daemon running) should have a setup.py
with:

  install_requires=["foolscap[tor]"],

and the Tub setup code should do:

  from foolscap.connections import tor
  tub.addConnectionHintHandler("tor", tor.default_socks())

Full examples and docs are available in docs/connection-handlers.rst.

The default connection-negotiation timeout was increased from 60s to 120s, to
accomodate tor/i2p daemon startup times.


## Release 0.12.0 (20-Jul-2016)

### API changes: no more automatic configuration

Foolscap has moved from automatic listener configuration (randomly-allocated
TCP ports, automatically-determined IP address) to using more predictable
manual configuration. In our experience, the automatic configuration only
worked on hosts which had external IP addresses, which (sadly) is not the
case for most computers attached to the modern internet. #252

Applications must now explicitly provide Foolscap with port numbers (for
Tub.listenOn) and hostnames (for Tub.setLocation). Applications are
encouraged to give users configuration controls to teach Foolscap what
hostname and port number it should advertise to external hosts in the FURLs
it creates. See https://tahoe-lafs.org/trac/tahoe-lafs/ticket/2773 for ideas.

The specific API changes were:

- Tub.setLocationAutomatically() has been deprecated
- Listener.getPortnum() has been deprecated
- calling Tub.listenOn("tcp:0") is also deprecated: callers should allocate a
  port themselves (the foolscap.util.allocate_tcp_port utility function,
  which does not block, has been added for this purpose).

Foolscap tools like "flappserver create" and "flogtool create-gatherer" will
no longer try to deduce their external IP address in an attempt to build
externally-reachable FURLs, and will no longer accept "tcp:0" as a listening
port (they now default to specific port numbers). Instead, they have
--location= and --port arguments. The user must provide '--location' with a
connection-hint string like 'tcp:hostname.example.org:3117' (which is put
into the server's FURLs). This must match the corresponding '--port'
argument, if provided.

- for all tools, if '--port' is provided, it must not be tcp:0
- 'flappserver create' now requires --location, and '--port' defaults to
  tcp:3116
- 'flogtool create-gatherer' requires --location, default port is tcp:3117
- 'flogtool create-incident-gatherer' does too, default is tcp:3118

For backwards-compatibility, old flappservers will have "tcp:0" written into
their "BASEDIR/port" file, and an empty string in "BASEDIR/location": these
must then be edited to allow the flappserver to start. For example, write
"tcp:12345" into "BASEDIR/port" to assign a portnumber, and
"tcp:HOSTNAME:12345" into "BASEDIR/location" to expose it in the generated
FURL.

### Other API changes

Tub.listenOn() now takes a string or an Endpoint (something that implements
twisted.internet.interfaces.IStreamServerEndpoint). This makes it possible to
listen on non-IPv4 sockets (e.g. IPv6-only sockets, or unix-domain sockets,
or more exotic endpoints), as long as Tub.setLocation() is set to something
which the other end's connection handlers can deal with. #203 #243

The "DefaultTCP" handler (which manages normal "tcp:HOST:PORT" connection
hints) has been moved to foolscap.connections.tcp . This makes room for new
Tor/I2P/SOCKS handlers to live in e.g. foolscap.connections.tor . #260

Connection handlers are now allowed to return a Deferred from
hint_to_endpoint(), which should make some handlers easier to write. #262

Note that RemoteReference.notifyOnDisconnect() will be deprecated in the next
release (once all internal uses have been removed from Foolscap).
Applications should stop using it as soon as possible. #42 #140 #207

### Compatibility Changes

This release removes support for the old (py2.4) "sets" module. This was
retained to support applications which were trying to maintain py2.4
compatibility, but it's been so long since this was necessary, it's time to
remove it.

### Other Changes

The internal `allocate_tcp_port()` function was fixed: unexpected kernel
behavior meant that sometimes it would return a port that was actually in
use. This caused unit tests to fail randomly about 5% of the time. #258

IPv6 support is nearly complete: listening on a plain TCP port will typically
accept connections via both IPv4 and IPv6, and the DefaultTCP handler will do
a hostname lookup that can use both A and AAAA records. So as long as your
server has a DNS entry that points at its IPv6 address, and you provide the
hostname to Tub.setLocation(), Foolscap will connect over IPv6. There is one
piece missing for complete support: the DefaultTCP connection handler must be
modified to accept square-bracketed numeric IPv6 addresses, for rare
situations where the host has a known (stable) IPv6 address, but no DNS name.


## Release 0.11.0 (23-Mar-2016)

### Packaging Fixes

Foolscap now declares a dependency on "twisted[tls]" instead of just
"twisted": the "[tls]" extra means "we need Twisted and its TLS support".
That's how we ask for Twisted to depend upon service_identity and other
supporting packages. By using "[tls]", we no longer need to manually depend
upon service_identity ourselves. If Twisted switches to some other scheme for
TLS support, this will correctly ask for that to be included. (#249)

Note that we still depend on pyOpenSSL ourselves, because we need its code to
control certificate validation (if Twisted actually moved away from pyOpenSSL
for TLS, Foolscap might break altogether).

The Twisted dependency was updated to >=16.0.0 (the current version), to get
an important HostnameEndpoint fix (#155).

The "flogtool", "flappserver", and "flappclient" executables are now provided
as "entry_points" on all platforms, not just windows. The old bin/* scripts
have been removed. The "flogtool" entrypoint was fixed (a one-character typo
in the setup.py specification): apparently it was always broken on windows
and nobody noticed.

We now use "tox" to run tests, instead of "trial foolscap", although the
latter is still fine when run in a virtualenv into which Foolscap has been
installed (and is what "tox" does under the hood).

This release also moves all source code from "foolscap/" to "src/foolscap/",
which should avoid some confusion as to which code is being tested.
Developers who work from a git checkout should manually "rm -rf foolscap"
after pulling this change, because otherwise the leftover .pyc files are
likely to cause spurious test failures. (#250, #251)

### partial IPv6 support

Foolscap's outbound connections now use HostnameEndpoint, which means that
connection hints which contain DNS names which map to AAAA (and maybe A6)
records should successfully connect to those IPv6 addresses. There is not yet
any support to *listen* on IPv6 ports, so this probably does not enable IPv6
completely. But a client running this release may be able to connect to
server running some future IPv6-capable release and advertising v6-based
hostnames. (#155)


## Release 0.10.1 (21-Jan-2016)

### Packaging Fixes

This release fixes a version-string management failure when the "log
publisher" feature was used in a tree built from a release tarball (rather
than from a git checkout). This caused a unit test failure, as well as
operational failures when using `flogtool tail`. Thanks to Ramakrishnan
Muthukrishnan (vu3rdd) for the catch and the patch. (#248)


## Release 0.10.0 (15-Jan-2016)

### Compatibility Fixes

This release is compatible with Twisted-15.3.0 through 15.5.0. A change in
15.3.0 triggered a bug in Foolscap which produced a somewhat-infinite series
of log messages when run under `twistd`. This release fixes that bug, and
slightly changes the semantics of calling `log.msg()` with additional
parameters. (#244)

Foolscap no longer claims compatibility with python-2.6.x . Twisted-15.5.0
was the last release to offer 2.6 support, and subsequent releases actively
throw errors when run against 2.6, so we've turned off Foolscap's automated
testing for 2.6. It may remain compatible by accident for a while. (#245)


## Release 0.9.1 (21-Sep-2015)

Point release to deal with PyPI upload problems. No code changes.


## Release 0.9.0 (21-Sep-2015)

### Plugins for Connection Handlers (#236)

New types of connection hints can now be used, by installing a suitable
connection handler into the Tub. These hints could point to I2P servers or
Tor hidden-service (.onion) addresses. The built-in TCP handler can be
replaced entirely to protect a client's IP address by routing all connections
through Tor. Implementation of these plugins are left as exercise for the
reader: Foolscap only provides the built-in "DefaultTCP" handler. See
doc/connection-handlers.rst for details.

### Shared Listeners are removed (#239)

Until this version, it was possible to create a single Listener that serviced
multiple Tubs (by passing the Listener returned from `l=tubA.listenOn(where)`
into `tubB.listenOn(l)`). This seemed useful a long time ago, but in fact was
not, and the implementation caused irreparable problems that were exposed
while testing the new connection handlers. So support for shared Listeners
has been removed: Tubs can still use multiple Listeners, but each Listener
now services at most one Tub. In particular, `Tub.listenOn()` now only
accepts a string, not a Listener instance.

Note that relays and redirects are still on the roadmap, but neither feature
requires sharing a Listener between multiple local Tubs.

### Extended-Form Connection Hints are removed

Support for extended-form connection hints has been removed. These were hints
with explicit key names like "tcp:host=example.org:port=12345", or
"tcp:example.org:timeout=30". They were added in the 0.7.0 release, but since
then we've realized that this is power that should not be granted to external
FURL providers.

The parser now only accepts "tcp:example.org:12345" and "example.org:12345".
Foolscap has never particularly encouraged applications to call
Tub.setLocation() with anything other than these two forms, so we do not
expect any compatibility problems.

### Option to Disable Gifts (#126)

"Gifts", more precisely known as "third-party reference introductions", occur
when one Tub sends you a message that includes a reference to some object on
a third Tub. This allows references to be passed around transparently,
without regard to which Tub they live on (yours, mine, or theirs), but allows
other Tubs to cause you to create network connections to hosts and ports of
their choosing. If this bothers you, the new `tub.setOption("accept-gifts",
False)` option instructs your Tub to reject these third-party references,
causing the calls that used them to signal a Violation error instead.

### Unreachable Tubs now fully supported (#208)

Unreachable "client-only" Tubs can be created by simply not calling either
`tub.listenOn()` nor `tub.setLocation()`. These Tubs can make outbound
connections, but will not accept inbound ones. `tub.registerReference()` will
throw an error, and Gifts delivered to third parties will not work.

Previous versions suggested using `tub.setLocation("")`: this is no longer
recommended.

### new util.allocate_tcp_port() function

To support a future deprecation of `Tub.listenOn("tcp:0")`, the new
allocate_tcp_port() function was added to return (synchronously) a
currently-unused TCP port integer. This can be used during app configuration
to decide on a listening port, which can then be passed into
`Tub.listenOn("tcp:%d" % portnum)`. This may allow Tub.setLocation() to be
called *before* the reactor is started, simplifying application startup code
(this also requires a suitable hostname or IP address, which is a separate
issue).

### Packaging/Dependency Changes

Foolscap now requires Twisted 10.1.0 or newer, to use Endpoints and
connection handler plugins.

Foolscap's logging system (specifically the twisted-to-foolscap bridge) is
now compatible with Twisted-15.2.0. The previous version had problems with
the new contents of twisted.logger's "eventDict" objects. (#235)


## Release 0.8.0 (15-Apr-2015)

### UnauthenticatedTub is gone

As announced in the previous release, UnauthenticatedTub has been removed.
All Tubs are fully authenticated now.

### Security Improvements

Foolscap now generates better TLS certificates, with 2048-bit RSA keys and
SHA256 digests. Previous versions used OpenSSL's defaults, which typically
meant 1024-bit MD5.

To benefit from the new certificates, you must regenerate your Tubs, which
means creating new FURLs (with new TubIDs). Previously-created Tubs will
continue to work normally: only new Tubs will be different.

### Packaging/Dependency Changes

setup.py now requires setuptools

Foolscap now requires pyOpenSSL unconditionally, because all Tubs are
authenticated.

We now recommend "pip install ." to install Foolscap and all its
dependencies, instead of "python setup.py install". See #231 for details.


## Release 0.7.0 (23-Sep-2014)

### Security Fixes

The "flappserver" feature was found to have a vulnerability in the
service-lookup code which, when combined with an attacker who has the ability
to write files to a location where the flappserver process could read them,
would allow that attacker to obtain control of the flappserver process.

Users who run flappservers should upgrade to 0.7.0, where this was fixed as
part of #226.

Each flappserver runs from a "base directory", and uses multiple files within
the basedir to track the services that have been configured. The format of
these files has changed. The flappserver tool in 0.7.0 remains capable of
reading the old format (safely), but will upgrade the basedir to the new
format when you use "flappserver add" to add a new service. Brand new
servers, created with "flappserver create", will use the new format.

The flappserver tool in 0.6.5 (or earlier) cannot handle this new format, and
will believe that no services have been configured. Therefore downgrading to
an older version of Foolscap will require manual reconstruction of the
configured services.

### Major Changes

UnauthenticatedTub has been deprecated, and will be removed in the next
release (0.8.0). This seldom-used feature provides Foolscap's RPC semantics
without any of the security, and was included to enable the use of Foolscap
without depending upon the (challenging-to-install) PyOpenSSL library.
However, in practice, the lack of a solid dependency on PyOpenSSL has made
installation more difficult for applications that *do* want the security, and
UnauthenticatedTub is a footgun waiting to go off. Foolscap's code and
packaging will be simpler without it. (#67)

### Minor Changes

The "git-foolscap" tools, which make it possible to publish and clone Git
repositories over a Foolscap (flappserver) connection, have been moved from
their hiding place in doc/examples/ into their own project, hosted at
https://github.com/warner/git-foolscap . They will also be published on PyPI,
to enable "pip install git-foolscap".

The documentation was converted from Lore to ReStructuredText (.rst). Thanks
to Koblaid for the patient work. (#148)

The connection-hint parser in 0.7.0 has been changed to handle all TCP forms
of Twisted's "Client Endpoint Descriptor" syntax, including the short
"tcp:127.0.0.1:9999" variant. A future version should handle arbitrary
endpoint descriptors (including Tor and i2p, see #203), but this small step
should improve forward compatibility. (#216, #217)


## Release 0.6.5 (12-Aug-2014)

### Compatibility Fixes

This release is compatible with Twisted-14.0.0.

Foolscap no longer claims compatability with python-2.4.x or 2.5.x . These
old versions might still work, but there are no longer automated tests to
ensure this. Future versions will almost certainly *not* work with anything
older than python-2.6.x . Foolscap remains incompatible with py3, sorry.

### Forward Compatibility

When parsing FURLs, the connection hints can now use TCP sockets described
with the Twisted Endpoints syntax (e.g. "tcp:host=127.0.0.1:port=9999"), in
addition to the earlier host:port "127.0.0.1:9999" form. Foolscap-0.6.5
ignores any hint that is not in one of these two forms. This should make it
easier to introduce new hint types in the future.

### Minor Changes

The "ChangeLog" file is no longer updated.

Violation reports now include the method name. (#201)

The "flappserver" tool explicitly rejects unicode input, rather than
producing hard-to-diagnose errors later. (#209)


## Release 0.6.4 (18-Jun-2012)

### Minor Changes

The unreliable 'extras_require' property in setup.py, which allowed other
python programs to declare a dependency on foolscap's "secure_connections"
feature, was removed. See README.packagers for alternate instructions. (#174)

'flogtool' log-dumping commands (dump, tail, web-viewer) now accept a
consistent --timestamps= argument to control how event times are displayed
(UTC, local, seconds-since-epoch, etc). (#192, #193)

Certain invalid "location" strings (accepted by Tub.setLocation and put into
FURLs) are rejected earlier, and with better error messages. The error
message produced when 'flogtool dump' is given a FURL-file (instead of an
event log file) has been improved.

The Incident Gatherer will tolerate incident-file errors better, fetching
remaining incidents instead of halting. (#190)

The git-over-foolscap tools were cleaned up, and the documentation was
brought into line with the implementation. (#197)

Other minor bugs were fixed: #179, #191, #194, #195, #196


## Release 0.6.3 (05-Jan-2012)

### Compatibility Fixes

This release really is compatible with Twisted-11.1.0 . The previous Foolscap
release (0.6.2), despite the changes described below, suffered mild
incompatibilites with the new TLS code in the final Twisted-11.1.0 release.
The most common symptom is a DirtyReactorError in unit tests that use
Tub.stopService() in their tearDown() method (to coordinate shutdown and
cleanup). Another symptom is tests overlapping with one another, causing
port-already-in-use errors.

This incompatibility did not generally affect normal operation, but only
impacted unit tests.

### Other Changes

The Debian packaging tools in misc/ were removed, as they were pretty stale.
These days, both Debian and Ubuntu make their own Foolscap packages.


## Release 0.6.2 (15-Oct-2011)

### Compatibility Fixes

Foolscap-0.6.2 will be compatible with future versions of Twisted (>11.0.0).
The 0.6.1 release will not: a TLS change went into Twisted trunk recently
(after the 11.0.0 release) which broke Foolscap 0.6.1 and earlier.

This release also fixes a minor incompatibility with newer versions of
OpenSSL (0.9.8o was ok, 1.0.0d was not), which caused errors in the test
suite (but normal runtime operation) on e.g. Ubuntu 11.10 "Oneiric".

### Git-Over-Foolscap Tools

The doc/examples/ directory contains two executables (git-foolscap and
git-remote-pb) which, when placed in your $PATH, make it easy to use Foolscap
to access a Git repository. These use the flappserver/flappclient tools and
let you build a FURL that provides read-only or read-write access to a single
repository. This is somewhat like providing SSH access to a repo, but with a
much smaller scope: the client will only be able to manipulate the one
repository, and gets no other authority on the target system. See the tool's
inline comments for usage instructions.

### Minor Fixes

Using 'flappserver upload-file FILE1 FILE2 FILE3..' (with three or more
files) now correctly uploads all files: previously it only managed to upload
the first and last.

'flappserver' argument handling was improved slightly. A workaround was added
to handle a Twisted stdio-closing bug which affected flappserver's
run-command function and broke the git-foolscap tool. Several changes were
made for the benefit of Windows: log filenames all use hyphens (not colons),
log filtering tools tolerate the lack of atomic-rename filesystem operations,
and some unixisms in the test suite were removed.

The Tub.setLogGathererFURL() method can now accept a list (iterable) of log
gatherer FURLs, not just a single one.


## Release 0.6.1 (16-Jan-2011)

### Minor Fixes

The old "sets" module is no longer imported without wrapping the import in a
DeprecationWarning suppressor. We still import it from slicers.set for
compatibility with older code, but that import will not produce a warning.
This should make Foolscap quieter when used with Python 2.6 or later.

A new RemoteReference method named getDataLastReceivedAt() was added, which
will tell you when data was most recently received on the connection
supporting that reference. This can be compared against time.time() to see
how "live" the connection is. For performance reasons, this is only enabled
when keepalives are turned on, otherwise it returns None. (#169)

Some unreachable code was removed. (#165)


## Release 0.6.0 (28-Dec-2010)

### API Changes

#### "foolscap.api" now mandatory

The old import names from foolscap/__init__.py have been removed, finishing
the transition begun with 0.5.0 . Applications must now import Tub,
Referenceable, and so on from "foolscap.api". (#122)

### Compatibility Fixes

Foolscap-0.6.0 is compatible with Twisted-10.2 (released 29-Nov-2010). The
0.5.1 release was not: pb.Listener was depending upon the behavior of an
internal Twisted function that changed, causing an AttributeError in
"StreamServerEndpointService". This is fixed, but the code is still using an
undocumented internal attribute to handle port=0 which will need to be
replaced eventually. (#167)

The first unit test ("test__versions") spuriously failed against Twisted-10.1
and 10.2, mistakenly believing that 10.1 was older than 8.1.0 due to a
lexicographic comparison that should have been numeric.

### Other Changes

Incident filenames are now like "2008-08-22--16:20:28Z.flog" which are in UTC
and mostly ISO-8601 format (the real ISO-8601 would use "_" instead of "--").
This is also used for log-gatherer filenames. (#111)

The logging code now honors FLOGLEVEL= when using FLOGTOTWISTED=1; previously
FLOGLEVEL= was ignored when deciding which log events should be bridged to
the twisted logger. (#154)

Some minor packaging bugs were fixed.


## Release 0.5.1 (25 Mar 2010)

### Bugfixes

This release fixes a significant performance problem, causing receivers a
very long time (over 10 seconds) to process large (>10MB) messages, for
example when receiving a large string in method arguments. Receiver CPU time
was quadratic in the size of the message. (#149)

### Other Changes

This release removes some unused code involved in the now-abandoned
resource-exhaustion defenses. (#127)


## Release 0.5.0 (18 Jan 2010)

### Compatibility

The wire format remains the same as in earlier releases. The preferred API
import path has changed, see below.

### API changes: import statements, foolscap.api

To reduce circular dependencies in Foolscap's internal code, a new
"foolscap.api" module has been created. Applications should use:

 from foolscap.api import Tub

instead of e.g. "from foolscap import Tub". Deprecation warnings will be
raised for code which imports symbols directly from the "foolscap" module.
These warnings will turn into errors in the 0.6.0 release. (see ticket #122
for details)

The nearly-useless getRemoteURL_TCP() function was removed.

### setup.py is more windows-friendly

The main setup.py script has been modified to use setuptools "entry_points="
on windows, which should help create runnable executables of "flogtool" and
"flappserver", with proper extensions. Entry-point scripts are not used on
non-windows platforms, but setuptools still creates fairly opaque executable
scripts (which makes it hard to figure out that e.g. /usr/bin/flogtool wants
to import the "foolscap" module). To get non-opaque scripts, install with
"setup.py install --single-version-externally-managed". (#109)

### tool changes

#### flappserver

"flappserver create" now records the umask value from its environment, and
uses it later when the server is started (since normally twistd resets the
umask to a very restrictive value). A new --umask argument was added to
override this. The server's base directory is chmod go-rwx to protect the
private key from other users.

The "flappserver start" command uses twisted.scripts.twistd.run(), instead of
spawning an intermediate "twistd" process with os.execvp(). This should make
things work better in environments where Twisted is not fully installed
(especially on windows) and correctly launching "twistd" is non-trivial, such
as when some other package is installing it as a setuptools dependency.

"flappclient upload-file ~/foo.txt" will use os.path.expanduser() on the
filename, even if your shell does not. This should make it easier to use from
e.g. buildbot upload commands. (#134)

#### logging

The "flogtool dump" and "flogtool web-viewer" commands now have a
--timestamps argument, which controls how timestamps are expressed (UTC vs
localtime, ISO-9601, etc). The web-viewer HTML pages now have more timestamp
and sorting options, and hyperlinks to select each. (#100)

"flogtool web-viewer --open" will tell your local web browser to open to the
correct page, using the Python stdlib "webbrowser" module.

"flogtool dump" now emits a better error when told to open a missing file.

#### examples

Examples of running the Git version-control-system over a flappserver-based
secure connection have been added to doc/examples/ . This enables
remote-update authority to be expressed as a FURL with no other shell
privileges. To accomplish the same with ssh "authorized_keys" command
restrictions is annoying and error-prone. See
doc/examples/git-proxy-flappclient for setup instructions. This will probably
be simplified to a single "git-furl" executable in a later release.

The xfer-client/xfer-server/command-client examples have been removed,
obsoleted by the flappserver/flappclient tools.

### Other changes

The DeprecationWarning for the obsolete "sets" module is now removed on
python2.6 (#124)

When a getReference() call fails because the remote Tub does not recognize
the FURL, it now only emits the first two letters of the secret swissnum in
the exception, instead of the whole thing. This reduces information leakage
into e.g. stderr logs from a "flappclient --furlfile=X upload-file" command.

DeadReferenceError now includes the remote tubid, interfacename, and remote
method name of the message that was being sent when the lost connection was
discovered, so log.err() calls which record a DeadReferenceError should
include this information. This may make it easier to locate the code that
provoked the error.


## Release 0.4.2 (16 Jun 2009)

### Compatibility

Same as 0.4.1

### the Foolscap Application Server

The big new feature in this release is the "Foolscap Application Server".
This is both a demo of what you can do with Foolscap, and an easy way to
deploy a few simple services that run over secure connections. You create and
start a "flappserver" on one machine, and then use the new "flappclient" on
the other side. The server can contain multiple services, each with a
separate FURL. You give the client a FURL for a specific services, it
connects, does a job, and shuts down.

See doc/flappserver.xhtml for details.

Two service types are provided in this release. The first is a simple
file-uploader: the holder of the FURL gets to upload arbitrary files into a
specific target directory, and nowhere else. The second is a pre-configured
command runner: the service is configured with a shell command, and the
client gets to make it run (but doesn't get to influence anything about what
gets run). The run-command service defaults to sending stdout/stderr/exitcode
to the client program, which will behave as if it were the command being run
(stdout and stderr appear at right time, and it exits with the same
exitcode). The service can be configured to accept stdin, or to turn off
stdout or stderr. The service always runs in a preconfigured working
directory.

To do this with SSH, you'd need to create a new keypair, then set up an
authorized_keys entry to limit that pubkey to a single command, and hope that
environment variables and the working directory don't cause any surprises.
Implementing the fixed-directory file-uploader would probably require a
specialized helper program.

The flappserver provides an easy-to-configure capability-based replacement
those sorts of SSH setups. The first use-case is to allow buildslaves to
upload newly-created debian packages to a central repository and then trigger
a package-index rebuild script. By using FURLs instead of raw SSH keys, the
buildslaves will be unable to affect any .debs in other directories, or any
other files on the repository host, nor will they be able to run arbitrary
commands on that host. By storing the FURLs in a file and using the
--furlfile argument to "flappclient", a buildbot transcript of the upload
step will not leak the upload authority.

### new RemoteReference APIs

RemoteReference now features two new methods. rref.isConnected() returns a
boolean, True if the remote connection is currently live, False if it has
been lost. This is an immediate form of the rref.notifyOnDisconnect()
callback-registration mechanism, and can make certain types of
publish-subscribe code easier to write.


The second is rref.getLocationHints(), which returns a list of location hints
as advertised by the host Tub. Most hints are a ("ipv4",host,portnum) tuple,
but other types may be defined in the future. Note that this is derived from
the FURL that each Tub sends with its my-reference sequence (i.e. it is
entirely controlled by the Tub in which that Referenceable lives), so
getLocationHints() is quite distinct from rref.getPeer() (which returns an
IPv4Address or LoopbackAddress instance describing the other end of the
actual network connection). getLocationHints() indicates what the other Tub
wants you to use for new connections, getPeer() indicates what was used for
the existing connection (which might not accept new connections due to NAT or
proxy issues).

getLocationHints() is meant to make it easier to write connection-status
display code, for example in a server which holds connections to a number of
peers. A status web page can loop over the peer RemoteReferences and display
location information for each one without needing to look deep inside the
hidden RemoteReferenceTracker instance to find it.

### giving up on resource-consumption defenses

Ticket #127 contains more detail, but beginning with this release, Foolscap
will be slowly removing the code that attempted to prevent memory-exhaustion
attacks. Doing this in a single process is just too hard, and the limits that
were enforced provided more problems than protection. To this end, an
internal 200-byte limit on FURL length (applied in Gifts) has been removed.
Later releases will remove more code, hopefully simplifying the deserization
path.

### other bugfixes

Previous releases would throw an immediate exception when Tub.getReference()
or Tub.connectTo() was called with an unreachable FURL (one with a corrupted
or empty set of location hints). In code which walks a list of FURLs and
tries to initiate connections to all of them, this synchronous exception
would bypass all FURLs beyond the troublesome one.

This has been improved: Tub.getReference() now always returns a Deferred,
even if the connection is doomed to fail because of a bad FURL. These
problems are now indicated by a Deferred that errbacks instead of a
synchronous exception.


## Release 0.4.1 (22 May 2009)

### Compatibility

Same as 0.4.0

### Bug fixes

The new RemoteException class was not stringifiable under python2.4 (i.e.
str(RemoteException(f)) would raise an AttributeError), causing problems
especially when callRemote errbacks attempted to record the received Failure
with log.msg(failure=f). This has been fixed.


## Release 0.4.0 (19 May 2009)

### Compatibility

The wire protocol remains the same as before, unchanged since 0.2.6 .

The main API entry point has moved to "foolscap.api": e.g. you should do
"from foolscap.api import Tub" instead of "from foolscap import Tub".
Importing symbols directly from the "foolscap" module is now deprecated.
(this makes it easier to reorganize the internal structure of Foolscap
without causing circular dependencies). (#122)

A near-future release (probably 0.4.1) will add proper
DeprecationWarnings-raising wrappers to all classes and functions in
foolscap/__init__.py . The next major release (probably 0.5.0) will remove
these symbols from foolscap/__init__.py altogether.

Logging functions are still meant to be imported from foolscap.logging.* .

### expose-remote-exception-types (#105)

Remote exception reporting is changing. Please see the new document
docs/failures.xhtml for full details. This release adds a new option:

 tub.setOption("expose-remote-exception-types", BOOL)

The default is True, which provides the same behavior as previous releases:
remote exceptions are presented to look as much as possible like local
exceptions.

If you set it to False, then all remote exceptions will be collapsed into a
single "foolscap.api.RemoteException" type, with an attribute named .failure
that can be used to get more details about the remote exception. This means
that callRemote will either fire its Deferred with a regular value, or
errback with one of three exception types from foolscap.api:
DeadReferenceError, Violation, or RemoteException. (When the option is True,
it could errback with any exception type, limited only by what the remote
side chose to raise)

A future version of Foolscap may change the default value of this option.
We're not sure yet: we need more experience to see which mode is safer and
easier to code with. If the default is changed, the deprecation sequence will
probably be:

 0.5.0: require expose-remote-exception-types to be set
 0.6.0: change the default to False, stop requiring the option to be set
 0.7.0: remove the option

### major bugs fixed:

Shared references now work after a Violation (#104)

The tubid returned by rref.getSturdyRef() is now reliable (#84)

Foolscap should work with python-2.6: Decimal usage fixed, sha/md5
deprecation warnings fixed, import of 'sets' still causes a warning. (#118,
#121)

Foolscap finally uses new-style classes everywhere (#96)

bin/flogtool might work better on windows now (#108)

logfiles now store library versions and process IDs (#80, #97)

The "flogtool web-viewer" tool listens at a URL of "/" instead of "/welcome",
making it slightly easier to use (#120)

You can now setOption() on both log-gatherer-furl and log-gatherer-furlfile
on the same Tub. Previously this caused an error. (#114)


## Release 0.3.2 (14 Oct 2008)

### Compatibility: same as 0.2.6

Incident classifier functions (introduced in 0.3.0) have been changed: if you
have written custom functions for an Incident Gatherer, you will need to
modify them upon upgrading to this release.

### Logging Changes

The log.msg counter now uses a regular Python integer/bigint. The counter in
0.3.1 used itertools.count(), which, despite its documentation, stores the
counter in a C signed int, and thus throws an exception when the message
number exceeds 2**31-1 . This exception would pretty much kill any program
which ran long enough to emit this many messages, a situation which was
observed in a busy production server with an uptime of about three or four
weeks. The 0.3.2 counter will be promoted to a bigint when necessary,
removing this limitation. (ticket #99)

The Incident-Gatherer now imports classification functions from files named
'classify_*.py' in the gatherer's directory. This effectively adds
"classifier plugins". The signature of the functions has changed since the
0.3.0 release, making them easier to use. If you have written custom
functions (and edited the gatherer.tac file to activate them, using
gs.add_classifier()), you will need to modify the functions to take a single
'trigger' argument.

These same 'classify_*.py' plugins are used by a new "flogtool
classify-incident" subcommand, which can be pointed at an incident file, and
performs the same kind of classification as the Incident Gatherer. (#102).

The logfiles produced by the "flogtool tail" command and the internal
incident-reporter now include the PID of the reporting process. This can be
seen by passing the --verbose option to "flogtool dump", and will be made
more visible in later releases. (#80).

The "flogtool web-viewer" tool now marks Incident triggers (#79), and
features a "Reload Logfile" button to re-read the logfile on disk (#103).
This is most useful when running unit tests, in conjunction with the
FLOGFILE= environment variable.

### Other Changes

When running unit tests, if the #62 bug is encountered (pyopenssl >= 0.7 and
twisted <= 8.1.0 and selectreactor), the test process will emit a warning and
pause for ten seconds to give the operator a chance to halt the test and
re-run it with --reactor=poll. This may help to reduce the confusion of a
hanging+failing test run.

The xfer-client.py example tool (in doc/listings/) has been made more
useable, by calling os.path.expanduser() on its input files, and by doing
sys.exit(1) on failure (instead of hanging), so that external programs can
react appropriately.


## Release 0.3.1 (03 Sep 2008)

### Compatibility: same as 0.2.6

### callRemote API changes: DeadReferenceError

All partitioning exceptions are now mapped to DeadReferenceError. Previously
there were three separate exceptions that might indicate a network partition:
DeadReferenceError, ConnectionLost, and ConnectionDone. (a network partition
is when one party cannot reach the other party, due to a variety of reasons:
temporary network failure, the remote program being shut down, the remote
host being taken offline, etc).

This means that, if you want to send a message and don't care whether that
message makes it to the recipient or not (but you *do* still care if the
recipient raises an exception during processing of that message), you can set
up the Deferred chain like this:

 d = rref.callRemote("message", args)
 d.addCallback(self.handle_response)
 d.addErrback(lambda f: f.trap(foolscap.DeadReferenceError))
 d.addErrback(log.err)

The first d.addErrback will use f.trap to catch DeadReferenceError, but will
pass other exceptions through to the log.err() errback. This will cause
DeadReferenceError to be ignored, but other errors to be logged.

DeadReferenceError will be signalled in any of the following situations:

 1: the TCP connection was lost before callRemote was invoked
 2: the connection was lost after the request was sent, but before
    the response was received
 3: when the active connection is dropped because a duplicate connection was
    established. This can occur when two programs are simultaneously
    connecting to each other.

### logging improvements

#### bridge foolscap logs into twistd.log

By calling foolscap.logging.log.bridgeLogsToTwisted(), or by setting the
$FLOGTOTWISTED environment variable (to anything), a subset of Foolscap log
events will be copied into the Twisted logging system. The default filter
will not copy events below the log.OPERATIONAL level, nor will it copy
internal foolscap events (i.e. those with a facility name that starts with
"foolscap"). This mechanism is careful to avoid loops, so it is safe to use
both bridgeLogsToTwisted() and bridgeTwistedLogs() at the same time. The
events that are copied into the Twisted logging system will typically show up
in the twistd.log file (for applications that are run under twistd).

An alternate filter function can be passed to bridgeLogsToTwisted().

This feature provides a human-readable on-disk record of significant events,
using a traditional one-line-per-event all-text sequential logging structure.
It does not record parent/child relationships, structured event data, or
causality information.

#### Incident Gatherer improvements

If an Incident occurs while a previous Incident is still being recorded (i.e.
during the "trailing log period"), the two will be folded together.
Specifically, the second event will not trigger a new Incident, but will be
recorded in the first Incident as a normal log event. This serves to address
some performance problems we've seen when incident triggers occur in
clusters, which used to cause dozens of simultaneous Incident Recorders to
swing into action.

The Incident Gatherer has been changed to only fetch one Incident at a time
(per publishing application), to avoid overloading the app with a large
outbound TCP queue.

The Incident Gatherer has also been changed to scan the classified/* output
files and reclassify any stored incidents it has that are not mentioned in
one of these files. This means that you can update the classification
functions (to add a function for some previously unknown type of incident),
delete the classified/unknown file, then restart the incident gatherer, and
it will only reclassify the previously-unknown incidents. This makes it much
easier to iteratively develop classification functions.

#### Application Version data

The table of application versions, previously displayed only by the 'flogtool
tail' command, is now recorded in the header of both Incidents and the
'flogtool tail --save-to' output file.

The API to add application versions has changed: now programs should call
foolscap.logging.app_versions.add_version(name, verstr).


## Release 0.3.0 (04 Aug 2008)

### Compatibility: same as 0.2.6

The wire-level protocol remains the same as other recent releases.

The new incident-gatherer will only work with applications that use Foolscap
0.3.0 or later.

### logging improvements

The "incident gatherer" has finally been implemented. This is a service, like
the log-gatherer, which subscribes to an application's logport and collects
incident reports: each is a dump of accumulated log messages, triggered by
some special event (such as those above a certain severity threshold). The
"flogtool create-incident-gatherer" command is used to create one, and twistd
is used to start it. Please see doc/logging.xhtml for more details.

The incident publishing API was changed to support the incident-gatherer. The
incident-gatherer will only work with logports using foolscap 0.3.0 or newer.

The log-publishing API was changed slightly, to encourage the use of
subscription.unsubscribe() rather than publisher.unsubscribe(subscription).
The old API remains in place for backwards compatibility with log-gatherers
running foolscap 0.2.9 or earlier.

The Tub.setOption("log-gatherer-furlfile") can accept a file with multiple
FURLs, one per line, instead of just a single FURL. This makes the
application contact multiple log gatherers, offering its logport to each
independently, e.g. to connect to both a log-gatherer and an
incident-gatherer.

### API Additions

RemoteReferences now have a getRemoteTubID() method, which returns a string
(base32-encoded) representing the secure Tub ID of the remote end of the
connection. For any given Tub ID, only the possessor of the matching private
key should be able to provide a RemoteReference for which getRemoteTubID()
will return that value. I'm not yet sure if getRemoteTubID() is a good idea
or not (the traditional object-capability model discourages making
access-control decisions on the basis of "who", instead these decisions
should be controlled by "what": what objects do they have access to). This
method is intended for use by application code that needs to use TubIDs as an
index into a table of some sort. It is used by Tahoe to securely compute
shared cryptographic secrets for each remote server (by hashing the TubID
together with some other string).

Note that the rref.getSturdyRef() call (which has been present in Foolscap
since forever) is *not* secure: the remote application controls all parts of
the sturdy ref FURL, including the tubid. A future version of foolscap may
remedy this.

### Bug fixes

The log-gatherer FURL can now be set before Tub.setLocation (the connection
request will be deferred until setLocation is called), and
getLogPort/getLogPortFURL cannot be called until after setLocation. These two
changes, in combination, resolve a problem (#55) in which the gatherer
connection could be made before the logport was ready, causing the
log-gatherer to fail to subscribe to receive log events.

### Dependent Libraries

Foolscap uses PyOpenSSL for all of its cryptographic routines. A bug (#62)
has been found in which the current version of Twisted (8.1.0) and the
current version of PyOpenSSL (0.7) interact badly, causing Foolscap's unit
tests to fail. This problem will affect application code as well
(specifically, Tub.stopService will hang forever). The problem only appears
to affect the selectreactor, so the current recommended workaround is to run
unit tests (and applications that need to shut down Tubs) with --reactor=poll
(or whatever other reactor is appropriate for the platform, perhaps iocp). A
less-desireable workaround is to downgrade PyOpenSSL to 0.6, or Twisted to
something older. The Twisted maintainers are aware of the problem and intend
to fix it in an upcoming Twisted release.


## Release 0.2.9 (02 Jul 2008)

### Compatibility: exactly the same as 0.2.6

### logging bugs fixed

The foolscap.logging.log.setLogDir() option would throw an exception if the
directory already existed, making it unsuitable for use in an application
which is expected to be run multiple times. This has been fixed.

### logging improvements

'flogtool tail' now displays the process ID and version information about the
remote process. The tool will tolerate older versions of foolscap which do
not offer the get_pid interface. (foolscap ticket #71)

The remote logport now uses a size-limited queue for messages going to a
gatherer or 'flogtool tail', to prevent the monitored process from using
unbounded amounts of memory during overload situations (when it is generating
messages faster than the receiver can handle them). This solves a runaway
load problem we've seen in Tahoe production systems, in which a busy node
sends log messages to a gatherer too quickly for it to absorb, using lots of
memory to hold the pending messages, which causes swapping, which causes more
load, making the problem worse. We frequently see an otherwise well-behaved
process swell to 1.4GB due to this problem, occasionally failing due to VM
exhaustion. Of course, a bounded queue means that new log events will be
dropped during this overload situation. (#72)

### serialization added for the Decimal type (#50)

### debian packaging targets added for gutsy and hardy

The Makefile now has 'make debian-gutsy' and 'make debian-hardy' targets.
These do the same thing as 'make debian-feisty'. (#76)


## Release 0.2.8 (04 Jun 2008)

### Compatibility: exactly the same as 0.2.6

### setuptools dependencies updated

Foolscap (when built with setuptools) now uses the "extras_require" feature
to declare that it needs pyOpenSSL if you want to use the
"secure_connections" feature. This makes easy_install easier to use in
projects that depend upon Foolscap (and also insist upon using secure
connections): they do not need to declare a dependency on pyOpenSSL
themselves, instead they declare a dependency on
"Foolscap[secure_connections]". See the following documentation for more
details:
http://peak.telecommunity.com/DevCenter/setuptools#declaring-extras-optional-features-with-their-own-dependencies

### New RemoteReference.getPeer() method

The new rref.getPeer() method will return address information about the far
end of the connection, allowing you to determine their IP address and port
number. This may be useful for debugging or diagnostic purposes.

### Minor bugs fixed

Tub.registerReference() with both name= and furlFile= arguments now works
even when the furlFile= already exists.

Tubs which have been shutdown now give more useful error messages when you
(incorrectly) try to use them again. Previously a bug caused them to emit a
TypeError.


## Release 0.2.7 (13 May 2008)

### Compatibility: exactly the same as 0.2.6

### flogtool works again

The "flogtool" utility was completely non-functional in 0.2.6 . This has been
fixed.

### Known Issues

#### some debian packages are wrong

When using the 'make debian-dapper' target (to build a .deb for a dapper
system), the resulting .deb sometimes includes a full copy of Twisted, and is
probably unsuitable for installation. This appears to be a result of
installation behavior changing due to setuptools being imported (even though
it is not explicitly used). No other platforms .deb files seem to be affected
this way. Package builders are advised to examine the generated .deb closely
before using it.


## Release 0.2.6 (06 May 2008)

### Compatibility

All releases between 0.1.3 and 0.2.6 (inclusive) are fully wire-compatible.

The saved logfiles produced (by e.g. 'flogtool tail --save-to' and the
log-gatherer) in 0.2.6 and beyond are not readable by tools (e.g. 'flogtool
dump' and 'flogtool filter') from 0.2.5 and earlier.

FURLs which contain "extensions" (described below) will not be tolerated by
foolscap 0.2.5 or earlier. If, at some point in the future, we add such
extensions to published FURLs, then such an application will require
foolscap-0.2.6 or later to interpret those FURLs.

### Logging Changes

#### "Incident" Logging

This release finally implements the "strangeness-triggered logging" espoused
in doc/logging.xhtml . By giving the foolscap logging code a directory to
work with, the logging system will automatically save a compressed pickled
logfile containing the messages that lead up to sufficiently-severe log
event. The docs explain how to control what "sufficiently-severe" means.
These events are retrievable through the logport, although no tools have been
written yet to actually extract them. They are also retrievable by using
'flogtool dump' directly on the incident files.

#### 'flogtool as a subcommand

The implementation of the 'flogtool' executable has been rearranged to make
it possible to add a 'flogtool' subcommand to some other executable.

#### 'flogtool filter' now has --above LEVEL and --from TUBID options
#### 'flogtool dump' has --rx-time option, also shows failure tracebacks
#### gatherer: don't add erroneous UTC-implying "Z" suffix to filename timestamps
#### 'flogtool tail': don't add spurious "0" to timestamps

### constraints no longer reject ('reference',) sequences

The foolscap/banana serialization protocol responds to sending two separate
copies of the same object in the same callRemote message by emitting one
serialized object sequence and one 'reference' sequence: this is the standard
way by which cycles are broken in the serialized data. Unfortunately, the
wire-level constraint checkers in 0.2.5 and earlier would reject reference
sequences with a Violation exception: if they were expecting a tuple, they
would reject anything else, even a reference sequence that pointed at a
tuple.

Worse yet, python's normal constant-object folding code can produce shared
references where you might not expect. In the following example, the two
tuples are identical objects (and result in a 'reference' sequence on the
wire), despite the programmer having typed them separately:

 rref.callRemote("haveTwoTuples", (0,1), (0,1) )

Foolscap-0.2.6 now allows reference sequence in all wire-level constraint
checks, to avoid this false-negative Violation. The post-deserialization
check will still enforce the constraint properly. It just does it late enough
to be able to tell what the reference points to.

### Twisted/pyopenssl compatibility

#### compatible with Twisted-8.0.x

Some unit test failures under Twisted-8.0.x (the most recent release) were
fixed: tests now pass against Twisted-8.0.x, and a buildbot is used to make
sure compatibility is maintained in the future.

#### incompatible with pyOpenSSL-0.7

An incompatibility has been discovered with the most recent version of
PyOpenSSL. pyopenssl 0.6 works correctly, but pyopenssl 0.7 causes modern
versions of Twisted (both 2.5.x and 8.0.x) to follow a code path that breaks
the Foolscap unit tests. This may or may not cause a problem in actual
application use (the symptom is that the non-winning parallel connections are
not disconnected properly, and several negotiation timers are left running).
Until a fix is developed for either Twisted or PyOpenSSL, the recommended
workaround is to downgrade to PyOpenSSL-0.6 . Twisted bug #3218 and Foolscap
bug #62 exist to track this problem.

### setup.py is more setuptools-friendly

The foolscap version string is located with a regular expression rather than
an import, allowing setuptools to install Foolscap as a build-dependency of
some other project without having Twisted available first. If setuptools is
available, we also declare a dependency upon Twisted (at least 2.4.0), to
give more information to the setuptools dependency-auto-installer.

### Unauthenticated FURLs can now contain multiple connection hints

Previously they were limited to a single one

### FURLs can now contain extensions, providing forwards-compatibility

The parsing of FURLs has been refined to tolerate (and ignore) certain kinds
of extensions. The "tubid" section will be able to have additional
identifiers (perhaps stronger hashes for the public key, or an
encryption-ready EC-DSA public key). In addition, the "connection hints"
section will be able to contain alternate protocol specifiers (for TCP over
IPv6, or a less connection-oriented UDP transport).

By ignoring such extensions, foolscap-0.2.6 will tolerate FURLs produced
(with extensions) by some future version of foolscap. This marks the
beginning of a "transition period": when such extensions are introduced,
0.2.6 will be the oldest version still capable of interoperating with the
extension-using new version.


## Release 0.2.5 (25 Mar 2008)

### Compatibility

All releases between 0.1.3 and 0.2.5 (inclusive) are fully wire-compatible.

The new 'flogtool tail --catch-up' command requires a log publisher running
0.2.5 or later. 'flogtool tail' without the --catch-up option will work with
earlier publishers.

### Licensing clarification

Foolscap is distributed under the (very liberal) terms of the MIT license,
which is the same license that Twisted uses. It's been like this since the
beginning, but this is the first release to make this obvious by including a
LICENSE file.

### foolscap.logging Changes

'flogtool tail' now has a --catch-up option, which prompts the remote
publisher to deliver stored historical events to the subscribe, in proper
sequential order. This allows you to connect to a process that has just done
something interesting and grab a copy of the log events relevant to that
event.

'flogtool tail' also has a --save-to option, which specifies a filename to
which all captured events should be saved. This file can be processed further
with 'flogtool dump', 'flogtool filter', or 'flogtool web-viewer'. This
behaves much like the unix 'tee' utility, except that the saved data is
recorded in a lossless binary format (whereas the text emitted to stdout is
not particularly machine-readable).

'flogtool tail' and 'flogtool dump' both emit human-readable log messages by
default. The --verbose option will emit raw event dictionaries, which contain
slightly more information but are harder to read.

'flogtool create-gatherer' will create a log gatherer .tac file in a new
working directory. This .tac file can be launched with 'twistd', the standard
Twisted daemon-launching program. This is significantly easier to work with
than the previous 'flogtool gather' command (which has been removed). The new
--rotate option will cause the log-gatherer to switch to a new output file
every N seconds. The --bzip option will make it compress the logfiles after
rotating them. For example, a log gatherer that rotates and compresses log
files once per day could be created and launched with:

 flogtool create-gatherer --rotate 86400 --bzip ./workdir
 (cd workdir && twistd -y gatherer.tac)

### New sample programs

doc/listings/command-server.py and command-client.py are a pair of programs
that let you safely grant access to a specific command. The server is
configured with a command line to run, and a directory to run it from. The
client gets a FURL: when the client is executed, the server will run its
preconfigured command. The client gets to see stdout and stderr (and the exit
status), but does not get to influence the command being run in any way.
This is much like setting up an ssh server with a restricted command, but
somewhat easier to configure.

doc/listings/xfer-server.py and xfer-client.py are similar, but provide file
transfer services instead of command execution.

### New Features

Tub.setLocationAutomatically() will try to determine an externally-visible IP
address and feed it to Tub.setLocation(). It does this by preparing to send a
packet to a well-known public IP address (one of the root DNS servers) and
seeing which network interface would be used. This will tend to find the
outbound default route, which of course is only externally-visible if the
host is externally-visible. Applications should not depend upon this giving a
useful value, and should give the user a way to configure a list of
hostname+portnumbers so that manually-configured firewalls, port forwarders,
and NAT boxes can be dealt with.


## Release 0.2.4 (28 Jan 2008)

### Compatibility

All releases between 0.1.3 and 0.2.4 (inclusive) are fully wire-compatible.

### foolscap.logging Changes

#### 'flogtool filter' command added

This mode is used to take one event-log file and produce another with a
subset of the events. There are several options to control the filtering:
"--strip-facility=foolscap" would remove all the foolscap-related messages,
and "--after=start --before=end" will retain events that occur within the
given period. The syntax is still in flux, expect these options to change in
the next few releases. The main idea is to take a very large logfile and turn
it into a smaller, more manageable one.

#### error logging

Applications should avoid recording application-specific instances in log
events. Doing so will forces the log viewer to access the original source
code. The current release of foolscap uses pickle, so such instances will be
loadable if the viewer can import the same code, but future versions will
probably switch to using Banana, at which point trying to log such instances
will cause an error.

In this release, foolscap stringifies the type of an exception/Failure passed
in through the failure= kwarg, to avoid inducing this import dependency in
serialized Failures. It also uses the CopiedFailure code to improve
portability of Failure instances, and CopiedFailures have been made
pickleable.

The preferred way to log a Failure instance is to pass it like so:

 def _oops(f):
   log.msg("Oh no, it failed", failure=f, level=log.BAD)
 d.addErrback(_oops)

Finally, a 'log.err()' method was added, which behaves just like Twisted's
normal log.err(): it can be used in a Deferred errback, or inside an
exception handler.

#### 'flogtool web-viewer'

Adding a "sort=time" query argument to the all-events viewing page URL will
turn off the default nested view, and instead will sort all events strictly
by time of generation (note that unsynchronized clocks may confuse the
relative ordering of events on different machines). "sort=number" sorts all
events by their event number, which is of dubious utility (since these
numbers are only scoped to the Tub). "sort=nested" is the default mode.

The web-viewer now provides "summary views", which show just the events that
occurred at a given severity level. Each event is a hyperlink to the line in
the all-events page (using anchor/fragment tags), which may make them more
convenient to bookmark or reference externally.


## Release 0.2.3 (24 Dec 2007)

### Compatibility

All releases between 0.1.3 and 0.2.3 (inclusive) are fully wire-compatible.

### Bug Fixes

RemoteReference.getSturdyRef() didn't work (due to bitrot). It has been
fixed.

### foolscap.logging Changes

This release is mostly about flogging improvements: some bugs and misfeatures
were fixed:

#### tolerate '%' in log message format strings

Dictionary-style kwarg formatting is now done with a twisted-style style
format= argument instead of happening implicitly. That means the acceptable
ways to call foolscap.logging.log.msg are:

 log.msg("plain string")
 log.msg("no args means use 0% interpolation")
 log.msg("pre-interpolated: %d apples" % apples)
 log.msg("posargs: %d apples and %d oranges", apples, oranges)
 log.msg(format="kwargs: %(numapples)d apples", numapples=numapples)

The benefit of the latter two forms are that the arguments are recorded
separately in the event dictionary, so viewing tools can filter on the
structured data, think of something like:

  [e for e in allEvents if e.get("numapples",0) > 4]

#### log facility names are now dot-separated, to match stdlib logging
#### log levels are derived from numerical stdlib logging levels
#### $FLOGFILE to capture flog events during 'trial' runs

One challenge of the flogging system is that, once an application was changed
to write events to flogging instead of twisted's log, those events do not
show up in the normal places where twisted writes its logfiles. For full
applications this will be less of an issue, because application startup will
tell flogging where events should go (flogging is intended to supplant
twisted logging for these applications). But for events emitted during unit
tests, such as those driven by Trial, these events would get lost.

To address this problem, the 0.2.3 flogging code looks for the "FLOGFILE"
environment variable at import time. This specifies a filename where flog
events (a series of pickled event dictionaries) should be written. The file
is opened at import time, events are written during the lifetime of the
process, then the file is closed at shutdown using a Twisted "system event
trigger" (which happens to be enough to work properly under Trial: other
environments may not work so well). If the FLOGFILE filename ends in .bz2,
the event pickles will be compressed, which is highly recommended because it
can result in a 30x space savings (and e.g. the Tahoe unit test run results
in 90MB of uncompressed events). All 'flogtool' modes know how to handle a
.bz2 compressed flogfile as well as an uncompressed one.

The "FLOGTWISTED" environment variable, if set, will cause this same code to
bridge twisted log messages into the flogfile. This makes it easier to see
the relative ordering of Twisted actions and foolscap/application events.
(without this it becomes very hard to correlate the two sources of events).

The "FLOGLEVEL" variable specifies a minimum severity level that will be put
into the flogfile. This defaults to "1", which puts pretty much everything
into the file. The idea is that, for tests, you might as well record
everything, and use the filtering tools to control the display and isolate
the important events. Real applications will use more sophisticated tradeoffs
between disk space and interpretation effort.

The recommended way to run Trial on a unit test suite for an application that
uses Foolscap is:

 FLOGFILE=flog.out FLOGTWISTED=1 trial PACKAGENAME

Note that the logfile cannot be placed in _trial_temp/, because trial deletes
that directory after flogging creates the logfile, so the logfile would get
deleted too. Also note that the file created by $FLOGFILE is truncated on
each run of the program.


## Release 0.2.2 (12 Dec 2007)

### Compatibility

All releases between 0.1.3 and 0.2.2 (inclusive) are fully wire-compatible.
New (optional) negotiation parameters were added in 0.2.1 (really in 0.2.0).

### Bug Fixes

The new duplicate-connection handling code in 0.2.1 was broken. This release
probably fixes it.

There were other bugs in 0.2.1 which were triggered when a duplicate
connection was shut down, causing remote calls to never be retired, which
would also prevent the Reconnector from doing its job. These should be fixed
now.

### Other Changes

Foolscap's connection-negotiation mechanism has been modified to use foolscap
logging ("flog") instead of twisted.log .

Setting the FLOGFILE= environment variable will cause a Foolscap-using
program to write pickled log events to a file of that name. This is
particularly useful when you want to record log events during 'trial' unit
test run. The normal API for setting this file will be added later. The
FLOGTWISTED= environment variable will cause the creation of a twisted.log
bridge, to copy all events from the twisted log into the foolscap log.

The 'flogtool web-view' mode has been enhanced to color-code events according
to their severity, and to format Failure tracebacks in a more-readable way.


## Release 0.2.1 (10 Dec 2007)

### Compatibility

All releases between 0.1.3 and 0.2.1 (inclusive) are fully wire-compatible.
0.2.1 introduces some new negotiation parameters (to handle duplicate
connections better), but these are ignored by older versions, and their lack
is tolerated by 0.2.1 .

### New Features

#### new logging support

Foolscap is slowly acquiring advanced diagnostic event-logging features. See
doc/logging.xhtml for the philosophy and design of this logging system. 0.2.1
contains the first few pieces, including a tool named bin/flogtool that can
be used to watch events on a running system, or gather events from multiple
applications into a single place for later analysis. This support is still
preliminary, and many of the controls and interfaces described in that
document are not yet implemented.

#### better handling of duplicate connections / NAT problems

The connection-management code in 0.1.7 and earlier interacted badly with
programs that run behind NAT boxes (especially those with aggressive
connection timeouts) or on laptops which get unplugged from the network
abruptly. Foolscap seeks to avoid duplicate connections, and various
situtations could cause the two ends to disagree about the viability of any
given connection. The net result (no pun intended) was that a client might
have to wait up to 35 minutes (depending upon various timeout values) before
being able to reestablish a connection, and the Reconnector's exponential
backoff strategy could easily push this into 90 minutes of downtime.

0.2.1 uses a different approach to accomplish duplicate-suppression, and
should provide much faster reconnection after netquakes. To benefit from
this, both ends must be running foolscap-0.2.1 or newer, however there is an
additional setting (not enabled by default) to improve the behavior of
pre-0.2.1 clients: tub.setOption("handle-old-duplicate-connections", True).

#### new Reconnector methods

The Reconnector object (as returned by Tub.connectTo) now has three utility
methods that may be useful during debugging. reset() drops the backoff timer
down to one second, causing the Reconnector to reconnect quickly: you could
use this to avoid an hour-long delay if you've just restarted the server or
re-enabled a network connection that was the cause of the earlier connection
failures. getDelayUntilNextAttempt() returns the number of seconds remaining
until the next connection attempt. And getLastFailure() returns a Failure
object explaining why the last connection attempt failed, which may be a
useful diagnostic in trying to resolve the connection problems.

### Bug Fixes

There were other minor changes: an OS-X unit test failure was resolved,
CopiedFailures are serialized in a way that doesn't cause constraint
violations, and the figleaf code-coverage tools (used by foolscap developers
to measure how well the unit tests exercise the code base) have been improved
(including an emacs code-used/unused annotation tool).


## Release 0.2.0 (10 Dec 2007)

This release had a fatal bug that wasn't caught by the unit tests, and was
superseded almost immediately by 0.2.1 .


## Release 0.1.7 (24 Sep 2007)

### Compatibility

All releases between 0.1.3 and 0.1.7 (inclusive) are fully wire-compatible.

### Bug Fixes

#### slow remote_ methods shouldn't delay subsequent messages (#25)

In earlier releases, a remote_ method which runs slowly (i.e. one which
returns a Deferred and does not fire it right away) would have the
unfortunate side-effect of delaying all subsequent calls from the same
Broker. Those later calls would not be delivered until the first message had
completed processing. If, for some reason, that Deferred were never fired,
this Foolscap bug would prevent any other remote_ methods from ever being
called.

This is not how Foolscap's message-ordering logic is designed to work.
Foolscap guarantees in-order *delivery* of messages, but does not require
that they be completed/retired in that same order.

This has now been fixed. The invocation of remote_* is done in-order: any
further sequencing is up to the receiving application.

For example, in the following code:

 sender:
   rref.callRemote("quick", 1)
   rref.callRemote("slow", 2)
   rref.callRemote("quick", 3)

 receiver:
   def remote_quick(self, num):
     print num
   def remote_slow(self, num):
     print num
     d = Deferred()
     def _done():
       print "DONE"
       d.callback(None)
     reactor.callLater(5.0, _done)
     return d

The intended order of printed messages is 1,2,3,DONE . This bug caused the
ordering to be 1,2,DONE,3 instead.

#### default size limits removed from all Constraints (#26)

Constraints in Foolscap serve two purposes: DoS attack mitigation, and strong
typing on remote interfaces to help developers find problems sooner. To
support the former, most container-based Constraints had default size limits.
For example, the default StringConstraint enforced a maximum length of 1000
characters, and the ListConstraint had a maxLength of 30 elements.

In practice, these limits turned out to be more surprising than helpful.
Applications which worked fine in testing would mysteriously break when
subjected to data that was larger than expected. Developers who used
Constraints for their type-checking properties were surprised to discover
that they were getting size limitations as well. In addition, the
DoS-mitigation code in foolscap is not yet complete, so the cost/benefit
ratio of this feature was dubious.

For these reasons, all default size limits have been removed from this
release. The 0.1.7 StringConstraint() schema is equivalent to the 0.1.6
StringConstraint(maxLength=None) version. To get the 0.1.6 behavior, use
StringConstraint(maxLength=1000). The same is true for ListConstraint,
DictConstraint, SetConstraint, and UnicodeConstraint.

### New features

#### Tub.registerReference(furlFile=)

In the spirit of Tub(certFile=), a new argument was added to
registerReference that instructs Foolscap to find and store a
randomly-generated name in the given file. This makes it convenient to allow
subsequent invocations of the same program to use the same stable (yet
unguessable) identifier for long-lived objects. For example, a Foolscap-based
server can make its Server object available under the same FURL from one run
of the program to the next with the following startup code:

  s = MyServer()
  furl = tub.registerReference(s, furlFile=os.path.join(basedir, "server"))

If the furlFile= exists before registerReference is called, a FURL will be
read from it, and a name extracted to use for the object. If not, the file
will be created and filled with a FURL that uses a randomly-generated name.

#### Tub.serialize()

Work is ongoing to implement E-style cryptographic Sealers/Unsealers in
Foolscap (see ticket #20). Part of that work has made it into this release.
The new Tub.serialize() and Tub.unserialize() methods provide access to the
underlying object-graph-serialization code. Normally this code is used to
construct a bytestream that is immediately sent over an SSL connection to a
remote host; these methods return a string instead. Eventually, a Sealer will
return an encrypted version of this string, and the corresponding Unsealer
will take the encrypted string and build a new object graph.

The foolscap.serialize() and .unserialize() functions have existed for a
while. The new Tub.serialize()/.unserialize() methods are special in that you
can serialize Referenceables and RemoteReferences. These are encoded with
their FURLs, so that the unserializing Tub can establish a new live reference
to their targets. foolscap.serialize() cannot handle referenceables.

Note that both Tub.serialize() and foolscap.serialize() are currently
"unsafe", in that they will serialize (and unserialize!) instances of
arbitrary classes, much like the stdlib pickle module. This is a significant
security problem, as this results in arbitrary object constructors being
executed during deserialization. In a future release of Foolscap, this mode
of operation will *not* be the default, and a special argument will have to
be passed to enable such behavior.


### Other Improvements

When methods fail, the error messages that get logged have been improved. The
new messages contain information about which source+dest TubIDs were
involved, and which RemoteInterface and method name was being used.

A new internal method named Tub.debug_listBrokers() will provide information
on which messages are waiting for delivery, either inbound or outbound. It is
intended to help diagnose problems like #25. Any message which remains
unresolved for a significant amount of time is likely to indicate a problem.


## Release 0.1.6 (02 Sep 2007)

### Compatibility

All releases between 0.1.3 and 0.1.6 (inclusive) are fully wire-compatible.

### Bug Fixes

Using a schema of ChoiceOf(StringConstraint(2000), None) would fail to accept
strings between 1000 and 2000 bytes: it would accept a short string, or None,
but not a long string. This has been fixed. ChoiceOf() remains a troublesome
constraint: having it is awfully nice, and things like ChoiceOf(str,None)
seem to work, but it is unreliable. Using ChoiceOf with non-terminal children
is not recommended (the garden-path problem is unlikely to be easy to solve):
schemas are not regular expressions.

The debian packaging rules have been fixed. The ones in 0.1.5 failed to run
because of some renamed documentation files.

### Minor Fixes

Several minor documentation errors have been corrected. A new 'make api-docs'
target has been added to run epydoc and build HTML versions of the API
documentation.

When a remote method fails and needs to send a traceback over the wire, and
when the traceback is too large, trim out the middle rather than the end,
since usually it's the beginning and the end that are the most useful.


## Release 0.1.5 (07 Aug 2007)

### Compatibility

This release is fully compatible with 0.1.4 and 0.1.3 .

### CopiedFailure improvements

When a remote method call fails, the calling side gets back a CopiedFailure
instance. These instances now behave slightly more like the (local) Failure
objects that they are intended to mirror, in that .type now behaves much like
the original class. This should allow trial tests which result in a
CopiedFailure to be logged without exploding. In addition, chained failures
(where A calls B, and B calls C, and C fails, so C's Failure is eventually
returned back to A) should work correctly now.

### Gift improvements

Gifts inside return values should properly stall the delivery of the response
until the gift is resolved. Gifts in all sorts of containers should work
properly now. Gifts which cannot be resolved successfully (either because the
hosting Tub cannot be reached, or because the name cannot be found) will now
cause a proper error rather than hanging forever. Unresolvable gifts in
method arguments will cause the message to not be delivered and an error to
be returned to the caller. Unresolvable gifts in method return values will
cause the caller to receive an error.

### IRemoteReference() adapter

The IRemoteReference() interface now has an adapter from Referenceable which
creates a wrapper that enables the use of callRemote() and other
IRemoteReference methods on a local object.

The situation where this might be useful is when you have a central
introducer and a bunch of clients, and the clients are introducing themselves
to each other (to create a fully-connected mesh), and the introductions are
using live references (i.e. Gifts), then when a specific client learns about
itself from the introducer, that client will receive a local object instead
of a RemoteReference. Each client will wind up with n-1 RemoteReferences and
a single local object.

This adapter allows the client to treat all these introductions as equal. A
client that wishes to send a message to everyone it's been introduced to
(including itself) can use:

  for i in introductions:
    IRemoteReference(i).callRemote("hello", args)

In the future, if we implement coercing Guards (instead of
compliance-asserting Constraints), then IRemoteReference will be useful as a
guard on methods that want to insure that they can do callRemote (and
notifyOnDisconnect, etc) on their argument.

### Tub.registerNameLookupHandler

This method allows a one-argument name-lookup callable to be attached to the
Tub. This augments the table maintained by Tub.registerReference, allowing
Referenceables to be created on the fly, or persisted/retrieved on disk
instead of requiring all of them to be generated and registered at startup.


## Release 0.1.4 (14 May 2007)

### Compatibility

This release is fully compatible with 0.1.3 .

### getReference/connectTo can be called before Tub.startService()

The Tub.startService changes that were suggested in the 0.1.3 release notes
have been implemented. Calling getReference() or connectTo() before the Tub
has been started is now allowed, however no action will take place until the
Tub is running. Don't forget to start the Tub, or you'll be left wondering
why your Deferred or callback is never fired. (A log message is emitted when
these calls are made before the Tub is started, in the hopes of helping
developers find this mistake faster).

### constraint improvements

The RIFoo -style constraint now accepts gifts (third-party references). This
also means that using RIFoo on the outbound side will accept either a
Referenceable that implements the given RemoteInterface or a RemoteReference
that points to a Referenceable that implements the given RemoteInterface.
There is a situation (sending a RemoteReference back to its owner) that will
pass the outbound constraint but be rejected by the inbound constraint on the
other end. It remains to be seen how this will be fixed.

### foolscap now deserializes into python2.4-native 'set' and 'frozenset' types

Since Foolscap is dependent upon python2.4 or newer anyways, it now
unconditionally creates built-in 'set' and 'frozenset' instances when
deserializing 'set'/'immutable-set' banana sequences. The pre-python2.4
'sets' module has non-built-in set classes named sets.Set and
sets.ImmutableSet, and these are serialized just like the built-in forms.

Unfortunately this means that Set and ImmutableSet will not survive a
round-trip: they'll be turned into set and frozenset, respectively. Worse
yet, 'set' and 'sets.Set' are not entirely compatible. This may cause a
problem for older applications that were written to be compatible with both
python-2.3 and python-2.4 (by using sets.Set/sets.ImmutableSet), for which
the compatibility code is still in place (i.e. they are not using
set/frozenset). These applications may experience problems when set objects
that traverse the wire via Foolscap are brought into close proximity with set
objects that remained local. This is unfortunate, but it's the cleanest way
to support modern applications that use the native types exclusively.

### bug fixes

Gifts inside containers (lists, tuples, dicts, sets) were broken: the target
method was frequently invoked before the gift had properly resolved into a
RemoteReference. Constraints involving gifts inside containers were broken
too. The constraints may be too loose right now, but I don't think they
should cause false negatives.

The unused SturdyRef.asLiveRef method was removed, since it didn't work
anyways.

### terminology shift: FURL

The preferred name for the sort of URL that you get back from
registerReference (and hand to getReference or connectTo) has changed from
"PB URL" to "FURL" (short for Foolscap URL). They still start with 'pb:',
however. Documentation is slowly being changed to use this term.


## Release 0.1.3 (02 May 2007)

### Incompatibility Warning

The 'keepalive' feature described below adds a new pair of banana tokens,
PING and PONG, which introduces a compatibility break between 0.1.2 and 0.1.3
. Older versions would throw an error upon receipt of a PING token, so the
version-negotiation mechanism is used to prevent banana-v2 (0.1.2) peers from
connecting to banana-v3 (0.1.3+) peers. Our negotiation mechanism would make
it possible to detect the older (v2) peer and refrain from using PINGs, but
that has not been done for this release.

### Tubs must be running before use

Tubs are twisted.application.service.Service instances, and as such have a
clear distinction between "running" and "not running" states. Tubs are
started by calling startService(), or by attaching them to a running service,
or by starting the service that they are already attached to. The design rule
in operation here is that Tubs are not allowed to perform network IO until
they are running.

This rule was not enforced completely in 0.1.2, and calls to
getReference()/connectTo() that occurred before the Tub was started would
proceed normally (initiating a TCP connection, etc). Starting with 0.1.3,
this rule *is* enforced. For now, that means that you must start the Tub
before calling either of these methods, or you'll get an exception. In a
future release, that may be changed to allow these early calls, and queue or
otherwise defer the network IO until the Tub is eventually started. (the
biggest issue is how to warn users who forget to start the Tub, since in the
face of such a bug the getReference will simply never complete).

### Keepalives

Tubs now keep track of how long a connection has been idle, and will send a
few bytes (a PING of the other end) if no other traffic has been seen for
roughly 4 to 8 minutes. This serves two purposes. The first is to convince an
intervening NAT box that the connection is still in use, to prevent it from
discarding the connection's table entry, since that would block any further
traffic. The second is to accelerate the detection of such blocked
connections, specifically to reduce the size of a window of buggy behavior in
Foolscap's duplicate-connection detection/suppression code.

This problem arises when client A (behind a low-end NAT box) connects to
server B, perhaps using connectTo(). The first connection works fine, and is
used for a while. Then, for whatever reason, A and B are silent for a long
time (perhaps as short as 20 minutes, depending upon the NAT box). During
this silence, A's NAT box thinks the connection is no longer in use and drops
the address-translation table entry. Now suppose that A suddenly decides to
talk to B. If the NAT box creates a new entry (with a new outbound port
number), the packets that arrive on B will be rejected, since they do not
match any existing TCP connections. A sees these rejected packets, breaks the
TCP connection, and the Reconnector initiates a new connection. Meanwhile, B
has no idea that anything has gone wrong. When the second connection reaches
B, it thinks this is a duplicate connection from A, and that it already has a
perfectly functional (albeit quiet) connection for that TubID, so it rejects
the connection during the negotiation phase. A sees this rejection and
schedules a new attempt, which ends in the same result. This has the
potential to prevent hosts behind NAT boxes from ever reconnecting to the
other end, at least until the the program at the far end is restarted, or it
happens to try to send some traffic of its own.

The same problem can occur if a laptop is abruptly shut down, or unplugged
from the network, then moved to a different network. Similar problems have
been seen with virtual machine instances that were suspended and moved to a
different network.

The longer-term fix for this is a deep change to the way duplicate
connections (and cross-connect race conditions) are handled. The keepalives,
however, mean that both sides are continually checking to see that the
connection is still usable, enabling TCP to break the connection once the
keepalives go unacknowledged for a certain amount of time. The default
keepalive timer is 4 minutes, and due to the way it is implemented this means
that no more than 8 minutes will pass without some traffic being sent. TCP
tends to time out connections after perhaps 15 minutes of unacknowledged
traffic, which means that the window of unconnectability is probably reduced
from infinity down to about 25 minutes.

The keepalive-sending timer defaults to 4 minutes, and can be changed by
calling tub.setOption("keepaliveTimeout", seconds).

In addition, an explicit disconnect timer can be enabled, which tells
Foolscap to drop the connection unless traffic has been seen within some
minimum span of time. This timer can be set by calling
tub.setOption("disconnectTimeout", seconds). Obviously it should be set to a
higher value than the keepaliveTimeout. This will close connections faster
than TCP will. Both TCP disconnects and the ones triggered by this
disconnectTimeout run the risk of false negatives, of course, in the face of
unreliable networks.

### New constraints

When a tuple appears in a method constraint specification, it now maps to an
actual TupleOf constraint. Previously they mapped to a ChoiceOf constraint.
In practice, TupleOf appears to be much more useful, and thus better
deserving of the shortcut.

For example, a method defined as follows:

  def get_employee(idnumber=int):
      return (str, int, int)  # (name, room_number, age)

can only return a three-element tuple, in which the first element is a string
(specifically it conforms to a default StringConstraint), and the second two
elements are ints (which conform to a default IntegerConstraint, which means
it fits in a 32-bit signed twos-complement value).

To specify a constraint that can accept alternatives, use ChoiceOf:

  def get_record(key=str):
      """Return the record (a string) if it is present, or None if
          it is not present."""
      return ChoiceOf(str, None)

UnicodeConstraint has been added, with minLength=, maxLength=, and regexp=
arguments.

The previous StringConstraint has been renamed to ByteStringConstraint (for
accuracy), and it is defined to *only* accept string objects (not unicode
objects). 'StringConstraint' itself remains equivalent to
ByteStringConstraint for now, but in the future it may be redefined to be a
constraint that accepts both bytestrings and unicode objects. To accomplish
the bytestring-or-unicode constraint now, you might try
schema.AnyStringConstraint, but it has not been fully tested, and might not
work at all.

### Bugfixes

Errors during negotiation were sometimes delivered in the wrong format,
resulting in a "token prefix is limited to 64 bytes" error message. Several
error messages (including that one) have been improved to give developers a
better chance of determining where the actual problem lies.

RemoteReference.notifyOnDisconnect was buggy when called on a reference that
was already broken: it failed to fire the callback. Now it fires the callback
soon (using an eventual-send). This should remove a race condition from
connectTo+notifyOnDisconnect sequences and allow them to operate reliably.
notifyOnDisconnect() is now tolerant of attempts to remove something twice,
which should make it easier to use safely.

Remote methods which raise string exceptions should no longer cause Foolscap
to explode. These sorts of exceptions are deprecated, of course, and you
shouldn't use them, but at least they won't break Foolscap.

The Reconnector class (accessed by tub.connectTo) was not correctly
reconnecting in certain cases (which appeared to be particularly common on
windows). This should be fixed now.

CopyableSlicer did not work inside containers when streaming was enabled.
Thanks to iacovou-AT-gmail.com for spotting this one.

### Bugs not fixed

Some bugs were identified and characterized but *not* fixed in this release

#### RemoteInterfaces aren't defaulting to fully-qualified classnames

When defining a RemoteInterface, you can specify its name with
__remote_name__, or you can allow it to use the default name. Unfortunately,
the default name is only the *local* name of the class, not the
fully-qualified name, which means that if you have an RIFoo in two different
.py files, they will wind up with the same name (which will cause an error on
import, since all RemoteInterfaces known to a Foolscap-using program must
have unique names).

It turns out that it is rather difficult to determine the fully-qualified
name of the RemoteInterface class early enough to be helpful. The workaround
is to always add a __remote_name__ to your RemoteInterface classes. The
recommendation is to use a globally-unique string, like a URI that includes
your organization's DNS name.

#### Constraints aren't constraining inbound tokens well enough

Constraints (and the RemoteInterfaces they live inside) serve three purposes.
The primary one is as documentation, describing how remotely-accessible
objects behave. The second purpose is to enforce that documentation, by
inspecting arguments (and return values) before invoking the method, as a
form of precondition checking. The third is to mitigate denial-of-service
attacks, in which an attacker sends so much data (or carefully crafted data)
that the receiving program runs out of memory or stack space.

It looks like several constraints are not correctly paying attention to the
tokens as they arrive over the wire, such that the third purpose is not being
achieved. Hopefully this will be fixed in a later release. Application code
can be unaware of this change, since the constraints are still being applied
to inbound arguments before they are passed to the method. Continue to use
RemoteInterfaces as usual, just be aware that you are not yet protected
against certain DoS attacks.

### Use os.urandom instead of falling back to pycrypto

Once upon a time, when Foolscap was compatible with python2.3 (which lacks
os.urandom), we would try to use PyCrypto's random-number-generation routines
when creating unguessable object identifiers (aka "SwissNumbers"). Now that
we require python2.4 or later, this fallback has been removed, eliminating
the last reference to pycrypto within the Foolscap source tree.


## Release 0.1.2 (04 Apr 2007)

### Bugfixes

Yesterday's release had a bug in the new SetConstraint which rendered it
completely unusable. This has been fixed, along with some new tests.

### More debian packaging

Some control scripts were added to make it easier to create debian packages
for the Ubuntu 'edgy' and 'feisty' distributions.


## Release 0.1.1 (03 Apr 2007)

### Incompatibility Warning

Because of the technique used to implement callRemoteOnly() (specifically the
commandeering of reqID=0), this release is not compatible with the previous
release. The protocol negotiation version numbers have been bumped to avoid
confusion, meaning that 0.1.0 Tubs will refuse to connect to 0.1.1 Tubs, and
vice versa. Be aware that the errors reported when this occurs may not be
ideal, in particular I think the "reconnector" (tub.connectTo) might not log
this sort of connection failure in a very useful way.

### changes to Constraints

Method specifications inside RemoteInterfaces can now accept or return
'Referenceable' to indicate that they will accept a Referenceable of any
sort. Likewise, they can use something like 'RIFoo' to indicate that they
want a Referenceable or RemoteReference that implements RIFoo. Note that this
restriction does not quite nail down the directionality: in particular there
is not yet a way to specify that the method will only accept a Referenceable
and not a RemoteReference. I'm waiting to see if such a thing is actually
useful before implementing it. As an example:

class RIUser(RemoteInterface):
    def get_age():
        return int

class RIUserListing(RemoteInterface):
    def get_user(name=str):
        """Get the User object for a given name."""
        return RIUser

In addition, several constraints have been enhanced. StringConstraint and
ListConstraint now accept a minLength= argument, and StringConstraint also
takes a regular expression to apply to the string it inspects (the regexp can
either be passed as a string or as the output of re.compile()). There is a
new SetConstraint object, with 'SetOf' as a short alias. Some examples:

HexIdConstraint = StringConstraint(minLength=20, maxLength=20,
                                   regexp=r'[\dA-Fa-f]+')
class RITable(RemoteInterface):
    def get_users_by_id(id=HexIdConstraint):
        """Get a set of User objects; all will have the same ID number."""
        return SetOf(RIUser, maxLength=200)

These constraints should be imported from foolscap.schema . Once the
constraint interface is stabilized and documented, these classes will
probably be moved into foolscap/__init__.py so that you can just do 'from
foolscap import SetOf', etc.

#### UnconstrainedMethod

To disable schema checking for a specific method, use UnconstrainedMethod in
the RemoteInterface definition:

from foolscap.remoteinterface import UnconstrainedMethod

class RIUse(RemoteInterface):
    def set_phone_number(area_code=int, number=int):
        return bool
    set_arbitrary_data = UnconstrainedMethod

The schema-checking code will allow any sorts of arguments through to this
remote method, and allow any return value. This is like schema.Any(), but for
entire methods instead of just specific values. Obviously, using this defeats
te whole purpose of schema checking, but in some circumstances it might be
preferable to allow one or two unconstrained methods rather than resorting to
leaving the entire class left unconstrained (by not declaring a
RemoteInterface at all).

#### internal schema implementation changes

Constraints underwent a massive internal refactoring in this release, to
avoid a number of messy circular imports. The new way to convert a
"shorthand" description (like 'str') into an actual constraint object (like
StringConstraint) is to adapt it to IConstraint.

In addition, all constraints were moved closer to their associated
slicer/unslicer definitions. For example, SetConstraint is defined in
foolscap.slicers.set, right next to SetSlicer and SetUnslicer. The
constraints for basic tokens (like lists and ints) live in
foolscap.constraint .

### callRemoteOnly

A new "fire and forget" API was added to tell Foolscap that you want to send
a message to the remote end, but do not care when or even whether it arrives.
These messages are guaranteed to not fire an errback if the connection is
already lost (DeadReferenceError) or if the connection is lost before the
message is delivered or the response comes back (ConnectionLost). At present,
this no-error philosophy is so strong that even schema Violation exceptions
are suppressed, and the callRemoteOnly() method always returns None instead
of a Deferred. This last part might change in the future.

This is most useful for messages that are tightly coupled to the connection
itself, such that if the connection is lost, then it won't matter whether the
message was received or not. If the only state that the message modifies is
both scoped to the connection (i.e. not used anywhere else in the receiving
application) and only affects *inbound* data, then callRemoteOnly might be
useful. It may involve less error-checking code on the senders side, and it
may involve fewer round trips (since no response will be generated when the
message is delivered).

As a contrived example, a message which informs the far end that all
subsequent messages on this connection will sent entirely in uppercase (such
that the recipient should apply some sort of filter to them) would be
suitable for callRemoteOnly. The sender does not need to know exactly when
the message has been received, since Foolscap guarantees that all
subsequently sent messages will be delivered *after* the 'SetUpperCase'
message. And, the sender does not need to know whether the connection was
lost before or after the receipt of the message, since the establishment of a
new connection will reset this 'uppercase' flag back to some known
initial-contact state.

  rref.callRemoteOnly("set_uppercase", True)  # returns None!

This method is intended to parallel the 'deliverOnly' method used in E's
CapTP protocol. It is also used (or will be used) in some internal Foolscap
messages to reduce unnecessary network traffic.

### new Slicers: builtin set/frozenset

Code has been added to allow Foolscap to handle the built-in 'set' and
'frozenset' types that were introduced in python-2.4 . The wire protocol does
not distinguish between 'set' and 'sets.Set', nor between 'frozenset' and
'sets.ImmutableSet'.

For the sake of compatibility, everything that comes out of the deserializer
uses the pre-2.4 'sets' module. Unfortunately that means that a 'set' sent
into a Foolscap connection will come back out as a 'sets.Set'. 'set' and
'sets.Set' are not entirely interoperable, and concise things like 'added =
new_things - old_things' will not work if the objects are of different types
(but note that things like 'added = new_things.difference(old_things)' *do*
work).

The current workaround is for remote methods to coerce everything to a
locally-preferred form before use. Better solutions to this are still being
sought. The most promising approach is for Foolscap to unconditionally
deserialize to the builtin types on python >= 2.4, but then an application
which works fine on 2.3 (by using sets.Set) will fail when moved to 2.4 .

### Tub.stopService now indicates full connection shutdown, helping Trial tests

Like all twisted.application.service.MultiService instances, the
Tub.stopService() method returns a Deferred that indicates when shutdown has
finished. Previously, this Deferred could fire a bit early, when network
connections were still trying to deliver the last bits of data. This caused
problems with the Trial unit test framework, which insist upon having a clean
reactor between tests.

Trial test writers who use Foolscap should include the following sequence in
their twisted.trial.unittest.TestCase.tearDown() methods:

def tearDown(self):
    from foolscap.eventual import flushEventualQueue
    d = tub.stopService()
    d.addCallback(flushEventualQueue)
    return d

This will insure that all network activity is complete, and that all message
deliveries thus triggered have been retired. This activity includes any
outbound connections that were initiated (but not completed, or finished
negotiating), as well as any listening sockets.

The only remaining problem I've seen so far is with reactor.resolve(), which
is used to translate DNS names into addresses, and has a window during which
you can shut down the Tub and it will leave a cleanup timer lying around. The
only solution I've found is to avoid using DNS names in URLs. Of course for
real applications this does not matter: it only makes a difference in Trial
unit tests which are making heavy use of short-lived Tubs and connections.


## Release 0.1.0 (15 Mar 2007)

### usability improvements

#### Tubs now have a certFile= argument

A certFile= argument has been added to the Tub constructor to allow the Tub
to manage its own certificates. This argument provides a filename where the
Tub should read or write its certificate. If the file exists, the Tub will
read the certificate data from there. If not, the Tub will generate a new
certificate and write it to the file.

The idea is that you can point certFile= at a persistent location on disk,
perhaps in the application's configuration or preferences subdirectory, and
then not need to distinguish between the first time the Tub has been created
and later invocations. This allows the Tub's identity (derived from the
certificate) to remain stable from one invocation to the next. The related
problem of how to make (unguessable) object names persistent from one program
run to the next is still outstanding, but I expect to implement something
similar in the future (some sort of file to which object names are written
and read later).

certFile= is meant to be used somewhat like this:

 where = os.path.expanduser("~/.myapp.cert")
 t = Tub(certFile=where)
 t.registerReference(obj) # ...

#### All eventual-sends are retired on each reactor tick, not just one.

Applications which make extensive use of the eventual-send operations (in
foolscap.eventual) will probably run more smoothly now. In previous releases,
the _SimpleCallQueue class would only execute a single eventual-send call per
tick, then take care of all pending IO (and any pending timers) before
servicing the next eventual-send. This could probably lead to starvation, as
those eventual-sends might generate more work (and cause more network IO),
which could cause the event queue to grow without bound. The new approach
finishes as much eventual-send work as possible before accepting any IO. Any
new eventual-sends which are queued during the current tick will be put off
until the next tick, but everything which was queued before the current tick
will be retired in the current tick.

### bug fixes

#### Tub certificates can now be used the moment they are created

In previous releases, Tubs were only willing to accept SSL certificates that
created before the moment of checking. If two systems A and B had
unsynchronized clocks, and a Foolscap-using application on A was run for the
first time to connect to B (thus creating a new SSL certificate), system B
might reject the certificate because it looks like it comes from the future.

This problem is endemic in systems which attempt to use the passage of time
as a form of revocation. For now at least, to resolve the practical problem
of certificates generated on demand and used by systems with unsynchronized
clocks, Foolscap does not use certificate lifetimes, and will ignore
timestamps on the certificates it examines.


## Release 0.0.7 (16 Jan 2007)

### bug fixes

#### Tubs can now connect to themselves

In previous releases, Tubs were unable to connect to themselves: the
following code would fail (the negotiation would never complete, so the
connection attempt would eventually time out after about 30 seconds):

 url = mytub.registerReference(target)
 d = mytub.getReference(url)

In release 0.0.7, this has been fixed by catching this case and making it use
a special loopback transport (which serializes all messages but does not send
them over a wire). There may be still be problems with this code, in
particular connection shutdown is not completely tested and producer/consumer
code is completely untested.

#### Tubs can now getReference() the same URL multiple times

A bug was present in the RemoteReference-unslicing code which caused the
following code to fail:

 d = mytub.getReference(url)
 d.addCallback(lambda ref: mytub.getReference(url))

In particular, the second call to getReference() would return None rather
than the RemoteReference it was supposed to.

This bug has been fixed. If the previous RemoteReference is still alive, it
will be returned by the subsequent getReference() call. If it has been
garbage-collected, a new one will be created.

#### minor fixes

Negotiation errors (such as having incompatible versions of Foolscap on
either end of the wire) may be reported more usefully.

In certain circumstances, disconnecting the Tub service from a parent service
might have caused an exception before. It might behave better now.


## Release 0.0.6 (18 Dec 2006)

### INCOMPATIBLE PROTOCOL CHANGES

Version 0.0.6 will not interoperate with versions 0.0.5 or earlier, because
of changes to the negotiation process and the method-calling portion of the
main wire protocol. (you were warned :-). There are still more incompatible
changes to come in future versions as the feature set and protocol
stabilizes. Make sure you can upgrade both ends of the wire until a protocol
freeze has been declared.

#### Negotiation versions now specify a range, instead of a single number

The two ends of a connection will agree to use the highest mutually-supported
version. This approach should make it much easier to maintain backwards
compatibility in the future.

#### Negotiation now includes an initial VOCAB table

One of the outputs of connection negotiation is the initial table of VOCAB
tokens to use for abbreviating commonly-used strings into short tokens
(usually just 2 bytes). Both ends have the ability to modify this table at any
time, but by setting the initial table during negotiation we same some
protocol traffic. VOCAB-izing common strings (like 'list' and 'dict') have
the potential to compress wire traffic by maybe 50%.

#### remote methods now accept both positional and keyword arguments

Previously you had to use a RemoteInterface specification to be able to pass
positional arguments into callRemote(). (the RemoteInterface schema was used
to convert the positional arguments into keyword arguments before sending
them over the wire). In 0.0.6 you can pass both posargs and kwargs over the
wire, and the remote end will pass them directly to the target method. When
schemas are in effect, the arguments you send will be mapped to the method's
named parameters in the same left-to-right way that python does it. This
should make it easier to port oldpb code to use Foolscap, since you don't
have to rewrite everything to use kwargs exclusively.

### Schemas now allow =None and =RIFoo

You can use 'None' in a method schema to indicate that the argument or return
value must be None. This is useful for methods that always return None. You
can also require that the argument be a RemoteReference that provides a
particular RemoteInterface. For example:

class RIUser(RemoteInterface):
    def get_age():
        return int
    def delete():
        return None

class RIUserDatabase(RemoteInterface):
    def get_user(username=str):
        return RIUser

Note that these remote interface specifications are parsed at import time, so
any names they refer to must be defined before they get used (hence placing
RIUserDatabase before RIUser would fail). Hopefully we'll figure out a way to
fix this in the future.

### Violations are now annotated better, might keep more stack-trace information

### Copyable improvements

The Copyable documentation has been split out to docs/copyable.xhtml and
somewhat expanded.

The new preferred Copyable usage is to have a class-level attribute named
"typeToCopy" which holds the unique string. This must match the class-level
"copytype" attribute of the corresponding RemoteCopy class. Copyable
subclasses (or ICopyable adapters) may still implement getTypeToCopy(), but
the default just returns self.typeToCopy . Most significantly, we no longer
automatically use the fully-qualified classname: instead we *require* that
the class definition include "typeToCopy". Feel free to use any stable and
globally-unique string here, like a URI in a namespace that you control, or
the fully-qualified package/module/classname of the Copyable subclass.

The RemoteCopy subclass must set the 'copytype' attribute, as it is used for
auto-registration. These can set copytype=None to inhibit auto-registration.


## Release 0.0.5 (04 Nov 2006)

### add Tub.setOption, add logRemoteFailures and logLocalFailures

These options control whether we log exceptions (to the standard twisted log)
that occur on other systems in response to messages that we've sent, and that
occur on our system in response to messages that we've received
(respectively). These may be useful while developing a distributed
application. All such log messages have each line of the stack trace prefixed
by REMOTE: or LOCAL: to make it clear where the exception is happening.

### add sarge packaging, improve dependencies for sid and dapper .debs

### fix typo that prevented Reconnector from actually reconnecting


## Release 0.0.4 (26 Oct 2006)

### API Changes

#### notifyOnDisconnect() takes args/kwargs

RemoteReference.notifyOnDisconnect(), which registers a callback to be fired
when the connection to this RemoteReference is lost, now accepts args and
kwargs to be passed to the callback function. Without this, application code
needed to use inner functions or bound methods to close over any additional
state you wanted to get into the disconnect handler.

notifyOnDisconnect() returns a "marker", an opaque values that should be
passed into the corresponding dontNotifyOnDisconnect() function to deregister
the callback. (previously dontNotifyOnDisconnect just took the same argument
as notifyOnDisconnect).

For example:

class Foo:
    def _disconnect(self, who, reason):
        print "%s left us, because of %s" % (who, reason)
    def connect(self, url, why):
        d = self.tub.getReference(url)
        def _connected(rref):
            self.rref = rref
            m = rref.notifyOnDisconnect(self._disconnect, who, reason=why)
            self.marker = m
        d.addCallback(_connected)
    def stop_caring(self):
        self.rref.dontNotifyOnDisconnect(self.marker)

#### Reconnector / Tub.connectTo()

There is a new connection API for applications that want to connect to a
target and to reconnect to it if/when that connection is lost. This is like
ReconnectingClientFactory, but at a higher layer. You give it a URL to
connect to, and a callback (plus args/kwargs) that should be called each time
a connection is established. Your callback should use notifyOnDisconnect() to
find out when it is disconnected. Reconnection attempts use exponential
backoff to limit the retry rate, and you can shut off reconnection attempts
when you no longer want to maintain a connection.

Use it something like this:

class Foo:
    def __init__(self, tub, url):
        self.tub = tub
        self.reconnector = tub.connectTo(url, self._connected, "arg")
    def _connected(self, rref, arg):
        print "connected"
        assert arg == "arg"
        self.rref = rref
        self.rref.callRemote("hello")
        self.rref.notifyOnDisconnect(self._disconnected, "blag")
    def _disconnected(self, blag):
        print "disconnected"
        assert blag == "blag"
        self.rref = None
    def shutdown(self):
        self.reconnector.stopConnecting()

Code which uses this pattern will see "connected" events strictly interleaved
with "disconnected" events (i.e. it will never see two "connected" events in
a row, nor two "disconnected" events).

The basic idea is that each time your _connected() method is called, it
should re-initialize all your state by making method calls to the remote
side. When the connection is lost, all that state goes away (since you have
no way to know what is happening until you reconnect).

### Behavioral Changes

#### All Referenceable object are now implicitly "giftable"

In 0.0.3, for a Referenceable to be "giftable" (i.e. useable as the payload
of an introduction), two conditions had to be satisfied. #1: the object must
be published through a Tub with Tub.registerReference(obj). #2: that Tub must
have a location set (with Tub.setLocation). Once those conditions were met,
if the object was sent over a wire from this Tub to another one, the
recipient of the corresponding RemoteReference could pass it on to a third
party. Another side effect of calling registerReference() is that the Tub
retains a strongref to the object, keeping it alive (with respect to gc)
until either the Tub is shut down or the object is explicitly de-registered
with unregisterReference().

Starting in 0.0.4, the first condition has been removed. All objects which
pass through a setLocation'ed Tub will be usable as gifts. This makes it much
more convenient to use third-party references.

Note that the Tub will *not* retain a strongref to these objects (merely a
weakref), so such objects might disappear before the recipient has had a
chance to claim it. The lifecycle of gifts is a subject of much research. The
hope is that, for reasonably punctual recipients, the gift will be kept alive
until they claim it. The whole gift/introduction mechanism is likely to
change in the near future, so this lifetime issue will be revisited in a
later release.

### Build Changes

The source tree now has some support for making debian-style packages (for
both sid and dapper). 'make debian-sid' and 'make debian-dapper' ought to
create a .deb package.


## Release 0.0.3 (05 Oct 2006)

### API Changes

The primary entry point for Foolscap is now the "Tub":

    import foolscap
    t = foolscap.Tub()
    d = t.getReference(pburl)
    d.addCallback(self.gotReference)
    ...

The old "PBService" name is gone, use "Tub" instead. There are now separate
classes for "Tub" and "UnauthenticatedTub", rather than using an "encrypted="
argument. Tubs always use encryption if available: the difference between the
two classes is whether this Tub should use a public key for its identity or
not. Note that you always need encryption to connect to an authenticated Tub.
So install pyopenssl, really.

### eventual send operators

Foolscap now provides 'eventually' and 'fireEventually', to implement the
"eventual send" operator advocated by Mark Miller's "Concurrency Among
Strangers" paper (http://www.erights.org/talks/promises/index.html).
eventually(cb, *args, **kwargs) runs the given call in a later reactor turn.
fireEventually(value=None) returns a Deferred that will be fired (with
'value') in a later turn. These behave a lot like reactor.callLater(0,..),
except that Twisted doesn't actually promise that a pair of callLater(0)s
will be fired in the right order (they usually do under unix, but they
frequently don't under windows). Foolscap's eventually() *does* make this
guarantee. In addition, there is a flushEventualQueue() that is useful for
unit tests, it returns a Deferred that will only fire when the entire queue
is empty. As long as your code only uses eventually() (and not callLater(0)),
putting the following in your trial test cases should keep everything nice
and clean:

 def tearDown(self):
     return foolscap.flushEventualQueue()

### Promises

An initial implementation of Promises is in foolscap.promise for
experimentation. Only "Near" Promises are implemented to far (promises which
resolve to a local object). Eventually Foolscap will offer "Far" Promises as
well, and you will be able to invoke remote method calls through Promises as
well as RemoteReferences. See foolscap/test/test_promise.py for some hints.

### Bug Fixes

Messages containing "Gifts" (third-party references) are now delivered in the
correct order. In previous versions, the presence of these references could
delay delivery of the containing message, causing methods to be executed out
of order.

The VOCAB-manipulating code used to have nasty race conditions, which should
be all fixed now. This would be more important if we actually used the
VOCAB-manipulating code yet, but we don't.

Lots of internal reorganization (put all slicers in a subpackage), not really
user-visible.

Updated to work with recent Twisted HEAD, specifically changes to sslverify.
This release of Foolscap ought to work with the upcoming Twisted-2.5 .

### Incompatible protocol changes

There are now separate add-vocab and set-vocab sequences, which add a single
new VOCAB token and replace the entire table, respectively. These replace the
previous 'vocab' sequence which behaved like set-vocab does now. This would
be an incompatible protocol change, except that previous versions never sent
the vocab sequence anyways. This version doesn't send either vocab-changing
sequence either, but when we finally do start using it, it'll be ready.

## Release 0.0.2 (14 Sep 2006)

Renamed to "Foolscap", extracted from underneat the Twisted packaged,
consolidated API to allow a simple 'import foolscap'. No new features or bug
fixes relative to pb2-0.0.1 .


## Release 0.0.1 (29 Apr 2006)

First release! All basic features are in place. The wire protocol will almost
certainly change at some point, so compatibility with future versions is not
guaranteed.
