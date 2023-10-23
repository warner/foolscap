# Foolscap

[![PyPI](http://img.shields.io/pypi/v/foolscap.svg)](https://pypi.python.org/pypi/foolscap)
[![Build Status](https://travis-ci.org/warner/foolscap.svg?branch=master)](https://travis-ci.org/warner/foolscap)

Foolscap is an RPC/RMI (Remote Procedure Call / Remote Method Invocation)
protocol for use with Twisted, derived/inspired by Twisted's built-in
"Perspective Broker" package.

If you have control of both ends of the wire, and are thus not constrained to
use some other protocol like HTTP/XMLRPC/CORBA/etc, you might consider using
Foolscap.

Fundamentally, Foolscap allows you to make a python object in one process
available to code in other processes, which means you can invoke its methods
remotely. This includes a data serialization layer to convey the object
graphs for the arguments and the eventual response, and an object reference
system to keep track of which objects you are connecting to. It uses a
capability-based security model, such that once you create a non-public
object, it is only accessible to clients to whom you've given the
(unguessable) FURL. You can of course publish world-visible objects that
have well-known FURLs.

Full documentation and examples are in the doc/ directory.

## DEPENDENCIES

* Python 3.8 or higher
* Twisted 16.0.0 or later
* PyOpenSSL (tested against 16.0.0)


## INSTALLATION

To install foolscap into your system's normal python library directory, just
run the following (you will probably have to do this as root):

```
pip install .
```

You can also just add the foolscap source tree to your PYTHONPATH, since
there are no compile steps or .so/.dll files involved.


## COMPATIBILITY

Foolscap's wire protocol is unlikely to change in the near future.

Foolscap has a built-in version-negotiation mechanism that allows the two
processes to determine how to best communicate with each other. The two ends
will agree upon the highest mutually-supported version for all their
traffic. If they do not have any versions in common, the connection will
fail with a NegotiationError.

Please check the NEWS file for announcements of compatibility-breaking
changes in any given release.

As of Foolscap-0.14.0, this library is mostly compatible with Python 3
(specifically 3.5 or higher), and is tested against 3.5, 3.6, 3.7, and 3.8.
It will retain compatibility with Python 2.7 for a little while longer, to
ease the transition, but since Python 2 was marked End-Of-Life in January
2020, this compatibility will not be maintained forever.


## HISTORY

Foolscap is a rewrite of the Perspective Broker protocol provided by Twisted
(in the twisted.pb package), with the goal of improving serialization
flexibility and connection security. It also adds features to assist
application development, such as distributed/incident-triggered logging,
Service management, persistent object naming, and debugging tools.

For a brief while, it was intended to replace Perspective Broker, so it had
a name of "newpb" or "pb2". However we no longer expect Foolscap to ever be
added to the Twisted source tree.

A "foolscap" is a size of paper, probably measuring 17 by 13.5 inches. A
twisted foolscap of paper makes a good fool's cap. Also, "cap" implies
capabilities, and Foolscap is a protocol to implement a distributed
object-capabilities model in python.

## AUTHOR

Brian Warner is responsible for this thing. Please discuss it on the
twisted-python mailing list.

The Foolscap home page is a Trac instance at
<http://foolscap.lothar.com/trac>. It contains pointers to the latest
release, bug reports, patches, documentation, and other resources.

Foolscap is distributed under the same license as Twisted itself, namely the
MIT license. Details are in the LICENSE file.

