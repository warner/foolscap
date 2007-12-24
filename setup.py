#!/usr/bin/python

import sys
from distutils.core import setup
from foolscap import __version__

if __name__ == '__main__':
    setup(
        name="foolscap",
        version=__version__,
        description="Foolscap contains an RPC protocol for Twisted.",
        author="Brian Warner",
        author_email="warner-foolscap@lothar.com",
        url="http://foolscap.lothar.com/trac",
        license="MIT",
        long_description="""\
Foolscap (aka newpb) is a new version of Twisted's native RPC protocol, known
as 'Perspective Broker'. This allows an object in one process to be used by
code in a distant process. This module provides data marshaling, a remote
object reference system, and a capability-based security model.
""",
        classifiers=[
        "Development Status :: 3 - Alpha",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Distributed Computing",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Object Brokering",
        ],
        platforms=["any"],
        
        packages=["foolscap", "foolscap/slicers", "foolscap/logging",
                  "foolscap/test"],
        scripts=["bin/flogtool"],
        )
