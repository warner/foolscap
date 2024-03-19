#!/usr/bin/env python

from setuptools import setup, Command

import versioneer

commands = versioneer.get_cmdclass().copy()

class Trial(Command):
    description = "run trial"
    user_options = []

    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        import sys
        from twisted.scripts import trial
        sys.argv = ["trial", "--rterrors", "foolscap.test"]
        trial.run()  # does not return
commands["trial"] = Trial
commands["test"] = Trial

trove_classifiers = [
    "Development Status :: 6 - Mature",
    "Operating System :: OS Independent",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: Implementation :: CPython",
    "Topic :: Internet",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Distributed Computing",
    "Topic :: System :: Networking",
    "Topic :: Software Development :: Object Brokering",
    ]

setup_args = {
    "name": "foolscap",
    "version": versioneer.get_version(),
    "description": "Foolscap contains an RPC protocol for Twisted.",
    "author": "Brian Warner",
    "author_email": "warner-foolscap@lothar.com",
    "url": "http://foolscap.lothar.com/trac",
    "license": "MIT",
    "long_description": """\
Foolscap (aka newpb) is a new version of Twisted's native RPC protocol, known
as 'Perspective Broker'. This allows an object in one process to be used by
code in a distant process. This module provides data marshaling, a remote
object reference system, and a capability-based security model.
""",
    "classifiers": trove_classifiers,
    "platforms": ["any"],

    "package_dir": {"": "src"},
    "packages": ["foolscap", "foolscap.slicers", "foolscap.logging",
                 "foolscap.connections",
                 "foolscap.appserver", "foolscap.test"],
    "entry_points": {"console_scripts": [
        "flogtool = foolscap.logging.cli:run_flogtool",
        "flappserver = foolscap.appserver.cli:run_flappserver",
        "flappclient = foolscap.appserver.client:run_flappclient",
        ] },
    "cmdclass": commands,
    "install_requires": ["six", "twisted[tls] >= 16.0.0", "pyOpenSSL"],
    "extras_require": {
        "dev": ["txtorcon >= 19.0.0",
                "txi2p-tahoe >= 0.3.5; python_version > '3.0'",
                "txi2p >= 0.3.2; python_version < '3.0'",
                "pywin32 ; sys_platform == 'win32'"],
        "tor": ["txtorcon >= 19.0.0"],
        "i2p": ["txi2p-tahoe >= 0.3.5; python_version > '3.0'",
                "txi2p >= 0.3.2; python_version < '3.0'"],
        },
    "python_requires": ">=3.8",
}

setup_args.update(
    include_package_data=True,
)

if __name__ == "__main__":
    setup(**setup_args)
