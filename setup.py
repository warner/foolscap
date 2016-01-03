#!/usr/bin/env python

import platform
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
    "classifiers": [
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
    "platforms": ["any"],

    "packages": ["foolscap", "foolscap.slicers", "foolscap.logging",
                 "foolscap.appserver", "foolscap.test"],
    "scripts": ["bin/flogtool", "bin/flappserver", "bin/flappclient"],
    "cmdclass": commands,
    "install_requires": ["twisted >= 10.1.0", "pyOpenSSL", "service_identity",
                         "txsocksx"],
}

if platform.system() == "Windows":
    # I prefer scripts over entry_points, but they don't work on windows
    del setup_args["scripts"]
    setup_args["entry_points"] = {"console_scripts": [
        "flogtool = foolscap.logging.cli.run_flogtool",
        "flappserver = foolscap.appserver.cli:run_flappserver",
        "flappclient = foolscap.appserver.client:run_flappclient",
        ] }

if __name__ == "__main__":
    setup(**setup_args)

