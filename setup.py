#!/usr/bin/env python

import re
from distutils.core import setup

VERSIONFILE = "foolscap/_version.py"
verstr = "unknown"
try:
    verstrline = open(VERSIONFILE, "rt").read()
except EnvironmentError:
    pass # Okay, there is no version file.
else:
    VSRE = r"^verstr = ['\"]([^'\"]*)['\"]"
    mo = re.search(VSRE, verstrline, re.M)
    if mo:
        verstr = mo.group(1)
    else:
        print "unable to find version in %s" % (VERSIONFILE,)
        raise RuntimeError("if %s.py exists, it is required to be well-formed"
                           % (VERSIONFILE,))

setup_args = {
        'name': "foolscap",
        'version': verstr,
        'description': "Foolscap contains an RPC protocol for Twisted.",
        'author': "Brian Warner",
        'author_email': "warner-foolscap@lothar.com",
        'url': "http://foolscap.lothar.com/trac",
        'license': "MIT",
        'long_description': """\
Foolscap (aka newpb) is a new version of Twisted's native RPC protocol, known
as 'Perspective Broker'. This allows an object in one process to be used by
code in a distant process. This module provides data marshaling, a remote
object reference system, and a capability-based security model.
""",
        'classifiers': [
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
        'platforms': ["any"],

        'packages': ["foolscap", "foolscap.slicers", "foolscap.logging",
                     "foolscap.appserver", "foolscap.test"],
        'scripts': ["bin/flogtool", "bin/flappserver", "bin/flappclient"],
}

have_setuptools = False
try:
    # If setuptools is installed, then we'll add setuptools-specific
    # arguments to the setup args. If we're on windows, this includes
    # entry_points= scripts to create the appropriate .bat files.
    import setuptools
    _hush_pyflakes = [setuptools]
    have_setuptools = True
except ImportError:
    pass

if have_setuptools:
    from setuptools import Command

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
            sys.argv = ['trial', '--rterrors', 'foolscap.test']
            trial.run()  # does not return

    setup_args['cmdclass'] = {"trial": Trial, "test": Trial}

    import platform
    if platform.system() == "Windows":
        del setup_args["scripts"]
        setup_args["entry_points"] = {"console_scripts": [
            "flogtool = foolscap.logging.cli.run_flogtool",
            "flappserver = foolscap.appserver.cli:run_flappserver",
            "flappclient = foolscap.appserver.client:run_flappclient",
            ] }
    setup_args['install_requires'] = setup_args['tests_require'] = ['twisted >= 2.5.0']
    # note that pyOpenSSL-0.7 and recent Twisted causes unit test failures,
    # see bug #62

if __name__ == '__main__':
    setup(**setup_args)

