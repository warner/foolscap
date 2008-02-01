#! /usr/bin/python

"""This program is a server that receives file-upload requests from
xfer-client.py. Anyone who knows the server's FURL will be able to put files
in the TARGETDIR (and nowhere else). When you want an unattended process on
one machine to be able to place files in a remote directory, you could give
its parent process an ssh account on the target, with an empty passphrase,
but that provides too much power. This program is a least-privilege
replacement for the ssh/scp approach.

Give the server a --basedir where it can store persistent private data, so it
can use the same FURL from one run to the next. The server's FURL will be
stored in 'server.furl' in that directory, and will also be printed to stdout
(unless you pass --quiet).

This server should be placed into the background, like this:

 xfer-server.py --quiet --basedir ~/private 12345 ~/targetdir &

It may be convenient to launch this from a cron @reboot job, so that it is
always available.
"""

from os import chmod
import os.path
from twisted.internet import reactor
from foolscap import Tub, Referenceable
from twisted.python import usage

class Options(usage.Options):
    synopsis = "xfer-server.py PORTNUM TARGETDIR"
    optParameters = [
        ["basedir", "b", "~/.foolscap-xfer-server",
         "Directory to store my private certificate and FURL file."],
        ["mode", "m", "0644",
         "(octal) mode to set uploaded files to, use 0644 for world-readable"],
        ]
    optFlags = [
        ["quiet", "q", "Do not print the server FURL at startup."],
        ]

    def parseArgs(self, port, targetdir):
        self['port'] = port
        self['targetdir'] = os.path.abspath(targetdir)

class BadFilenameError(Exception):
    pass

class FileReceiver(Referenceable):
    def __init__(self, targetdir, mode):
        self.targetdir = targetdir
        self.mode = mode

    def remote_putfile(self, name, data):
        if "/" in name or name == "..":
            raise BadFilenameError()
        targetfile = os.path.join(self.targetdir, name)
        f = open(targetfile, "w")
        f.write(data)
        f.close()
        chmod(targetfile, self.mode)

opts = Options()
opts.parseOptions()
mode = opts["mode"]
if mode.startswith("0"):
    mode = int(mode, 8)
else:
    mode = int(mode)
gr = FileReceiver(opts["targetdir"], mode)

tub = Tub(certFile=os.path.join(opts["basedir"], "tub.pem"))
l = tub.listenOn(opts["port"])
tub.startService()
furlfile = os.path.join(opts["basedir"], "receiver.furl")
d = tub.setLocationAutomatically()
d.addCallback(lambda res: tub.registerReference(gr, furlFile=furlfile))
def _print_furl(furl):
    if not opts["quiet"]:
        print "Server is listening on:"
        print " " + furl
d.addCallback(_print_furl)

reactor.run()
