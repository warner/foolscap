#!/usr/bin/env python

"""This program is a server that runs a specific command when asked by a
client. The command is completely controlled by the server's command-line
arguments. The client only gets to decide when it gets run.

When you want an unattended process on one machine to be able to trigger a
command on a remote machine, you could give its parent process an ssh account
on the target, with an empty passphrase, but that provides too much power.
This program is a least-privilege replacement for the ssh approach.

The client will get to see stdout and stderr of the process.

Give the server a --private-dir where it can store persistent private data,
so it can use the same FURL from one run to the next. The server's FURL will
be stored in 'server.furl' in that directory, and will also be printed to
stdout (unless you pass --quiet). You'll also need to give it a TCP port
number to listen on.

Also give the server a --command-dir from which the command ought to be run.
This defaults to the current working directory when the server is started.

The command to be run is taken from the remaining arguments.

This server should be placed into the background, like this:

 command-server.py --quiet --private-dir ~/private 12345 make update &

It may be convenient to launch this from a cron @reboot job, so that it is
always available.
"""

import os, os.path
from twisted.internet import reactor, utils
from foolscap import Tub, Referenceable
from twisted.python import usage

class Options(usage.Options):
    synopsis = "command-server.py PORTNUM COMMAND.."
    optParameters = [
        ["private-dir", "b", "~/.foolscap-command-server",
         "Directory to store my private certificate and FURL file."],
        ["command-dir", "c", ".",
         "Directory to run commands run, defaults to current working dir"],
        ]
    optFlags = [
        ["quiet", "q", "Do not print the server FURL at startup."],
        ]

    def parseArgs(self, port, *command):
        self['port'] = port
        self['command'] = command

    def postOptions(self):
        self["command-dir"] = os.path.abspath(self["command-dir"])

class CommandRunner(Referenceable):
    def __init__(self, command_dir, command):
        self.command_dir = command_dir
        self.command = command

    def remote_run(self):
        # returns (out, err, rc)
        d = utils.getProcessOutputAndValue(self.command[0], self.command[1:],
                                           os.environ, self.command_dir)
        return d

opts = Options()
opts.parseOptions()
gr = CommandRunner(opts["command-dir"], opts["command"])

tub = Tub(certFile=os.path.join(opts["private-dir"], "tub.pem"))
l = tub.listenOn(opts["port"])
tub.startService()
furlfile = os.path.join(opts["private-dir"], "command.furl")
d = tub.setLocationAutomatically()
d.addCallback(lambda res: tub.registerReference(gr, furlFile=furlfile))
def _print_furl(furl):
    if not opts["quiet"]:
        print "Server is listening on:"
        print " " + furl
d.addCallback(_print_furl)

reactor.run()

