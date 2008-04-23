#!/usr/bin/env python

"""This program is a client that triggers command-server.py. You give it the
server's FURL, and it causes the server to run its pre-configured command.
All stdout and stderr from that command will appear on stdout/stderr of the
client. The exit code of the client will be the same as the remote command.
"""

import sys
from twisted.internet import reactor
from foolscap import UnauthenticatedTub
from twisted.python import usage

class Options(usage.Options):
    synopsis = "command-client.py (--furl FURL | --furlfile furlfile)"
    optParameters = [
        ["furl", "f", None,
         "The server FURL. You must either provide --furl or --furlfile."],
        ["furlfile", "l", None,
         "A file containing the server FURL."],
        ]
    optFlags = [
        ["quiet", "q", "Do not emit stdout or stderr, and always exit with 0."],
        ]

    def postOptions(self):
        if not self["furl"] and not self["furlfile"]:
            raise usage.UsageError("you must either provide --furl or --furlfile")

opts = Options()
opts.parseOptions()
tub = UnauthenticatedTub()
tub.startService()
if opts["furl"]:
    furl = opts["furl"]
else:
    furl = open(opts["furlfile"], "r").read().strip()
d = tub.getReference(furl)
def _run(rref):
    return rref.callRemote("run")
d.addCallback(_run)
exit_code = []
def _success(res):
    reactor.stop()
    if not opts["quiet"]:
        out, err, rc = res
        if out:
            print >>sys.stdout, out,
        if err:
            print >>sys.stderr, err,
        return rc
    return 0
def _failure(res):
    reactor.stop()
    print res
    return -1
d.addCallbacks(_success, _failure)
d.addBoth(exit_code.append)

reactor.run()
sys.exit(exit_code[0])
