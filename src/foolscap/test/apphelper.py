
"""
I am the command executed by test_appserver.py when it exercises the
'run-command' server. On a unix box, we'd use /bin/cat and /bin/dd ; this
script lets the test work on windows too.
"""

from __future__ import unicode_literals
import sys, os.path
import six

def wrap_in_binary_mode(f):
    if hasattr(f, "buffer"):
        # py3 "text file", as returned by open(), or sys.std(in|out|err)
        return f.buffer # _io.BufferedWriter
    return f
stdin = wrap_in_binary_mode(sys.stdin)
stdout = wrap_in_binary_mode(sys.stdout)
stderr = wrap_in_binary_mode(sys.stderr)

if sys.argv[1] == "cat":
    if not os.path.exists(sys.argv[2]):
        stderr.write(six.ensure_binary("cat: %s: No such file or directory\n" % sys.argv[2]))
        sys.exit(1)
    f = open(sys.argv[2], "rb")
    data = f.read()
    f.close()
    stdout.write(data)
    sys.exit(0)

if sys.argv[1] == "dd":
    assert sys.argv[2].startswith("of=")
    fn = sys.argv[2][3:]
    f = open(fn, "wb")
    data = stdin.read()
    f.write(data)
    f.close()
    stderr.write(b"0+1 records in\n")
    stderr.write(b"0+1 records out\n")
    stderr.write(b"%d bytes transferred in 42 seconds\n" % len(data))
    sys.exit(0)
