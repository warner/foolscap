
import sys,os,socket,itertools
from twisted.python.runtime import platformType

print "platformType:", platformType
target = int(sys.argv[1])
print "allocating ports, will stop if we're given %d" % target

def allocate_tcp_port():
    """Return an (integer) available TCP port on localhost. This briefly
    listens on the port in question, then closes it right away."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if platformType == "posix" and sys.platform != "cygwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #s.bind(("127.0.0.1", 0))
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def test(port, do_listen):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if platformType == "posix" and sys.platform != "cygwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    if do_listen:
        s.listen(5)
    s.close()

tried = set()
failed = set()
for i in itertools.count():
    if i > 1000000:
        print "reached iteration limit, exiting"
        break
    port = allocate_tcp_port()
    if port in tried:
        print "looped around, exiting"
        break
    tried.add(port)
    #print port
    try:
        test(port, not True)
    except socket.error as e:
        print "test failed for port %d" % port
        failed.add(port)
        continue
    if port == target:
        print "allocated target, exiting"
        break

print "tried", min(tried), "-", max(tried)
print "failures:", sorted(failed)

# on OS-X, s.bind(("0.0.0.0"),0).getsockname()[1];s.close() will allocate you
# a port that is currently in use by some other outbound connection. It will
# allocate a port that's in use as a listening socket bound to 127.0.0.1.

# It can't
# be used: a subsequent s.bind(("0.0.0.0",port)) on a new socket will throw
# EADDRINUSE, even with SO_REUSEADDR on both. This
