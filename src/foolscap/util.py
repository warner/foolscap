import os, sys
import socket
import time
from twisted.internet import defer, reactor, protocol
from twisted.python.runtime import platformType

class AsyncAND(defer.Deferred):
    """Like DeferredList, but results are discarded and failures handled
    in a more convenient fashion.

    Create me with a list of Deferreds. I will fire my callback (with None)
    if and when all of my component Deferreds fire successfully. I will fire
    my errback when and if any of my component Deferreds errbacks, in which
    case I will absorb the failure. If a second Deferred errbacks, I will not
    absorb that failure.

    This means that you can put a bunch of Deferreds together into an
    AsyncAND and then forget about them. If all succeed, the AsyncAND will
    fire. If one fails, that Failure will be propagated to the AsyncAND. If
    multiple ones fail, the first Failure will go to the AsyncAND and the
    rest will be left unhandled (and therefore logged).
    """

    def __init__(self, deferredList):
        defer.Deferred.__init__(self)

        if not deferredList:
            self.callback(None)
            return

        self.remaining = len(deferredList)
        self._fired = False

        for d in deferredList:
            d.addCallbacks(self._cbDeferred, self._cbDeferred,
                           callbackArgs=(True,), errbackArgs=(False,))

    def _cbDeferred(self, result, succeeded):
        self.remaining -= 1
        if succeeded:
            if not self._fired and self.remaining == 0:
                # the last input has fired. We fire.
                self._fired = True
                self.callback(None)
                return
        else:
            if not self._fired:
                # the first Failure is carried into our output
                self._fired = True
                self.errback(result)
                return None
            else:
                # second and later Failures are not absorbed
                return result

# adapted from Tahoe: finds a single publically-visible address, or None.
# Tahoe also uses code to run /bin/ifconfig (or equivalent) to find other
# addresses, but that's a bit heavy for this. Note that this runs
# synchronously. Also note that this doesn't require the reactor to be
# running.
def get_local_ip_for(target='A.ROOT-SERVERS.NET'):
    """Find out what our IP address is for use by a given target.

    @return: the IP address as a dotted-quad string which could be used by
              to connect to us. It might work for them, it might not. If
              there is no suitable address (perhaps we don't currently have an
              externally-visible interface), this will return None.
    """
    try:
        target_ipaddr = socket.gethostbyname(target)
    except socket.gaierror:
        # DNS isn't running
        return None
    udpprot = protocol.DatagramProtocol()
    port = reactor.listenUDP(0, udpprot)
    try:
        udpprot.transport.connect(target_ipaddr, 7)
        localip = udpprot.transport.getHost().host
    except socket.error:
        # no route to that host
        localip = None
    port.stopListening() # note, this returns a Deferred
    return localip

FORMAT_TIME_MODES = ["short-local", "long-local", "utc", "epoch"]
def format_time(when, mode):
    if mode == "short-local":
        time_s = time.strftime("%H:%M:%S", time.localtime(when))
        time_s = time_s + ".%03d" % int(1000*(when - int(when)))
    elif mode == "long-local":
        lt = time.localtime(when)
        time_s = time.strftime("%Y-%m-%d_%H:%M:%S", lt)
        time_s = time_s + ".%06d" % int(1000000*(when - int(when)))
        time_s += time.strftime("%z", lt)
    elif mode == "utc":
        time_s = time.strftime("%Y-%m-%d_%H:%M:%S", time.gmtime(when))
        time_s = time_s + ".%06d" % int(1000000*(when - int(when)))
        time_s += "Z"
    elif mode == "epoch":
        time_s = "%.03f" % when
    return time_s


def move_into_place(source, dest):
    """Atomically replace a file, or as near to it as the platform allows.
    The dest file may or may not exist."""
    # from Tahoe
    if "win32" in sys.platform.lower():
        try:
            os.remove(dest)
        except:
            pass
    os.rename(source, dest)

def isSubstring(small, big):
    assert type(small) is str and type(big) is str
    return small in big

def allocate_tcp_port():
    """Return an (integer) available TCP port on localhost. This briefly
    listens on the port in question, then closes it right away."""

    # Making this work correctly on multiple OSes is non-trivial:
    # * on OS-X:
    #   * Binding the test socket to 127.0.0.1 lets the kernel give us a
    #     LISTEN port that some other process is using, if they bound it to
    #     ANY (0.0.0.0). These will fail when we attempt to
    #     listen(bind=0.0.0.0) ourselves
    #   * Binding the test socket to 0.0.0.0 lets the kernel give us LISTEN
    #     ports bound to 127.0.0.1, although then our subsequent listen()
    #     call usually succeeds.
    #   * In both cases, the kernel can give us a port that's in use by the
    #     near side of an ESTABLISHED socket. If the process which owns that
    #     socket is not owned by the same user as us, listen() will fail.
    #   * Doing a listen() right away (on the kernel-allocated socket)
    #     succeeds, but a subsequent listen() on a new socket (bound to
    #     the same port) will fail.
    # * on Linux:
    #   * The kernel never gives us a port in use by a LISTEN socket, whether
    #     we bind the test socket to 127.0.0.1 or 0.0.0.0
    #   * Binding it to 127.0.0.1 does let the kernel give us ports used in
    #     an ESTABLISHED connection. Our listen() will fail regardless of who
    #     owns that socket. (note that we are using SO_REUSEADDR but not
    #     SO_REUSEPORT, which would probably affect things).
    #

    #
    # So to make this work properly everywhere, allocate_tcp_port() needs two
    # phases: first we allocate a port (with 0.0.0.0), then we close that
    # socket, then we open a second socket, bind the second socket to the
    # same port, then try to listen. If the listen() fails, we loop back and
    # try again.

    # In addition, on at least OS-X, the kernel will give us a port that's in
    # use by some other process, when that process has bound it to 127.0.0.1,
    # and our bind/listen (to 0.0.0.0) will succeed, but a subsequent caller
    # who tries to bind it to 127.0.0.1 will get an error in listen(). So we
    # must actually test the proposed socket twice: once bound to 0.0.0.0,
    # and again bound to 127.0.0.1. This probably isn't complete for
    # applications which bind to a specific outward-facing interface, but I'm
    # ok with that; anything other than 0.0.0.0 or 127.0.0.1 is likely to use
    # manually-selected ports, assigned by the user or sysadmin.

    # Ideally we'd refrain from doing listen(), to minimize impact on the
    # system, and we'd bind the port to 127.0.0.1, to avoid making it look
    # like we're accepting data from the outside world (in situations where
    # we're going to end up binding the port to 127.0.0.1 anyways). But for
    # the above reasons, neither would work. We *do* add SO_REUSEADDR, to
    # make sure our lingering socket won't prevent our caller from opening it
    # themselves in a few moments (note that Twisted's
    # tcp.Port.createInternetSocket sets SO_REUSEADDR, among other flags).

    count = 0
    while True:
        s = _make_socket()
        s.bind(("0.0.0.0", 0))
        port = s.getsockname()[1]
        s.close()

        s = _make_socket()
        try:
            s.bind(("0.0.0.0", port))
            s.listen(5) # this is what sometimes fails
            s.close()
            s = _make_socket()
            s.bind(("127.0.0.1", port))
            s.listen(5)
            s.close()
            return port
        except socket.error:
            s.close()
            count += 1
            if count > 100:
                raise
            # try again

def _make_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if platformType == "posix" and sys.platform != "cygwin":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s
