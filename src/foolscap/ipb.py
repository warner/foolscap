

from zope.interface import interface
Interface = interface.Interface

# TODO: move these here
from foolscap.tokens import ISlicer, IRootSlicer, IUnslicer
_ignored = [ISlicer, IRootSlicer, IUnslicer] # hush pyflakes

class InvalidHintError(Exception):
    """The hint was malformed and could not be used."""

class IConnectionHintHandler(Interface):
    def hint_to_endpoint(hint, reactor, update_status):
        """Return (endpoint, hostname), or a Deferred that fires with the
        same, where endpoint is an IStreamClientEndpoint object, and hostname
        is a string (for use in the HTTP headers during negotiation). The
        endpoint, once connected, must be capable of handling .startTLS().
        Hints are strings which always start with 'TYPE:', and handlers are
        registered for specific types (and will not be called with hints of
        other types). update_status() can be called (with a string) to report
        progress, and should typically be set just before waiting for some
        connections step (e.g. connecting to a Tor daemon). Raise
        InvalidHintError (or return a Deferred that errbacks with one) if the
        hint could not be parsed or otherwise turned into an Endpoint. Set an
        attribute named 'foolscap_connection_handler_error' on the exception
        object to have `ConnectionInfo.connectorStatuses()` report that
        string instead of an exception-class -based status message."""

    def describe():
        """Return a short string describing this handler, like 'tcp' or
        'tor'. If this method is not implemented, the handler's repr will be
        used."""

class DeadReferenceError(Exception):
    """The RemoteReference is dead, Jim."""
    def __init__(self, why=None, remote_tubid=None, request=None):
        self.why = why
        self.remote_tubid = remote_tubid
        self.request = request

    def __str__(self):
        args = []
        if self.why:
            args.append(self.why)
        if self.remote_tubid:
            args.append("(to tubid=%s)" % self.remote_tubid)
        if self.request:
            iname, mname = self.request.getMethodNameInfo()
            args.append("(during method=%s:%s)" % (iname, mname))
        return " ".join([str(a) for a in args])


class IReferenceable(Interface):
    """This object is remotely referenceable. This means it is represented to
    remote systems as an opaque identifier, and that round-trips preserve
    identity.
    """

    def processUniqueID():
        """Return a unique identifier (scoped to the process containing the
        Referenceable). Most objects can just use C{id(self)}, but objects
        which should be indistinguishable to a remote system may want
        multiple objects to map to the same PUID."""

class IRemotelyCallable(Interface):
    """This object is remotely callable. This means it defines some remote_*
    methods and may have a schema which describes how those methods may be
    invoked.
    """

    def getInterfaceNames():
        """Return a list of RemoteInterface names to which this object knows
        how to respond."""

    def doRemoteCall(methodname, args, kwargs):
        """Invoke the given remote method. This method may raise an
        exception, return normally, or return a Deferred."""

class ITub(Interface):
    """This marks a Tub."""

class IBroker(Interface):
    """This marks a broker."""

class IRemoteReference(Interface):
    """This marks a RemoteReference."""

    def notifyOnDisconnect(callback, *args, **kwargs):
        """Register a callback to run when we lose this connection.

        The callback will be invoked with whatever extra arguments you
        provide to this function. For example::

         def my_callback(name, number):
             print name, number+4
         cookie = rref.notifyOnDisconnect(my_callback, 'bob', number=3)

        This function returns an opaque cookie. If you want to cancel the
        notification, pass this same cookie back to dontNotifyOnDisconnect::

         rref.dontNotifyOnDisconnect(cookie)

        Note that if the Tub is shutdown (via stopService), all
        notifyOnDisconnect handlers are cancelled.
        """

    def dontNotifyOnDisconnect(cookie):
        """Deregister a callback that was registered with notifyOnDisconnect.
        """

    def callRemote(name, *args, **kwargs):
        """Invoke a method on the remote object with which I am associated.

        I always return a Deferred. This will fire with the results of the
        method when and if the remote end finishes. It will errback if any of
        the following things occur::

         the arguments do not match the schema I believe is in use by the
         far end (causes a Violation exception)

         the connection to the far end has been lost (DeadReferenceError)

         the arguments are not accepted by the schema in use by the far end
         (Violation)

         the method executed by the far end raises an exception (arbitrary)

         the return value of the remote method is not accepted by the schema
         in use by the far end (Violation)

         the connection is lost before the response is returned
         (ConnectionLost)

         the return value is not accepted by the schema I believe is in use
         by the far end (Violation)
        """

    def callRemoteOnly(name, *args, **kwargs):
        """Invoke a method on the remote object with which I am associated.

        This form is for one-way messages that do not require results or even
        acknowledgement of completion. I do not wait for the method to finish
        executing. The remote end will be instructed to not send any
        response. There is no way to know whether the method was successfully
        delivered or not.

        I always return None.
        """

