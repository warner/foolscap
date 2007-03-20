

from zope.interface import interface
Interface = interface.Interface

# TODO: move these here
from foolscap.tokens import ISlicer, IRootSlicer, IUnslicer
_ignored = [ISlicer, IRootSlicer, IUnslicer] # hush pyflakes

class DeadReferenceError(Exception):
    """The RemoteReference is dead, Jim."""


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

    def callRemote(name, *args, **kwargs):
        """Invoke a method on the remote object with which I am associated.

        I always return a Deferred.
        """

