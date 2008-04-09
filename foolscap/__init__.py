"""Foolscap"""

from _version import verstr as __version__

# here are the primary entry points
from foolscap.pb import Tub, UnauthenticatedTub, getRemoteURL_TCP

# names we import so that others can reach them as foolscap.foo
from foolscap.remoteinterface import RemoteInterface
from foolscap.referenceable import Referenceable, SturdyRef
from foolscap.copyable import Copyable, RemoteCopy, registerRemoteCopy
from foolscap.copyable import registerCopier, registerRemoteCopyFactory
from foolscap.ipb import DeadReferenceError
from foolscap.tokens import BananaError
from foolscap import schema # necessary for the adapter_hooks side-effect
from foolscap.storage import serialize, unserialize
# TODO: Violation?

# hush pyflakes
_unused = [
    __version__,
    Tub, UnauthenticatedTub, getRemoteURL_TCP,
    RemoteInterface,
    Referenceable, SturdyRef,
    Copyable, RemoteCopy, registerRemoteCopy,
    registerCopier, registerRemoteCopyFactory,
    DeadReferenceError,
    BananaError,
    schema,
    serialize, unserialize,
    ]
del _unused
