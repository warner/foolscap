
# application code should import all names from here instead of from
# __init__.py . Use code like this:
#
#  from foolscap.api import Tub
#
# This will make it easier to rearrange Foolscap's internals in the future.
# Anything you might import from outside foolscap.api is subject to movement
# in new releases.

from foolscap._version import verstr as __version__

# here are the primary entry points
from foolscap.pb import Tub, UnauthenticatedTub

# names we import so that others can reach them as foolscap.api.foo
from foolscap.remoteinterface import RemoteInterface
from foolscap.referenceable import Referenceable, SturdyRef
from foolscap.copyable import Copyable, RemoteCopy, registerRemoteCopy
from foolscap.copyable import registerCopier, registerRemoteCopyFactory
from foolscap.ipb import DeadReferenceError
from foolscap.tokens import BananaError
from foolscap.schema import StringConstraint, IntegerConstraint, \
    ListOf, TupleOf, SetOf, DictOf, ChoiceOf, Any
from foolscap.storage import serialize, unserialize
from foolscap.tokens import Violation, RemoteException
from foolscap.eventual import eventually, fireEventually, flushEventualQueue
from foolscap.logging import app_versions

# hush pyflakes
_unused = [
    __version__,
    Tub, UnauthenticatedTub,
    RemoteInterface,
    Referenceable, SturdyRef,
    Copyable, RemoteCopy, registerRemoteCopy,
    registerCopier, registerRemoteCopyFactory,
    DeadReferenceError,
    BananaError,
    StringConstraint, IntegerConstraint,
    ListOf, TupleOf, SetOf, DictOf, ChoiceOf, Any,
    serialize, unserialize,
    Violation, RemoteException,
    eventually, fireEventually, flushEventualQueue,
    app_versions,
    ]
del _unused

