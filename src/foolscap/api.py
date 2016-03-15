
# application code should import all names from here instead of from
# __init__.py . Use code like this:
#
#  from foolscap.api import Tub
#
# This will make it easier to rearrange Foolscap's internals in the future.
# Anything you might import from outside foolscap.api is subject to movement
# in new releases.

from foolscap._version import get_versions
__version__ = str(get_versions()['version'])
del get_versions

# here is the primary entry point
from foolscap.pb import Tub

# names we import so that others can reach them as foolscap.api.foo
from foolscap.remoteinterface import RemoteInterface
from foolscap.referenceable import Referenceable, SturdyRef
from foolscap.copyable import Copyable, RemoteCopy, registerRemoteCopy
from foolscap.copyable import registerCopier, registerRemoteCopyFactory
from foolscap.ipb import DeadReferenceError, IConnectionHintHandler
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
    Tub,
    RemoteInterface,
    Referenceable, SturdyRef,
    Copyable, RemoteCopy, registerRemoteCopy,
    registerCopier, registerRemoteCopyFactory,
    DeadReferenceError, IConnectionHintHandler,
    BananaError,
    StringConstraint, IntegerConstraint,
    ListOf, TupleOf, SetOf, DictOf, ChoiceOf, Any,
    serialize, unserialize,
    Violation, RemoteException,
    eventually, fireEventually, flushEventualQueue,
    app_versions,
    ]
del _unused

