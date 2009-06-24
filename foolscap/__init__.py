"""Foolscap"""

from _version import verstr as __version__

from foolscap import schema as _for_side_effect # register adapters

# All names here are now deprecated. Please import them from foolscap.api
# instead. This file will become empty (except for __version__) in the next
# major release.

# here are the primary entry points
from deprecated import Tub, UnauthenticatedTub
from deprecated import RemoteInterface, Referenceable, SturdyRef

# names we import so that others can reach them as foolscap.foo
from deprecated import Copyable, RemoteCopy, registerRemoteCopy
from deprecated import registerCopier, registerRemoteCopyFactory
from deprecated import DeadReferenceError
from deprecated import BananaError
from deprecated import schema
from deprecated import serialize, unserialize

# hush pyflakes
_unused = [
    __version__,
    _for_side_effect,
    Tub, UnauthenticatedTub,
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
del _for_side_effect
