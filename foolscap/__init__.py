"""Foolscap"""

__version__ = "0.0.2+"

# here are the primary entry points
from foolscap.pb import Tub, UnencryptedTub, getRemoteURL_TCP

# names we import so that others can reach them as foolscap.foo
from foolscap.remoteinterface import RemoteInterface
from foolscap.referenceable import Referenceable, SturdyRef
from foolscap.copyable import Copyable, RemoteCopy, registerRemoteCopy
from foolscap.ipb import DeadReferenceError
from foolscap.tokens import BananaError
