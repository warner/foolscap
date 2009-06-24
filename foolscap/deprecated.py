import warnings

def _wrap_function(wrappee, name):
    def deprecated_wrapper(*args, **kwargs):
        warnings.warn("Importing function %s directly from 'foolscap' "
                      "is deprecated since Foolscap 0.4.3. Please "
                      "import foolscap.api.%s instead" % (name, name),
                      DeprecationWarning, 3)
        return wrappee(*args, **kwargs)
    return deprecated_wrapper

def _wrap_class(wrappee, name):
    class _DeprecatedWrapper(wrappee):
        def __init__(self, *args, **kwargs):
            warnings.warn("Importing class %s directly from 'foolscap' "
                          "is deprecated since Foolscap 0.4.3. Please "
                          "import foolscap.api.%s instead" % (name, name),
                          DeprecationWarning, 2)
            wrappee.__init__(self, *args, **kwargs)
    _DeprecatedWrapper.__name__ = "Deprecated(%s)" % name
    return _DeprecatedWrapper

def _wrap_metaclass(wrappee, name):
    class _DeprecatedWrapper(wrappee):
        def __init__(self, iname, bases=(), attrs=None, __module__=None):
            if attrs:
                warnings.warn("Importing class %s directly from 'foolscap' "
                              "is deprecated since Foolscap 0.4.3. Please "
                              "import foolscap.api.%s instead" % (name, name),
                              DeprecationWarning, 2)
                wrappee.__init__(self, iname, bases, attrs, __module__)
            else:
                wrappee.__init__(self, iname, bases, attrs, __module__)
    return _DeprecatedWrapper

from foolscap import pb, remoteinterface, referenceable

Tub = _wrap_class(pb.Tub, "Tub")
UnauthenticatedTub = _wrap_class(pb.UnauthenticatedTub, "UnauthenticatedTub")

_DeprecatedRemoteInterfaceClass = _wrap_metaclass(remoteinterface.RemoteInterfaceClass,
                                                  "RemoteInterface")
RemoteInterface = _DeprecatedRemoteInterfaceClass("RemoteInterface",
                                                  __module__="pb.flavors")

class _DeprecateReferenceableWhenSubclassing(type):
    def __init__(self, name, bases, dict):
        type.__init__(self, name, bases, dict)
        if name != "_DeprecatedReferenceable":
            # this occurs upon subclassing
            warnings.warn("Importing class Referenceable1 directly from "
                          "'foolscap' is deprecated since Foolscap 0.4.3. "
                          "Please import foolscap.api.Referenceable instead",
                          DeprecationWarning, 3)
            # for foolscap.logging.tail doing:
            #  import foolscap
            #  class LogSaver(foolscap.Referenceable)
            # we want warn(stackdepth=3)
            #
            # for something else, we want stackdepth=2

class _DeprecatedReferenceable(referenceable.Referenceable):
    __metaclass__ = _DeprecateReferenceableWhenSubclassing
    def __init__(self, *args, **kwargs):
        if self.__class__ is _DeprecatedReferenceable:
            # this occurs upon instantiation of Referenceable(). Subclasses
            # do not get a warning here; they were noted at subclassing time.
            warnings.warn("Importing class Referenceable directly from "
                          "'foolscap' is deprecated since Foolscap 0.4.3. "
                          "Please import foolscap.api.Referenceable instead",
                          DeprecationWarning, 2)
        referenceable.Referenceable.__init__(self, *args, **kwargs)

Referenceable = _DeprecatedReferenceable

# Some symbols are too hard to wrap: SturdyRef (being a Copyable), Copyable
# itself. Leave them alone, and assume that users will see the warnings for
# Tub and Referenceable and the more common symols.
SturdyRef = referenceable.SturdyRef

from foolscap import copyable
Copyable = copyable.Copyable
RemoteCopy = copyable.RemoteCopy
registerRemoteCopy = _wrap_function(copyable.registerRemoteCopy,
                                    "registerRemoteCopy")
registerCopier = _wrap_function(copyable.registerCopier,
                                "registerCopier")
registerRemoteCopyFactory = _wrap_function(copyable.registerRemoteCopyFactory,
                                           "registerRemoteCopyFactory")

import foolscap.ipb
DeadReferenceError = _wrap_class(foolscap.ipb.DeadReferenceError, "DeadReferenceError")
import foolscap.tokens
BananaError = _wrap_class(foolscap.tokens.BananaError, "BananaError")
import foolscap.schema
schema = foolscap.schema

import foolscap.storage
serialize = _wrap_function(foolscap.storage.serialize, "serialize")
unserialize = _wrap_function(foolscap.storage.unserialize, "unserialize")
