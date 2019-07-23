import json
from contextlib import closing
from twisted.python import failure

class ExtendedEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, failure.Failure):
            # this includes CopyableFailure
            #
            # pickled Failures get the following modified attributes: frames,
            # tb=None, stack=, pickled=1
            return {"@": "Failure",
                    "str": str(o),
                    "repr": repr(o),
                    "traceback": o.getTraceback(),
                    # o.frames? .stack? .type?
                    }
        try:
            return {"@": "UnJSONable",
                    "message": "log.msg() was given an object that could not be encoded into JSON. I've replaced it with this UnJSONable object. The object's repr is in .repr",
                    "repr": repr(o),
                    }
        except Exception as e:
            try:
                return {"@": "Unreprable",
                        "message": "log.msg() was given an object that could not be encoded into JSON, and when I tried to repr() it I got an error too. I've put the repr of the exception in .exception_repr",
                        "exception_repr": repr(e),
                        }
            except Exception:
                return {"@": "ReallyUnreprable",
                        "message": "log.msg() was given an object that could not be encoded into JSON, and when I tried to repr() it I got an error too. That exception wasn't repr()able either. I give up. Good luck.",
                        }


def serialize_raw_header(f, header):
    json.dump({"header": header}, f, cls=ExtendedEncoder)
    f.write("\n")

def serialize_header(f, type, **kwargs):
    header = {"header": {"type": type} }
    for k,v in list(kwargs.items()):
        header["header"][k] = v
    json.dump(header, f, cls=ExtendedEncoder)
    f.write("\n")

def serialize_raw_wrapper(f, wrapper):
    json.dump(wrapper, f, cls=ExtendedEncoder)
    f.write("\n")

def serialize_wrapper(f, ev, from_, rx_time):
    wrapper = {"from": from_,
               "rx_time": rx_time,
               "d": ev}
    json.dump(wrapper, f, cls=ExtendedEncoder)
    f.write("\n")

MAGIC = "# foolscap flogfile v1\n"
class BadMagic(Exception):
    """The file is not a flogfile: wrong magic number."""
class EvilPickleFlogFile(BadMagic):
    """This is an old (pickle-based) flogfile, and cannot be loaded safely."""
class ThisIsActuallyAFurlFileError(BadMagic):
    pass

def get_events(fn):
    if fn.endswith(".bz2"):
        import bz2
        f = bz2.BZ2File(fn, "r")
        # note: BZ2File in py2.6 is not a context manager
    else:
        f = open(fn, "rb")

    with closing(f):
        maybe_magic = f.read(len(MAGIC))
        if maybe_magic != MAGIC:
            if maybe_magic.startswith("(dp0"):
                raise EvilPickleFlogFile()
            if maybe_magic.startswith("pb:"):
                # this happens when you point "flogtool dump" at a furlfile
                # (e.g. logport.furl) by mistake. Emit a useful error
                # message.
                raise ThisIsActuallyAFurlFileError
            raise BadMagic(repr(maybe_magic))
        for line in f.readlines():
            yield json.loads(line)
