import pickle
from contextlib import closing

def serialize_raw_header(f, header):
    pickle.dump({"header": header}, f)

def serialize_header(f, type, **kwargs):
    header = {"header": {"type": type} }
    for k,v in kwargs.items():
        header["header"][k] = v
    pickle.dump(header, f)

def serialize_raw_wrapper(f, wrapper):
    pickle.dump(wrapper, f)

def serialize_wrapper(f, ev, from_, rx_time):
    wrapper = {"from": from_,
               "rx_time": rx_time,
               "d": ev}
    pickle.dump(wrapper, f)

class ThisIsActuallyAFurlFileError(Exception):
    pass

def get_events(fn, ignore_value_error=False):
    if fn.endswith(".bz2"):
        import bz2
        f = bz2.BZ2File(fn, "r")
        # note: BZ2File in py2.6 is not a context manager
    else:
        f = open(fn, "rb")

    with closing(f):
        while True:
            try:
                e = pickle.load(f)
                yield e
            except EOFError:
                break
            except ValueError:
                if ignore_value_error:
                    break
                raise
            except IndexError:
                # this happens when you point "flogtool dump" at a furl by
                # mistake (which cannot be parsed as a pickle). Emit a useful
                # error message.
                f.seek(0)
                if f.read(3) == "pb:":
                    raise ThisIsActuallyAFurlFileError

