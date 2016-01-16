import pickle
from contextlib import closing

def sanitize_event(event):
    # We trial-serialize the event, and if that works we return it unchanged.
    # But if it fails, we find the (one? two?) keys/values that are causing
    # problems, and stringify those with an error message.

    # The performance hit of serializing things twice is a drag, but the
    # faster approach (try pickle.dump, catch an exception, then try again
    # with a sanitized dictionary) is likely to write partially-serialized
    # fragments to the file, corrupting it.

    try:
        pickle.dumps(event)
        return event
    except pickle.PickleError:
        pass

    new_event = {}
    for key,value in event.items():
        try:
            pickle.dumps(key)
            safe_key = key
        except pickle.PickleError:
            safe_key = "[unpickleable key: %s]" % str(key)

        try:
            pickle.dumps(value)
            safe_value = value
        except pickle.PickleError:
            safe_value = "[unpickleable value: %s]" % str(value)

        new_event[safe_key] = safe_value
    return new_event

def serialize_raw_header(f, header):
    pickle.dump({"header": header}, f)

def serialize_header(f, type, **kwargs):
    header = {"type": type}
    for k,v in kwargs.items():
        header[k] = v
    serialize_raw_header(f, header)

def serialize_raw_wrapper(f, wrapper):
    pickle.dump(wrapper, f)

def serialize_wrapper(f, ev, from_, rx_time):
    wrapper = {"from": from_,
               "rx_time": rx_time,
               "d": sanitize_event(ev)}
    serialize_raw_wrapper(f, wrapper)

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

