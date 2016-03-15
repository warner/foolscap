import re
from foolscap import base32

class BadFURLError(Exception):
    pass

AUTH_STURDYREF_RE = re.compile(r"pb://([^@]+)@([^/]*)/(.+)$")

def decode_furl(furl):
    """Returns (tubID, location_hints, name)"""
    # pb://key@{ip:port,host:port,[ipv6]:port}[/unix]/swissnumber
    # i.e. pb://tubID@{locationHints..}/name
    #
    # it can live at any one of a (TODO) variety of network-accessible
    # locations, or (TODO) at a single UNIX-domain socket.

    mo_auth_furl = AUTH_STURDYREF_RE.search(furl)
    if mo_auth_furl:
        # we only pay attention to the first 32 base32 characters
        # of the tubid string. Everything else is left for future
        # extensions.
        tubID_s = mo_auth_furl.group(1)
        tubID = tubID_s[:32]
        if not base32.is_base32(tubID):
            raise BadFURLError("'%s' is not a valid tubid" % (tubID,))
        hints = mo_auth_furl.group(2)
        location_hints = hints.split(",")
        if location_hints == [""]:
            location_hints = []
        if "" in location_hints:
            raise BadFURLError("no connection hint may be empty")
        # it is legal to have no hints at all: an empty string turns into an
        # empty list
        name = mo_auth_furl.group(3)

    else:
        raise ValueError("unknown FURL prefix in %r" % (furl,))
    return (tubID, location_hints, name)

def encode_furl(tubID, location_hints, name):
    location_hints_s = ",".join(location_hints)
    return "pb://" + tubID + "@" + location_hints_s + "/" + name
