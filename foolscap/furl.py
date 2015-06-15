import re
from foolscap import base32

class BadFURLError(Exception):
    pass

AUTH_STURDYREF_RE = re.compile(r"pb://([^@]+)@([^/]*)/(.+)$")

# This can match IPv4 IP addresses + port numbers *or* host names +
# port numbers.
DOTTED_QUAD_RESTR=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

DNS_NAME_RESTR=r"[A-Za-z.0-9\-]+"

OLD_STYLE_HINT_RE=re.compile(r"^(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                        DNS_NAME_RESTR))

def encode_location_hint(hint):
    assert hint[0] == "tcp"
    host, port = hint[1:]
    return "%s:%d" % (host, port)

# _tokenize(), _parse() and _parseClientTCP() are copied from
# twisted.internet.endpoints

_OP, _STRING = range(2)

def _tokenize(description):
    """
    Tokenize a strports string and yield each token.

    @param description: a string as described by L{serverFromString} or
        L{clientFromString}.

    @return: an iterable of 2-tuples of (L{_OP} or L{_STRING}, string).  Tuples
        starting with L{_OP} will contain a second element of either ':' (i.e.
        'next parameter') or '=' (i.e. 'assign parameter value').  For example,
        the string 'hello:greet\=ing=world' would result in a generator
        yielding these values::

            _STRING, 'hello'
            _OP, ':'
            _STRING, 'greet=ing'
            _OP, '='
            _STRING, 'world'
    """
    current = ''
    ops = ':='
    nextOps = {':': ':=', '=': ':'}
    description = iter(description)
    for n in description:
        if n in ops:
            yield _STRING, current
            yield _OP, n
            current = ''
            ops = nextOps[n]
        elif n == '\\':
            current += description.next()
        else:
            current += n
    yield _STRING, current

def _parse(description):
    """
    Convert a description string into a list of positional and keyword
    parameters, using logic vaguely like what Python does.

    @param description: a string as described by L{serverFromString} or
        L{clientFromString}.

    @return: a 2-tuple of C{(args, kwargs)}, where 'args' is a list of all
        ':'-separated C{str}s not containing an '=' and 'kwargs' is a map of
        all C{str}s which do contain an '='.  For example, the result of
        C{_parse('a:b:d=1:c')} would be C{(['a', 'b', 'c'], {'d': '1'})}.
    """
    args, kw = [], {}
    def add(sofar):
        if len(sofar) == 1:
            args.append(sofar[0])
        else:
            kw[sofar[0]] = sofar[1]
    sofar = ()
    for (type, value) in _tokenize(description):
        if type is _STRING:
            sofar += (value,)
        elif value == ':':
            add(sofar)
            sofar = ()
    add(sofar)
    return args, kw

def _parseClientTCP(*args, **kwargs):
    """
    Perform any argument value coercion necessary for TCP client parameters.

    Valid positional arguments to this function are host and port.

    Valid keyword arguments to this function are all L{IReactorTCP.connectTCP}
    arguments.

    @return: The coerced values as a C{dict}.
    """

    if len(args) == 2:
        kwargs['port'] = int(args[1])
        kwargs['host'] = args[0]
    elif len(args) == 1:
        if 'host' in kwargs:
            kwargs['port'] = int(args[0])
        else:
            kwargs['host'] = args[0]

    try:
        kwargs['port'] = int(kwargs['port'])
    except KeyError:
        pass

    try:
        kwargs['timeout'] = int(kwargs['timeout'])
    except KeyError:
        pass

    try:
        kwargs['bindAddress'] = (kwargs['bindAddress'], 0)
    except KeyError:
        pass

    return kwargs

# Each location hint must start with "TYPE:" (where TYPE is alphanumeric) and
# then can contain any characters except "," and "/". These are expected to
# look like Twisted endpoint descriptors, or contain other ":"-separated
# fields (e.g. "TYPE:key=value:key=value" or "TYPE:stuff:morestuff"). We also
# accept old-syle implicit TCP hints (host:port). To avoid being interpreted
# as an old-style hint, the part after TYPE: may not consist of only 1-5
# digits (so "type:123" will be treated as type="tcp" and hostname="type").

# Future versions of foolscap may put hints in their FURLs which we do not
# understand. We will ignore such hints. This version understands two types
# of hints:
#
#  HOST:PORT                 (implicit tcp)
#  tcp:host=HOST:port=PORT }
#  tcp:HOST:PORT           } (endpoint syntax for TCP connections
#  tcp:host=HOST:PORT      }  in full, compact and mixed forms)
#  tcp:HOST:port=PORT      }

def decode_location_hints(hints_s):
    hints = []
    if hints_s:
        for hint_s in hints_s.split(","):
            if hint_s == '':
                raise BadFURLError("bad connection hint '%s' "
                                   "(empty string)" % hint_s)

            mo = OLD_STYLE_HINT_RE.search(hint_s)
            if mo:
                hint = ( "tcp", mo.group(1), int(mo.group(2)) )
                hints.append(hint)
            else:
                args, kwargs = _parse(hint_s)
                aname = args.pop(0)
                name = aname.upper()
                if name == 'TCP':
                    fields = _parseClientTCP(*args, **kwargs)
                    hint = ("tcp", fields["host"], fields["port"])
                    hints.append(hint)
                else:
                    # Ignore other things from the future.
                    pass
    return hints

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
        location_hints = decode_location_hints(hints)
        name = mo_auth_furl.group(3)

    else:
        raise ValueError("unknown FURL prefix in %r" % (furl,))
    return (tubID, location_hints, name)

def encode_furl(tubID, location_hints, name):
    location_hints_s = ",".join([encode_location_hint(hint)
                                 for hint in location_hints])
    return "pb://" + tubID + "@" + location_hints_s + "/" + name
