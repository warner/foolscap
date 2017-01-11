import re
from zope.interface import implementer
from twisted.internet.endpoints import HostnameEndpoint
from foolscap.ipb import IConnectionHintHandler, InvalidHintError

DOTTED_QUAD_RESTR=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
# In addition to the usual colon-hex IPv6 addresses, accept "::FFFF:1.2.3.4"
# (IPv4-mapped), and "FE8::1%en0" (local-scope/site-scope with a zone-id)
COLON_HEX_RESTR=(r"\[[A-Fa-f0-9:]+" +
                 r"(?:" + DOTTED_QUAD_RESTR + r"|%[a-zA-Z0-9.]+)?\]")
DNS_NAME_RESTR=r"[A-Za-z.0-9\-]+"

# This matches just (hostname or IPv4 address) and port number
OLD_STYLE_HINT_RE=re.compile(r"^(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                        DNS_NAME_RESTR))
# This matches "tcp:" prefix plus (hostname or IPv4 address or []-wrapped
# IPv6 address) plus port number
NEW_STYLE_HINT_RE=re.compile(r"^tcp:(%s|%s|%s):(\d+){1,5}$" %
                             (DOTTED_QUAD_RESTR, COLON_HEX_RESTR,
                              DNS_NAME_RESTR))

# Each location hint must start with "TYPE:" (where TYPE is alphanumeric) and
# then can contain any characters except "," and "/". These are generally
# expected to contain ":"-separated fields (e.g. "TYPE:stuff:morestuff" or
# "TYPE:key=value:key=value").

# For compatibility with current and older Foolscap releases, we also accept
# old-syle implicit TCP hints ("host:port"). These are caught and converted
# into new-style "tcp:HOST:PORT" hints in convert_legacy_hint() before we
# look up the handler. In this case, HOST can either be a DNS name or a
# dotted-quad IPv4 address.

# To avoid being interpreted as an old-style hint, the part after TYPE: may
# not consist of only 1-5 digits (so "type:123" will be treated as type="tcp"
# and hostname="type"). Creators of new hint types are advised to either use
# multiple colons (e.g. tor:HOST:PORT), or use key=value in the right-hand
# portion (e.g. systemd:fd=3).

# Future versions of foolscap may put hints in their FURLs which we do not
# understand. We will ignore such hints. This version understands two types
# of hints:
#
#  HOST:PORT                 (old-style implicit tcp)
#  tcp:HOST:PORT             (endpoint syntax for TCP connections)

# For new-style hints, HOST can be a DNS name, a dotted-quad IPv4 address, or
# a square-bracked-wrapped colon-hex IPv6 address.

def convert_legacy_hint(location):
    mo = OLD_STYLE_HINT_RE.search(location)
    if mo:
        host, port = mo.group(1), int(mo.group(2))
        return "tcp:%s:%d" % (host, port)
    return location

@implementer(IConnectionHintHandler)
class DefaultTCP:
    def hint_to_endpoint(self, hint, reactor, update_status):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        mo = NEW_STYLE_HINT_RE.search(hint)
        if not mo:
            raise InvalidHintError("unrecognized TCP hint")
        host, port = mo.group(1), int(mo.group(2))
        host = host.lstrip("[").rstrip("]")
        return HostnameEndpoint(reactor, host, port), host

    def describe(self):
        return "tcp"

def default():
    return DefaultTCP()
