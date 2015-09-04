import re
from twisted.internet import endpoints

# This can match IPv4 IP addresses + port numbers *or* host names +
# port numbers.
DOTTED_QUAD_RESTR=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
DNS_NAME_RESTR=r"[A-Za-z.0-9\-]+"
OLD_STYLE_HINT_RE=re.compile(r"^(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                        DNS_NAME_RESTR))
NEW_STYLE_HINT_RE=re.compile(r"^tcp:(%s|%s):(\d+){1,5}$" % (DOTTED_QUAD_RESTR,
                                                            DNS_NAME_RESTR))

# Each location hint must start with "TYPE:" (where TYPE is alphanumeric) and
# then can contain any characters except "," and "/". These are expected to
# contain ":"-separated fields (e.g. "TYPE:stuff:morestuff" or
# "TYPE:key=value:key=value"). For compatibility with current and older
# Foolscap releases, we also accept old-syle implicit TCP hints
# ("host:port"). To avoid being interpreted as an old-style hint, the part
# after TYPE: may not consist of only 1-5 digits (so "type:123" will be
# treated as type="tcp" and hostname="type").

# Future versions of foolscap may put hints in their FURLs which we do not
# understand. We will ignore such hints. This version understands two types
# of hints:
#
#  HOST:PORT                 (implicit tcp)
#  tcp:HOST:PORT           } (endpoint syntax for TCP connections)

class DefaultTCP:
    def hint_to_endpoint(self, hint, reactor):
        # Return (endpoint, hostname), where "hostname" is what we pass to the
        # HTTP "Host:" header so a dumb HTTP server can be used to redirect us.
        # Return (None,None) if the hint isn't recognized.
        mo = OLD_STYLE_HINT_RE.search(hint)
        if mo:
            host, port = mo.group(1), int(mo.group(2))
            return endpoints.TCP4ClientEndpoint(reactor, host, port), host
        mo = NEW_STYLE_HINT_RE.search(hint)
        if mo:
            host, port = mo.group(1), int(mo.group(2))
            return endpoints.TCP4ClientEndpoint(reactor, host, port), host
        # Ignore other things from the future.
        return (None, None)
