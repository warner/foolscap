
try:
    import avahi_publish
    import avahi_discover
    zeroconf_PublishTub = avahi_publish.AvahiPublishTub
    zeroconf_DiscoverTubs = avahi_discover.AvahiDiscoverTubs
except:
    raise

supported_hints = {"mdns-sd": (zeroconf_DiscoverTubs, zeroconf_PublishTub)}

def start_publishing_using(hint, tub):
    return supported_hints[hint][1](tub)

def start_discovery_using(hint, addcb, remcb):
    return supported_hints[hint][0](addcb, remcb)
