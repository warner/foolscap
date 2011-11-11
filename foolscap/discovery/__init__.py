
try:
    import avahi_publish
    import avahi_discover
    PublishTub = avahi_publish.AvahiPublishTub
    DiscoverTubs = avahi_discover.AvahiDiscoverTubs
except:
    raise

supported_hints = {"zeroconf": (DiscoverTubs, PublishTub)}

def start_discovery_using(hint, addcb, remcb):
    return supported_hints[hint][0](addcb, remcb)
