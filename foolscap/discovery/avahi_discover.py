import dbus
import avahi
from collections import namedtuple
from twisted.application import service
from dbus.mainloop.glib import DBusGMainLoop
DBusGMainLoop(set_as_default=True)

ResolvedService = namedtuple("ResolvedService",
                             ["iface", "proto", "name", "type", "domain",
                              "host", "aproto", "addr", "port", "txt", "flags"])

class AvahiDiscoverTubs(service.Service):
    SERVICE_TYPE = "_foolscap-rpc._tcp"
    def __init__(self, addcb, remcb):
        self.dbus = self.browser = None
        self._addcb = addcb
        self._remcb = remcb
        self.known_services = {}

    def startService(self):
        self.__dbus_connect()
        service.Service.startService(self)

    def __dbus_connect(self):
        bus = dbus.SystemBus()
        self.dbus = dbus.Interface(
                bus.get_object( avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER ),
                avahi.DBUS_INTERFACE_SERVER )

        self.browser = dbus.Interface(bus.get_object(avahi.DBUS_NAME,
                                          self.dbus.ServiceBrowserNew(
                                                                        avahi.IF_UNSPEC,
                                                                        avahi.PROTO_INET,
                                                                        self.SERVICE_TYPE,
                                                                        '',
                                                                        0
                                                                        )
                                            ),
                                      avahi.DBUS_INTERFACE_SERVICE_BROWSER)
        self.browser.connect_to_signal("ItemNew", self.__new_service)
        self.browser.connect_to_signal("ItemRemove", self.__remove_service)
    
    def __new_service(self, iface, proto, name, stype, domain, flags):
        def service_resolved(*args):
            args = ResolvedService(*args)
            self.known_services[args[2]] = args
            self._addcb(args)

        def service_resolve_error(*args):
            pass
        
        self.dbus.ResolveService(iface, proto, name, stype, domain,
                                   avahi.PROTO_UNSPEC, dbus.UInt32(0),
                                   reply_handler=service_resolved,
                                   error_handler=service_resolve_error)

    def __remove_service(self, iface, proto, name, stype, domain, flags):
        self._remcb(self.known_services[name])
        del self.known_services[name]

if __name__ == "__main__":
    from twisted.internet import glib2reactor
    glib2reactor.install()
    from twisted.internet import reactor
    disco = AvahiDiscoverTahoeNodes()
    reactor.run()
