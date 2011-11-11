import dbus
import avahi

#from twisted.internet import glib2reactor
#glib2reactor.install()

from dbus.mainloop.glib import DBusGMainLoop
DBusGMainLoop(set_as_default=True)

class AvahiPublishTub:
    SERVICE_TYPE = "_foolscap-rpc._tcp"
    supported_hints = ("zeroconf",)
    def __init__(self, tub):
        self.dbus = None
        self.groups = {} 
        self.tub = tub
        self.collisionfix = 0

    def __dbus_connect(self):
        self.sys_dbus = dbus.SystemBus()

        self.dbus = dbus.Interface(
                self.sys_dbus.get_object( avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER ),
                avahi.DBUS_INTERFACE_SERVER )

    def __avahi_new_group(self, listener):
        group = dbus.Interface(
                self.sys_dbus.get_object( avahi.DBUS_NAME, self.dbus.EntryGroupNew()),
                avahi.DBUS_INTERFACE_ENTRY_GROUP)
        
        group.connect_to_signal('StateChanged', self.__dbus_state_change(listener))
        return group

    def __dbus_state_change(self, listener):
        def cb(state, what):
            if state == avahi.SERVER_COLLISION:
                self.__resolve_collision(listener)
        return cb

    def __resolve_collision(self, listener):
        self.collisionfix += 1
        self.listenOn(listener)

    def listenOn(self, listener):
        if not self.dbus:
            self.__dbus_connect()

        name = self.tub.getTubID()
        if self.collisionfix > 0:
            name += " #%d" % self.collisionfix

        if listener not in self.groups:
            group = self.groups[listener] = self.__avahi_new_group(listener)
        
        add_service(
                group,
                name,
                self.SERVICE_TYPE,
                "",
                "",
                listener.getPortnum(),
                repr(self.tub.parent)
                )
            
    def stopListeningOn(self, listener):
        try:
            self.groups[listener].Reset()
        except KeyError:
            pass
        else:
            del self.groups[listener]
#endclass

def add_service(group, name, stype, domain, host, port, txt):
    group.AddService(
            avahi.IF_UNSPEC,
            avahi.PROTO_UNSPEC,
            dbus.UInt32(avahi.PUBLISH_UPDATE), # flags
            name, stype,
            domain, host,
            dbus.UInt16(port),
            avahi.string_array_to_txt_array(txt))
    group.Commit()

