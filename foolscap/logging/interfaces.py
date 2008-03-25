
from foolscap.remoteinterface import RemoteInterface
from foolscap.schema import DictOf, ListOf, Any, Optional

TubID = str # printable: either base32 encoded or "<unauth>"

class RILogObserver(RemoteInterface):
    __remote_name__ = "RILogObserver.foolscap.lothar.com"
    def msg(logmsg=DictOf(str, Any())):
        return None
    def done():
        return None

class RILogFile(RemoteInterface):
    __remote_name__ = "RILogFile.foolscap.lothar.com"
    def get_header():
        # (tubid, incarnation,
        #  (first_event: number, time), (last_event: number, time),
        #  num_events,
        #  level_map, # maps string severity to count of messages
        # )
        return (TubID, int, (int, int), (int, int), int, DictOf(str, int))
    def get_events(receiver=RILogObserver):
        """The designated receiver will be sent every event in the logfile,
        followed by a done() call."""
        return None

class RISubscription(RemoteInterface):
    __remote_name__ = "RISubscription.foolscap.lothar.com"
    pass

class RILogPublisher(RemoteInterface):
    __remote_name__ = "RILogPublisher.foolscap.lothar.com"
    def get_versions():
        return DictOf(str, str)
    def subscribe_to_all(observer=RILogObserver,
                         catch_up=Optional(bool, False)):
        return RISubscription
    def unsubscribe(subscription=Any()):
        # I don't know how to get the constraint right: unsubscribe() should
        # accept return value of subscribe_to_all()
        return None

    def enumerate_logfiles():
        return ListOf(RILogFile)

class RILogGatherer(RemoteInterface):
    __remote_name__ = "RILogGatherer.foolscap.lothar.com"
    def logport(nodeid=TubID, logport=RILogPublisher):
        return None

