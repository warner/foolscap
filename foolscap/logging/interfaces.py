
from foolscap import RemoteInterface
from foolscap.schema import DictOf, ListOf, Any


class RILogObserver(RemoteInterface):
    def msg(logmsg=DictOf(str, Any())):
        return None
    def done():
        return None

class RILogFile(RemoteInterface):
    def get_header():
        # (tubid, incarnation,
        #  (first_event: number, time), (last_event: number, time),
        #  num_events,
        #  level_map, # maps string severity to count of messages
        # )
        return (str, int, (int, int), (int, int), int, DictOf(str, int))
    def get_events(receiver=RILogObserver):
        """The designated receiver will be sent every event in the logfile,
        followed by a done() call."""
        return None

class RISubscription(RemoteInterface):
    pass

class RILogPublisher(RemoteInterface):
    def get_versions():
        return DictOf(str, str)
    def subscribe_to_all(observer=RILogObserver):
        return RISubscription
    def unsubscribe(subscription=Any()):
        # I don't know how to get the constraint right: unsubscribe() should
        # accept return value of subscribe_to_all()
        return None

    def enumerate_logfiles():
        return ListOf(RILogFile)

class RILogGatherer(RemoteInterface):
    def logport(nodeid=str, logport=RILogPublisher):
        return None

