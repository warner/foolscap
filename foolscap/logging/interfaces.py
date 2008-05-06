
from zope.interface import Interface
from foolscap.remoteinterface import RemoteInterface
from foolscap.schema import DictOf, ListOf, Any, Optional, ChoiceOf

TubID = str # printable: either base32 encoded or "<unauth>"
Incarnation = (str, ChoiceOf(str, None))
Header = DictOf(str, Any())
Event = DictOf(str, Any()) # this has message:, level:, facility:, etc
EventWrapper = DictOf(str, Any()) # this has from:, rx_time:, and d:

class RILogObserver(RemoteInterface):
    __remote_name__ = "RILogObserver.foolscap.lothar.com"
    def msg(logmsg=Event):
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

    def list_incidents():
        """Return a dict that maps an 'incident name' (a string) to tuple of
        (tubid string, incarnation, triggering event). The incident name can
        be passed to get_incident() to obtain the list of events (including
        header) contained inside the incident report. Incident names will
        sort in chronological order."""
        return DictOf(str, (TubID, Incarnation, Event) )

    def get_incident(incident_name=str):
        """Given an incident name, return the header dict and list of event
        dicts for that incident."""
        # note that this puts all the events in memory at the same time, but
        # we expect the logfiles to be of a reasonable size: not much larger
        # than the circular buffers that we keep around anyways.
        return (Header, ListOf(Event))

class RILogGatherer(RemoteInterface):
    __remote_name__ = "RILogGatherer.foolscap.lothar.com"
    def logport(nodeid=TubID, logport=RILogPublisher):
        return None

class IIncidentReporter(Interface):
    def incident_declared(triggering_event):
        """This is called when an Incident needs to be recorded."""
