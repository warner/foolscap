
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

    def new_incident(name=str, trigger=Event):
        # should this give (tubid, incarnation, trigger) like list_incidents?
        return None
    def done_with_incident_catchup():
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
    def unsubscribe():
        """Cancel a subscription. Once this method has been completed (and
        its Deferred has fired), no further messages will be received by the
        observer (i.e. the response to unsubscribe() will wait until all
        pending messages have been queued).

        This method is idempotent: calling it multiple times has the same
        effect as calling it just once."""
        return None

class RILogPublisher(RemoteInterface):
    __remote_name__ = "RILogPublisher.foolscap.lothar.com"
    def get_versions():
        return DictOf(str, str)
    def get_pid():
        return int

    def subscribe_to_all(observer=RILogObserver,
                         catch_up=Optional(bool, False)):
        """
        Call unsubscribe() on the returned RISubscription object to stop
        receiving messages.
        """
        return RISubscription
    def unsubscribe(subscription=Any()):
        # NOTE: this is deprecated. Use subscription.unsubscribe() instead.
        # I don't know how to get the constraint right: unsubscribe() should
        # accept return value of subscribe_to_all()
        return None

    def enumerate_logfiles():
        return ListOf(RILogFile)

    # Incident support

    def list_incidents(since=Optional(str, "")):
        """Return a dict that maps an 'incident name' (a string of the form
        'incident-TIMESTAMP-UNIQUE') to the triggering event (a single event
        dictionary). The incident name can be passed to get_incident() to
        obtain the list of events (including header) contained inside the
        incident report. Incident names will sort in chronological order.

        If the optional since= argument is provided, then this will only
        return incident names that are alphabetically greater (and thus
        chronologically later) than the given string. This can be used to
        poll an application for incidents that have occurred since a previous
        query. For real-time reporting, use subscribe_to_incidents() instead.
        """
        return DictOf(str, Event)

    def subscribe_to_incidents(observer=RILogObserver,
                               catch_up=Optional(bool, False),
                               since=Optional(str, "")):
        """Subscribe to hear about new Incidents, optionally catching up on
        old ones.

        Each new Incident will be reported by name+trigger to the observer by
        a new_incident() message. This message will be sent after the
        incident reporter has finished working (usually a few seconds after
        the triggering event).

        If catch_up=True, then old Incidents will be sent to the observer
        before any new ones are reported. When the publisher has finished
        sending the names of all old events, it will send a
        done_with_incident_catchup() message to the observer. Only old
        Incidents with a name that is alphabetically greater (and thus later)
        than the since= argument will be sent. Use since='' to catch up on
        all old Incidents.

        Call unsubscribe() on the returned RISubscription object to stop
        receiving messages.
        """
        return RISubscription

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
    def new_trigger(triggering_event):
        """This is called when a triggering event occurs while an incident is
        already being reported. If the event happened later, it would trigger
        a new incident. Since it overlapped with the existing incident, it
        will just be added to that incident.

        The triggering event will also be reported through the usual
        event-publish-subscribe mechanism. This method is provided to give
        the reporter the opportunity to mark the event somehow, for the
        benefit of incident-file analysis tools.
        """
    def is_active():
        """Returns True if the reporter is still running. While in this
        state, new Incident triggers will be passed to the existing reporter
        instead of causing a new Incident to be declared. This will tend to
        coalesce back-to-back problems into a single Incident."""

