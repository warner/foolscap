
class ConnectionInfo:
    def __init__(self):
        self._connected = False
        self._connector_statuses = {}
        self._handler_descriptions = {}
        self._listener_description = None
        self._listener_status = None
        self._winning_hint = None
        self._established_at = None
        self._lost_at = None

    def _set_connected(self, connected):
        self._connected = connected

    def _set_connection_status(self, location, status):
        self._connector_statuses[location] = status
    def _describe_connection_handler(self, location, description):
        self._handler_descriptions[location] = description
    def _set_established_at(self, when):
        self._established_at = when
    def _set_winning_hint(self, location):
        self._winning_hint = location
    def _set_listener_description(self, description):
        self._listener_description = description
    def _set_listener_status(self, status):
        self._listener_status = status
    def _set_lost_at(self, when):
        self._lost_at = when

    def connected(self):
        return self._connected

    def connectorStatuses(self):
        return self._connector_statuses
    def connectionHandlers(self):
        return self._handler_descriptions

    def connectionEstablishedAt(self):
        return self._established_at
    def winningHint(self):
        return self._winning_hint
    def listenerStatus(self):
        return (self._listener_description, self._listener_status)

    def connectionLostAt(self):
        return self._lost_at
