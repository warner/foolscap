
class ConnectionInfo:
    def __init__(self):
        self.connected = False
        self.connectorStatuses = {}
        self.connectionHandlers = {}
        self.listenerStatus = (None, None)
        self.winningHint = None
        self.establishedAt = None
        self.lostAt = None

    def _set_connected(self, connected):
        self.connected = connected

    def _set_connection_status(self, location, status):
        self.connectorStatuses[location] = status
    def _describe_connection_handler(self, location, description):
        self.connectionHandlers[location] = description
    def _set_established_at(self, when):
        self.establishedAt = when
    def _set_winning_hint(self, location):
        self.winningHint = location
    def _set_listener_description(self, description):
        self.listenerStatus = (description, self.listenerStatus[1])
    def _set_listener_status(self, status):
        self.listenerStatus = (self.listenerStatus[0], status)
    def _set_lost_at(self, when):
        self.lostAt = when
