from twisted.trial import unittest
from foolscap import info

class Info(unittest.TestCase):
    def test_stages(self):
        ci = info.ConnectionInfo()

        self.assertEqual(ci.connected(), False)
        self.assertEqual(ci.connectorStatuses(), {})
        self.assertEqual(ci.connectionHandlers(), {})
        self.assertEqual(ci.connectionEstablishedAt(), None)
        self.assertEqual(ci.winningHint(), None)
        self.assertEqual(ci.listenerStatus(), (None, None))
        self.assertEqual(ci.connectionLostAt(), None)

        ci._describe_connection_handler("hint1", "tcp")
        ci._set_connection_status("hint1", "working")
        self.assertEqual(ci.connectorStatuses(), {"hint1": "working"})
        self.assertEqual(ci.connectionHandlers(), {"hint1": "tcp"})

        ci._set_connection_status("hint1", "successful")
        ci._set_winning_hint("hint1")
        ci._set_established_at(10.0)
        ci._set_connected(True)

        self.assertEqual(ci.connected(), True)
        self.assertEqual(ci.connectorStatuses(), {"hint1": "successful"})
        self.assertEqual(ci.connectionHandlers(), {"hint1": "tcp"})
        self.assertEqual(ci.connectionEstablishedAt(), 10.0)
        self.assertEqual(ci.winningHint(), "hint1")
        self.assertEqual(ci.listenerStatus(), (None, None))
        self.assertEqual(ci.connectionLostAt(), None)

        ci._set_connected(False)
        ci._set_lost_at(15.0)

        self.assertEqual(ci.connected(), False)
        self.assertEqual(ci.connectionLostAt(), 15.0)
