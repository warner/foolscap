
"""
storage.py: support for using Banana as if it were pickle

This includes functions for serializing to and from strings, instead of a
network socket.

This functionality is isolated here because it is never used for data coming
over network connections.
"""

from io import BytesIO

from foolscap import banana
from twisted.internet.defer import Deferred
from foolscap.slicers.root import ScopedRootSlicer, ScopedRootUnslicer


# the root slicer for storage is exactly like the regular root slicer
class StorageRootSlicer(ScopedRootSlicer):
    pass

# the root unslicer for storage is just like the regular one, but hands
# received objects to the StorageBanana
class StorageRootUnslicer(ScopedRootUnslicer):
    def receiveChild(self, obj, ready_deferred):
        self.protocol.receiveChild(obj, ready_deferred)

class StorageBanana(banana.Banana):
    object = None
    violation = None
    disconnectReason = None
    slicerClass = StorageRootSlicer
    unslicerClass = StorageRootUnslicer

    def prepare(self):
        self.d = Deferred()
        return self.d

    def receiveChild(self, obj, ready_deferred):
        if ready_deferred:
            ready_deferred.addBoth(self.d.callback)
            self.d.addCallback(lambda res: obj)
        else:
            self.d.callback(obj)
        del self.d

    def receivedObject(self, obj):
        self.object = obj

    def sendError(self, msg):
        pass

    def reportViolation(self, why):
        self.violation = why

    def reportReceiveError(self, f):
        self.disconnectReason = f
        f.raiseException()

class SerializerTransport:
    def __init__(self, sio):
        self.sio = sio
    def write(self, data):
        self.sio.write(data)
    def loseConnection(self, why="ignored"):
        pass

def serialize(obj, outstream=None, root_class=StorageRootSlicer, banana=None):
    """Serialize an object graph into a sequence of bytes. Returns a Deferred
    that fires with the sequence of bytes."""
    if banana:
        b = banana
    else:
        b = StorageBanana()
        b.slicerClass = root_class
    if outstream is None:
        sio = BytesIO()
    else:
        sio = outstream
    b.transport = SerializerTransport(sio)
    b.connectionMade()
    d = b.send(obj)
    def _report_error(res):
        if b.disconnectReason:
            return b.disconnectReason
        if b.violation:
            return b.violation
        return res
    d.addCallback(_report_error)
    if outstream is None:
        d.addCallback(lambda res: sio.getvalue())
    else:
        d.addCallback(lambda res: outstream)
    return d

def unserialize(str_or_instream, banana=None, root_class=StorageRootUnslicer):
    """Unserialize a sequence of bytes back into an object graph."""
    if banana:
        b = banana
    else:
        b = StorageBanana()
        b.unslicerClass = root_class
    b.connectionMade()
    d = b.prepare() # this will fire with the unserialized object
    if isinstance(str_or_instream, bytes):
        b.dataReceived(str_or_instream)
    else:
        raise RuntimeError("input streams not implemented yet")
    def _report_error(res):
        if b.disconnectReason:
            return b.disconnectReason
        if b.violation:
            return b.violation
        return res # return the unserialized object
    d.addCallback(_report_error)
    return d

