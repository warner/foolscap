import StringIO
from foolscap import storage

class TestTransport(StringIO.StringIO):
    disconnectReason = None
    def loseConnection(self):
        pass

class B(object):
    def setup_huge_string(self, N):
        """ This is actually a test for acceptable performance, and it needs to
        be made more explicit, perhaps by being moved into a separate
        benchmarking suite instead of living in this test suite. """
        self.banana = storage.StorageBanana()
        self.banana.slicerClass = storage.UnsafeStorageRootSlicer
        self.banana.unslicerClass = storage.UnsafeStorageRootUnslicer
        self.banana.transport = TestTransport()
        self.banana.connectionMade()
        d = self.banana.send("a"*N)
        d.addCallback(lambda res: self.banana.transport.getvalue())
        def f(o):
            self._encoded_huge_string = o
        d.addCallback(f)
        reactor.runUntilCurrent()

    def bench_huge_string_decode(self, N):
        """ This is actually a test for acceptable performance, and it needs to
        be made more explicit, perhaps by being moved into a separate
        benchmarking suite instead of living in this test suite. """
        o = self._encoded_huge_string
        # results = []
        self.banana.prepare()
        # d.addCallback(results.append)
        CHOMP = 4096
        for i in range(0, len(o), CHOMP):
            self.banana.dataReceived(o[i:i+CHOMP])
        # print results

import sys
from twisted.internet import reactor
from pyutil import benchutil
b = B()
for N in 10**3, 10**4, 10**5, 10**6, 10**7:
    print "%8d" % N,
    sys.stdout.flush()
    benchutil.rep_bench(b.bench_huge_string_decode, N, b.setup_huge_string)
