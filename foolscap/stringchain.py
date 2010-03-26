import copy

from collections import deque

# Note: when changing this class, you should un-comment all the lines that say
# "assert self._assert_invariants()".

class StringChain(object):
    def __init__(self):
        self.d = deque()
        self.ignored = 0
        self.tailignored = 0
        self.len = 0

    def append(self, s):
        """ Add s to the end of the chain. """
        #assert self._assert_invariants()
        if not s:
            return

        # First trim off any ignored tail bytes.
        if self.tailignored:
            self.d[-1] = self.d[-1][:-self.tailignored]
            self.tailignored = 0

        self.d.append(s)
        self.len += len(s)
        #assert self._assert_invariants()

    def appendleft(self, s):
        """ Add s to the beginning of the chain. """
        #assert self._assert_invariants()
        if not s:
            return

        # First trim off any ignored bytes.
        if self.ignored:
            self.d[0] = self.d[0][self.ignored:]
            self.ignored = 0

        self.d.appendleft(s)
        self.len += len(s)
        #assert self._assert_invariants()

    def __str__(self):
        """ Return the entire contents of this chain as a single
        string. (Obviously this requires copying all of the bytes, so don't do
        this unless you need to.) This has a side-effect of collecting all the
        bytes in this StringChain object into a single string which is stored
        in the first element of its internal deque. """
        self._collapse()
        if self.d:
            return self.d[0]
        else:
            return ''

    def popleft_new_stringchain(self, bytes):
        """ Remove some of the leading bytes of the chain and return them as a
        new StringChain object. (Use str() on it if you want the bytes in a
        string, or call popleft() instead of popleft_new_stringchain().) """
        #assert self._assert_invariants()
        if not bytes or not self.d:
            return self.__class__()

        assert bytes >= 0, bytes

        # We need to add at least this many bytes to the new StringChain.
        bytesleft = bytes + self.ignored
        n = self.__class__()
        n.ignored = self.ignored

        while bytesleft > 0 and self.d:
            s = self.d.popleft()
            self.len -= (len(s) - self.ignored)
            n.d.append(s)
            n.len += (len(s)-self.ignored)
            self.ignored = 0
            bytesleft -= len(s)

        overrun = - bytesleft

        if overrun > 0:
            self.d.appendleft(s)
            self.len += overrun
            self.ignored = len(s) - overrun
            n.len -= overrun
            n.tailignored = overrun
        else:
            self.ignored = 0

        # Either you got exactly how many you asked for, or you drained self entirely and you asked for more than you got.
        #assert (n.len == bytes) or ((not self.d) and (bytes > self.len)), (n.len, bytes, len(self.d))

        #assert self._assert_invariants()
        #assert n._assert_invariants()
        return n

    def popleft(self, bytes):
        """ Remove some of the leading bytes of the chain and return them as a
        string. """
        #assert self._assert_invariants()
        if not bytes or not self.d:
            return ''

        assert bytes >= 0, bytes

        # We need to add at least this many bytes to the result.
        bytesleft = bytes
        resstrs = []

        s = self.d.popleft()
        if self.ignored:
            s = s[self.ignored:]
            self.ignored = 0
        self.len -= len(s)
        resstrs.append(s)
        bytesleft -= len(s)

        while bytesleft > 0 and self.d:
            s = self.d.popleft()
            self.len -= len(s)
            resstrs.append(s)
            bytesleft -= len(s)

        overrun = - bytesleft

        if overrun > 0:
            self.d.appendleft(s)
            self.ignored = (len(s) - overrun)
            self.len += overrun
            resstrs[-1] = resstrs[-1][:-overrun]

        resstr = ''.join(resstrs)

        # Either you got exactly how many you asked for, or you drained self entirely and you asked for more than you got.
        #assert (len(resstr) == bytes) or ((not self.d) and (bytes > self.len)), (len(resstr), bytes, len(self.d), overrun)

        #assert self._assert_invariants()

        return resstr

    def __len__(self):
        #assert self._assert_invariants()
        return self.len

    def trim(self, bytes):
        """ Trim off some of the leading bytes. """
        #assert self._assert_invariants()
        self.ignored += bytes
        self.len -= bytes
        while self.d and self.ignored >= len(self.d[0]):
            s = self.d.popleft()
            self.ignored -= len(s)
        if self.len < 0:
            self.len = 0
        if not self.d:
            self.ignored = 0
        #assert self._assert_invariants()

    def clear(self):
        """ Empty it out. """
        #assert self._assert_invariants()
        self.d.clear()
        self.ignored = 0
        self.tailignored = 0
        self.len = 0
        #assert self._assert_invariants()

    def copy(self):
        n = self.__class__()
        n.ignored = self.ignored
        n.tailignored = self.tailignored
        n.len = self.len
        n.d = copy.copy(self.d)
        #assert n._assert_invariants()
        return n

    def _assert_invariants(self):
        assert self.ignored >= 0, self.ignored
        assert self.tailignored >= 0, self.tailignored
        assert self.len >= 0, self.len
        assert (not self.d) or (self.d[0]), \
               ("First element is required to be non-empty.", self.d and self.d[0])
        assert (not self.d) or (self.ignored < len(self.d[0])), \
               (self.ignored, self.d and len(self.d[0]))
        assert (not self.d) or (self.tailignored < len(self.d[-1])), \
               (self.tailignored, self.d and len(self.d[-1]))
        assert self.ignored+self.len+self.tailignored == sum([len(x) for x in self.d]), \
               (self.ignored, self.len, self.tailignored, sum([len(x) for x in self.d]))
        return True

    def _collapse(self):
        """ Concatenate all of the strings into one string and make that string
        be the only element of the chain. (Obviously this requires copying all
        of the bytes, so don't do this unless you need to.) """
        #assert self._assert_invariants()
        # First trim off any leading ignored bytes.
        if self.ignored:
            self.d[0] = self.d[0][self.ignored:]
            self.ignored = 0
        # Then any tail ignored bytes.
        if self.tailignored:
            self.d[-1] = self.d[-1][:-self.tailignored]
            self.tailignored = 0
        if len(self.d) > 1:
            newstr = ''.join(self.d)
            self.d.clear()
            self.d.append(newstr)
        #assert self._assert_invariants()
