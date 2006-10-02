# -*- test-case-name: foolscap.test.test_banana -*-

import sets
from foolscap.slicers.list import ListSlicer, ListUnslicer

class SetSlicer(ListSlicer):
    opentype = ("set",)
    trackReferences = True
    slices = sets.Set

    def sliceBody(self, streamable, banana):
        for i in self.obj:
            yield i

try:
    set
    # python2.4 has a builtin 'set' type, which is mutable
    class BuiltinSetSlicer(SetSlicer):
        slices = set
except NameError:
    # oh well, I guess we don't have 'set'
    pass

class SetUnslicer(ListUnslicer):
    opentype = ("set",)
    def receiveClose(self):
        return sets.Set(self.list), None

class ImmutableSetSlicer(SetSlicer):
    opentype = ("immutable-set",)
    trackReferences = False
    slices = sets.ImmutableSet

class ImmutableSetUnslicer(ListUnslicer):
    opentype = ("immutable-set",)
    def receiveClose(self):
        return sets.ImmutableSet(self.list), None
