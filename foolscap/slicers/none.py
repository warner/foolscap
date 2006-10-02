# -*- test-case-name: foolscap.test.test_banana -*-

from foolscap.tokens import BananaError
from foolscap.slicer import BaseSlicer, LeafUnslicer

class NoneSlicer(BaseSlicer):
    opentype = ('none',)
    trackReferences = False
    slices = type(None)
    def sliceBody(self, streamable, banana):
        # hmm, we need an empty generator. I think a sequence is the only way
        # to accomplish this, other than 'if 0: yield' or something silly
        return []

class NoneUnslicer(LeafUnslicer):
    opentype = ('none',)

    def checkToken(self, typebyte, size):
        raise BananaError("NoneUnslicer does not accept any tokens")
    def receiveClose(self):
        return None, None

