import base64

def encode(b):
    assert isinstance(b, bytes), (type(b), b)
    return base64.b32encode(b).lower().rstrip(b"=")

# we use the rfc4648 base32 alphabet, in lowercase
BASE32_ALPHABET = b'abcdefghijklmnopqrstuvwxyz234567'

def is_base32(s):
    assert isinstance(s, bytes), (type(s), s)
    for c in s.lower():
        if c not in BASE32_ALPHABET:
            return False
    return True
