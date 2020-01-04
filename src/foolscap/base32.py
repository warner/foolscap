import six, base64

def encode(b): # takes bytes, returns native string
    assert isinstance(b, bytes), (type(b), b)
    out = base64.b32encode(b).lower().rstrip(b"=")
    return six.ensure_str(out)

# we use the rfc4648 base32 alphabet, in lowercase
BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

def is_base32(s):
    assert isinstance(s, str), (type(s), s)
    for c in s.lower():
        if c not in BASE32_ALPHABET:
            return False
    return True
