
# copied from the waterken.org Web-Calculus python implementation

def encode(bytes):
    chars = ""
    buffer = 0;
    n = 0;
    for b in bytes:
        buffer = buffer << 8
        buffer = buffer | ord(b)
        n = n + 8
        while n >= 5:
            chars = chars + _encode((buffer >> (n - 5)) & 0x1F)
            n = n - 5;
        buffer = buffer & 0x1F  # To quiet any warning from << operator
    if n > 0:
        buffer = buffer << (5 - n)
        chars = chars + _encode(buffer & 0x1F)
    return chars

def _encode(v):
    if v < 26:
        return chr(ord('a') + v)
    else:
        return chr(ord('2') + (v - 26))

# we use the rfc4648 base32 alphabet, in lowercase
BASE32_ALPHABET = "".join([_encode(i) for i in range(0x20)])
# 'abcdefghijklmnopqrstuvwxyz234567'

def is_base32(s):
    for c in s.lower():
        if c not in BASE32_ALPHABET:
            return False
    return True
