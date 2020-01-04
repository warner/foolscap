from hashlib import sha1
import six

# here is the list of initial vocab tables. If the two ends negotiate to use
# initial-vocab-table-index N, then both sides will start with the words from
# INITIAL_VOCAB_TABLES[n] for their VOCABized tokens.

vocab_v0 = []
vocab_v1 = [ # all opentypes used in 0.0.6
    b"none", b"boolean", b"reference",
    b"dict", b"list", b"tuple", b"set", b"immutable-set",
    b"unicode", b"set-vocab", b"add-vocab",
    b"call", b"arguments", b"answer", b"error",
    b"my-reference", b"your-reference", b"their-reference", b"copyable",
    # these are only used by storage.py
    b"instance", b"module", b"class", b"method", b"function",
    # I'm not sure this one is actually used anywhere, but the first 127 of
    # these are basically free.
    b"attrdict",
    ]
INITIAL_VOCAB_TABLES = { 0: vocab_v0, 1: vocab_v1 }

# to insure both sides agree on the actual words, we can hash the vocab table
# into a short string. This is included in the negotiation decision and
# compared by the receiving side.

def hashVocabTable(table_index):
    data = b"\x00".join([six.ensure_binary(v) for v in INITIAL_VOCAB_TABLES[table_index]])
    digest = sha1(data).hexdigest()
    return digest[:4]

def getVocabRange():
    keys = list(INITIAL_VOCAB_TABLES.keys())
    return min(keys), max(keys)
