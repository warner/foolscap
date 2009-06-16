
# this file will go away when we finally drop python2.4 support

try:
    import hashlib
    sha1_hasher = hashlib.sha1
    md5_hasher = hashlib.md5 # only used for session IDs in sslverify.py
except ImportError:
    import sha
    import md5
    sha1_hasher = sha.new
    md5_hasher = md5.new

