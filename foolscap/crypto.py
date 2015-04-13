# -*- test-case-name: foolscap.test.test_crypto -*-

from OpenSSL import SSL
from twisted.internet.ssl import CertificateOptions, DistinguishedName, \
     KeyPair, Certificate, PrivateCertificate
from foolscap import base32

peerFromTransport = Certificate.peerFromTransport

def alwaysValidate(conn, cert, errno, depth, preverify_ok):
    # This function is called to validate the certificate received by
    # the other end. OpenSSL calls it multiple times, each time it
    # see something funny, to ask if it should proceed.

    # We do not care about certificate authorities or revocation
    # lists, we just want to know that the certificate has a valid
    # signature and follow the chain back to one which is
    # self-signed. The TubID will be the digest of one of these
    # certificates. We need to protect against forged signatures, but
    # not the usual SSL concerns about invalid CAs or revoked
    # certificates.

    # these constants are from openssl-0.9.7g/crypto/x509/x509_vfy.h
    # and do not appear to be exposed by pyopenssl. Ick. TODO. We
    # could just always return '1' here (ignoring all errors), but I
    # think that would ignore forged signatures too, which would
    # obviously be a security hole.
    things_are_ok = (0,  # X509_V_OK
                     9, # X509_V_ERR_CERT_NOT_YET_VALID
                     10, # X509_V_ERR_CERT_HAS_EXPIRED
                     18, # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
                     19, # X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
                     )
    if errno in things_are_ok:
        return 1
    # TODO: log the details of the error, because otherwise they get
    # lost in the PyOpenSSL exception that will eventually be raised
    # (possibly OpenSSL.SSL.Error: certificate verify failed)

    # I think that X509_V_ERR_CERT_SIGNATURE_FAILURE is the most
    # obvious sign of hostile attack.
    return 0

class FoolscapContextFactory(CertificateOptions):
    def getContext(self):
        ctx = CertificateOptions.getContext(self)

        # VERIFY_PEER means we ask the the other end for their certificate.
        # not adding VERIFY_FAIL_IF_NO_PEER_CERT means it's ok if they don't
        # give us one (i.e. if an anonymous client connects to an
        # authenticated server). I don't know what VERIFY_CLIENT_ONCE does.
        ctx.set_verify(SSL.VERIFY_PEER |
                       #SSL.VERIFY_FAIL_IF_NO_PEER_CERT |
                       SSL.VERIFY_CLIENT_ONCE,
                       alwaysValidate)
        return ctx

def digest32(colondigest):
    digest = "".join([chr(int(c,16)) for c in colondigest.split(":")])
    digest = base32.encode(digest)
    return digest

def createCertificate():
    # this is copied from test_sslverify.py
    dn = DistinguishedName(commonName="newpb_thingy")
    keypair = KeyPair.generate(size=2048)
    req = keypair.certificateRequest(dn, digestAlgorithm="sha256")
    certData = keypair.signCertificateRequest(dn, req,
                                              lambda dn: True,
                                              1, # serial number
                                              digestAlgorithm="sha256",
                                              )
    cert = keypair.newCertificate(certData)
    #opts = cert.options()
    # 'opts' can be given to reactor.listenSSL, or to transport.startTLS
    return cert

def loadCertificate(certData):
    cert = PrivateCertificate.loadPEM(certData)
    return cert
