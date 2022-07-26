from typing import Tuple, Dict
from base64 import urlsafe_b64encode, urlsafe_b64decode
import hashlib
from asn1crypto import pem as asn1_pem
from asn1crypto import csr as asn1_csr
from asn1crypto import crl as asn1_crl
from asn1crypto import x509 as asn1_x509
from asn1crypto.keys import (
    PublicKeyInfo,
    RSAPublicKey,
    PublicKeyAlgorithm,
    PublicKeyAlgorithmId,
)

from .error import UnsupportedJWTAlgorithm


def to_base64url(data: bytes) -> str:
    enc = urlsafe_b64encode(data).strip(b"=")
    return enc.decode("utf-8")


def from_base64url(b64url: str) -> bytes:
    data = b64url.encode("utf-8")
    padding = b"=" * (4 - (len(data) % 4))
    dec = urlsafe_b64decode(data + padding)
    return dec


def pem_to_sha256_fingerprint(pem: str) -> str:
    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    return hashlib.sha256(data).hexdigest()


# https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
def pem_to_sha1_fingerprint(pem: str) -> str:
    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    return hashlib.sha1(data).hexdigest()


def public_key_info_to_pem(public_key_info: PublicKeyInfo) -> str:
    pem: bytes = asn1_pem.armor("PUBLIC KEY", public_key_info.dump())
    return pem.decode("utf-8")


def jwk_key_to_pem(data: Dict[str, str]) -> str:
    rsa = RSAPublicKey()
    rsa["modulus"] = int(from_base64url(data["modulus"]).decode("utf-8"))
    rsa["public_exponent"] = int(
        from_base64url(data["public_exponent"]).decode("utf-8")
    )

    pki = PublicKeyInfo()
    pka = PublicKeyAlgorithm()
    pka["algorithm"] = PublicKeyAlgorithmId("rsa")
    pki["algorithm"] = pka
    pki["public_key"] = rsa

    return public_key_info_to_pem(pki)


def pem_key_to_jwk(pem: str) -> Dict[str, str]:
    ret: Dict[str, str] = {}

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    key = PublicKeyInfo().load(data)

    if "rsa" == key["algorithm"].native["algorithm"]:
        print("rsa detected")

        ret["kty"] = "rsa"
        ret["modulus"] = to_base64url(
            str(key["public_key"].native["modulus"]).encode("utf-8")
        )
        ret["public_exponent"] = to_base64url(
            str(key["public_key"].native["public_exponent"]).encode("utf-8")
        )
        ret["kid"] = to_base64url(hashlib.sha1(key.dump()).hexdigest().encode("utf-8"))
        return ret

    if "eliptic curve" == key["algorithm"].native["algorithm"]:
        raise NotImplementedError
    raise UnsupportedJWTAlgorithm


def public_key_pem_from_csr(pem: str) -> str:
    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    csr = asn1_csr.CertificationRequest().load(data)
    return public_key_info_to_pem(csr["certification_request_info"]["subject_pk_info"])


def public_key_pem_from_cert(pem: str) -> str:
    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)
    return public_key_info_to_pem(cert["tbs_certificate"]["subject_public_key_info"])


def not_before_not_after_from_cert(pem: str) -> Tuple[str, str]:
    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)
    not_before = cert["tbs_certificate"]["validity"]["not_before"].native
    not_after = cert["tbs_certificate"]["validity"]["not_after"].native
    return str(not_before), str(not_after)


def this_update_next_update_from_crl(pem: str) -> Tuple[str, str]:
    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    crl = asn1_crl.CertificateList().load(data)
    this_update = crl["tbs_cert_list"]["this_update"].native
    next_update = crl["tbs_cert_list"]["next_update"].native
    return str(this_update), str(next_update)
