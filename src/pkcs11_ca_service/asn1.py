"""ASN1 module, mstly using asn1crypto"""

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
    """Encode to base64url.

    Parameters:
    data (bytes): input data

    Returns:
    str
    """

    enc = urlsafe_b64encode(data).strip(b"=")
    return enc.decode("utf-8")


def from_base64url(b64url: str) -> bytes:
    """Decode base64url.

    Parameters:
    b64url (str): input data

    Returns:
    bytes
    """

    data = b64url.encode("utf-8")
    padding = b"=" * (4 - (len(data) % 4))
    dec = urlsafe_b64decode(data + padding)
    return dec


def pem_to_sha256_fingerprint(pem: str) -> str:
    """Get the sha256 hash from pem data.

    Parameters:
    pem (str): input data

    Returns:
    str
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    return hashlib.sha256(data).hexdigest()


def pem_cert_to_name_dict(pem: str) -> Dict[str, str]:
    """Get the subject name dict from pem data as a dict.

    Parameters:
    pem (bytes): input data

    Returns:
    Dict[str, str]
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    cert = asn1_x509.Certificate().load(data)
    ret: Dict[str, str] = cert["tbs_certificate"]["subject"].native
    return ret


def public_key_pem_to_sha1_fingerprint(pem: str) -> str:
    """Get the sha1 fingerprint for the public key in pem data.

    See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2

    Parameters:
    pem (str): input data

    Returns:
    str
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    key = PublicKeyInfo().load(data)
    fingerprint: str = key.sha1.hex()
    return fingerprint


def public_key_info_to_pem(public_key_info: PublicKeyInfo) -> str:
    """Get pem from public key info data

    Parameters:
    public_key_info (asn1crypto.keys.PublicKeyInfo): input data

    Returns:
    str
    """

    pem: bytes = asn1_pem.armor("PUBLIC KEY", public_key_info.dump())
    return pem.decode("utf-8")


def jwk_key_to_pem(data: Dict[str, str]) -> str:
    """Get pem for public key from jwk key

    Parameters:
    data (Dict[str, str]): input data

    Returns:
    str
    """

    rsa = RSAPublicKey()
    rsa["modulus"] = int(from_base64url(data["modulus"]).decode("utf-8"))
    rsa["public_exponent"] = int(from_base64url(data["public_exponent"]).decode("utf-8"))

    pki = PublicKeyInfo()
    pka = PublicKeyAlgorithm()
    pka["algorithm"] = PublicKeyAlgorithmId("rsa")
    pki["algorithm"] = pka
    pki["public_key"] = rsa

    return public_key_info_to_pem(pki)


def pem_key_to_jwk(pem: str) -> Dict[str, str]:
    """Get jwk key from pem

    Parameters:
    pem (str): input data

    Returns:
    Dict[str, str]
    """

    ret: Dict[str, str] = {}

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    key = PublicKeyInfo().load(data)

    if "rsa" == key["algorithm"].native["algorithm"]:
        # print("rsa detected")

        ret["kty"] = "rsa"
        ret["modulus"] = to_base64url(str(key["public_key"].native["modulus"]).encode("utf-8"))
        ret["public_exponent"] = to_base64url(str(key["public_key"].native["public_exponent"]).encode("utf-8"))
        ret["kid"] = to_base64url(key.sha1.hex().encode("utf-8"))
        return ret

    if "eliptic curve" == key["algorithm"].native["algorithm"]:
        raise NotImplementedError
    raise UnsupportedJWTAlgorithm


def public_key_pem_from_csr(pem: str) -> str:
    """Get public key in pem from csr

    Parameters:
    pem (str): csr input data

    Returns:
    str
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    csr = asn1_csr.CertificationRequest().load(data)
    return public_key_info_to_pem(csr["certification_request_info"]["subject_pk_info"])


def public_key_pem_from_cert(pem: str) -> str:
    """Get public key in pem from cert

    Parameters:
    pem (str): cert input data

    Returns:
    str
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)
    return public_key_info_to_pem(cert["tbs_certificate"]["subject_public_key_info"])


def not_before_not_after_from_cert(pem: str) -> Tuple[str, str]:
    """Get not_before and not_after from cert

    Parameters:
    pem (str): cert input data

    Returns:
    Tuple[str, str]
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)
    not_before = cert["tbs_certificate"]["validity"]["not_before"].native
    not_after = cert["tbs_certificate"]["validity"]["not_after"].native
    return str(not_before), str(not_after)


def this_update_next_update_from_crl(pem: str) -> Tuple[str, str]:
    """Get this_update and next_update from crl

    Parameters:
    pem (str): crl input data

    Returns:
    Tuple[str, str]
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    crl = asn1_crl.CertificateList().load(data)
    this_update = crl["tbs_cert_list"]["this_update"].native
    next_update = crl["tbs_cert_list"]["next_update"].native
    return str(this_update), str(next_update)
