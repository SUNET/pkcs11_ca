"""ASN1 module, mostly using asn1crypto"""

from typing import Tuple, Dict, Union
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64decode, b64encode
import hashlib
import datetime
import urllib.parse

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey as cryptoRSAPublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512

from python_x509_pkcs11.crypto import convert_rs_ec_signature

import jwt
import requests
from asn1crypto import pem as asn1_pem
from asn1crypto import csr as asn1_csr
from asn1crypto import crl as asn1_crl
from asn1crypto import x509 as asn1_x509
from asn1crypto.keys import (
    PublicKeyInfo,
    RSAPublicKey,
    PublicKeyAlgorithm,
    PublicKeyAlgorithmId,
    NamedCurve,
    ECDomainParameters,
    ECPointBitString,
)

from .config import ROOT_URL
from .error import UnsupportedJWTAlgorithm


def ocsp_decode(data: str) -> bytes:
    """Decode OCSP data.

    Parameters:
    data (str): Input data.

    Returns:
    bytes
    """

    b64_request = urllib.parse.unquote(data).encode("utf-8")
    return b64decode(b64_request)


def ocsp_encode(data: bytes) -> str:
    """Encode OCSP data.

    Parameters:
    data (bytes): Input data.

    Returns:
    str
    """

    b64_encoded = b64encode(data)
    return urllib.parse.quote(b64_encoded.decode("utf-8"), safe="")


def to_base64url(data: bytes) -> str:
    """Encode to base64url.

    Parameters:
    data (bytes): Input data.

    Returns:
    str
    """

    enc = urlsafe_b64encode(data).strip(b"=")
    return enc.decode("utf-8")


def from_base64url(b64url: str) -> bytes:
    """Decode base64url.

    Parameters:
    b64url (str): Input data.

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
    pem (str): PEM input data.

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
    pem (str): PEM input data.

    Returns:
    Dict[str, str]
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    cert = asn1_x509.Certificate().load(data)
    ret: Dict[str, str] = cert["tbs_certificate"]["subject"].native
    return ret


def pem_cert_verify_signature(pem: str, signature: bytes, signed_data: bytes) -> None:
    """Verify signature dome by the certificates private key
    raises cryptography.exceptions.InvalidSignature if invalid signature or ValueError if the public key is not supported.

    Potentially fails if the signature is made using nonstandard hasing of the data.

    Parameters:
    pem (str): PEM input data.

    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    cert = asn1_x509.Certificate().load(data)

    pub_key = load_der_public_key(cert["tbs_certificate"]["subject_public_key_info"].dump())

    if isinstance(pub_key, cryptoRSAPublicKey):
        try:
            pub_key.verify(signature, signed_data, PKCS1v15(), SHA256())
        except InvalidSignature:
            try:
                pub_key.verify(signature, signed_data, PKCS1v15(), SHA384())
            except InvalidSignature:
                pub_key.verify(signature, signed_data, PKCS1v15(), SHA512())

    elif isinstance(pub_key, EllipticCurvePublicKey):
        if pub_key.curve.name == "secp256r1":
            try:
                pub_key.verify(signature, signed_data, ECDSA(SHA256()))
            except InvalidSignature:
                converted_signature = convert_rs_ec_signature(signature, "secp256r1")
                pub_key.verify(converted_signature, signed_data, ECDSA(SHA256()))
        elif pub_key.curve.name == "secp384r1":
            try:
                pub_key.verify(signature, signed_data, ECDSA(SHA384()))
            except InvalidSignature:
                converted_signature = convert_rs_ec_signature(signature, "secp384r1")
                pub_key.verify(converted_signature, signed_data, ECDSA(SHA384()))
        elif pub_key.curve.name == "secp521r1":
            try:
                pub_key.verify(signature, signed_data, ECDSA(SHA512()))
            except InvalidSignature:
                converted_signature = convert_rs_ec_signature(signature, "secp521r1")
                pub_key.verify(converted_signature, signed_data, ECDSA(SHA512()))
        else:
            raise ValueError("Unsupported EC curve")

    elif isinstance(pub_key, (Ed25519PublicKey, Ed448PublicKey)):
        pub_key.verify(signature, signed_data)

    else:
        raise ValueError("Non supported public key in certificate")


def pem_cert_to_key_hash(pem: str) -> bytes:
    """Get the key hash from pem data as a dict.

    Parameters:
    pem (str): PEM input data.

    Returns:
    bytes
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    cert = asn1_x509.Certificate().load(data)

    for _, extension in enumerate(cert["tbs_certificate"]["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.14":
            ret: bytes = extension["extn_value"].native
            return ret
    raise ValueError("No SKI extension in cert")


def public_key_pem_to_sha1_fingerprint(pem: str) -> str:
    """Get the sha1 fingerprint for the public key in pem data.

    See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2

    Parameters:
    pem (str): PEM input data.

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
    """Get pem from public key info data.

    Parameters:
    public_key_info (asn1crypto.keys.PublicKeyInfo): Input data.

    Returns:
    str
    """

    pem: bytes = asn1_pem.armor("PUBLIC KEY", public_key_info.dump())
    return pem.decode("utf-8")


def jwk_key_to_pem(data: Dict[str, str]) -> str:
    """Get pem for public key from jwk key.

    Parameters:
    data (Dict[str, str]): Input data.

    Returns:
    str
    """

    pki = PublicKeyInfo()
    pka = PublicKeyAlgorithm()

    if data["kty"] == "RSA":
        rsa = RSAPublicKey()
        rsa["modulus"] = int.from_bytes(from_base64url(data["n"]), "big")
        rsa["public_exponent"] = int.from_bytes(from_base64url(data["e"]), "big")

        pka["algorithm"] = PublicKeyAlgorithmId("rsa")
        pki["algorithm"] = pka
        pki["public_key"] = rsa

    elif data["kty"] == "EC":
        pka["algorithm"] = PublicKeyAlgorithmId("ec")
        pki["algorithm"] = pka
        if data["crv"] == "P-256":
            pka["parameters"] = ECDomainParameters({"named": NamedCurve("secp256r1")})
        elif data["crv"] == "P-384":
            pka["parameters"] = ECDomainParameters({"named": NamedCurve("secp384r1")})
        elif data["crv"] == "P-521":
            pka["parameters"] = ECDomainParameters({"named": NamedCurve("secp521r1")})
        else:
            raise UnsupportedJWTAlgorithm

        if data["crv"] == "p-521":
            key_string = b"\x04" + from_base64url(data["x"]) + from_base64url(data["y"])
        else:
            key_string = ECPointBitString.from_coords(
                int.from_bytes(from_base64url(data["x"]), "big"), int.from_bytes(from_base64url(data["y"]), "big")
            )

        pki["public_key"] = key_string

    elif data["kty"] == "OKP":
        if data["crv"] == "Ed25519":
            pka["algorithm"] = PublicKeyAlgorithmId("ed25519")
        elif data["crv"] == "Ed448":
            pka["algorithm"] = PublicKeyAlgorithmId("ed448")
        else:
            raise UnsupportedJWTAlgorithm

        pki["algorithm"] = pka
        pki["public_key"] = from_base64url(data["x"])

    _ = pki.native  # Ensure valid data
    return public_key_info_to_pem(pki)


def pem_key_to_jwk(pem: str) -> Dict[str, str]:
    """Get jwk key from pem.

    Parameters:
    pem (str): Input data.

    Returns:
    Dict[str, str]
    """

    ret: Dict[str, str] = {}

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    key = PublicKeyInfo().load(data)
    _ = key.native  # Ensure valid data

    # Work on https://www.rfc-editor.org/rfc/rfc7517#section-4
    if key["algorithm"].native["algorithm"] == "rsa":
        ret["kty"] = "RSA"
        ret["use"] = "sig"
        ret["alg"] = "RS256"
        ret["n"] = to_base64url(key["public_key"].native["modulus"].to_bytes(key.byte_size, "big"))
        ret["e"] = to_base64url(key["public_key"].native["public_exponent"].to_bytes(3, "big"))
        ret["kid"] = to_base64url(key.sha1.hex().encode("utf-8"))

    elif key["algorithm"].native["algorithm"] == "ec":
        ret["kty"] = "EC"
        ret["use"] = "sig"

        if key["algorithm"].native["parameters"] == "secp256r1":
            ret["crv"] = "P-256"
            ret["alg"] = "ES256"
            ret["x"] = to_base64url(key["public_key"].to_coords()[0].to_bytes(32, "big"))
            ret["y"] = to_base64url(key["public_key"].to_coords()[1].to_bytes(32, "big"))
        elif key["algorithm"].native["parameters"] == "secp384r1":
            ret["crv"] = "P-384"
            ret["alg"] = "ES384"
            ret["x"] = to_base64url(key["public_key"].to_coords()[0].to_bytes(48, "big"))
            ret["y"] = to_base64url(key["public_key"].to_coords()[1].to_bytes(48, "big"))
        elif key["algorithm"].native["parameters"] == "secp521r1":
            ret["crv"] = "P-521"
            ret["alg"] = "ES512"
            ret["x"] = to_base64url(key["public_key"].to_coords()[0].to_bytes(66, "big"))
            ret["y"] = to_base64url(key["public_key"].to_coords()[1].to_bytes(66, "big"))
        else:
            raise UnsupportedJWTAlgorithm

        ret["kid"] = to_base64url(key.sha1.hex().encode("utf-8"))

    elif key["algorithm"].native["algorithm"] in ["ed25519", "ed448"]:
        ret["kty"] = "OKP"
        ret["use"] = "sig"
        ret["alg"] = "EdDSA"

        if key["algorithm"].native["algorithm"] == "ed25519":
            ret["crv"] = "Ed25519"
            ret["x"] = to_base64url(key["public_key"].contents[-32:])  # The last bytes are the key

        elif key["algorithm"].native["algorithm"] == "ed448":
            ret["crv"] = "Ed448"
            ret["x"] = to_base64url(key["public_key"].contents[-57:])  # The last bytes are the key
        else:
            raise UnsupportedJWTAlgorithm

        ret["kid"] = to_base64url(key.sha1.hex().encode("utf-8"))
    return ret


def public_key_pem_from_csr(pem: str) -> str:
    """Get public key in pem from csr.

    Parameters:
    pem (str): csr input data.

    Returns:
    str
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    csr = asn1_csr.CertificationRequest().load(data)
    return public_key_info_to_pem(csr["certification_request_info"]["subject_pk_info"])


def public_key_pem_from_cert(pem: str) -> str:
    """Get public key in pem from cert.

    Parameters:
    pem (str): PEM certificate input data.

    Returns:
    str
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)
    return public_key_info_to_pem(cert["tbs_certificate"]["subject_public_key_info"])


def not_before_not_after_from_cert(pem: str) -> Tuple[str, str]:
    """Get not_before and not_after from cert.

    Parameters:
    pem (str): PEM certificate input data.

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
    """Get this_update and next_update from crl.

    Parameters:
    pem (str): PEM CRL input data.

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


def cert_pem_serial_number(pem: str) -> int:
    """Get serial number from cert in pem form.

    Parameters:
    pem (str): PEM certificate input data.

    Returns:
    str
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)

    ret: int = cert["tbs_certificate"]["serial_number"].native
    return ret


def cert_is_ca(pem: str) -> bool:
    """If certificate is a CA.

    Parameters:
    pem (str): PEM certificate input data.

    Returns:
    bool
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)

    for _, ext in enumerate(cert["tbs_certificate"]["extensions"]):
        if ext[0].dotted == "2.5.29.19":
            ret: bool = ext[1].native
            return ret
    return False


def crl_expired(pem: str) -> bool:
    """Check if CRL has expired from its next_update field compared to current time.

    Parameters:
    pem (str): PEM CRL input data.

    Returns:
    bool
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    crl = asn1_crl.CertificateList().load(data)

    next_update: datetime.datetime = crl["tbs_cert_list"]["next_update"].native
    utc_time = datetime.datetime.now(datetime.timezone.utc)
    return next_update < utc_time


def cert_revoked_time(serial_number: int, pem: str) -> Tuple[datetime.datetime, Union[asn1_crl.CRLReason, None]]:
    """Check if CRL has expired from its next_update field compared to current time.

    Parameters:
    serial_number (int): Serial number for the revoked ceritficate.
    pem (str): PEM CRL input data.

    Returns:
    Tuple[datetime.datetime, Union[asn1_crl.CRLReason, None]]
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    crl = asn1_crl.CertificateList().load(data)

    if len(crl["tbs_cert_list"]["revoked_certificates"]) != 0:
        for _, revoked in enumerate(crl["tbs_cert_list"]["revoked_certificates"]):
            if serial_number == revoked["user_certificate"].native:
                for _, ext in enumerate(revoked["crl_entry_extensions"]):
                    if ext["extn_id"].dotted == "2.5.29.21":
                        return revoked["revocation_date"].native, asn1_crl.CRLReason(ext["extn_value"].native)
    raise ValueError


def cert_revoked(serial_number: int, crl_pem: str) -> bool:
    """Check if certs serial number is revoked in the CRL.

    Parameters:
    serial_number (int): Serial number to check
    crl_pem (str): PEN CRL input data.

    Returns:
    bool
    """

    data = crl_pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    crl = asn1_crl.CertificateList().load(data)

    if len(crl["tbs_cert_list"]["revoked_certificates"]) != 0:
        for _, revoked in enumerate(crl["tbs_cert_list"]["revoked_certificates"]):
            if serial_number == revoked["user_certificate"].native:
                return True

    return False


def aia_and_cdp_exts(issuer_path: str) -> asn1_x509.Extensions:
    """Create AIA and CDP extensions.

    Parameters:
    issuer_path (str): Path to issuer CA.

    Returns:
    bool
    """

    # AIA
    access_description_ca = asn1_x509.AccessDescription(
        {
            "access_method": "ca_issuers",
            "access_location": asn1_x509.GeneralName(
                name="uniform_resource_identifier", value=(ROOT_URL + "/ca/" + issuer_path)
            ),
        }
    )
    # ocsp
    access_description_ocsp = asn1_x509.AccessDescription(
        {
            "access_method": "ocsp",
            "access_location": asn1_x509.GeneralName(name="uniform_resource_identifier", value=ROOT_URL + "/ocsp/"),
        }
    )
    aia = asn1_x509.AuthorityInfoAccessSyntax([access_description_ca, access_description_ocsp])
    aia_ext = asn1_x509.Extension()
    aia_ext["extn_id"] = asn1_x509.ExtensionId("1.3.6.1.5.5.7.1.1")
    aia_ext["extn_value"] = aia

    # CDP
    g_n = asn1_x509.GeneralName(name="uniform_resource_identifier", value=ROOT_URL + "/crl/" + issuer_path)
    g_ns = asn1_x509.GeneralNames()
    g_ns.append(g_n)
    dist_point = asn1_x509.DistributionPoint()
    dist_point["distribution_point"] = asn1_x509.DistributionPointName(name="full_name", value=g_ns)
    crl_dist_points = asn1_x509.CRLDistributionPoints()
    crl_dist_points.append(dist_point)
    cdp_ext = asn1_x509.Extension()
    cdp_ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.31")
    cdp_ext["extn_value"] = crl_dist_points

    exts = asn1_x509.Extensions()
    exts.append(aia_ext)
    exts.append(cdp_ext)
    return exts


def create_jwt_header_str(pub_key: bytes, priv_key: bytes, url: str) -> str:
    """Create jwt header string.

    Parameters:
    pub_key (bytes): Public key bytes.
    priv_key (bytes): Private key bytes.
    url (str): URL to request.

    Returns:
    str
    """

    req = requests.head(
        url.split("/")[0] + "//" + url.split("/")[2] + "/new-nonce", timeout=5, verify="./tls_certificate.pem"
    )
    nonce = req.headers["Replay-Nonce"]
    jwt_headers = {"nonce": nonce, "url": url}
    jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
    encoded = jwt.encode(jwk_key_data, priv_key.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
    ret: str = "Bearer " + encoded
    return ret


def cert_as_der(pem: str) -> bytes:
    """Certificate in DER form.

    Parameters:
    pem (str): PEM certificate input data.

    Returns:
    bytes
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)
    ret: bytes = cert.dump()
    return ret


def crl_as_der(pem: str) -> bytes:
    """CRL in DER form.

    Parameters:
    pem (str): PEM CRL input data.

    Returns:
    bytes
    """

    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    crl = asn1_crl.CertificateList().load(data)
    ret: bytes = crl.dump()
    return ret


def csr_from_der(der: bytes) -> str:
    """Get CSR from DER form.

    Parameters:
    der (bytes): DER encoded csr.

    Returns:
    bytes
    """

    data = der
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    csr = asn1_csr.CertificationRequest().load(data)
    pem: bytes = asn1_pem.armor("CERTIFICATE REQUEST", csr.dump())
    return pem.decode("utf-8")
