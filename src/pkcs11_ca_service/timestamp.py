"""Timestamp functions"""
import datetime
import hashlib
import secrets
from typing import Dict, List, Union

from asn1crypto import algos as asn1_algos
from asn1crypto import cms as asn1_cms
from asn1crypto import core as asn1_core
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto import tsp as asn1_tsp
from asn1crypto import x509 as asn1_x509
from python_x509_pkcs11.csr import sign_csr
from python_x509_pkcs11.lib import signed_digest_algo
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

from .asn1 import aia_and_cdp_exts, cert_pem_serial_number
from .base import DataBaseObject, DataClassObject, InputObject
from .ca import CaInput
from .config import (
    TIMESTAMP_CERT_KEY_LABEL,
    TIMESTAMP_KEYS_TYPE,
    TIMESTAMP_ROOT_KEY_LABEL,
    TIMESTAMP_SIGNING_KEY_LABEL,
    TIMESTAMP_SIGNING_NAME_DICT,
)
from .pkcs11_key import Pkcs11KeyInput
from .route_functions import ca_request, pkcs11_key_request


class TimestampInput(InputObject):
    """Class to represent a timestamp matching from HTTP post data"""

    serial_number: Union[str, None] = None


class Timestamp(DataClassObject):
    """Class to represent a timestamp"""

    db: DataBaseObject
    serial_number: str
    cert_key_label: str
    gen_time: str
    created: str

    db_table_name = "timestamp"
    db_fields = {
        "serial_number": str,
        "cert_key_label": str,
        "gen_time": str,
        "created": str,
    }
    db_reference_fields: Dict[str, str] = {}
    db_unique_fields = ["serial_number"]


def _set_tbs_version(
    tbs: asn1_csr.CertificationRequestInfo,
) -> asn1_csr.CertificationRequestInfo:
    tbs["version"] = 0
    return tbs


def _set_tbs_subject(
    tbs: asn1_csr.CertificationRequestInfo, subject_name: Dict[str, str]
) -> asn1_csr.CertificationRequestInfo:
    tbs["subject"] = asn1_csr.Name().build(subject_name)
    return tbs


def _set_tbs_subject_pk_info(
    tbs: asn1_csr.CertificationRequestInfo,
    pk_info: asn1_x509.PublicKeyInfo,
) -> asn1_csr.CertificationRequestInfo:
    tbs["subject_pk_info"] = pk_info
    return tbs


async def _set_csr_signature(
    key_label: str, key_type: str, signed_csr: asn1_csr.CertificationRequest
) -> asn1_csr.CertificationRequest:
    signed_csr["signature_algorithm"] = signed_digest_algo(key_type)
    signed_csr["signature"] = await PKCS11Session().sign(
        key_label, signed_csr["certification_request_info"].dump(), key_type=key_type
    )
    return signed_csr


def _set_tbs_key_usage(
    tbs: asn1_csr.CertificationRequestInfo,
) -> asn1_csr.CertificationRequestInfo:
    # https://github.com/wbond/asn1crypto/blob/master/asn1crypto/x509.py#L438
    # Bit 0, 5 ,6, from left to right
    k_u = asn1_x509.KeyUsage(("110000000",))
    ext = asn1_x509.Extension()
    ext["extn_id"] = asn1_x509.ExtensionId("2.5.29.15")
    ext["critical"] = True
    ext["extn_value"] = k_u

    exts = asn1_x509.Extensions()
    exts.append(ext)

    ses = asn1_csr.SetOfExtensions()
    ses.append(exts)

    cria = asn1_csr.CRIAttribute()
    cria["type"] = asn1_csr.CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = asn1_csr.CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)

    return tbs


def _set_tbs_extensions(issuer_path: str, tbs: asn1_csr.CertificationRequestInfo) -> asn1_csr.CertificationRequestInfo:
    """Set all x509 extensions"""

    tbs = _set_tbs_key_usage(tbs)
    exts = aia_and_cdp_exts(issuer_path, True)

    ses = asn1_csr.SetOfExtensions()
    ses.append(exts)

    cria = asn1_csr.CRIAttribute()
    cria["type"] = asn1_csr.CSRAttributeType("1.2.840.113549.1.9.14")
    cria["values"] = ses

    if len(tbs["attributes"]) == 0:
        crias = asn1_csr.CRIAttributes()
        crias.append(cria)
        tbs["attributes"] = crias
    else:
        tbs["attributes"].append(cria)

    return tbs


def _create_tbs(
    issuer_path: str,
    subject_name: Dict[str, str],
    pk_info: asn1_x509.PublicKeyInfo,
) -> asn1_csr.CertificationRequestInfo:
    tbs = asn1_csr.CertificationRequestInfo()

    # Set all extensions
    tbs = _set_tbs_extensions(issuer_path, tbs)

    # Set non extensions
    tbs = _set_tbs_version(tbs)
    tbs = _set_tbs_subject(tbs, subject_name)
    tbs = _set_tbs_subject_pk_info(tbs, pk_info)
    return tbs


async def create_timestamp_certificate(
    issuer_path: str,
    key_label: str,
    subject_name: Dict[str, str],
    key_type: str,
    signer_key_label: str,
    signer_subject_name: Dict[str, str],
    signer_key_type: str,
) -> str:
    """Create a timestamp certificate signed by a PKCS11 key.
    Returns the PEM encoded certificate

    Parameters:
    issuer_path (str): The path for CRL and AIA extension to write into the cert
    key_label (str): The pkcs11 key label to create the certificate's key.
    subject_name (Dict[str, str]): The certificate's subject name dict.
    key_type (str): The certificate's key type.
    signer_key_label (str): The pkcs11 key label to sign the certificate.
    signer_subject_name (Dict[str, str]): The certificate's issuers subject name dict.
    signer_key_type (str): The certificate's signers key type.

    Returns:
    str
    """

    # pk_info, _ = await PKCS11Session().create_keypair(key_label, key_type=key_type)

    # TS test block uncomment above line
    priv = b"0w\x02\x01\x01\x04 \xc1\x96a \xd3M\xe2\x04\xaaY\xe8{%F\x0eTt?\xa7\x0c\x85\xf3Hh\xbd,&\xe5\x8c\xb5\xa3[\xa0\n\x06\x08*\x86H\xce=\x03\x01\x07\xa1D\x03B\x00\x04\xae-\x90\t\xee-\x8d\xe4\x1b\xcfC\xb4TJ\x89[\x89\x82\x85+9\xb7\x96\xef\x12\xae\xfeG\x1f\xf7aX\x88\xca\xcf\xab9\x0b\xcd>\xb8\xfc\x95g\xa4\xca \r\x9d_\xa2\x1b1*\x17\x11\xc2\x8b\xd0\x98\x94Za\x82"  # pylint: disable=C0301
    pub = b"0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04\xae-\x90\t\xee-\x8d\xe4\x1b\xcfC\xb4TJ\x89[\x89\x82\x85+9\xb7\x96\xef\x12\xae\xfeG\x1f\xf7aX\x88\xca\xcf\xab9\x0b\xcd>\xb8\xfc\x95g\xa4\xca \r\x9d_\xa2\x1b1*\x17\x11\xc2\x8b\xd0\x98\x94Za\x82"  # pylint: disable=C0301
    await PKCS11Session.import_keypair(pub, priv, key_label, key_type="secp256r1")
    pk_info, _ = await PKCS11Session.public_key_data(key_label, key_type="secp256r1")

    data = pk_info.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)

    tbs = _create_tbs(issuer_path, subject_name, asn1_x509.PublicKeyInfo.load(data))
    signed_csr = asn1_csr.CertificationRequest()
    signed_csr["certification_request_info"] = tbs
    signed_csr = await _set_csr_signature(key_label, key_type, signed_csr)
    pem_enc: bytes = asn1_pem.armor("CERTIFICATE REQUEST", signed_csr.dump())

    return await sign_csr(
        signer_key_label,
        signer_subject_name,
        pem_enc.decode("utf-8"),
        not_before=None,
        not_after=datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc),
        keep_csr_extensions=True,
        key_type=signer_key_type,
    )


async def create_timestamp_response_packet(hashed_message: bytes, nonce: Union[int, None]) -> asn1_tsp.TSTInfo:
    """Create a timestamp response asn1 package

    Parameters:
    hashed_message (bytes): The timestamp request.
    nonce (Union[int, None]): The nonce

    Returns:
    asn1crypto.tsp.TSTInfo
    """

    tst_info = asn1_tsp.TSTInfo()
    tst_info["version"] = 1
    # FIXME Apple has 1.2.3 as policy so I guess we also have it?
    tst_info["policy"] = "1.2.3"
    tst_info["message_imprint"] = asn1_tsp.MessageImprint(
        {
            "hash_algorithm": asn1_algos.DigestAlgorithm(
                {"algorithm": asn1_algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")}
            ),
            "hashed_message": hashed_message,
        }
    )
    serial_number: int = secrets.randbits(158)
    gen_time = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    tst_info["serial_number"] = serial_number

    # Store the serial number
    timestamp_obj = Timestamp(
        {"serial_number": str(serial_number), "cert_key_label": TIMESTAMP_CERT_KEY_LABEL, "gen_time": str(gen_time)}
    )
    await timestamp_obj.save()

    tst_info["gen_time"] = gen_time

    if nonce is not None:
        tst_info["nonce"] = nonce

    return tst_info


async def create_timestamp_signed_data(hashed_message: bytes, nonce: Union[int, None]) -> asn1_cms.ContentInfo:
    """Create a timestamp signed data asn1 structure

    Parameters:
    hashed_message (bytes): The timestamp request.
    nonce (Union[int, None]): The nonce

    Returns:
    asn1crypto.cms.ContentInfo
    """

    signer_pkcs11_key = await pkcs11_key_request(Pkcs11KeyInput(key_label=TIMESTAMP_SIGNING_KEY_LABEL))
    signer = await ca_request(CaInput(pkcs11_key=signer_pkcs11_key.serial))

    root_pkcs11_key = await pkcs11_key_request(Pkcs11KeyInput(key_label=TIMESTAMP_ROOT_KEY_LABEL))
    root_signer = await ca_request(CaInput(pkcs11_key=root_pkcs11_key.serial))

    timestamp_cert = await PKCS11Session.export_certificate(TIMESTAMP_CERT_KEY_LABEL)

    chain: List[asn1_x509.Certificate] = [
        asn1_x509.Certificate.load(asn1_pem.unarmor(root_signer.pem.encode("utf-8"))[2]),
        asn1_x509.Certificate.load(asn1_pem.unarmor(signer.pem.encode("utf-8"))[2]),
        asn1_x509.Certificate.load(asn1_pem.unarmor(timestamp_cert.encode("utf-8"))[2]),
    ]

    packet = await create_timestamp_response_packet(hashed_message, nonce)

    eci = asn1_cms.EncapsulatedContentInfo()
    eci["content_type"] = asn1_cms.ContentType("1.2.840.113549.1.9.16.1.4")
    packet_data = asn1_core.ParsableOctetString()
    packet_data.set(packet.dump())
    eci["content"] = packet_data

    signed_data = asn1_cms.SignedData()
    signed_data["version"] = 3
    signed_data["digest_algorithms"] = asn1_cms.DigestAlgorithms(
        {asn1_algos.DigestAlgorithm({"algorithm": asn1_algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")})}
    )
    signed_data["encap_content_info"] = eci

    signer_info = asn1_cms.SignerInfo()
    signer_info["version"] = 1
    signer_info["sid"] = asn1_cms.SignerIdentifier(
        {
            "issuer_and_serial_number": asn1_cms.IssuerAndSerialNumber(
                {
                    "issuer": asn1_cms.Name().build(TIMESTAMP_SIGNING_NAME_DICT),
                    "serial_number": cert_pem_serial_number(timestamp_cert),
                }
            )
        }
    )

    cms_attributes = asn1_cms.CMSAttributes()
    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {
                "type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.3"),
                "values": asn1_cms.SetOfContentType([asn1_cms.ContentType("1.2.840.113549.1.9.16.1.4")]),
            }
        )
    )

    # The message digest
    hash_module = hashlib.sha256()
    hash_module.update(signed_data["encap_content_info"]["content"].contents)
    digest = hash_module.digest()

    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {
                "type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.5"),
                "values": asn1_cms.SetOfTime([asn1_core.UTCTime(datetime.datetime.now(datetime.timezone.utc))]),
            }
        )
    )

    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {"type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.4"), "values": asn1_cms.SetOfOctetString([digest])}
        )
    )

    ess_cert_idv2s = asn1_tsp.ESSCertIDv2s()
    ess_cert_idv2s.append(
        asn1_tsp.ESSCertIDv2(
            {"cert_hash": asn1_x509.Certificate.load(asn1_pem.unarmor(timestamp_cert.encode("utf-8"))[2]).sha256}
        )
    )

    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {
                "type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.16.2.47"),
                "values": asn1_tsp.SetOfSigningCertificatesV2(
                    [asn1_tsp.SigningCertificateV2({"certs": ess_cert_idv2s})]
                ),
            }
        )
    )

    signer_info["signed_attrs"] = cms_attributes

    signer_info["digest_algorithm"] = asn1_algos.DigestAlgorithm(
        {"algorithm": asn1_algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")}
    )
    signer_info["signature_algorithm"] = signed_digest_algo(TIMESTAMP_KEYS_TYPE)
    signer_info["signature"] = await PKCS11Session().sign(
        TIMESTAMP_CERT_KEY_LABEL, signer_info["signed_attrs"].retag(17).dump(), key_type=TIMESTAMP_KEYS_TYPE
    )

    signed_data["signer_infos"] = asn1_cms.SignerInfos({signer_info})
    signed_data["certificates"] = asn1_cms.CertificateSet(chain)

    cmc_resp = asn1_cms.ContentInfo()
    cmc_resp["content_type"] = asn1_cms.ContentType("1.2.840.113549.1.7.2")
    cmc_resp["content"] = signed_data

    return cmc_resp


async def create_timestamp_response(hashed_message: bytes, nonce: Union[int, None] = None) -> bytes:
    """Create a timestamp certificate.

    Parameters:
    hashed_message (bytes): The hashed message.
    nonce (Union[int, None]): The request nonce.

    Returns:
    bytes
    """

    # FIXME handle errors
    pki_status_info = asn1_tsp.PKIStatusInfo()
    pki_status_info["status"] = 0

    timestamp_resp = asn1_tsp.TimeStampResp()
    timestamp_resp["status"] = pki_status_info
    timestamp_resp["time_stamp_token"] = await create_timestamp_signed_data(hashed_message, nonce)
    ret: bytes = timestamp_resp.dump()

    # print("timestamp response for debugging")
    # print(ret.hex())

    return ret


async def timestamp_handle_request(data: bytes) -> bytes:
    """Handle and respond to a timestamp request.

    Parameters:
    data (bytes): The timestamp request.

    Returns:
    bytes
    """

    ts_req = asn1_tsp.TimeStampReq.load(data)
    _ = ts_req.native  # Ensure valid data

    # Dont assume hash is sha256
    hashed_message = ts_req["message_imprint"]["hashed_message"].native
    nonce: Union[int, None] = ts_req["nonce"].native

    # FIXME - Fetch policy in request if exists and enure the response have the same policy

    if not isinstance(hashed_message, bytes) or len(hashed_message) < 3:
        raise ValueError("Problem with hashed message in timestamp request")

    if nonce is None or not isinstance(nonce, int):
        raise ValueError("Problem with nonce in timestamp request")

    return await create_timestamp_response(hashed_message, nonce)
