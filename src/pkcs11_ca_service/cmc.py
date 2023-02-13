"""CMC functions, lazy implementation"""
from typing import Dict, Any
import datetime
import hashlib
from random import randint

# from fastapi import HTTPException
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto.core import (
    Asn1Value,
    Sequence,
    Set,
    ObjectIdentifier,
    Integer,
    OctetString,
    ParsableOctetString,
    UTCTime,
    UTF8String,
)
import asn1crypto.x509 as asn1_x509
import asn1crypto.cms as asn1_cms
import asn1crypto.algos as asn1_algos

from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from python_x509_pkcs11.csr import sign_csr

from .route_functions import ca_request, pkcs11_key_request
from .ca import CaInput
from .pkcs11_key import Pkcs11KeyInput
from .public_key import PublicKey
from .certificate import Certificate
from .csr import Csr
from .asn1 import aia_and_cdp_exts, public_key_pem_from_csr, cert_is_ca, pem_cert_to_key_hash
from .config import (
    CMC_CERT_ISSUING_KEY_LABEL,
    CMC_CERT_ISSUING_NAME_DICT,
    CMC_SIGNING_KEY_LABEL,
)

# fixme
# https://www.rfc-editor.org/rfc/rfc4211#page-16
class CertificationRequestInfo2(Sequence):  # type: ignore
    """Ugly hack to create CSR from a CMC CRMF request"""

    _fields = [
        ("version", asn1_csr.Version, {"implicit": 0, "default": "v1"}),
        ("subject", asn1_x509.Name, {"explicit": 5}),
        ("subject_pk_info", asn1_x509.PublicKeyInfo, {"implicit": 6}),
        ("attributes", asn1_csr.CRIAttributes, {"implicit": 9, "optional": True}),
    ]


class Set30(Set):  # type: ignore
    """Subclass to PKI response"""

    _fields = [
        ("0", OctetString),
    ]


class Packet310(Sequence):  # type: ignore
    """Subclass to PKI response"""

    _fields = [
        ("0", Integer),
    ]


class Packet31(Sequence):  # type: ignore
    """Subclass to PKI response"""

    _fields = [
        ("0", Integer),
        ("1", Packet310),
        ("2", UTF8String, {"optional": True}),
        ("3", Integer, {"optional": True}),
    ]


class Set31(Set):  # type: ignore
    """Subclass to PKI response"""

    _fields = [
        ("0", Packet31),
    ]


class Packet20(Sequence):  # type: ignore
    """Subclass to PKI response"""

    _fields = [
        ("0", Integer),
        ("1", ObjectIdentifier),
        ("2", Set30),
    ]


class Packet21(Sequence):  # type: ignore
    """Subclass to PKI response"""

    _fields = [
        ("0", Integer),
        ("1", ObjectIdentifier),
        ("2", Set31),
    ]


class Packet0(Sequence):  # type: ignore
    """Subclass to PKI response"""

    _fields = [
        ("0", Packet20),
        ("1", Packet21),
        ("2", Packet20, {"optional": True}),
    ]


class Packet(Sequence):  # type: ignore
    """PKI response"""

    _fields = [
        ("0", Packet0),
        ("1", Sequence),
        ("2", Sequence),
    ]


def _fix_constructed_classes_into_seqs(data: bytes) -> bytes:
    if len(data) == 0:
        return b""

    # if data[0] < 128:
    # return data[2:2+data[1]]
    #    return data[2:2+data[1]] + _fix_constructed_classes_into_seqs(data[2:])

    # if data[1] < 128:
    #     length = data[1]
    #     start = 2
    # else:
    #     if data[1] == 129:
    #         length = data[2]
    #         start = 3
    #     elif data[1] == 130:
    #         length = data[2] * 256 + data[3]
    #         start = 4
    #     else:
    #         # print(data)
    #         raise ValueError("FIXME, finish this")

    if data[0] > 128:
        return b"0" + data[1:]

    return data


def _fix_set_data(data: bytes) -> bytes:
    if data[0] != 49:  # Code for ASN1 SET
        raise ValueError("Failed")

    length = 0
    start = 2

    if data[1] < 128:
        length = data[1]
    else:
        if data[1] == 129:
            length = data[2]
            start = 3
        elif data[1] == 130:
            length = data[2] * 256 + data[3]
            start = 4
        else:
            raise ValueError("FIXME, finish this")

    return data[start : length + start]


def _create_cmc_failed_response_packet(request_data: Dict[str, Any]) -> Packet:
    packet_20 = Packet20(
        {
            "0": randint(10000000, 99999999),
            "1": ObjectIdentifier("1.3.6.1.5.5.7.7.7"),
            "2": Set30({"0": request_data["id-cmc-senderNonce"]}),
        }
    )
    packet_21 = Packet21(
        {
            "0": randint(10000000, 99999999),
            "1": ObjectIdentifier("1.3.6.1.5.5.7.7.25"),
            "2": Set31(
                {
                    "0": Packet31(
                        {
                            "0": 2,  # error code
                            "1": Packet310({"0": request_data["req_integer"]}),
                            "2": UTF8String("Error, fixme"),
                            "3": Integer(11),  # internal CA error, fixme here
                        }
                    )
                }
            ),
        }
    )

    packet_0 = Packet0({"0": packet_20, "1": packet_21})
    packet = Packet({"0": packet_0, "1": Sequence.load(b"0\x00"), "2": Sequence.load(b"0\x00")})
    return packet


def _create_cmc_response_packet(request_data: Dict[str, Any]) -> Packet:
    packet_20 = Packet20(
        {
            "0": randint(10000000, 99999999),
            "1": ObjectIdentifier("1.3.6.1.5.5.7.7.7"),
            "2": Set30({"0": request_data["id-cmc-senderNonce"]}),
        }
    )
    packet_21 = Packet21(
        {
            "0": randint(10000000, 99999999),
            "1": ObjectIdentifier("1.3.6.1.5.5.7.7.25"),
            "2": Set31({"0": Packet31({"0": 0, "1": Packet310({"0": request_data["req_integer"]})})}),
        }
    )
    packet_22 = Packet20(
        {
            "0": randint(10000000, 99999999),
            "1": ObjectIdentifier("1.3.6.1.5.5.7.7.19"),
            "2": Set30({"0": request_data["id-cmc-regInfo"]}),
        }
    )

    packet_0 = Packet0({"0": packet_20, "1": packet_21, "2": packet_22})
    packet = Packet({"0": packet_0, "1": Sequence.load(b"0\x00"), "2": Sequence.load(b"0\x00")})
    return packet


async def create_cmc_response(request_data: Dict[str, Any], created_cert: bytes, failed: bool) -> bytes:
    """Create a CMS responce containing a CMC package"""

    # issuer_pkcs11_key = await pkcs11_key_request(Pkcs11KeyInput(key_label="cmc_issuer_test3"))
    # issuer = await ca_request(CaInput(pkcs11_key=issuer_pkcs11_key.serial))
    signer_pkcs11_key = await pkcs11_key_request(Pkcs11KeyInput(key_label=CMC_SIGNING_KEY_LABEL))
    signer = await ca_request(CaInput(pkcs11_key=signer_pkcs11_key.serial))

    # fixme make this into a recursive chain instead of assuming next is root

    # root_pem = await issuer.issuer_pem()
    # root = asn1_x509.Certificate.load(asn1_pem.unarmor(root_pem.encode("utf-8"))[2])
    # chain = [root, asn1_x509.Certificate.load(asn1_pem.unarmor(issuer.pem.encode("utf-8"))[2]), created_cert]
    if not failed:
        chain = [created_cert, asn1_x509.Certificate.load(asn1_pem.unarmor(signer.pem.encode("utf-8"))[2])]
        packet = _create_cmc_response_packet(request_data)
    else:
        chain = [asn1_x509.Certificate.load(asn1_pem.unarmor(signer.pem.encode("utf-8"))[2])]
        packet = _create_cmc_failed_response_packet(request_data)

    eci = asn1_cms.EncapsulatedContentInfo()
    eci["content_type"] = asn1_cms.ContentType("1.3.6.1.5.5.7.12.3")
    packet_data = ParsableOctetString()
    packet_data.set(packet.dump())
    eci["content"] = packet_data

    signed_data = asn1_cms.SignedData()
    signed_data["version"] = 2
    signed_data["digest_algorithms"] = asn1_cms.DigestAlgorithms(
        {asn1_algos.DigestAlgorithm({"algorithm": asn1_algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")})}
    )
    signed_data["encap_content_info"] = eci

    signer_info = asn1_cms.SignerInfo()
    signer_info["version"] = 1
    signer_info["sid"] = asn1_cms.SignerIdentifier({"subject_key_identifier": pem_cert_to_key_hash(signer.pem)})

    cms_attributes = asn1_cms.CMSAttributes()
    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {
                "type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.3"),
                "values": asn1_cms.SetOfContentType([asn1_cms.ContentType("1.3.6.1.5.5.7.12.3")]),
            }
        )
    )

    # The message digest
    hash_module = hashlib.sha256()
    hash_module.update(signed_data["encap_content_info"]["content"].contents)
    digest = hash_module.digest()

    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {"type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.4"), "values": asn1_cms.SetOfOctetString([digest])}
        )
    )

    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {
                "type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.5"),
                "values": asn1_cms.SetOfTime([UTCTime(datetime.datetime.now(datetime.timezone.utc))]),
            }
        )
    )

    cms_attributes.append(
        asn1_cms.CMSAttribute(
            {
                "type": asn1_cms.CMSAttributeType("1.2.840.113549.1.9.52"),
                "values": asn1_cms.SetOfCMSAlgorithmProtection(
                    [
                        asn1_cms.CMSAlgorithmProtection(
                            {
                                "digest_algorithm": asn1_algos.DigestAlgorithm(
                                    {"algorithm": asn1_algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")}
                                ),
                                "signature_algorithm": asn1_algos.SignedDigestAlgorithm(
                                    {"algorithm": asn1_algos.SignedDigestAlgorithmId("1.2.840.10045.4.3.2")}
                                ),
                            }
                        )
                    ]
                ),
            }
        )
    )

    signer_info["signed_attrs"] = cms_attributes

    signer_info["digest_algorithm"] = asn1_algos.DigestAlgorithm(
        {"algorithm": asn1_algos.DigestAlgorithmId("2.16.840.1.101.3.4.2.1")}
    )
    signer_info["signature_algorithm"] = asn1_algos.SignedDigestAlgorithm(
        {"algorithm": asn1_algos.SignedDigestAlgorithmId("1.2.840.10045.4.3.2")}
    )
    signer_info["signature"] = await PKCS11Session().sign(
        "cmc_signer_test3", signer_info["signed_attrs"].retag(17).dump(), key_type="secp256r1"
    )

    signed_data["signer_infos"] = asn1_cms.SignerInfos({signer_info})
    signed_data["certificates"] = asn1_cms.CertificateSet(chain)

    cmc_resp = asn1_cms.ContentInfo()
    cmc_resp["content_type"] = asn1_cms.ContentType("1.2.840.113549.1.7.2")
    cmc_resp["content"] = signed_data

    ret: bytes = cmc_resp.dump()
    # print("cmc response")
    # print(ret.hex())
    return ret


async def create_cert_from_csr(csr_data: asn1_csr.CertificationRequest) -> asn1_x509.Certificate:
    """Create cert from a csr"""
    issuer_pkcs11_key = await pkcs11_key_request(Pkcs11KeyInput(key_label=CMC_CERT_ISSUING_KEY_LABEL))
    issuer = await ca_request(CaInput(pkcs11_key=issuer_pkcs11_key.serial))

    csr_pem: bytes = asn1_pem.armor("CERTIFICATE REQUEST", csr_data.dump())

    extra_extensions = aia_and_cdp_exts(issuer.path)

    signed_cert = await sign_csr(
        CMC_CERT_ISSUING_KEY_LABEL,
        CMC_CERT_ISSUING_NAME_DICT,
        csr_pem.decode("utf-8"),
        extra_extensions=extra_extensions,
        ignore_auth_exts=True,
        key_type="secp256r1",
    )
    # print("signed_cert_in_cmc_response")
    # print(signed_cert)

    # Get public key from csr
    public_key_obj = PublicKey({"pem": public_key_pem_from_csr(csr_pem.decode("utf-8")), "authorized_by": 1})  # FIXME
    await public_key_obj.save()

    # Save csr
    csr_internal_obj = Csr(
        {"pem": csr_pem.decode("utf-8"), "authorized_by": 1, "public_key": public_key_obj.serial}
    )  # FIXME
    await csr_internal_obj.save()

    # Save cert
    cert_obj = Certificate(
        {
            "pem": signed_cert,
            "authorized_by": 1,  # FIXME
            "csr": csr_internal_obj.serial,
            "public_key": public_key_obj.serial,
            "issuer": issuer.serial,
        }
    )
    await cert_obj.save()
    if cert_is_ca(signed_cert):
        print("Warning: Treating CA as a certificate since we dont have the private key")

    return asn1_x509.Certificate.load(asn1_pem.unarmor(signed_cert.encode("utf-8"))[2])


async def cmc_handle_crmf_request(dummy_cert_req: CertificationRequestInfo2) -> asn1_csr.CertificationRequest:
    """Manually handle the CRMF request into a CSR
    since we use CSR as data type in the database and currently all certs have a csr which the are created from"""
    attrs = asn1_csr.CRIAttributes()

    cert_req_info = asn1_csr.CertificationRequestInfo()
    cert_req_info["version"] = dummy_cert_req["version"]
    cert_req_info["subject"] = dummy_cert_req["subject"]
    cert_req_info["subject_pk_info"] = dummy_cert_req["subject_pk_info"]

    set_of_exts = asn1_csr.SetOfExtensions()
    exts = asn1_x509.Extensions()

    for attr in range(len(dummy_cert_req["attributes"])):
        ext = dummy_cert_req["attributes"][attr]
        if isinstance(dummy_cert_req["attributes"][attr], asn1_csr.CRIAttribute):
            ext_id = asn1_x509.ExtensionId(dummy_cert_req["attributes"][attr]["type"].native)
            critical = False
            if (
                isinstance(dummy_cert_req["attributes"][attr]["values"].native, bool)
                and dummy_cert_req["attributes"][attr]["values"].native is True
            ):
                critical = True

            ext = asn1_x509.Extension()
            ext["extn_id"] = ext_id
            ext["critical"] = critical
            # ext["extn_value": extn_value,

            if critical:
                extn_value = ext.spec("extn_value").load(dummy_cert_req["attributes"][attr].native["2"])
            else:
                try:
                    extn_value = ext.spec("extn_value").load(dummy_cert_req["attributes"][attr]["values"].dump())
                except ValueError:
                    extn_value = ext.spec("extn_value").load(dummy_cert_req["attributes"][attr].native["values"])
            ext["extn_value"] = extn_value
            exts.append(ext)

    if len(exts) > 0:
        set_of_exts.append(exts)
        cri_attr = asn1_csr.CRIAttribute(
            {"type": asn1_csr.CSRAttributeType("1.2.840.113549.1.9.14"), "values": set_of_exts}
        )
        attrs.append(cri_attr)

    cert_req_info["attributes"] = attrs

    cert_req = asn1_csr.CertificationRequest()
    cert_req["certification_request_info"] = cert_req_info
    cert_req["signature_algorithm"] = asn1_algos.SignedDigestAlgorithm(
        {"algorithm": asn1_algos.SignedDigestAlgorithmId("1.2.840.10045.4.3.2")}
    )
    cert_req["signature"] = b"dummy_sig"
    return cert_req


async def cmc_handle_request(data: bytes) -> bytes:
    """Handle and extract CMS CMC request"""

    values: Dict[str, Any] = {}
    values["subject_name_info"] = {}

    content_info = asn1_cms.ContentInfo.load(data)
    content_data = content_info["content"]["encap_content_info"]["content"].parsed

    # for id_cmc_nonce
    for attr in range(len(content_data[0])):
        if content_data[0][attr][1].native == "1.3.6.1.5.5.7.7.6":
            values["id-cmc-senderNonce"] = Asn1Value.load(_fix_set_data(content_data[0][attr][2].dump())).native
            break
    # for id-cmc-regInfo
    for attr in range(len(content_data[0])):
        if content_data[0][attr][1].native == "1.3.6.1.5.5.7.7.18":
            values["id-cmc-regInfo"] = Asn1Value.load(_fix_set_data(content_data[0][attr][2].dump())).native
            break

    for attr in range(len(content_data[0])):
        if content_data[0][attr][1].native == "1.3.6.1.5.5.7.7.11":
            values["id-cmc-lraPOPWitness"] = Asn1Value.load(_fix_set_data(content_data[0][attr][2].dump())).native
            break

    try:  # CRMF
        req_data0 = Asn1Value.load(_fix_constructed_classes_into_seqs(content_data[1][0].dump()))

        req_data2 = Asn1Value.load(Asn1Value.load(_fix_constructed_classes_into_seqs(req_data0[0].dump()))[1].dump())

        dummy_cert_req = CertificationRequestInfo2.load(req_data2.dump())
        _ = dummy_cert_req.native
        values["CRMF"] = True
        content_data10_data = Asn1Value.load(_fix_constructed_classes_into_seqs(content_data[1][0].dump()))
        values["req_integer"] = content_data10_data[0][0].native
        cert_req = await cmc_handle_crmf_request(dummy_cert_req)
    except ValueError:  # CSR
        next_seq = content_data[1].dump()
        if next_seq[1] == 130:
            req_integer_data0 = Asn1Value.load(_fix_constructed_classes_into_seqs(next_seq[0:4] + b"0" + next_seq[5:]))
        elif next_seq[1] == 129:
            req_integer_data0 = Asn1Value.load(_fix_constructed_classes_into_seqs(next_seq[0:3] + b"0" + next_seq[4:]))
        else:
            req_integer_data0 = Asn1Value.load(_fix_constructed_classes_into_seqs(next_seq[0:2] + b"0" + next_seq[3:]))

        req_integer_data1 = Asn1Value.load(_fix_constructed_classes_into_seqs(req_integer_data0[0].dump()))

        values["req_integer"] = req_integer_data1[0].native
        cert_req = asn1_csr.CertificationRequest.load(req_integer_data1[1].dump())

    try:
        created_cert = await create_cert_from_csr(cert_req)
        ret = await create_cmc_response(values, created_cert, failed=False)
    except:  # fixme
        ret = await create_cmc_response(values, b"0", failed=True)

    return ret
