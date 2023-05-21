"""CMC functions"""
import datetime
import hashlib
import secrets
from typing import Dict, List, Union

from asn1crypto import algos as asn1_algos
from asn1crypto import cms as asn1_cms
from asn1crypto import core as asn1_core
from asn1crypto import csr as asn1_csr
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509
from cryptography.exceptions import InvalidSignature
from fastapi import HTTPException
from python_cmc import cmc as asn1_cmc
from python_x509_pkcs11.csr import sign_csr
from python_x509_pkcs11.lib import signed_digest_algo
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

from .asn1 import (
    aia_and_cdp_exts,
    cert_is_ca,
    cert_pem_serial_number,
    pem_cert_to_key_hash,
    pem_cert_to_name_dict,
    pem_cert_verify_signature,
    public_key_pem_from_csr,
)
from .base import db_load_data_class
from .ca import Ca, CaInput
from .certificate import Certificate, CertificateInput
from .config import (
    CMC_CERT_ISSUING_KEY_LABEL,
    CMC_CERT_ISSUING_NAME_DICT,
    CMC_KEYS_TYPE,
    CMC_REQUEST_CERTS,
    CMC_SIGNING_KEY_LABEL,
)
from .csr import Csr
from .pkcs11_key import Pkcs11KeyInput
from .public_key import PublicKey
from .route_functions import ca_request, pkcs11_key_request


async def cmc_revoke(revoke_data: bytes) -> None:
    """Revoke a certificate based on the CMC RevokeRequest"""

    set_of_revoke_request = asn1_cmc.SetOfRevokeRequest.load(revoke_data)
    revoked_certs = 0

    for _, revoke_request in enumerate(set_of_revoke_request):
        # Try certs
        db_certificate_objs = await db_load_data_class(
            Certificate, CertificateInput(serial_number=str(revoke_request["serial_number"].native))
        )
        for obj in db_certificate_objs:
            if isinstance(obj, Certificate):
                if pem_cert_to_name_dict(await obj.issuer_pem()) == revoke_request["issuerName"].native:
                    await obj.revoke(1, int(revoke_request["reason"]))  # Change to cmc request signer
                    revoked_certs += 1
                    print("Revoked cert due to CMC request")

        # Try Ca's
        db_ca_objs = await db_load_data_class(Ca, CaInput(serial_number=str(revoke_request["serial_number"].native)))
        for obj in db_ca_objs:
            if isinstance(obj, Ca):
                if pem_cert_to_name_dict(await obj.issuer_pem()) == revoke_request["issuerName"].native:
                    await obj.revoke(1, int(revoke_request["reason"]))  # Change to cmc request signer
                    revoked_certs += 1
                    print("Revoked cert due to CMC request")

    if revoked_certs == 0:
        print("Could not find the certificate to revoke from CMC RevokeRequest")
        raise ValueError


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
            "serial_number": str(cert_pem_serial_number(signed_cert)),
            "public_key": public_key_obj.serial,
            "issuer": issuer.serial,
        }
    )
    await cert_obj.save()
    if cert_is_ca(signed_cert):
        print("Warning: Treating CA as a certificate since we dont have the private key")

    return asn1_x509.Certificate.load(asn1_pem.unarmor(signed_cert.encode("utf-8"))[2])


def _create_cmc_response_status_packet(
    created_certs: Dict[int, asn1_x509.Certificate],
    failed: bool,
) -> asn1_cmc.TaggedAttribute:
    body_part_references = asn1_cmc.BodyPartReferences()

    for req_id in created_certs:
        body_part_references.append(asn1_cmc.BodyPartReference({"bodyPartID": req_id}))

    status_v2 = asn1_cmc.CMCStatusInfoV2()
    if len(body_part_references) == 0:
        status_v2["bodyList"] = asn1_cmc.BodyPartReferences([])
    else:
        status_v2["bodyList"] = body_part_references

    if failed:
        status_v2["cMCStatus"] = asn1_cmc.CMCStatus(2)
        status_v2["statusString"] = "Failed processing CMC request"
        status_v2["otherInfo"] = asn1_cmc.OtherStatusInfo({"failInfo": asn1_cmc.CMCFailInfo(11)})
    else:
        status_v2["cMCStatus"] = asn1_cmc.CMCStatus(0)
        status_v2["statusString"] = "OK"

    status_v2_attr_values = asn1_cmc.SetOfCMCStatusInfoV2()
    status_v2_attr_values.append(status_v2)
    status_v2_attr = asn1_cmc.TaggedAttribute()
    status_v2_attr["bodyPartID"] = secrets.randbelow(4294967293)
    status_v2_attr["attrType"] = asn1_cmc.TaggedAttributeType("1.3.6.1.5.5.7.7.25")
    status_v2_attr["attrValues"] = status_v2_attr_values
    return status_v2_attr


async def create_cmc_response_packet(
    controls: asn1_cmc.Controls,
    created_certs: Dict[int, asn1_x509.Certificate],
    failed: bool,
) -> asn1_cmc.PKIResponse:
    """Create a CMC response package.
    Revoke cert(s) if the request had a RevokeRequest(s).
    """

    response_controls = asn1_cmc.Controls()
    nonce: Union[bytes, None] = None
    reg_info: Union[bytes, None] = None

    for _, control_value in enumerate(controls):
        if control_value["attrType"].native == "id-cmc-senderNonce":
            nonce = control_value["attrValues"].dump()

    for _, control_value in enumerate(controls):
        if control_value["attrType"].native == "id-cmc-regInfo":
            reg_info = control_value["attrValues"].dump()

    # If a revoke request
    if not failed:
        for _, control_value in enumerate(controls):
            if control_value["attrType"].native == "id-cmc-revokeRequest":
                revoke_request = control_value["attrValues"].dump()
                await cmc_revoke(revoke_request)

    if nonce is not None:
        nonce_attr = asn1_cmc.TaggedAttribute()
        nonce_attr["bodyPartID"] = secrets.randbelow(4294967293)
        nonce_attr["attrType"] = asn1_cmc.TaggedAttributeType("1.3.6.1.5.5.7.7.7")
        nonce_attr["attrValues"] = asn1_cms.SetOfOctetString.load(nonce)
        response_controls.append(nonce_attr)

    if reg_info is not None:
        reg_info_attr = asn1_cmc.TaggedAttribute()
        reg_info_attr["bodyPartID"] = secrets.randbelow(4294967293)
        reg_info_attr["attrType"] = asn1_cmc.TaggedAttributeType("1.3.6.1.5.5.7.7.19")
        reg_info_attr["attrValues"] = asn1_cms.SetOfOctetString.load(reg_info)
        response_controls.append(reg_info_attr)

    status_v2_attr = _create_cmc_response_status_packet(created_certs, failed)
    response_controls.append(status_v2_attr)

    pki_response = asn1_cmc.PKIResponse()
    pki_response["controlSequence"] = response_controls
    pki_response["cmsSequence"] = asn1_cmc.TaggedContentInfos([])
    pki_response["otherMsgSequence"] = asn1_cmc.OtherMsgs([])
    return pki_response


async def create_cmc_response(  # pylint: disable-msg=too-many-locals
    controls: asn1_cmc.Controls,
    created_certs: Dict[int, asn1_x509.Certificate],
    failed: bool,
) -> bytes:
    """Create a CMS response containing a CMC package"""

    signer_pkcs11_key = await pkcs11_key_request(Pkcs11KeyInput(key_label=CMC_SIGNING_KEY_LABEL))
    signer = await ca_request(CaInput(pkcs11_key=signer_pkcs11_key.serial))

    # FIXME make this into a recursive chain instead of assuming next is root and
    # Dont issue all certs are issued by the same issuer
    chain: List[asn1_x509.Certificate] = [asn1_x509.Certificate.load(asn1_pem.unarmor(signer.pem.encode("utf-8"))[2])]

    for req_id in created_certs:
        chain.append(created_certs[req_id])

    packet = await create_cmc_response_packet(controls, created_certs, failed)

    eci = asn1_cms.EncapsulatedContentInfo()
    eci["content_type"] = asn1_cms.ContentType("1.3.6.1.5.5.7.12.3")
    packet_data = asn1_core.ParsableOctetString()
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
                "values": asn1_cms.SetOfTime([asn1_core.UTCTime(datetime.datetime.now(datetime.timezone.utc))]),
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
                                "signature_algorithm": signed_digest_algo(CMC_KEYS_TYPE),
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
    signer_info["signature_algorithm"] = signed_digest_algo(CMC_KEYS_TYPE)
    signer_info["signature"] = await PKCS11Session().sign(
        CMC_SIGNING_KEY_LABEL, signer_info["signed_attrs"].retag(17).dump(), key_type=CMC_KEYS_TYPE
    )

    signed_data["signer_infos"] = asn1_cms.SignerInfos({signer_info})
    signed_data["certificates"] = asn1_cms.CertificateSet(chain)

    cmc_resp = asn1_cms.ContentInfo()
    cmc_resp["content_type"] = asn1_cms.ContentType("1.2.840.113549.1.7.2")
    cmc_resp["content"] = signed_data

    ret: bytes = cmc_resp.dump()

    # print("cmc response for debugging")
    # print(ret.hex())

    return ret


# FIXME This need to be improved to fully support crmf, not just basics
def create_csr_from_crmf(cert_req: asn1_cmc.CertReqMsg) -> asn1_csr.CertificationRequest:
    """Manually handle the CRMF request into a CSR
    since we use CSR as data type in the database and currently all certs have a csr which the are created from"""
    attrs = asn1_csr.CRIAttributes()

    cert_req_info = asn1_csr.CertificationRequestInfo()
    cert_req_info["version"] = 0
    cert_req_info["subject"] = cert_req["subject"]
    cert_req_info["subject_pk_info"] = cert_req["publicKey"]

    set_of_exts = asn1_csr.SetOfExtensions()

    set_of_exts.append(cert_req["extensions"])
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


def _check_request_signature(request_signers: asn1_cms.CertificateSet, signer_infos: asn1_cms.SignerInfos) -> None:
    for _, request_signer in enumerate(request_signers):
        for valid_cert in CMC_REQUEST_CERTS:
            _, _, valid_cert_pem = asn1_pem.unarmor(valid_cert.encode("UTF-8"))
            if request_signer.chosen.native == asn1_x509.Certificate.load(valid_cert_pem).native:
                for _, signer_info in enumerate(signer_infos):
                    signer_cert: bytes = asn1_pem.armor("CERTIFICATE", request_signer.chosen.dump())
                    try:
                        pem_cert_verify_signature(
                            signer_cert.decode("utf-8"),
                            signer_info["signature"].contents,
                            signer_info["signed_attrs"].retag(17).dump(),
                        )
                        return
                    except (InvalidSignature, ValueError, TypeError):
                        pass

    raise HTTPException(status_code=401, detail="Wrong or missing CMS signer")


# FIXME handle errors and store all CMC control attributes not only reginfo and nonce
async def cmc_handle_request(data: bytes) -> bytes:
    """Handle and extract CMS CMC request"""

    created_certs: Dict[int, asn1_x509.Certificate] = {}

    content_info = asn1_cms.ContentInfo.load(data)
    _ = content_info.native  # Ensure valid data

    # Ensure valid signature for the request
    if len(content_info["content"]["signer_infos"]) == 0 or len(content_info["content"]["certificates"]) == 0:
        raise HTTPException(status_code=401, detail="Invalid signature or certificate for the signature")
    _check_request_signature(
        content_info["content"]["certificates"],
        content_info["content"]["signer_infos"],
    )

    cmc_req = asn1_cmc.PKIData.load(content_info["content"]["encap_content_info"]["content"].parsed.dump())
    _ = cmc_req.native  # Ensure valid data

    try:
        for _, value in enumerate(cmc_req["reqSequence"]):
            if isinstance(value.chosen, asn1_cmc.CertReqMsg):  # CRMF
                req_id = int(value.chosen["certReq"]["certReqId"].native)
                crmf_csr = create_csr_from_crmf(value.chosen["certReq"]["certTemplate"])
                created_certs[req_id] = await create_cert_from_csr(crmf_csr)

            elif isinstance(value.chosen, asn1_cmc.TaggedCertificationRequest):  # CSR
                req_id = int(value.chosen["bodyPartID"].native)
                created_certs[req_id] = await create_cert_from_csr(value.chosen["certificationRequest"])

            elif isinstance(value.chosen, asn1_cmc.ORM):  # ORM
                print("ERROR: CMC request type is ORM, cannot handle this")
                raise HTTPException(status_code=400, detail="Cannot process CMC type ORM")

        ret = await create_cmc_response(cmc_req["controlSequence"], created_certs, failed=False)
    except (ValueError, TypeError):
        ret = await create_cmc_response(cmc_req["controlSequence"], created_certs, failed=True)

    return ret
