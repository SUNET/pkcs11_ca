"""OCSP functions"""
from typing import Dict, Tuple, Union, List
import datetime
from binascii import Error as binasciiError

from fastapi import HTTPException
from python_x509_pkcs11.ocsp import request_nonce, response
from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import core as asn1_core

# from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
# from .public_key import PublicKey, PublicKeyInput
# from .ca import CaInput, Ca
from .pkcs11_key import Pkcs11KeyInput
from .public_key import PublicKeyInput
from .ca import CaInput

from .route_functions import public_key_request, pkcs11_key_request, ca_request, crl_request
from .asn1 import cert_revoked, ocsp_decode, pem_cert_to_key_hash, cert_revoked_time, cert_is_self_signed

# Sign the request with the key for the first single request
# single requests for certificates by another CA will get unknown status
# PERHAPS redo this in the future


async def _ocsp_check_valid_cert(
    req: asn1_ocsp.Request,
) -> Tuple[str, str, List[str], Union[Dict[str, str], bytes], asn1_ocsp.CertStatus]:
    public_key_obj = await public_key_request(
        PublicKeyInput(fingerprint=req["req_cert"]["issuer_key_hash"].native.hex())
    )
    pkcs11_key_obj = await pkcs11_key_request(Pkcs11KeyInput(public_key=public_key_obj.serial))
    issuer_obj = await ca_request(CaInput(pkcs11_key=pkcs11_key_obj.serial))

    chain: List[str] = [issuer_obj.pem]

    # Add issuer to chain if this is not a self-signed cert
    if not cert_is_self_signed(issuer_obj.pem):
        chain.append(await issuer_obj.issuer_pem())

    # If cert is revoked
    crl = await crl_request(1, issuer_obj)
    if cert_revoked(req["req_cert"]["serial_number"].native, crl):
        revoked_info = asn1_ocsp.RevokedInfo()
        revoked_info["revocation_time"], revoked_info["revocation_reason"] = cert_revoked_time(
            req["req_cert"]["serial_number"].native, crl
        )
        return (
            pkcs11_key_obj.key_label,
            pkcs11_key_obj.key_type,
            chain,
            pem_cert_to_key_hash(issuer_obj.pem),
            asn1_ocsp.CertStatus({"revoked": revoked_info}),
        )
    return (
        pkcs11_key_obj.key_label,
        pkcs11_key_obj.key_type,
        chain,
        pem_cert_to_key_hash(issuer_obj.pem),
        asn1_ocsp.CertStatus("good"),
    )


async def _ocsp_response_data(
    ocsp_request: asn1_ocsp.OCSPRequest, nonce: Union[bytes, None]
) -> Tuple[
    str,
    Union[Dict[str, str], bytes],
    asn1_ocsp.Responses,
    int,
    Union[asn1_ocsp.ResponseDataExtensions, None],
    Union[datetime.datetime, None],
    Union[List[str], None],
    str,
]:
    responses = asn1_ocsp.Responses()
    status_code: int = 6
    key_label: str = ""
    key_type: str = ""
    name_dict: Union[Dict[str, str], bytes] = {}
    chain: Union[List[str], None] = None

    for _, req in enumerate(ocsp_request["tbs_request"]["request_list"]):
        curr_response = asn1_ocsp.SingleResponse()
        curr_response["cert_id"] = req["req_cert"]

        try:
            key_label, key_type, chain, name_dict, cert_status = await _ocsp_check_valid_cert(req)
            status_code = 0
            curr_response["cert_status"] = cert_status
        except HTTPException:
            curr_response["cert_status"] = asn1_ocsp.CertStatus("unknown")

        curr_response["this_update"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
        # WORK ON THIS
        curr_response["next_update"] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        # curr_response["single_extensions"] = NOT NEEDED NOW
        responses.append(curr_response)

    extra_extensions = asn1_ocsp.ResponseDataExtensions()

    if nonce:
        nonce_ext = asn1_ocsp.ResponseDataExtension()
        nonce_ext["extn_id"] = asn1_ocsp.ResponseDataExtensionId("1.3.6.1.5.5.7.48.1.2")
        nonce_ext["extn_value"] = nonce
        extra_extensions.append(nonce_ext)

    extended_revoke_ext = asn1_ocsp.ResponseDataExtension()
    extended_revoke_ext["extn_id"] = asn1_ocsp.ResponseDataExtensionId("1.3.6.1.5.5.7.48.1.9")
    extended_revoke_ext["extn_value"] = None
    extra_extensions.append(extended_revoke_ext)

    return key_label, name_dict, responses, status_code, extra_extensions, None, chain, key_type


async def _fix_broken_ocsp_request(request: asn1_ocsp.OCSPRequest) -> asn1_ocsp.OCSPRequest:
    parsable = asn1_core.ParsableOctetString()
    parsable.set(asn1_core.Asn1Value.load(request["tbs_request"]["request_extensions"][0].dump()).dump()[13:])
    request["tbs_request"]["request_extensions"][0]["extn_value"] = parsable
    return request


async def _fix_broken_ocsp_response(ok_response_data: bytes, nonce: bytes) -> bytes:
    ok_response = asn1_ocsp.OCSPResponse.load(ok_response_data)

    # Change the library class from ParsableOctetString to OctetString
    asn1_ocsp.ResponseDataExtension._fields = [
        ("extn_id", asn1_ocsp.ResponseDataExtensionId, {}),
        ("critical", asn1_core.Boolean, {"default": False}),
        ("extn_value", asn1_core.OctetString, {}),
    ]

    ext = asn1_ocsp.ResponseDataExtension()
    ext["extn_id"] = ok_response["response_bytes"]["response"].parsed["tbs_response_data"]["response_extensions"][0][
        "extn_id"
    ]
    ext["extn_value"] = ok_response["response_bytes"]["response"].parsed["tbs_response_data"]["response_extensions"][0][
        "extn_value"
    ] = nonce

    parsed = asn1_ocsp.BasicOCSPResponse.load(ok_response["response_bytes"]["response"].parsed.dump())
    parsed["tbs_response_data"]["response_extensions"][0]["extn_value"] = ext["extn_value"]

    parsed["signature"] = await PKCS11Session().sign(
        "cmc_issuer_test3", parsed["tbs_response_data"].dump(), key_type="secp256r1"
    )

    ok_response["response_bytes"]["response"] = parsed

    ret: bytes = ok_response.dump()

    # Restore the library class
    asn1_ocsp.ResponseDataExtension._fields = [
        ("extn_id", asn1_ocsp.ResponseDataExtensionId, {}),
        ("critical", asn1_core.Boolean, {"default": False}),
        ("extn_value", asn1_core.ParsableOctetString, {}),
    ]

    return ret


async def ocsp_response(request: bytes, encoded: bool = False) -> bytes:
    """Create an OCSP response

    Parameters:
    request (bytes): OCSP request in bytes.
    encoded (str): If the request is base64 + url encoded

    Returns:
    bytes
    """

    request_was_broken = False

    if encoded:
        try:
            request = ocsp_decode(request.decode("utf-8"))
        except binasciiError:
            return b"0"

    # Ensure valid ocsp request
    try:
        ocsp_request = asn1_ocsp.OCSPRequest.load(request)

        if not isinstance(ocsp_request, asn1_ocsp.OCSPRequest):
            raise ValueError

        try:
            _ = ocsp_request.native
        except ValueError:
            ocsp_request = await _fix_broken_ocsp_request(ocsp_request)
            request_was_broken = True

        if len(ocsp_request["tbs_request"]["request_list"]) == 0:
            raise ValueError

        # Get nonce if exists
        nonce = request_nonce(ocsp_request.dump())

        resp_data = await response(*await _ocsp_response_data(ocsp_request, nonce))

        if request_was_broken and nonce is not None:
            resp_data = await _fix_broken_ocsp_response(resp_data, nonce)

        return resp_data
    except ValueError:
        return b"0"
    except TypeError:
        return await response("", {}, asn1_ocsp.Responses(), 1)
