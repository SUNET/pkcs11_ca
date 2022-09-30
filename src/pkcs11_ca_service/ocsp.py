"""OCSP functions"""
from typing import Dict, Tuple, Union
import datetime
from binascii import Error as binasciiError

from fastapi import HTTPException
from python_x509_pkcs11.ocsp import request_nonce, response
from asn1crypto import ocsp as asn1_ocsp

# from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
# from .public_key import PublicKey, PublicKeyInput
# from .ca import CaInput, Ca
from .pkcs11_key import Pkcs11KeyInput
from .public_key import PublicKeyInput
from .ca import CaInput

from .route_functions import public_key_request, pkcs11_key_request, ca_request, crl_request
from .asn1 import cert_revoked, ocsp_decode, pem_cert_to_name_dict, cert_revoked_time

# Sign the request with the key for the first single request
# single requests for certificates by another CA will get unknown status
# PERHAPS redo this in the future


async def _ocsp_check_valid_cert(req: asn1_ocsp.Request) -> Tuple[str, Dict[str, str], asn1_ocsp.CertStatus]:
    public_key_obj = await public_key_request(
        PublicKeyInput(fingerprint=req["req_cert"]["issuer_key_hash"].native.hex())
    )
    pkcs11_key_obj = await pkcs11_key_request(Pkcs11KeyInput(public_key=public_key_obj.serial))
    issuer_obj = await ca_request(CaInput(pkcs11_key=pkcs11_key_obj.serial))

    # If cert is revoked
    crl = await crl_request(1, issuer_obj)
    if cert_revoked(req["req_cert"]["serial_number"].native, crl):
        revoked_info = asn1_ocsp.RevokedInfo()
        revoked_info["revocation_time"], revoked_info["revocation_reason"] = cert_revoked_time(
            req["req_cert"]["serial_number"].native, crl
        )
        return (
            pkcs11_key_obj.key_label,
            pem_cert_to_name_dict(issuer_obj.pem),
            asn1_ocsp.CertStatus({"revoked": revoked_info}),
        )
    return pkcs11_key_obj.key_label, pem_cert_to_name_dict(issuer_obj.pem), asn1_ocsp.CertStatus("good")


async def _ocsp_response_data(
    ocsp_request: asn1_ocsp.OCSPRequest, nonce: Union[bytes, None]
) -> Tuple[str, Dict[str, str], asn1_ocsp.Responses, int, Union[asn1_ocsp.ResponseDataExtensions, None]]:
    responses = asn1_ocsp.Responses()
    status_code: int = 6
    key_label: str = ""
    name_dict: Dict[str, str] = {}

    for _, req in enumerate(ocsp_request["tbs_request"]["request_list"]):
        curr_response = asn1_ocsp.SingleResponse()
        curr_response["cert_id"] = req["req_cert"]

        try:
            key_label, name_dict, cert_status = await _ocsp_check_valid_cert(req)
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

    return key_label, name_dict, responses, status_code, extra_extensions


async def ocsp_response(request: bytes, encoded: bool = False) -> bytes:
    """Create an OCSP response

    Parameters:
    request (bytes): OCSP request in bytes.
    encoded (str): If the request is base64 + url encoded

    Returns:
    bytes
    """

    if encoded:
        try:
            request = ocsp_decode(request.decode("utf-8"))
        except binasciiError:
            return b"0"

    # Ensure valid ocsp request
    try:
        ocsp_request = asn1_ocsp.OCSPRequest.load(request)
        if not isinstance(ocsp_request, asn1_ocsp.OCSPRequest) or len(ocsp_request["tbs_request"]["request_list"]) == 0:
            raise ValueError

        # Get nonce if exists
        nonce = request_nonce(request)

        return await response(*await _ocsp_response_data(ocsp_request, nonce))
    except ValueError:
        return b"0"
    except TypeError:
        return await response("", {}, asn1_ocsp.Responses(), 1)
