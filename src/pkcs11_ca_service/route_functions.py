"""Route functions"""
from fastapi import HTTPException

# from fastapi.responses import JSONResponse

from python_x509_pkcs11.crl import create as create_crl

from .ca import CaInput, Ca
from .crl import Crl
from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
from .asn1 import crl_expired, pem_cert_to_name_dict
from .base import db_load_data_class


async def ca_request(ca_input: CaInput) -> Ca:
    """Get CA object.

    Parameters:
    ca_input (CaInput): CA input object.

    Returns:
    Ca
    """

    issuer_objs = await db_load_data_class(Ca, ca_input)
    if not issuer_objs:
        raise HTTPException(status_code=400, detail="No such CA")
    issuer_obj = issuer_objs[0]
    if not isinstance(issuer_obj, Ca):
        raise HTTPException(status_code=400, detail="No such CA")
    return issuer_obj


async def pkcs11_key_request(issuer_obj: Ca) -> Pkcs11Key:
    """Get pkcs11 object.

    Parameters:
    issuer_object (Ca): CA object of its issuer

    Returns:
    Pkcs11Key
    """

    issuer_pkcs11_key_objs = await db_load_data_class(Pkcs11Key, Pkcs11KeyInput(serial=issuer_obj.pkcs11_key))
    if not issuer_pkcs11_key_objs:
        raise HTTPException(status_code=400, detail="No such CA with PKCS11 key")
    issuer_pkcs11_key_obj = issuer_pkcs11_key_objs[0]
    if not isinstance(issuer_pkcs11_key_obj, Pkcs11Key):
        raise HTTPException(status_code=400, detail="No such CA with PKCS11 key")
    return issuer_pkcs11_key_obj


async def crl_request(auth_by: int, issuer_obj: Ca) -> str:
    """Get CRL.

    Parameters:
    auth_by (int): Who is the author, comes from the auth.py file
    issuer_object (Ca): CA object of its issuer,

    Returns:
    str
    """

    revoke_data = await issuer_obj.db.revoke_data_for_ca(issuer_obj.serial)

    # If CRL has not expired
    curr_crl: str = revoke_data["crl"]

    if not crl_expired(curr_crl):
        crl_pem = curr_crl

    # Create a new CRL
    else:
        issuer_pkcs11_key_obj = await pkcs11_key_request(issuer_obj)
        crl_pem = await create_crl(
            issuer_pkcs11_key_obj.key_label, pem_cert_to_name_dict(issuer_obj.pem), old_crl_pem=curr_crl
        )
        crl_obj = Crl(
            {
                "pem": crl_pem,
                "authorized_by": auth_by,
                "issuer": issuer_obj.serial,
            }
        )
        await crl_obj.save()
    return crl_pem
