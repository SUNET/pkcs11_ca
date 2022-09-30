"""Route functions"""

from fastapi import HTTPException

from python_x509_pkcs11.crl import create as create_crl

from .public_key import PublicKey, PublicKeyInput
from .ca import CaInput, Ca
from .crl import Crl
from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
from .asn1 import crl_expired, pem_cert_to_name_dict
from .base import db_load_data_class


async def public_key_request(public_key_input: PublicKeyInput) -> PublicKey:
    """Get public key object.

    Parameters:
    public_key_input (CaInput): Public key input object.

    Returns:
    PublicKey
    """

    public_key_objs = await db_load_data_class(PublicKey, public_key_input)
    if not public_key_objs:
        raise HTTPException(status_code=400, detail="No such public key")
    public_key_obj = public_key_objs[0]
    if not isinstance(public_key_obj, PublicKey):
        raise HTTPException(status_code=400, detail="No such public key")
    return public_key_obj


async def pkcs11_key_request(pkcs11_key_input: Pkcs11KeyInput) -> Pkcs11Key:
    """Get pkcs11 key object.

    Parameters:
    pkcs11_key_input (Pkcs11KeyInput): PKCS11 key input object.

    Returns:
    Pkcs11Key
    """

    pkcs11_key_objs = await db_load_data_class(Pkcs11Key, pkcs11_key_input)
    if not pkcs11_key_objs:
        raise HTTPException(status_code=400, detail="No such pkcs11 key")
    pkcs11_key_obj = pkcs11_key_objs[0]
    if not isinstance(pkcs11_key_obj, Pkcs11Key):
        raise HTTPException(status_code=400, detail="No such pkcs11 key")
    return pkcs11_key_obj


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
        return curr_crl

    # Create a new CRL
    issuer_pkcs11_key_obj = await pkcs11_key_request(Pkcs11KeyInput(serial=issuer_obj.pkcs11_key))
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
