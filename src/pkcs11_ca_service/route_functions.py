"""Route functions"""

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from python_x509_pkcs11.crl import create as create_crl
from python_x509_pkcs11.csr import sign_csr as pkcs11_sign_csr
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

from .asn1 import aia_and_cdp_exts, cert_is_ca, cert_pem_serial_number, crl_expired, pem_cert_to_name_dict
from .base import db_load_data_class
from .ca import Ca, CaInput
from .certificate import Certificate
from .config import HEALTHCHECK_KEY_LABEL, HEALTHCHECK_KEY_TYPE
from .crl import Crl
from .csr import Csr
from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
from .public_key import PublicKey, PublicKeyInput


async def healthcheck() -> JSONResponse:
    """Healthcheck, query the DB, sign som data.
    If fail then send http status code 503.

    Returns:
    JSONResponse
    """

    try:
        # Check the DB
        await pkcs11_key_request(Pkcs11KeyInput(key_label=HEALTHCHECK_KEY_LABEL))

        # Sign some data
        data_to_be_signed = b"healthcheck"
        signature = await PKCS11Session.sign(
            HEALTHCHECK_KEY_LABEL, data_to_be_signed, verify_signature=True, key_type=HEALTHCHECK_KEY_TYPE
        )
        if len(signature) < 5:
            raise HTTPException(status_code=503, detail="Failed healthcheck")

        return JSONResponse(status_code=200, content={"healthcheck": "ok"})
    except BaseException as exception:
        print(exception)  # Log this
        raise HTTPException(status_code=503, detail="Failed healthcheck") from exception


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
        issuer_pkcs11_key_obj.key_label,
        pem_cert_to_name_dict(issuer_obj.pem),
        old_crl_pem=curr_crl,
        key_type=issuer_pkcs11_key_obj.key_type,
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


async def sign_csr(auth_by: int, issuer_obj: Ca, csr_obj: Csr, public_key_obj: PublicKey) -> str:
    """

    :param auth_by: DB public key id.
    :param issuer_obj: Which CA should sign the CSR.
    :param csr_obj: Which CSR object will be signed.
    :param public_key_obj: Which public key object created this csr.
    :return: str
    """
    # Get pkcs11 and its key label to sign the csr with from the CA
    issuer_pkcs11_key_obj = await pkcs11_key_request(Pkcs11KeyInput(serial=issuer_obj.pkcs11_key))

    extra_extensions = aia_and_cdp_exts(issuer_obj.path)

    # Sign csr
    cert_pem = await pkcs11_sign_csr(
        issuer_pkcs11_key_obj.key_label,
        pem_cert_to_name_dict(issuer_obj.pem),
        csr_obj.pem,
        extra_extensions=extra_extensions,
        key_type=issuer_pkcs11_key_obj.key_type,
    )

    # Save cert
    cert_obj = Certificate(
        {
            "pem": cert_pem,
            "authorized_by": auth_by,
            "csr": csr_obj.serial,
            "serial_number": str(cert_pem_serial_number(cert_pem)),
            "public_key": public_key_obj.serial,
            "issuer": issuer_obj.serial,
        }
    )
    await cert_obj.save()
    if cert_is_ca(cert_pem):
        print("Warning: Treating CA as a certificate since we dont have the private key")

    return cert_pem
