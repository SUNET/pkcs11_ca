"""EDUSIGN module"""
import datetime

from pkcs11.exceptions import NoSuchKey
from python_x509_pkcs11.crl import create as create_crl
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

from .config import (
    EDUSIGN_LONGTERM_CRL_CA_NAME_DICT,
    EDUSIGN_LONGTERM_CRL_KEY_LABEL,
    EDUSIGN_LONGTERM_CRL_KEY_TYPE,
)


async def create_edusign_longterm_crl() -> str:
    """Create an edusign longterm CRL in PEM format.

    The crl is empty and valid for one year.

    The CRL is not added to the database due to its external nature.
    It is coming from an old edusign CA and we simply borrow its key to create a crl.

    Returns:
    str
    """

    # Create edusign key if not exist in pkcs11 device
    try:
        _, _ = await PKCS11Session.public_key_data(
            key_label=EDUSIGN_LONGTERM_CRL_KEY_LABEL, key_type=EDUSIGN_LONGTERM_CRL_KEY_TYPE
        )
    except NoSuchKey:
        _, _ = await PKCS11Session.create_keypair(
            key_label=EDUSIGN_LONGTERM_CRL_KEY_LABEL, key_type=EDUSIGN_LONGTERM_CRL_KEY_TYPE
        )
        print(f"Created missing pkcs11 key label:{EDUSIGN_LONGTERM_CRL_KEY_LABEL} type:{EDUSIGN_LONGTERM_CRL_KEY_TYPE}")

    # Create a one year long empty CRL
    crl_this_update = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)).replace(
        microsecond=0
    )
    crl_next_update = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).replace(
        microsecond=0
    )

    return await create_crl(
        key_label=EDUSIGN_LONGTERM_CRL_KEY_LABEL,
        subject_name=EDUSIGN_LONGTERM_CRL_CA_NAME_DICT,
        this_update=crl_this_update,
        next_update=crl_next_update,
        key_type=EDUSIGN_LONGTERM_CRL_KEY_TYPE,
    )
