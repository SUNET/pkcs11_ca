from typing import List, Union, Dict
import json
import base64

from pkcs11.exceptions import NoSuchKey
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

from .base import InputObject, db_load_data_class


class Pkcs11SignInput(InputObject):
    """Class to represent ca matching from HTTP post data"""

    key_label: str
    key_type: str
    data: List[str]


async def pkcs11_sign(pkcs11_sign_input: Pkcs11SignInput) -> Dict[str, Union[str, List[str]]]:
    result: Dict[str, Union[str, List[str]]] = {}
    signed_data: List[str] = []

    # Get or create pkcs11 key
    try:
        signer_public_key, _ = await PKCS11Session.public_key_data(pkcs11_sign_input.key_label, pkcs11_sign_input.key_type)
    except NoSuchKey:
        signer_public_key, _ = await PKCS11Session.create_keypair(pkcs11_sign_input.key_label, pkcs11_sign_input.key_type)
        print(f"Created pkcs11 key label:{pkcs11_sign_input.key_label} type:{pkcs11_sign_input.key_type}")

    for data in pkcs11_sign_input.data:
        signature: bytes = await PKCS11Session.sign(
            key_label=pkcs11_sign_input.key_label,
            data=base64.b64decode(data),
            verify_signature=True,  # FIXME Change to False after testing
            key_type=pkcs11_sign_input.key_type)

        signed_data.append(base64.b64encode(signature).decode("utf-8"))

    result["data_encoding"] = "base64"
    result["signed_data"] = signed_data
    result["signer_public_key"] = signer_public_key

    if pkcs11_sign_input.key_type == "secp256r1":
        result["algorithm"] = "sha256_ecdsa"
    elif pkcs11_sign_input.key_type == "secp384r1":
        result["algorithm"] = "sha384_ecdsa"
    else:
        result["algorithm"] = "sha512_ecdsa"

    return result
