"""Module to handle certificate authorities"""
from typing import Dict, Union, List
from fastapi.responses import JSONResponse
from .base import DataClassObject, InputObject, db_load_data_class
from .asn1 import pem_to_sha256_fingerprint, not_before_not_after_from_cert

from .error import WrongDataType


class CaInput(InputObject):
    """Class to represent ca matching from HTTP post data """

    name_dict: Union[Dict[str, str], None]
    pem: Union[str, None]
    key_label: Union[str, None]
    issuer_pem: Union[str, None]
    key_size: int = 2048


class Ca(DataClassObject):
    """Class to represent a certificate authority"""

    db_table_name = "ca"
    db_fields = {
        "pem": str,
        "csr": int,
        "issuer": int,
        "pkcs11_key": int,  # pylint:disable=duplicate-code
        "authorized_by": int,
        "fingerprint": str,
        "not_before": str,
        "not_after": str,
        "created": str,
    }
    db_reference_fields = {
        "pkcs11_key": "pkcs11_key(serial)",
        "csr": "csr(serial)",
        "authorized_by": "public_key(serial)",
    }
    db_unique_fields = ["pem", "fingerprint"]  # pylint:disable=duplicate-code

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)
        if not isinstance(pem, str):
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem

        pkcs11_key = kwargs.get("pkcs11_key", None)
        if not isinstance(pkcs11_key, int):
            raise WrongDataType("'pkcs11_key', must be a 'int'")
        self.pkcs11_key = pkcs11_key

        self.fingerprint = pem_to_sha256_fingerprint(self.pem)
        self.not_before, self.not_after = not_before_not_after_from_cert(self.pem)


async def search(input_object: InputObject) -> JSONResponse:
    """Get cas matching the input_object pattern(s).
    Returns a fastAPI json response with a list of the cas.

    Parameters:
    input_object (InputObject): The search pattern data.

    Returns:
    fastapi.responses.JSONResponse
    """

    ca_objs: List[Ca] = []
    ca_pems: List[str] = []

    db_ca_objs = await db_load_data_class(Ca, input_object)
    for obj in db_ca_objs:
        if isinstance(obj, Ca):
            ca_objs.append(obj)

    for c_a in ca_objs:
        ca_pems.append(c_a.pem)

    return JSONResponse(status_code=200, content={"cas": ca_pems})
