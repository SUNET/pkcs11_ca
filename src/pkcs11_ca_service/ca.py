from typing import Dict, Union
from fastapi.responses import JSONResponse
from .base import DataClassObject, InputObject
from .asn1 import pem_to_sha256_fingerprint, not_before_not_after_from_cert

from .error import WrongDataType


class CaInput(InputObject):
    name_dict: Union[Dict[str, str], None]
    pem: Union[str, None]
    key_label: Union[str, None]
    issuer_pem: Union[str, None]
    key_size: int = 2048


class Ca(DataClassObject):

    db_table_name = "ca"
    db_fields = {
        "pkcs11_key": int,
        "pem": str,
        "csr": int,
        "issuer": int,
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
    db_unique_fields = ["pem", "fingerprint"]

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
