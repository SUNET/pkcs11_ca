from typing import Union, Dict

from .asn1 import pem_to_sha256_fingerprint, not_before_not_after_from_cert
from .base import DataClassObject, InputObject

from .error import WrongDataType


class CertificateInput(InputObject):
    pem: Union[str, None]
    fingerprint: Union[str, None]


class Certificate(DataClassObject):

    db_table_name = "certificate"
    db_fields = {
        "public_key": int,
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
        "public_key": "public_key(serial)",
        "csr": "csr(serial)",
        "issuer": "ca(serial)",
        "authorized_by": "public_key(serial)",
    }
    db_unique_fields = ["pem", "fingerprint"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)
        if not isinstance(pem, str):
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem

        self.fingerprint = pem_to_sha256_fingerprint(self.pem)
        self.not_before, self.not_after = not_before_not_after_from_cert(self.pem)
