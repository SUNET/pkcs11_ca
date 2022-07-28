from typing import Union, Dict
from .base import DataClassObject, InputObject
from .asn1 import this_update_next_update_from_crl

from .error import WrongDataType


class CrlInput(InputObject):
    pem: Union[str, None]
    ca_pem: Union[str, None]


class Crl(DataClassObject):

    db_table_name = "crl"
    db_fields = {
        "pem": str,
        "issuer": int,
        "authorized_by": int,
        "this_update": str,
        "next_update": str,
        "created": str,
    }
    db_reference_fields = {
        "public_key": "public_key(serial)",
        "issuer": "ca(serial)",
        "authorized_by": "public_key(serial)",
    }
    db_unique_fields = ["pem"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)
        if not isinstance(pem, str):
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem

        self.this_update, self.next_update = this_update_next_update_from_crl(self.pem)
