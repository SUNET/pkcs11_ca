from typing import Union, Dict
from .base import DataClassObject, InputObject

from .error import WrongDataType


class CsrInput(InputObject):
    pem: Union[str, None]


class Csr(DataClassObject):

    db_table_name = "csr"
    db_fields = {"public_key": int, "pem": str, "authorized_by": int, "created": str}
    db_reference_fields = {
        "public_key": "public_key(serial)",
        "authorized_by": "public_key(serial)",
    }
    db_unique_fields = ["pem"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)
        if not isinstance(pem, str):
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem
