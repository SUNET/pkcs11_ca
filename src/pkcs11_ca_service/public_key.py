from typing import Union, Dict
from .base import DataClassObject, InputObject
from .asn1 import public_key_pem_to_sha1_fingerprint

from .error import WrongDataType


class PublicKeyInput(InputObject):
    pem: Union[str, None]
    fingerprint: Union[str, None]
    admin: Union[int, None]

class PublicKey(DataClassObject):

    db_table_name = "public_key"
    db_fields = {
        "pem": str,
        "info": str,
        "admin": int,
        "authorized_by": int,
        "fingerprint": str,
        "created": str,
    }

    db_reference_fields: Dict[str, str] = {}
    db_unique_fields = ["pem", "fingerprint"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)
        if not isinstance(pem, str):
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem

        info = kwargs.get("info", None)
        if info is not None:
            if not isinstance(info, str):
                raise WrongDataType("'info', must be a 'str'")
            self.info = info
        else:
            self.info = "Missing info"

        admin = kwargs.get("admin", None)
        if admin is not None:
            if not isinstance(admin, int):
                raise WrongDataType("'admin', must be a 'int'")
            if (admin == 1 or admin == 0):
                self.admin = admin
            else:
                self.admin = 0
        else:
            self.admin = 0
            
        # https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
        self.fingerprint = public_key_pem_to_sha1_fingerprint(self.pem)
