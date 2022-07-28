from typing import Union, Dict
from .base import DataClassObject, InputObject

from .error import WrongDataType


class Pkcs11KeyInput(InputObject):
    key_label: Union[str, None]
    serial: Union[int, None]


class Pkcs11Key(DataClassObject):

    db_table_name = "pkcs11_key"
    db_fields = {
        "public_key": int,
        "key_label": str,
        "authorized_by": int,
        "created": str,
    }
    db_reference_fields = {
        "public_key": "public_key(serial)",
        "authorized_by": "public_key(serial)",
    }

    db_unique_fields = ["key_label"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        key_label = kwargs.get("key_label", None)
        if not isinstance(key_label, str):
            raise WrongDataType("'key_label', must be a 'str'")
        self.key_label = key_label
