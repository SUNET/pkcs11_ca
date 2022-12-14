"""Module to handle pkcs11 keys"""
from typing import Union, Dict
from .base import DataClassObject, DataBaseObject, InputObject

from .error import WrongDataType


class Pkcs11KeyInput(InputObject):
    """Class to represent PKCS11 key matching from HTTP post data"""

    key_label: Union[str, None]
    serial: Union[int, None]
    public_key: Union[int, None] = None
    key_type: Union[str, None]


class Pkcs11Key(DataClassObject):
    """Class to represent a PKCS11 key"""

    db: DataBaseObject

    db_table_name = "pkcs11_key"
    db_fields = {
        "public_key": int,
        "key_label": str,
        "key_type": str,
        "authorized_by": int,
        "created": str,
    }
    db_reference_fields = {
        "public_key": "public_key(serial)",
        "authorized_by": "public_key(serial)",
    }

    db_unique_fields = ["public_key", "key_label"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        key_label = kwargs.get("key_label", None)
        if not isinstance(key_label, str):
            raise WrongDataType("'key_label', must be a 'str'")
        self.key_label = key_label

        key_type = kwargs.get("key_type", None)
        if not isinstance(key_type, str):
            raise WrongDataType("'key_type', must be a 'str'")
        self.key_type = key_type
