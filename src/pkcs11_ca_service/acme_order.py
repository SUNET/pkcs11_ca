from typing import Dict, Union

from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .error import WrongDataType
from .config import ROOT_URL, ACME_ROOT

# FIXME use enum instead of str when appropriate


class AcmeOrder(DataClassObject):
    """Class to represent an ACME order"""

    db: DataBaseObject

    db_table_name = "acme_order"
    db_fields = {
        "account": int,
        "status": str,
        "expires": str,
        "identifiers": str,  # stored as base64url split by ","in DB
        "not_before": str,
        "not_after": str,
        # "error": str # Implement this
        "authorizations": str,  # stored as base64url split by ","in DB
        "finalize": str,
        "certificate": str,
        "path": str,
    }
    db_reference_fields: Dict[str, str] = {
        "account": "acme_account(serial)",
    }
    db_unique_fields = ["path"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        # pem = kwargs.get("pem", None)
        # if not isinstance(pem, str):
        #     raise WrongDataType("'pem', must be a 'str'")
        # self.pem = pem
