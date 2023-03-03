from typing import Dict, Union

from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .error import WrongDataType
from .config import ROOT_URL, ACME_ROOT

# FIXME use enum instead of str when appropriate


class AcmeAuthorization(DataClassObject):
    """Class to represent an ACME authorization"""

    db: DataBaseObject

    db_table_name = "acme_authorization"
    db_fields = {
        "identifier": int,
        "status": str,
        "expires": str,
        "wildcard": int,  # boolean
    }
    db_reference_fields: Dict[str, str] = {
        "identifier": "acme_identifier(serial)",
    }
    db_unique_fields = ["path"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        # pem = kwargs.get("pem", None)
        # if not isinstance(pem, str):
        #     raise WrongDataType("'pem', must be a 'str'")
        # self.pem = pem
