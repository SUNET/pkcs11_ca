from typing import Dict, Union

from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .error import WrongDataType
from .config import ROOT_URL, ACME_ROOT

# FIXME use enum instead of str when appropriate


class AcmeChallenge(DataClassObject):
    """Class to represent an ACME challenge"""

    db: DataBaseObject

    db_table_name = "acme_challenge"
    db_fields = {
        "authorization": int,
        "url": str,
        "type": str,
        "status": str,
        "token": str,
        "validated": str,
    }
    db_reference_fields: Dict[str, str] = {
        "authorization": "acme_authorization(serial)",
    }
    db_unique_fields = ["path"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        # pem = kwargs.get("pem", None)
        # if not isinstance(pem, str):
        #     raise WrongDataType("'pem', must be a 'str'")
        # self.pem = pem
