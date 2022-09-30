"""Module to handle crls"""
from typing import Union, Dict, List
from fastapi.responses import JSONResponse
from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .asn1 import this_update_next_update_from_crl

from .error import WrongDataType


class CrlInput(InputObject):
    """Class to represent crl matching from HTTP post data """

    pem: Union[str, None]
    ca_pem: Union[str, None]


class Crl(DataClassObject):
    """Class to represent a crl"""

    db: DataBaseObject

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


async def search(input_object: InputObject) -> JSONResponse:
    """Get crls matching the input_object pattern(s).
    Returns a fastAPI json response with a list of the crls.

    Parameters:
    input_object (InputObject): The search pattern data.

    Returns:
    fastapi.responses.JSONResponse
    """

    crl_objs: List[Crl] = []
    crl_pems: List[str] = []

    db_crl_objs = await db_load_data_class(Crl, input_object)
    for obj in db_crl_objs:
        if isinstance(obj, Crl):
            crl_objs.append(obj)

    for crl in crl_objs:
        crl_pems.append(crl.pem)

    return JSONResponse(status_code=200, content={"crls": crl_pems})
