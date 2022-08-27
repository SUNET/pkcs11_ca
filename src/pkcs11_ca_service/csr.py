"""Module to handle csrs"""
from typing import Union, Dict, List
from fastapi.responses import JSONResponse
from .base import DataClassObject, InputObject, db_load_data_class
from .error import WrongDataType


class CsrInput(InputObject):
    """Class to represent csr matching from HTTP post data """

    pem: Union[str, None]
    ca_pem: Union[str, None]


class Csr(DataClassObject):
    """Class to represent a csr"""

    db_table_name = "csr"
    db_fields = {"public_key": int, "pem": str, "authorized_by": int, "created": str}
    db_reference_fields = {
        "public_key": "public_key(serial)",
        "authorized_by": "public_key(serial)",
    }
    db_unique_fields = ["pem"]  # pylint:disable=duplicate-code

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)  # pylint:disable=duplicate-code
        if not isinstance(pem, str):
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem


async def search(input_object: InputObject) -> JSONResponse:
    """Get csrs matching the input_object pattern(s).
    Returns a fastAPI json response with a list of the csrs.

    Parameters:
    input_object (InputObject): The search pattern data.

    Returns:
    fastapi.responses.JSONResponse
    """

    csr_objs: List[Csr] = []
    csr_pems: List[str] = []

    db_csr_objs = await db_load_data_class(Csr, input_object)
    for obj in db_csr_objs:
        if isinstance(obj, Csr):
            csr_objs.append(obj)

    for csr in csr_objs:
        csr_pems.append(csr.pem)

    return JSONResponse(status_code=200, content={"csrs": csr_pems})
