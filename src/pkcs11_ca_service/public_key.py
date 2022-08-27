"""Module to handle public keys"""
from typing import Union, Dict, List
from fastapi.responses import JSONResponse

from .base import DataClassObject, InputObject, db_load_data_class
from .asn1 import public_key_pem_to_sha1_fingerprint
from .error import WrongDataType


class PublicKeyInput(InputObject):
    """Class to represent public key matching from HTTP post data """

    pem: Union[str, None]
    fingerprint: Union[str, None]
    admin: Union[int, None]


class PublicKey(DataClassObject):
    """Class to represent a public key"""

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
        pem = kwargs.get("pem", None)  # pylint:disable=duplicate-code
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
            if admin in (1, 0):
                self.admin = admin
            else:
                self.admin = 0
        else:
            self.admin = 0

        # https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
        self.fingerprint = public_key_pem_to_sha1_fingerprint(self.pem)


async def search(input_object: InputObject) -> JSONResponse:
    """Get public keys matching the input_object pattern(s).
    Returns a fastAPI json response with a list of the public keys.

    Parameters:
    input_object (InputObject): The search pattern data.

    Returns:
    fastapi.responses.JSONResponse
    """

    public_key_objs: List[PublicKey] = []
    public_key_pems: List[str] = []

    db_public_key_objs = await db_load_data_class(PublicKey, input_object)
    for obj in db_public_key_objs:
        if isinstance(obj, PublicKey):
            public_key_objs.append(obj)

    for public_key in public_key_objs:
        public_key_pems.append(public_key.pem)

    return JSONResponse(status_code=200, content={"public_keys": public_key_pems})


# @abstractmethod

# async def search_all() -> JSONResponse:
#     public_key_objs: List[PublicKey] = []
#     public_key_pems: List[str] = []

#     db_public_key_objs = await db_load_data_class(PublicKey, PublicKeyInput())
#     for obj in db_public_key_objs:
#         if isinstance(obj, PublicKey):
#             public_key_objs.append(obj)

#     for public_key in public_key_objs:
#         public_key_pems.append(public_key.pem)

#     return JSONResponse(status_code=200, content={"public_keys": public_key_pems})


# pass

# @abstractmethod
# async def post(self, input_object: InputObject) -> JSONResponse:
#   pass
