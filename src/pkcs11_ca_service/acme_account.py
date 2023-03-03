from typing import Dict, Union, Any

from fastapi.responses import JSONResponse
from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .error import WrongDataType
from .config import ROOT_URL, ACME_ROOT
from .nonce import generate_nonce

# FIXME use enum instead of str when appropriate

# FIXME add date_created field


class AcmeAccountInput(InputObject):
    """Class to represent an acme account matching from HTTP post data"""

    id: Union[str, None]
    public_key_pem: Union[str, None]


class AcmeAccount(DataClassObject):
    """Class to represent an ACME account"""

    db: DataBaseObject

    db_table_name = "acme_account"
    db_fields = {
        "public_key_pem": str,  # The account public key in pem form
        "status": str,
        "id": str,
        "contact": str,  # stored in base64url split by "," in DB
        # "termsOfServiceAgreed": int,  # boolean fixme
        # onlyReturnExisting, int, # fixme
        # "externalAccountBinding": str, # fixme
    }
    db_reference_fields: Dict[str, str] = {}
    db_unique_fields = ["id"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        # pem = kwargs.get("pem", None)
        # if not isinstance(pem, str):
        #     raise WrongDataType("'pem', must be a 'str'")
        # self.pem = pem


async def existing_account_response(account: Dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/acct/{account['id']}"},
        content={
            "status": account["status"],
            "public_key_pem": account["public_key_pem"],
            "orders": f"{ROOT_URL}{ACME_ROOT}/acct/{account['id']}/orders",
        },
        media_type="application/json",
    )
