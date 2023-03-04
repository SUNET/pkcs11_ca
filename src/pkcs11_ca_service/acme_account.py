from typing import Dict, Union, Any, List

from fastapi.responses import JSONResponse
from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .error import WrongDataType
from .config import ROOT_URL, ACME_ROOT
from .nonce import generate_nonce

from .asn1 import from_base64url

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
    db_unique_fields = ["id", "public_key_pem"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)

        status = kwargs.get("status", None)
        if not isinstance(status, str):
            raise WrongDataType("'status', must be a 'str'")
        self.status = status

        public_key_pem = kwargs.get("public_key_pem", None)
        if not isinstance(public_key_pem, str):
            raise WrongDataType("'public_key_pem', must be a 'str'")
        self.public_key_pem = public_key_pem

        account_id = kwargs.get("id", None)
        if not isinstance(account_id, str):
            raise WrongDataType("'id', must be a 'str'")
        self.id = account_id

        contact = kwargs.get("contact", None)
        if not isinstance(contact, str):
            raise WrongDataType("'contact', must be a 'str'")
        self.contact = contact

    def contact_as_list(self) -> List[str]:
        contact_as_list: List[str] = []

        for entry in self.contact.split(","):
            contact_as_list.append(from_base64url(entry).decode("utf-8"))
        return contact_as_list


async def existing_account_response(account: AcmeAccount) -> JSONResponse:
    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/acct/{account.id}"},
        content={
            "status": account.status,
            "public_key_pem": account.public_key_pem,
            "contact": account.contact_as_list(),
            "orders": f"{ROOT_URL}{ACME_ROOT}/acct/{account.id}/orders",
        },
        media_type="application/json",
    )
