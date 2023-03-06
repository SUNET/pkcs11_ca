from typing import Dict, Union, Any, List
import json

from fastapi.responses import JSONResponse
from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .error import WrongDataType
from .config import ROOT_URL, ACME_ROOT
from .nonce import generate_nonce

from .asn1 import from_base64url, to_base64url

# FIXME use enum instead of str when appropriate

# FIXME add date_created field


class AcmeAccountInput(InputObject):
    """Class to represent an acme account matching from HTTP post data"""

    id: Union[str, None]
    public_key_pem: Union[str, None]


class AcmeAccount(DataClassObject):
    """Class to represent an ACME account"""

    db: DataBaseObject
    public_key_pem: str
    status: str
    id: str
    contact: str

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

    def contact_as_list(self) -> List[str]:
        ret: List[str] = json.loads(from_base64url(self.contact))
        return ret


def contact_from_payload(payload: Dict[str, Any]) -> str:
    contacts: List[str] = []

    if "contact" in payload:
        req_contacts = payload["contact"]
        if isinstance(req_contacts, list):
            for entry in req_contacts:
                if isinstance(entry, str):
                    contacts.append(to_base64url(entry.encode("utf-8")))
            if len(contacts) > 0:
                return to_base64url(json.dumps(contacts).encode("utf-8"))

    return to_base64url(b"[]")


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
