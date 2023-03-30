"""ACME order module"""
import json
from typing import Any, Dict, List, Union

from fastapi import HTTPException

from .asn1 import from_base64url, to_base64url
from .base import DataBaseObject, DataClassObject, InputObject
from .config import ACME_IDENTIFIER_TYPES


class AcmeOrderInput(InputObject):
    """Class to represent an acme order matching from HTTP post data"""

    id: Union[str, None] = None
    account: Union[int, None] = None
    issued_certificate: Union[str, None] = None


class AcmeOrder(DataClassObject):
    """Class to represent an ACME order"""

    db: DataBaseObject
    account: int
    id: str
    status: str
    expires: str
    identifiers: str
    not_before: str
    not_after: str
    authorizations: str
    finalize: str
    certificate: str
    issued_certificate: str
    created: str

    db_table_name = "acme_order"
    db_fields = {
        "account": int,
        "id": str,
        "status": str,
        "expires": str,
        "identifiers": str,  # stored as base64url split by ","in DB
        "not_before": str,
        "not_after": str,
        # "error": str # Implement this
        "authorizations": str,  # stored as base64url split by ","in DB
        "finalize": str,
        "certificate": str,
        "issued_certificate": str,
        "created": str,
    }
    db_reference_fields: Dict[str, str] = {"account": "acme_account(serial)"}
    db_unique_fields = ["id", "issued_certificate"]

    def response_data(self) -> Dict[str, Any]:
        """The json view for an acme order

        Returns:
        Dict[str, Any]
        """

        ret = {
            "status": self.status,
            "expires": self.expires,
            "notBefore": self.not_before,
            "notAfter": self.not_after,
            "identifiers": self.identifiers_as_list(),
            "authorizations": self.authorizations_as_list(),
            "finalize": self.finalize,
        }

        if self.status == "valid":
            ret["certificate"] = self.certificate

        return ret

    def identifiers_as_list(self) -> List[Dict[str, str]]:
        """Get the orders identifiers as list.
        They are stored in base64url.

        Returns:
        List[Dict[str, str]]
        """

        ret: List[Dict[str, str]] = json.loads(from_base64url(self.identifiers))
        return ret

    def authorizations_as_list(self) -> List[str]:
        """Get the orders authorizations as list
        They are stored in base64url

        Returns:
        List[str]
        """

        ret: List[str] = json.loads(from_base64url(self.authorizations))
        return ret


def authorizations_from_list(auths: List[str]) -> str:
    """Base64url encode the acme authorizations.

    Parameters:
    auths (List[str]): List of auths.

    Returns:
    str
    """

    return to_base64url(json.dumps(auths).encode("utf-8"))


def identifiers_from_payload(payload: Dict[str, Any]) -> str:
    """Encode the acme order identifiers to base64url

    Parameters:
    payload (Dict[str, Any): The payload part pf the acme JWS.

    Returns:
    str
    """

    identifier_entries: List[Dict[str, str]] = []

    if "identifiers" not in payload:
        raise HTTPException(status_code=400, detail="identifiers not in jws")
    request_identifiers = payload["identifiers"]

    if not isinstance(request_identifiers, list) or len(request_identifiers) == 0:
        raise HTTPException(status_code=400, detail="Invalid identifiers in jws")

    for entry in request_identifiers:
        if not isinstance(entry, dict) or "type" not in entry or "value" not in entry:
            raise HTTPException(status_code=400, detail="Invalid identifiers")

        entry_type = entry["type"]
        entry_value = entry["value"]
        if not isinstance(entry_type, str) or not isinstance(entry_value, str) or len(entry_value) == 0:
            raise HTTPException(status_code=400, detail="Invalid identifiers")

        if entry_type not in ACME_IDENTIFIER_TYPES:
            raise HTTPException(status_code=400, detail="Invalid type in identifier")

        identifier_entries.append({"type": entry_type, "value": entry_value})

    if len(identifier_entries) == 0:
        raise HTTPException(status_code=400, detail="Must have least one identifier")

    return to_base64url(json.dumps(identifier_entries).encode("utf-8"))
