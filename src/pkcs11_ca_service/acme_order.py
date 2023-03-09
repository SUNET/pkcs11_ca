"""ACME order module"""
import json
from typing import Dict, Union, Any, List

from fastapi import HTTPException
from .base import DataClassObject, DataBaseObject, InputObject
from .config import ACME_IDENTIFIER_TYPES
from .asn1 import to_base64url, from_base64url


# FIXME use enum instead of str when appropriate


class AcmeOrderInput(InputObject):
    """Class to represent an acme order matching from HTTP post data"""

    id: Union[str, None]
    account: Union[int, None]
    issued_certificate: Union[str, None]


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
    }
    db_reference_fields: Dict[str, str] = {"account": "acme_account(serial)"}
    db_unique_fields = ["id", "issued_certificate"]

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


def identifiers_from_order(payload: Dict[str, Any]) -> str:
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


def authorizations_from_list(auths: List[str]) -> str:
    """Base64url encode the acme authorizations.

    Parameters:
    auths (List[str]): List of auths.

    Returns:
    str
    """

    return to_base64url(json.dumps(auths).encode("utf-8"))
