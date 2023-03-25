"""ACME account module"""
from typing import Dict, Union, Any, List
import json

from .base import DataClassObject, DataBaseObject, InputObject
from .asn1 import from_base64url, to_base64url


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
    created: str

    db_table_name = "acme_account"
    db_fields = {
        "public_key_pem": str,  # The account public key in pem form
        "status": str,
        "id": str,
        "contact": str,  # stored in base64url split by "," in DB
        # "termsOfServiceAgreed": int,  # boolean fixme
        # onlyReturnExisting, int, # fixme
        # "externalAccountBinding": str, # fixme
        "created": str,
    }
    db_reference_fields: Dict[str, str] = {}
    db_unique_fields = ["id", "public_key_pem"]

    def contact_as_list(self) -> List[str]:
        """Get the contacts for this account as a json list
        They are stored in base64url in the database.

        :return: The json list
        :rtype: list[str]
        """

        ret: List[str] = json.loads(from_base64url(self.contact))
        return ret


def contact_from_payload(payload: Dict[str, Any]) -> str:
    """Encode the acme new account contacts to base64url

    :param payload: The payload part pf the acme JWS.
    :type payload: dict[str, Any]

    :return: The json list contacts as a base64url encoded string
    :rtype: str
    """

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
