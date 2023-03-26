"""ACME authorization module"""
from typing import Dict, Union, List, Any
import json

from .base import DataClassObject, DataBaseObject, InputObject
from .asn1 import to_base64url, from_base64url


class AcmeAuthorizationInput(InputObject):
    """Class to represent an acme authorization matching from HTTP post data"""

    account: Union[int, None]
    id: Union[str, None]


class AcmeAuthorization(DataClassObject):
    """Class to represent an ACME authorization"""

    db: DataBaseObject
    account: int
    id: str
    status: str
    expires: str
    identifier: str
    challenges: str  # stored as base64url split by ","in DB
    wildcard: int
    created: str

    db_table_name = "acme_authorization"
    db_fields = {
        "account": int,
        "id": str,
        "status": str,
        "expires": str,
        "identifier": str,
        "challenges": str,  # stored as base64url split by ","in DB
        "wildcard": int,  # boolean
        "created": str,
    }
    db_reference_fields: Dict[str, str] = {"acme_order": "acme_order(serial)"}
    db_unique_fields = ["id"]

    def response_data(self) -> Dict[str, Any]:
        """The json view for an acme authorization

        Returns:
        Dict[str, Any]
        """

        return {
            "status": self.status,
            "expires": self.expires,
            "identifier": self.identifier_as_dict(),
            "challenges": self.challenges_as_list(),
        }

    def challenges_as_list(self) -> List[Dict[str, str]]:
        """Get the authorizations challenges as list.
        They are stored in base64url.

        Returns:
        List[Dict[str, str]]
        """

        ret: List[Dict[str, str]] = json.loads(from_base64url(self.challenges))
        return ret

    def identifier_as_dict(self) -> Dict[str, str]:
        """Get the orders identifiers as list.
        They are stored in base64url.

        Returns:
        List[Dict[str, str]]
        """

        ret: Dict[str, str] = json.loads(from_base64url(self.identifier))
        return ret


def challenges_from_list(challenges: List[Dict[str, str]]) -> str:
    """Base64url encode the acme challenges.

    Parameters:
    challenges (List[Dict[str, str]]): List of challenges

    Returns:
    str
    """

    return to_base64url(json.dumps(challenges).encode("utf-8"))
