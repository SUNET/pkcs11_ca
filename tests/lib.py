"""Global functions"""

from typing import List
import json
import requests
from src.pkcs11_ca_service.asn1 import create_jwt_header_str


def get_cas(pub_key: bytes, priv_key: bytes) -> List[str]:
    """Get all CAs"""

    request_headers = {}
    request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/search/ca")
    req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
    if req.status_code != 200:
        raise ValueError("NOT OK status when fetching all CAs")
    cas: List[str] = json.loads(req.text)["cas"]
    return cas
