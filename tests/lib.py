"""Global functions"""

from typing import List
import json
import requests
import jwt
from src.pkcs11_ca_service.asn1 import pem_key_to_jwk


def create_jwt_header_str(pub_key: bytes, priv_key: bytes, url: str) -> str:
    """Create jwt header string"""

    req = requests.head("http://localhost:8000/new_nonce")
    nonce = req.headers["Replay-Nonce"]
    jwt_headers = {"nonce": nonce, "url": url}
    jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
    encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
    return "Bearer " + encoded.decode("utf-8")


def get_cas(pub_key: bytes, priv_key: bytes) -> List[str]:
    """Get all CAs"""

    request_headers = {}
    request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/search/ca")
    req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
    if req.status_code != 200:
        raise ValueError("NOT OK status when fetching all CAs")
    cas: List[str] = json.loads(req.text)["cas"]
    return cas
