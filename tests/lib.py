"""Global functions"""

from typing import List
import json

import requests
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem
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


def cdp_url(pem: str) -> str:
    """GET CDP URL"""
    data = pem.encode("utf-8")
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)
    tbs = cert["tbs_certificate"]

    for _, extension in enumerate(tbs["extensions"]):
        if extension["extn_id"].dotted == "2.5.29.31":
            for _, point in enumerate(extension["extn_value"].native):
                for _, name in enumerate(point["distribution_point"]):
                    if "/crl/" in name:
                        ret: str = name
                        return ret

    raise ValueError
