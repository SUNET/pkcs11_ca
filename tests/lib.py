"""Global functions"""

from typing import List, Dict
import json
import os
import subprocess
from hashlib import sha256

import requests
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem
from src.pkcs11_ca_service.asn1 import create_jwt_header_str


def get_cas(pub_key: bytes, priv_key: bytes) -> List[str]:
    """Get all CAs"""
    request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, "http://localhost:8005/search/ca")}
    req = requests.get("http://localhost:8005/search/ca", headers=request_headers, timeout=5)
    if req.status_code != 200:
        raise ValueError("NOT OK status when fetching all CAs")
    cas: List[str] = json.loads(req.text)["cas"]
    return cas


def create_i_ca(pub_key: bytes, priv_key: bytes, name_dict: Dict[str, str]) -> str:
    """Create a CA"""
    request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, "http://localhost:8005/ca")}

    data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
    data["name_dict"] = name_dict
    data["issuer_pem"] = get_cas(pub_key, priv_key)[-1]

    req = requests.post("http://localhost:8005/ca", headers=request_headers, json=data, timeout=5)
    if req.status_code != 200:
        raise ValueError("NOT OK posting a new CA")
    new_ca: str = json.loads(req.text)["certificate"]
    if len(new_ca) < 10:
        raise ValueError("Problem with new CA")
    return new_ca


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


def write_ca_to_chain(der: bytes, path: str, leaf: bool = False) -> None:
    """Get CA for cert, recursive function"""
    curr_chain = b""
    if not leaf and os.path.isfile(path):
        with open(path, "rb") as f_data:
            curr_chain = f_data.read()

    data = der
    if asn1_pem.detect(data):
        _, _, data = asn1_pem.unarmor(data)
    cert = asn1_x509.Certificate().load(data)

    if not leaf:
        with open(path, "wb") as f_data:
            f_data.write(asn1_pem.armor("CERTIFICATE", cert.dump()))
            if len(curr_chain) > 3:
                f_data.write(curr_chain)

    tbs = cert["tbs_certificate"]
    url_ca = ""
    for _, extension in enumerate(tbs["extensions"]):
        if extension["extn_id"].dotted == "1.3.6.1.5.5.7.1.1":
            for _, descr in enumerate(extension["extn_value"].native):
                if descr["access_method"] == "ca_issuers":
                    url_ca = descr["access_location"]

    if len(url_ca) < 3:
        return

    resp = requests.get(url_ca, timeout=5)
    if resp.status_code != 200:
        raise ValueError("Could not download ca from ca_issuers")

    write_ca_to_chain(resp.content, path, leaf=False)


def verify_cert(pem: str) -> None:
    """Verify cert"""

    hash_obj = sha256()
    hash_obj.update(pem.encode("utf-8"))
    hash_digest = hash_obj.hexdigest()

    with open(hash_digest, "w", encoding="utf-8") as f_data:
        f_data.write(pem)

    # Get CA chain for this cert
    write_ca_to_chain(pem.encode("utf-8"), hash_digest + ".cafile", leaf=True)

    subprocess.check_call(
        "openssl verify -CAfile "
        + hash_digest
        + ".cafile "
        + hash_digest
        + " > /dev/null && rm -f "
        + hash_digest
        + ".cafile "
        + hash_digest,
        shell=True,
    )
