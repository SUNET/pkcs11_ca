"""Global functions"""

import json
import os
import subprocess
from hashlib import sha256
from typing import Any, Dict, OrderedDict, Union

import requests
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509

from src.pkcs11_ca_service.asn1 import create_jwt_header_str


def verify_pkcs11_ca_tls_cert() -> str:
    """Verify the PKCS11 CA TLS connection with this certificate"""

    return "./tls_certificate.pem"


def create_root_ca(root_url: str, pub_key: bytes, priv_key: bytes) -> str:
    """Create a root CA"""

    new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

    name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm_test",
        "organization_name": "SUNET",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": f"ca-test-{new_key_label[0:10]}.sunet.se",
    }

    # Create a root ca
    request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, root_url + "/ca")}

    data = json.loads('{"key_label": ' + '"' + new_key_label[:-2] + '"' + "}")
    data["name_dict"] = name_dict

    req = requests.post(
        root_url + "/ca", headers=request_headers, json=data, timeout=10, verify=verify_pkcs11_ca_tls_cert()
    )
    if req.status_code != 200:
        raise ValueError("Could not create root CA")

    ret = json.loads(req.text)["certificate"]
    if not isinstance(ret, str):
        raise ValueError("Could not create root CA")

    return ret


def create_i_ca(root_url: str, pub_key: bytes, priv_key: bytes, name_dict: Dict[str, str]) -> str:
    """Create an intermediate CA"""

    root_ca_pem = create_root_ca(root_url, pub_key, priv_key)

    request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, root_url + "/ca")}

    data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
    data["name_dict"] = name_dict
    data["issuer_pem"] = root_ca_pem

    req = requests.post(
        root_url + "/ca", headers=request_headers, json=data, timeout=10, verify=verify_pkcs11_ca_tls_cert()
    )
    if req.status_code != 200:
        raise ValueError("NOT OK posting a new CA")
    new_ca: str = json.loads(req.text)["certificate"]
    if len(new_ca) < 10 or not isinstance(new_ca, str):
        raise ValueError("Problem with new CA")
    return new_ca


def cdp_url_point(point: OrderedDict[str, Any]) -> Union[str, None]:
    for _, name in enumerate(point["distribution_point"]):
        if "/crl/" in name:
            ret: str = name
            return ret


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
                ret = cdp_url_point(point)
                if isinstance(ret, str):
                    return ret

    raise ValueError


def ca_url_from_cert(cert: asn1_x509.Certificate) -> Union[str, None]:
    """CA URL from AIA extension CA Issuers field"""

    tbs = cert["tbs_certificate"]

    for _, extension in enumerate(tbs["extensions"]):
        if extension["extn_id"].dotted == "1.3.6.1.5.5.7.1.1":
            for _, descr in enumerate(extension["extn_value"].native):
                if descr["access_method"] == "ca_issuers":
                    url_ca: str = descr["access_location"]
                    return url_ca

    return


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

    ca_url = ca_url_from_cert(cert)
    if ca_url is None or len(ca_url) < 3:
        return

    resp = requests.get(ca_url, timeout=10, verify=verify_pkcs11_ca_tls_cert())
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
