"""
Test our input data validation
"""
import unittest
import json
import os

import requests
from src.pkcs11_ca_service.asn1 import create_jwt_header_str
from src.pkcs11_ca_service.config import ROOT_URL

with open("data/trusted_keys/privkey1.key", "rb") as file_data:
    priv_key = file_data.read()
with open("data/trusted_keys/pubkey1.pem", "rb") as file_data:
    pub_key = file_data.read()


class TestValidate(unittest.TestCase):
    """
    Test our validate
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def test_validate(self) -> None:
        """
        Test validate
        """

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-validate-16.sunet.se",
        }

        # Test @ and key_label
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/public_key")}
        data = json.loads('{"key_label": ' + '"' + "dummy_string@" + '"' + "}")
        data["name_dict"] = name_dict
        data["issuer_pem"] = "dummyhere"
        req = requests.post(
            self.ca_url + "/ca", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 400)

        # Test char ;
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/public_key")}
        data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
        data[
            "pem"
        ] = """-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAV8X2UCh13YJ94P2qZ2cdo6B8RHF9N9nzqdf40Chr+99aAIAn
Tj5zjeJiywSdOZnFPloeE;ZB6raA
-----END PUBLIC KEY-----
"""
        req = requests.post(
            self.ca_url + "/public_key", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 400)

        # Test char "
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/public_key")}
        data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
        data["pem"] = (
            """-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAV8X2UCh13YJ94P2qZ2cdo6B8RHF9N9nzqdf40Chr+99aAIAn
Tj5zjeJiywSdOZnFPloeE"""
            + '"'
            + """ZB6raA
-----END PUBLIC KEY-----
"""
        )
        req = requests.post(
            self.ca_url + "/public_key", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 400)

        # Test char '
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/public_key")}
        data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
        data[
            "pem"
        ] = """-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAV8X2UCh13YJ94P2qZ2cdo6B8RHF9N9nzqdf40Chr+99aAIAn
Tj5zjeJiywSdOZnFPloeE'ZB6raA
-----END PUBLIC KEY-----
"""
        req = requests.post(
            self.ca_url + "/public_key", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 400)

        # Test ok chars
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/public_key")}
        data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
        data[
            "pem"
        ] = """-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAV8X2UCh13YJ94P2qZ2cdo6B8RHF9N9nzqdf40Chr+99aAIAn
Tj5zjeJiywSdOZnFPloeEMZB6raA
-----END PUBLIC KEY-----
"""
        req = requests.post(
            self.ca_url + "/public_key", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 200)
