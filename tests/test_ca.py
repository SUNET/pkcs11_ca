"""
Test our ca
"""
import unittest
from typing import List
import os
import json

import requests
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

from .lib import get_cas, create_jwt_header_str


class TestCa(unittest.TestCase):
    """
    Test our ca
    """

    def get_single_ca(self, pub_key: bytes, priv_key: bytes, cas: List[str]) -> None:
        """Get single ca"""

        # Get a ca
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/search/ca")

        data = json.loads('{"pem": ' + '"' + cas[1].replace("\n", "\\n") + '"' + "}")
        # data["name_dict"] = name_dict
        # data["issuer_pem"] = cas[1]
        req = requests.post("http://localhost:8000/search/ca", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)
        self.assertTrue(len(json.loads(req.text)["cas"]) == 1)

    def test_ca(self) -> None:
        """
        create ca
        """

        with open("trusted_keys/privkey1.key", "rb") as f_data:  # pylint:disable=duplicate-code
            priv_key = f_data.read()
        with open("trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()

        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/ca")

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-1.sunet.se",
            "email_address": "soc@sunet.se",
        }

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        data = json.loads('{"key_label": ' + '"' + new_key_label + '"' + "}")
        data["name_dict"] = name_dict

        cas = get_cas(pub_key, priv_key)
        data["issuer_pem"] = cas[0]

        req = requests.post("http://localhost:8000/ca", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        self.assertTrue(isinstance(asn1_x509.Certificate.load(data), asn1_x509.Certificate))

        # Get CAs
        cas2 = get_cas(pub_key, priv_key)

        # Ensure we now have one more ca than before
        self.assertTrue(len(cas2) == len(cas) + 1)
        cas = cas2

        # Create another ca
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/ca")

        data = json.loads('{"key_label": ' + '"' + new_key_label[:-1] + '"' + "}")
        data["name_dict"] = name_dict
        data["issuer_pem"] = cas[-1]

        req = requests.post("http://localhost:8000/ca", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        self.assertTrue(isinstance(asn1_x509.Certificate.load(data), asn1_x509.Certificate))
        self.get_single_ca(pub_key, priv_key, cas)

    def test_root_ca(self) -> None:
        """
        create ca
        """

        with open("trusted_keys/privkey1.key", "rb") as file_data:  # pylint:disable=duplicate-code
            priv_key = file_data.read()
        with open("trusted_keys/pubkey1.pem", "rb") as file_data:
            pub_key = file_data.read()

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-17.sunet.se",
            "email_address": "soc@sunet.se",
        }

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        # Create a root ca
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/ca")

        data = json.loads('{"key_label": ' + '"' + new_key_label[:-2] + '"' + "}")
        data["name_dict"] = name_dict

        req = requests.post("http://localhost:8000/ca", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        cert_curr = asn1_x509.Certificate().load(data)
        self.assertTrue(isinstance(cert_curr, asn1_x509.Certificate))

        tbs = cert_curr["tbs_certificate"]
        for _, extension in enumerate(tbs["extensions"]):
            if extension["extn_id"].dotted == "2.5.29.14":
                ski = extension["extn_value"].native

        for _, extension in enumerate(tbs["extensions"]):
            if extension["extn_id"].dotted == "2.5.29.35":
                aki = extension["extn_value"].native["key_identifier"]
        self.assertTrue(ski == aki)
