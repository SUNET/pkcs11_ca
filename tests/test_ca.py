"""
Test our ca
"""
import unittest
import requests
import datetime
import os
import jwt
import json

from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem
from src.pkcs11_ca_service.asn1 import pem_key_to_jwk


class TestCa(unittest.TestCase):
    """
    Test our ca
    """

    def test_ca(self) -> None:
        """
        create ca
        """

        with open("trusted_pub_keys/privkey1.key", "rb") as f:
            priv_key = f.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f:
            pub_key = f.read()

        # Get CAs
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 200)
        cas = json.loads(req.text)["cas"]

        # Create a ca
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")

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
        data["issuer_pem"] = cas[0]

        req = requests.post("http://localhost:8000/ca", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))

        # Get CAs
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 200)
        cas = json.loads(req.text)["cas"]

        # Create a ca
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-1.sunet.se",
            "email_address": "soc@sunet.se",
        }

        data = json.loads('{"key_label": ' + '"' + new_key_label[:-1] + '"' + "}")
        data["name_dict"] = name_dict
        data["issuer_pem"] = cas[-1]

        req = requests.post("http://localhost:8000/ca", headers=request_headers, json=data)
        # print(req.text)
        # print(req.status_code)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))
