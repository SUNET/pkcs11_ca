"""
Test our CRL creation
"""
import unittest
import requests
import datetime
import os
import jwt
import json

from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem
from src.pkcs11_ca_service.asn1 import pem_key_to_jwk


class TestCrl(unittest.TestCase):
    """
    Test our auth.
    """

    def test_csr(self) -> None:
        """
        Sign csrs
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

        # Sign a csr
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/crl"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")

        data = json.loads('{"ca_pem": ' + '"' + cas[0].replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/crl", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["crl"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))
