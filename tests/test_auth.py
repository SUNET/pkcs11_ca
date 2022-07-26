"""
Test our auth
"""
import unittest
import requests
import datetime
import os
import jwt

from src.pkcs11_ca_service.asn1 import pem_key_to_jwk


class TestAuth(unittest.TestCase):
    """
    Test our auth.
    """

    def test_auth(self) -> None:
        """
        Send requests with valid and invald jwt tokens
        """

        req = requests.head("http://localhost:8000/new_nonce")
        print(req.status_code)
        nonce = req.headers["Replay-Nonce"]
        # self.assertTrue(req.status_code == 401)

        with open("trusted_pub_keys/privkey1.key", "rb") as f:
            priv_key = f.read()
        with open("trusted_pub_keys/privkey2.key", "rb") as f:
            priv_key2 = f.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f:
            pub_key = f.read()

        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        headers = {}
        headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        # print (headers)
        req = requests.post("http://localhost:8000/public_key", headers=headers)
        self.assertTrue(req.status_code == 200)

        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key2, algorithm="PS256")
        headers = {}
        headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.post("http://localhost:8000/public_key", headers=headers)

        self.assertTrue(req.status_code == 401)

        req = requests.post("http://localhost:8000/public_key")
        self.assertTrue(req.status_code == 401)

        # self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))
