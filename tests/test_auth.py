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

        with open("trusted_pub_keys/privkey1.key", "rb") as f:
            priv_key1 = f.read()
        with open("trusted_pub_keys/privkey2.key", "rb") as f:
            priv_key2 = f.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f:
            pub_key1 = f.read()

        # Sign with key2 but send key1 as public key
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key2, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        # No nonce
        jwt_headers = {"url": "http://localhost:8000/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        # Wrong nonce
        jwt_headers = {
            "nonce": "AJCmF5Qw-7Dhp93FWDFY1jyQ506UNSz7brPG35bx6sR-3s8pyMhjgEqbXQqN2CQOr_kyZKcyWfyDiGRaK9HQgg",
            "url": "http://localhost:8000/ca",
        }
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        # No url in token
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        # Wrong url in token
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/ca_wrong_url"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        # Correct auth
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/ca", headers=request_headers)
        self.assertTrue(req.status_code == 200)
