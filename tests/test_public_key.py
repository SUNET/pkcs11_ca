"""
Test our public key creation
"""
import unittest
import requests
import datetime
import os
import jwt
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from asn1crypto.keys import PublicKeyInfo
from asn1crypto import pem as asn1_pem
from src.pkcs11_ca_service.asn1 import pem_key_to_jwk

def generate_keypair():
    # Generate new key
    new_private_key = rsa.generate_private_key(
        key_size=2048,
        public_exponent=65537,
    )
    new_private_key_pem = new_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    new_public_key_pem = new_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return new_private_key_pem.decode('utf-8'), new_public_key_pem.decode('utf-8')


class TestPublicKey(unittest.TestCase):
    """
    Test our public keys
    """

    def test_public_key(self) -> None:
        """
        Test public keys
        """

        with open("trusted_pub_keys/privkey1.key", "rb") as f:
            priv_key = f.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f:
            pub_key = f.read()


        # Test loading public keys
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/public_key", headers=request_headers)
        self.assertTrue(req.status_code == 200)

        public_keys = json.loads(req.text)
        data = public_keys["public_keys"]
        for pem_key in data:
            pem_key = pem_key.encode("utf-8")
            if asn1_pem.detect(pem_key):
                _, _, pem_key = asn1_pem.unarmor(pem_key)

            test_key = PublicKeyInfo.load(pem_key)
            self.assertTrue(isinstance(test_key, PublicKeyInfo))
            self.assertTrue(isinstance(test_key["public_key"].dump(), bytes))
            self.assertTrue(isinstance(test_key["public_key"].native["modulus"], int))


        # Create and post a key
        new_private_key, new_public_key = generate_keypair()
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")

        data = json.loads('{"pem": ' + '"' + new_public_key.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/public_key", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["public_key"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_key = PublicKeyInfo.load(data)
        self.assertTrue(isinstance(test_key, PublicKeyInfo))
        self.assertTrue(isinstance(test_key["public_key"].dump(), bytes))
        self.assertTrue(isinstance(test_key["public_key"].native["modulus"], int))

        # Test to ensure the key is not an admin key
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/public_key"}
        jwk_key_data = pem_key_to_jwk(new_public_key)
        encoded = jwt.encode(jwk_key_data, new_private_key.encode('utf-8'), algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/public_key", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        
        # Create and post an admin key
        new_private_key, new_public_key = generate_keypair()
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")

        data = json.loads('{"pem": ' + '"' + new_public_key.replace("\n", "\\n") + '"' + ',"admin": 1'"}")
        req = requests.post("http://localhost:8000/public_key", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["public_key"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_key = PublicKeyInfo.load(data)
        self.assertTrue(isinstance(test_key, PublicKeyInfo))
        self.assertTrue(isinstance(test_key["public_key"].dump(), bytes))
        self.assertTrue(isinstance(test_key["public_key"].native["modulus"], int))

        # Test to use the admin key
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/public_key"}
        jwk_key_data = pem_key_to_jwk(new_public_key)
        encoded = jwt.encode(jwk_key_data, new_private_key.encode('utf-8'), algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/public_key", headers=request_headers)
        self.assertTrue(req.status_code == 200)
