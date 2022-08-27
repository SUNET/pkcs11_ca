"""
Test our auth
"""
import unittest
import requests
import jwt

from src.pkcs11_ca_service.asn1 import pem_key_to_jwk

from .lib import create_jwt_header_str


class TestAuth(unittest.TestCase):
    """
    Test our auth.
    """

    def test_auth_nonce(self) -> None:
        """
        Test url nonce
        """

        with open("trusted_pub_keys/privkey1.key", "rb") as f_data:
            priv_key1 = f_data.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f_data:
            pub_key1 = f_data.read()

        # No nonce
        jwt_headers = {"url": "http://localhost:8000/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
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
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

    def test_auth_url(self) -> None:
        """
        Test url auth
        """

        with open("trusted_pub_keys/privkey1.key", "rb") as f_data:
            priv_key1 = f_data.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f_data:
            pub_key1 = f_data.read()

        # No url in token
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        # Wrong url in token
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/search/ca_wrong_url"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

    def test_auth(self) -> None:
        """
        Send requests with valid and invald jwt tokens
        """

        with open("trusted_pub_keys/privkey1.key", "rb") as f_data:
            priv_key1 = f_data.read()
        with open("trusted_pub_keys/privkey2.key", "rb") as f_data:
            priv_key2 = f_data.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f_data:
            pub_key1 = f_data.read()

        # Sign with key2 but send key1 as public key
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key2, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
        self.assertTrue(req.status_code == 401)

        # Correct auth, HEAD nonce
        req = requests.head("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
        self.assertTrue(req.status_code == 200)

        # Correct auth, GET nonce
        req = requests.get("http://localhost:8000/new_nonce")
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1, algorithm="PS256", headers=jwt_headers)
        request_headers = {}
        request_headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
        self.assertTrue(req.status_code == 200)

        # Test lib auth
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key1, priv_key1, "http://localhost:8000/search/ca")
        req = requests.get("http://localhost:8000/search/ca", headers=request_headers)
        self.assertTrue(req.status_code == 200)
