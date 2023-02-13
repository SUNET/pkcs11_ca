"""
Test our auth
"""
import unittest
import requests
import jwt

from src.pkcs11_ca_service.asn1 import create_jwt_header_str, pem_key_to_jwk, jwk_key_to_pem
from src.pkcs11_ca_service.config import KEY_TYPES


class TestAuth(unittest.TestCase):
    """
    Test our auth.
    """

    def test_auth_nonce(self) -> None:
        """
        Test url nonce
        """

        with open("data/trusted_keys/privkey1.key", "rb") as f_data:
            priv_key1 = f_data.read()
        with open("data/trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key1 = f_data.read()

        # No nonce
        jwt_headers = {"url": "https://localhost:8005/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

        # Wrong nonce
        jwt_headers = {
            "nonce": "AJCmF5Qw-7Dhp93FWDFY1jyQ506UNSz7brPG35bx6sR-3s8pyMhjgEqbXQqN2CQOr_kyZKcyWfyDiGRaK9HQgg",
            "url": "https://localhost:8005/ca",
        }
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

        # Wrong nonce, non valid base64 encoding
        jwt_headers = {
            "nonce": "AJCmF5Qw-7Dhp93FWDFY1jyQ506UNSz7brPG35bx6sR-3s8pyMhjgEqbXQqN2CQOr_kyZKcyWfyDiGRaK9Hasd!!Qgg",
            "url": "https://localhost:8005/ca",
        }
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

    def test_auth_url(self) -> None:
        """
        Test url auth
        """

        with open("data/trusted_keys/privkey1.key", "rb") as f_data:
            priv_key1 = f_data.read()
        with open("data/trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key1 = f_data.read()

        # No url in token
        req = requests.head("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

        # Wrong url in token
        req = requests.head("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/ca_wrong_url"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

    def test_auth(self) -> None:
        """
        Send requests with valid and invalid jwt tokens
        """

        with open("data/trusted_keys/privkey1.key", "rb") as f_data:
            priv_key1 = f_data.read()
        with open("data/trusted_keys/privkey2.key", "rb") as f_data:
            priv_key2 = f_data.read()
        with open("data/trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key1 = f_data.read()

        # Sign with key2 but send key1 as public key
        req = requests.head("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key2.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

        # Correct auth, HEAD nonce
        req = requests.head("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)

        # Correct auth, GET nonce
        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/ca"}
        jwk_key_data = pem_key_to_jwk(pub_key1.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key1.decode("utf-8"), algorithm="PS256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)

        # Test lib auth
        request_headers = {
            "Authorization": create_jwt_header_str(pub_key1, priv_key1, "https://localhost:8005/search/ca")
        }
        req = requests.get("https://localhost:8005/search/ca", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)

    def test_aia_cdp_auth(self) -> None:
        """
        No auth for these but 404 when non existing url
        """

        req = requests.get("https://localhost:8005/ca/acac22352343423", timeout=5, verify=False)
        self.assertTrue(req.status_code == 404)
        req = requests.get("https://localhost:8005/crl/acac22352343423", timeout=5, verify=False)
        self.assertTrue(req.status_code == 404)

    def test_auth_secp256r1(self) -> None:
        """
        Send requests with valid and invalid jwt tokens
        """

        if "secp256r1" not in KEY_TYPES:
            print("Skipping secp256r1 test")
            return

        with open("data/trusted_keys/privkey4.key", "rb") as f_data:
            priv_key4 = f_data.read()
        with open("data/trusted_keys/pubkey4.pem", "rb") as f_data:
            pub_key4 = f_data.read()

        # Correct auth, GET nonce
        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key4.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key4.decode("utf-8"), algorithm="ES256", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/public_key", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)

    def test_auth_secp384r1(self) -> None:
        """
        Send requests with valid and invalid jwt tokens
        """

        if "secp384r1" not in KEY_TYPES:
            print("Skipping secp384r1 test")
            return

        with open("data/trusted_keys/privkey5.key", "rb") as f_data:
            priv_key5 = f_data.read()
        with open("data/trusted_keys/pubkey5.pem", "rb") as f_data:
            pub_key5 = f_data.read()

        # Correct auth, GET nonce
        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key5.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key5.decode("utf-8"), algorithm="ES384", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/public_key", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)

    def test_auth_secp521r1(self) -> None:
        """
        Send requests with valid and invalid jwt tokens
        """

        if "secp521r1" not in KEY_TYPES:
            print("Skipping secp521r1 test")
            return

        with open("data/trusted_keys/privkey6.key", "rb") as f_data:
            priv_key6 = f_data.read()
        with open("data/trusted_keys/pubkey6.pem", "rb") as f_data:
            pub_key6 = f_data.read()

        # Correct auth, GET nonce
        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key6.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key6.decode("utf-8"), algorithm="ES512", headers=jwt_headers)

        # decoded_jwt = jwt.decode(encoded, algorithms=["ES384, ES512"], options={"verify_signature": False})

        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/public_key", headers=request_headers, timeout=5, verify=False)

        self.assertTrue(req.status_code == 200)

    def test_auth_ed25519(self) -> None:
        """
        Send requests with valid and invalid jwt tokens
        """
        if "ed25519" not in KEY_TYPES:
            print("Skipping ed25519 test")
            return

        with open("data/trusted_keys/privkey7.key", "rb") as f_data:
            priv_key7 = f_data.read()
        with open("data/trusted_keys/privkey9.key", "rb") as f_data:
            priv_key9 = f_data.read()
        with open("data/trusted_keys/pubkey7.pem", "rb") as f_data:
            pub_key7 = f_data.read()

        # Correct auth, GET nonce
        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key7.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key7.decode("utf-8"), algorithm="EdDSA", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/public_key", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)

        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)

        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key7.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key9.decode("utf-8"), algorithm="EdDSA", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/public_key", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

    def test_auth_ed448(self) -> None:
        """
        Send requests with valid and invalid jwt tokens
        """
        if "ed448" not in KEY_TYPES:
            print("Skipping ed448 test")
            return

        with open("data/trusted_keys/privkey8.key", "rb") as f_data:
            priv_key8 = f_data.read()
        with open("data/trusted_keys/privkey10.key", "rb") as f_data:
            priv_key10 = f_data.read()
        with open("data/trusted_keys/pubkey8.pem", "rb") as f_data:
            pub_key8 = f_data.read()

        # Correct auth, GET nonce
        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key8.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key8.decode("utf-8"), algorithm="EdDSA", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/public_key", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)

        req = requests.get("https://localhost:8005/new_nonce", timeout=5, verify=False)
        nonce = req.headers["Replay-Nonce"]
        self.assertTrue(req.status_code == 200)
        jwt_headers = {"nonce": nonce, "url": "https://localhost:8005/search/public_key"}
        jwk_key_data = pem_key_to_jwk(pub_key8.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key10.decode("utf-8"), algorithm="EdDSA", headers=jwt_headers)
        request_headers = {"Authorization": "Bearer " + encoded}
        req = requests.get("https://localhost:8005/search/public_key", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)
