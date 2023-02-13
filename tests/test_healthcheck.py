"""
Test our ca
"""
import unittest
import requests
from src.pkcs11_ca_service.asn1 import create_jwt_header_str

with open("data/trusted_keys/privkey1.key", "rb") as file_data:
    priv_key = file_data.read()
with open("data/trusted_keys/pubkey1.pem", "rb") as file_data:
    pub_key = file_data.read()


class TesthealthCheck(unittest.TestCase):
    """
    Test our ca
    """

    def test_healthcheck(self) -> None:
        """
        Test healthcheck
        """

        # Test no auth
        req = requests.get("https://localhost:8005/healthcheck", timeout=5, verify=False)
        self.assertTrue(req.status_code == 401)

        # Test ok auth
        request_headers = {
            "Authorization": create_jwt_header_str(pub_key, priv_key, "https://localhost:8005/healthcheck")
        }
        req = requests.get("https://localhost:8005/healthcheck", headers=request_headers, timeout=5, verify=False)
        self.assertTrue(req.status_code == 200)
