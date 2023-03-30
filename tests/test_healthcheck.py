"""
Test our ca
"""
import os
import unittest

import requests

from src.pkcs11_ca_service.asn1 import create_jwt_header_str
from src.pkcs11_ca_service.config import ROOT_URL

with open("data/trusted_keys/privkey1.key", "rb") as file_data:
    priv_key = file_data.read()
with open("data/trusted_keys/pubkey1.pem", "rb") as file_data:
    pub_key = file_data.read()


class TesthealthCheck(unittest.TestCase):
    """
    Test our ca
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def test_healthcheck(self) -> None:
        """
        Test healthcheck
        """

        # Test no auth
        req = requests.get(self.ca_url + "/healthcheck", timeout=10, verify="./tls_certificate.pem")
        self.assertTrue(req.status_code == 401)

        # Test ok auth
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/healthcheck")}
        req = requests.get(
            self.ca_url + "/healthcheck", headers=request_headers, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 200)
