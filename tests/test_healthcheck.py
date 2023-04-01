"""
Test our ca
"""
import os
import unittest

import requests

from src.pkcs11_ca_service.asn1 import create_jwt_header_str
from src.pkcs11_ca_service.config import ROOT_URL

from .lib import verify_pkcs11_ca_tls_cert

HEALTHCHECK_ENDPOINT = "/healthcheck"


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
        req = requests.get(self.ca_url + HEALTHCHECK_ENDPOINT, timeout=10, verify=verify_pkcs11_ca_tls_cert())
        self.assertTrue(req.status_code == 401)

        # Test ok auth
        request_headers = {
            "Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + HEALTHCHECK_ENDPOINT)
        }
        req = requests.get(
            self.ca_url + HEALTHCHECK_ENDPOINT, headers=request_headers, timeout=10, verify=verify_pkcs11_ca_tls_cert()
        )
        self.assertTrue(req.status_code == 200)
