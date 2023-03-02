"""
Test our pkcs11_sign
"""
import unittest
import os
import base64
import requests

from src.pkcs11_ca_service.config import ROOT_URL, PKCS11_SIGN_API_TOKEN


class TestPKCS11Sign(unittest.TestCase):
    """
    Test our pkcs11_sign
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    request_data = {
        "meta": {
            "version": 1,
            "encoding": "base64",
            "key_label": "pkcs11_sign_test15",
            "key_type": "secp256r1",
        },
        "documents": [
            {"id": "doc1", "data": "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149"},
            {"id": "doc2", "data": "913271fd1510ceb9827d3982bd83200722f434f50ada2578e57c19ef07c08367"},
            {"id": "doc3", "data": "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149"},
        ],
    }

    def test_pkcs11_sign(self) -> None:
        """
        Search for pkcs11_sign
        """

        request_headers = {
            "Authorization": f"Bearer {base64.b64encode(PKCS11_SIGN_API_TOKEN.encode('UTF-8')).decode('UTF-8')}"
        }

        req = requests.post(
            self.ca_url + "/pkcs11_sign",
            headers=request_headers,
            json=self.request_data,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)

