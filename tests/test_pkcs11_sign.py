"""
Test our pkcs11_sign
"""
import unittest
import os
import json
import base64
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.hashes import SHA256

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
            {
                "id": "doc3",
                "data": "MEQCIAJ2fcp/sSODCXbkr0HWCkdLYBgYtCzTdqC65bAOLj1PAiAqPv5kNZdtkdATrRYjZ8TETV0dsPUOz6zQutCEk7Uq/g==",  # pylint: disable=line-too-long
            },  # pylint: disable=line-too-long
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
        response_data = json.loads(req.text)

        # Load the signers public key
        signer_public_key = serialization.load_pem_public_key(
            response_data["meta"]["signer_public_key"].encode("utf-8")
        )
        if not isinstance(signer_public_key, EllipticCurvePublicKey):
            raise TypeError

        # Verify the signatures
        for index, _ in enumerate(response_data["signature_values"]):
            signer_public_key.verify(
                base64.b64decode(response_data["signature_values"][index]["signature"].encode("utf-8")),
                base64.b64decode(self.request_data["documents"][index]["data"].encode("utf-8")),  # type: ignore
                ECDSA(SHA256()),
            )
