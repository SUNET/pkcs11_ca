"""
Test our certificates
"""
import unittest
import json
import requests

from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

from src.pkcs11_ca_service.asn1 import create_jwt_header_str


class TestCertificate(unittest.TestCase):
    """
    Test our certificates.
    """

    def test_certificate(self) -> None:
        """
        Search for certificates
        """

        with open("trusted_keys/privkey1.key", "rb") as f_data:
            priv_key = f_data.read()
        with open("trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()

        # All certificates
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(
            pub_key, priv_key, "http://localhost:8000/search/certificate"
        )
        req = requests.get("http://localhost:8000/search/certificate", headers=request_headers)
        self.assertTrue(req.status_code == 200)
        certs = json.loads(req.text)["certificates"]
        self.assertTrue(isinstance(certs, list))

        if certs:
            # Search for certificates
            request_headers = {}
            request_headers["Authorization"] = create_jwt_header_str(
                pub_key, priv_key, "http://localhost:8000/search/certificate"
            )
            data = json.loads('{"pem": ' + '"' + certs[0].replace("\n", "\\n") + '"' + "}")
            req = requests.post("http://localhost:8000/search/certificate", headers=request_headers, json=data)
            self.assertTrue(req.status_code == 200)
            certs = json.loads(req.text)["certificates"]
            self.assertTrue(len(certs) == 1)

            cert_data = certs[0].encode("utf-8")
            if asn1_pem.detect(cert_data):
                _, _, cert_data = asn1_pem.unarmor(cert_data)
            self.assertTrue(isinstance(asn1_x509.Certificate.load(cert_data), asn1_x509.Certificate))
