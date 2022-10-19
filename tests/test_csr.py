"""
Test our csr signing
"""
import unittest
import json

import requests
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

from src.pkcs11_ca_service.asn1 import create_jwt_header_str
from .lib import get_cas, verify_cert


class TestCsr(unittest.TestCase):
    """
    Test our csrs.
    """

    def test_csr(self) -> None:
        """
        Sign csrs
        """

        with open("trusted_keys/privkey1.key", "rb") as f_data:
            priv_key = f_data.read()
        with open("trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()

        cas = get_cas(pub_key, priv_key)

        # Sign a csr
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/sign_csr")

        test_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIICtjCCAZ4CAQAwcTELMAkGA1UEBhMCQVUxDDAKBgNVBAgMA3NkZjEMMAoGA1UE
BwwDc2RmMQwwCgYDVQQKDANzZGYxDDAKBgNVBAsMA3NkZjEWMBQGA1UEAwwNc2Rm
c2RmLnNkZnNkZjESMBAGCSqGSIb3DQEJARYDc2RmMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAnBmLrb9R2xVk2A+XDhcSOrGB1aUVlB2QKXNZ2l1++fM7
Fb4zhfuaBsyGWGMgL7QBXLXgF4S+1QtYSSj6KcXNEtxWOqlDcH2AMT8HFzuaPz1w
2Qq/gw4VaYTPzW/ReRzjgxI4HZbgN7iTAHzSwyphQmA2zWeHSt4lTrkGhVJ9Brpv
dPVH6YMzpeMqoWA3Sdd0doF9jAnenb/zz4GWrhITo9iKsQVGF4pOGZhtdQNq9rYB
+qHCvvn2gWBKxVLnwlaDAXGZ6YfeME4awclYicXkFZuYFvArSqSEaiX+H2vngCF5
T/pamU7I/ChvOFCJlUVK9+PjCHgYDIoO0XWho4LwJQIDAQABoAAwDQYJKoZIhvcN
AQELBQADggEBAGnOwZ643cetJURpSkVvo8EHQUMS1e737K2mXCfal5u1uA0607ce
iRX+sfFFuxIkBXfWrD8YYmqarRT12AiY/PLc92thaL+mdZ2PdNn/8eYkggers9Vy
x6XUaMRekeY6oB6gwd1zVfPFz3h8zmvcZ0t8ON+Lwrwv6Xk4kofT0SSakZejNdZS
JWQgZse8HAlf250/6ceGkFVR9NOm9ZRpz2vJhfhMK0M0rL0AeaZOKPxH7I1V8auG
MLlDOStjm6AHkmVST6nJ9yL3NUHWk7Ze78xCXBY5s6mCaWwqbozQbkPc+bELa9tM
wN8Kg29Nb5vW5Pq0vUy3o1Hc/51W6Lyr1Go=
-----END CERTIFICATE REQUEST-----
"""

        data = json.loads(
            '{"pem": "'
            + test_csr.replace("\n", "\\n")
            + '"'
            + ","
            + '"ca_pem": '
            + '"'
            + cas[0].replace("\n", "\\n")
            + '"'
            + "}"
        )
        req = requests.post("http://localhost:8000/sign_csr", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        cert_given = json.loads(req.text)["certificate"]
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        self.assertTrue(isinstance(asn1_x509.Certificate.load(data), asn1_x509.Certificate))
        verify_cert(cert_given)

        # Get cert from our csr
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(
            pub_key, priv_key, "http://localhost:8000/search/certificate"
        )
        data = json.loads('{"pem": ' + '"' + cert_given.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/search/certificate", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)
        certs = json.loads(req.text)["certificates"]
        self.assertTrue(len(certs) == 1)
        self.assertTrue(certs[0] == cert_given)
