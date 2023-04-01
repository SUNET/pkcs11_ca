"""
Test our csr signing
"""
import json
import os
import unittest

import requests
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509

from src.pkcs11_ca_service.asn1 import create_jwt_header_str
from src.pkcs11_ca_service.config import ROOT_URL

from .lib import create_i_ca, verify_cert, verify_pkcs11_ca_tls_cert


class TestCsr(unittest.TestCase):
    """
    Test our csrs.
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm_test",
        "organization_name": "SUNET_csr",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test-csr-51.sunet.se",
    }

    def test_csr(self) -> None:
        """
        Sign csrs
        """

        with open("data/trusted_keys/privkey1.key", "rb") as f_data:
            priv_key = f_data.read()
        with open("data/trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()

        # Sign a csr
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/sign_csr")}

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

        data = {"pem": test_csr, "ca_pem": create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)}
        req = requests.post(
            self.ca_url + "/sign_csr",
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        cert_given = json.loads(req.text)["certificate"]
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        self.assertTrue(isinstance(asn1_x509.Certificate.load(data), asn1_x509.Certificate))
        verify_cert(cert_given)

        # Get cert from our csr
        request_headers = {
            "Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/search/certificate")
        }
        data = json.loads('{"pem": ' + '"' + cert_given.replace("\n", "\\n") + '"' + "}")
        req = requests.post(
            self.ca_url + "/search/certificate",
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)
        certs = json.loads(req.text)["certificates"]
        self.assertTrue(len(certs) == 1)
        self.assertTrue(certs[0] == cert_given)
