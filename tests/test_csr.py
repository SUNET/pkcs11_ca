"""
Test our auth
"""
import unittest
import requests
import datetime
import os
import jwt
import json

from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem
from src.pkcs11_ca_service.asn1 import pem_key_to_jwk


class TestCsr(unittest.TestCase):
    """
    Test our auth.
    """

    def test_csr(self) -> None:
        """
        Send requests with valid and invald jwt tokens
        """

        req = requests.head("http://localhost:8000/new_nonce")
        print(req.status_code)
        nonce = req.headers["Replay-Nonce"]
        # self.assertTrue(req.status_code == 401)

        with open("trusted_pub_keys/privkey1.key", "rb") as f:
            priv_key = f.read()
        with open("trusted_pub_keys/privkey2.key", "rb") as f:
            priv_key2 = f.read()
        with open("trusted_pub_keys/pubkey1.pem", "rb") as f:
            pub_key = f.read()
        with open("trusted_pub_keys/pubkey2.pem", "rb") as f:
            pub_key2 = f.read()

        jwt_headers = {"nonce": nonce, "url": "http://localhost:8000/sign_csr"}
        jwk_key_data = pem_key_to_jwk(pub_key.decode("utf-8"))
        encoded = jwt.encode(jwk_key_data, priv_key, algorithm="PS256", headers=jwt_headers)
        headers = {}
        headers["Authorization"] = "Bearer " + encoded.decode("utf-8")
        # print (headers)

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

        data = json.loads('{"pem": "' + test_csr.replace("\n", "\\n") + '"}')
        req = requests.post("http://localhost:8000/sign_csr", headers=headers, json=data)
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_cert = asn1_x509.Certificate.load(data)
        self.assertTrue(isinstance(test_cert, asn1_x509.Certificate))
