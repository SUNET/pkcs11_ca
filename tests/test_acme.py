"""
Test our acme
"""
from typing import Dict, Any
import unittest
import os
import json
import time

import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, generate_private_key, SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256

from src.pkcs11_ca_service.asn1 import pem_key_to_jwk, from_base64url, to_base64url
from src.pkcs11_ca_service.config import ROOT_URL, ACME_ROOT


def acme_nonce() -> str:
    req = requests.head(f"{ROOT_URL}{ACME_ROOT}/new-nonce", timeout=10, verify="./tls_certificate.pem")
    return req.headers["Replay-Nonce"]


def create_new_account_jws(jwk: Dict[str, Any], priv_key: EllipticCurvePrivateKey) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": f"{ROOT_URL}{ACME_ROOT}/new-account"}
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:cert-admin@example.org", "mailto:cert-admin2@example.org"],
    }

    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )

    signature = to_base64url(priv_key.sign(signed_data.encode("utf-8"), ECDSA(SHA256())))
    acme_req = {
        "protected": to_base64url(json.dumps(protected).encode("utf-8")),
        "payload": to_base64url(json.dumps(payload).encode("utf-8")),
        "signature": signature,
    }

    return acme_req


class TestAcme(unittest.TestCase):
    """
    Test our acme
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def test_acme(self) -> None:
        """
        Test acme
        """

        request_headers = {"Content-Type": "application/jose+json"}

        priv_key = generate_private_key(SECP256R1())
        public_key = priv_key.public_key()

        jwk = pem_key_to_jwk(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
        acme_req = create_new_account_jws(jwk, priv_key)

        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/new-account",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 201)
        response_data = json.loads(req.text)
        print("new-account")
        print(response_data)

        time.sleep(2)
        jwk = pem_key_to_jwk(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
        acme_req = create_new_account_jws(jwk, priv_key)

        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/new-account",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)
