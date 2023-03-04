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


def create_key_change_jws(
    kid: str,
    old_jwk: Dict[str, Any],
    inner_jwk: Dict[str, Any],
    priv_key: EllipticCurvePrivateKey,
    priv_key2: EllipticCurvePrivateKey,
) -> Dict[str, Any]:
    nonce = acme_nonce()
    inner_protected = {"alg": "ES256", "jwk": inner_jwk, "url": f"{ROOT_URL}{ACME_ROOT}/key-change"}
    inner_payload = {"account": kid, "oldKey": old_jwk}

    inner_signed_data = (
        to_base64url(json.dumps(inner_protected).encode("utf-8"))
        + "."
        + to_base64url(json.dumps(inner_payload).encode("utf-8"))
    )

    inner_signature = to_base64url(priv_key2.sign(inner_signed_data.encode("utf-8"), ECDSA(SHA256())))

    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": f"{ROOT_URL}{ACME_ROOT}/key-change"}
    payload = {
        "protected": to_base64url(json.dumps(inner_protected).encode("utf-8")),
        "payload": to_base64url(json.dumps(inner_payload).encode("utf-8")),
        "signature": inner_signature,
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


def create_update_account_jws(kid: str, priv_key: EllipticCurvePrivateKey) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": kid}
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:updated@example.org", "mailto:updated2@example.org"],
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
        pub_key_pem1 = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
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
        kid = req.headers["Location"]

        time.sleep(1)
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

        # Update the account
        jwk = pem_key_to_jwk(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
        acme_req = create_update_account_jws(kid, priv_key)
        req = requests.post(
            f"{kid}",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data_updated = json.loads(req.text)
        self.assertTrue(response_data["contact"] != response_data_updated["contact"])

        # key change
        priv_key2 = generate_private_key(SECP256R1())
        public_key2 = priv_key2.public_key()
        jwk2 = pem_key_to_jwk(public_key2.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
        acme_req = create_key_change_jws(kid, jwk, jwk2, priv_key, priv_key2)
        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/key-change",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        print(req.text)
        self.assertTrue(req.status_code == 200)

        time.sleep(1)
        # Try with old key Update the account
        acme_req = create_update_account_jws(kid, priv_key)
        req = requests.post(
            f"{kid}",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 401)

        # Try with old key Update the account
        acme_req = create_update_account_jws(kid, priv_key2)
        req = requests.post(
            f"{kid}",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
