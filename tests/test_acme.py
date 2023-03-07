"""
Test our acme
"""
from typing import Dict, Any, Union
import unittest
import os
import json
import hashlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

import subprocess

from asn1crypto import csr as asn1_csr
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, generate_private_key, SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256

from src.pkcs11_ca_service.asn1 import pem_key_to_jwk, from_base64url, to_base64url
from src.pkcs11_ca_service.config import ROOT_URL, ACME_ROOT


class AcmeChallengeHTTPRequestHandler(BaseHTTPRequestHandler):
    ACME_CHALLENGE: str

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.ACME_CHALLENGE.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(self.ACME_CHALLENGE.encode("utf-8"))
        self.server.shutdown()
        self.server.server_close()

    # Disable logging in unittest
    def log_request(self, code: Union[int, str] = "-", size: Union[int, str] = "-") -> None:
        pass


def run_http_server(key_authorization: str) -> None:
    server_address = ("", 80)
    AcmeChallengeHTTPRequestHandler.ACME_CHALLENGE = key_authorization

    httpd = HTTPServer(server_address, AcmeChallengeHTTPRequestHandler)
    httpd.timeout = 3
    httpd.handle_request()


def acme_nonce() -> str:
    req = requests.head(f"{ROOT_URL}{ACME_ROOT}/new-nonce", timeout=10, verify="./tls_certificate.pem")
    return req.headers["Replay-Nonce"]


def get_orders_jws(kid: str, priv_key2: EllipticCurvePrivateKey, url: str) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}
    payload: Dict[str, str] = {}

    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )

    signature = to_base64url(priv_key2.sign(signed_data.encode("utf-8"), ECDSA(SHA256())))
    acme_req = {
        "protected": to_base64url(json.dumps(protected).encode("utf-8")),
        "payload": to_base64url(json.dumps(payload).encode("utf-8")),
        "signature": signature,
    }

    return acme_req


def send_csr_jws(kid: str, priv_key2: EllipticCurvePrivateKey, url: str) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}

    cmd = [
        "bash",
        "-c",
        'openssl req -new -subj "/C=SE/CN='
        + os.environ["HOSTNAME"]
        + '" -addext "subjectAltName = DNS:'
        + os.environ["HOSTNAME"]
        + '" -newkey rsa:2048 -nodes -keyout key.pem -out req.pem 2> /dev/null',
    ]
    subprocess.call(cmd)
    with open("req.pem", "rb") as f_data:
        csr = f_data.read()

    cmd = ["bash", "-c", "rm -rf key.pem req.pem"]
    subprocess.call(cmd)

    if asn1_pem.detect(csr):
        _, _, csr = asn1_pem.unarmor(csr)
    csr_asn1 = asn1_csr.CertificationRequest().load(csr)

    payload: Dict[str, str] = {"csr": to_base64url(csr_asn1.dump())}

    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )

    signature = to_base64url(priv_key2.sign(signed_data.encode("utf-8"), ECDSA(SHA256())))
    acme_req = {
        "protected": to_base64url(json.dumps(protected).encode("utf-8")),
        "payload": to_base64url(json.dumps(payload).encode("utf-8")),
        "signature": signature,
    }

    return acme_req


def get_authz_jws(kid: str, priv_key2: EllipticCurvePrivateKey, url: str) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}
    payload: Dict[str, str] = {}

    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )

    signature = to_base64url(priv_key2.sign(signed_data.encode("utf-8"), ECDSA(SHA256())))
    acme_req = {
        "protected": to_base64url(json.dumps(protected).encode("utf-8")),
        "payload": to_base64url(json.dumps(payload).encode("utf-8")),
        "signature": signature,
    }

    return acme_req


def new_order_jws(kid: str, priv_key2: EllipticCurvePrivateKey) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": f"{ROOT_URL}{ACME_ROOT}/new-order"}
    payload = {
        "identifiers": [
            {"type": "dns", "value": os.environ["HOSTNAME"]},
            # {"type": "dns", "value": "www.test1"},
        ],
        "notBefore": "2023-01-01T00:04:00+04:00",
        "notAfter": "2025-01-01T00:04:00+04:00",
    }

    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )

    signature = to_base64url(priv_key2.sign(signed_data.encode("utf-8"), ECDSA(SHA256())))
    acme_req = {
        "protected": to_base64url(json.dumps(protected).encode("utf-8")),
        "payload": to_base64url(json.dumps(payload).encode("utf-8")),
        "signature": signature,
    }

    return acme_req


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
        orders = response_data["orders"]

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
        self.assertTrue(req.status_code == 200)

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

        # Create new order
        acme_req = new_order_jws(kid, priv_key2)
        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/new-order",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 201)
        response_data = json.loads(req.text)
        authz = response_data["authorizations"][0]

        # List orders
        acme_req = get_orders_jws(kid, priv_key2, orders)
        req = requests.post(
            orders,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)
        order = response_data["orders"][0]

        # Get order
        acme_req = get_authz_jws(kid, priv_key2, order)
        req = requests.post(
            order,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)
        self.assertTrue(response_data["status"] == "pending")

        # Get authz
        acme_req = get_authz_jws(kid, priv_key2, authz)
        req = requests.post(
            authz,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)
        challenge = response_data["challenges"][0]

        # Handle acme challenge in background http server
        hash_module = hashlib.sha256()
        hash_module.update(kid.encode("utf-8"))
        key_authorization = f"{challenge['token']}.{to_base64url(hash_module.digest())}"
        t = threading.Thread(target=run_http_server, args=(key_authorization,), daemon=True)
        t.start()

        # Trigger challenge
        acme_req = get_authz_jws(kid, priv_key2, challenge["url"])
        req = requests.post(
            challenge["url"],
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)

        # Get authz after challenge
        acme_req = get_authz_jws(kid, priv_key2, authz)
        req = requests.post(
            authz,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)
        self.assertTrue(response_data["status"] == "valid")

        # Get order after challenge
        acme_req = get_authz_jws(kid, priv_key2, order)
        req = requests.post(
            order,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)
        self.assertTrue(response_data["status"] == "ready")
        finalize_url = response_data["finalize"]

        # Send csr
        acme_req = send_csr_jws(kid, priv_key2, finalize_url)
        req = requests.post(
            finalize_url,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)

        # Get order after challenge
        acme_req = get_authz_jws(kid, priv_key2, order)
        req = requests.post(
            order,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)
        self.assertTrue(response_data["status"] == "valid")
        cert_url = response_data["certificate"]

        # get cert
        acme_req = get_authz_jws(kid, priv_key2, cert_url)
        req = requests.post(
            cert_url,
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        certs = req.text.split("-----BEGIN CERTIFICATE-----")
        for issued_cert in certs:
            if len(issued_cert) < 3:
                continue

            data = ("-----BEGIN CERTIFICATE-----" + issued_cert).encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)

            cert_asn1 = asn1_x509.Certificate().load(data)
            _ = cert_asn1.native
