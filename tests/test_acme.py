"""
Test our acme
"""
from typing import Dict, Any, Union
import unittest
import os
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import datetime
import base64
import secrets

import requests

from asn1crypto import csr as asn1_csr
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

from python_x509_pkcs11.crypto import convert_asn1_ec_signature

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_der_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, generate_private_key, SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography import x509
from cryptography.x509.oid import NameOID

from src.pkcs11_ca_service.asn1 import pem_key_to_jwk, to_base64url, jwk_thumbprint
from src.pkcs11_ca_service.config import ROOT_URL, ACME_ROOT


class AcmeChallengeHTTPRequestHandler(BaseHTTPRequestHandler):
    token: str
    key_authorization: str

    def do_GET(self) -> None:
        if self.path == f"/.well-known/acme-challenge/{self.token}":
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.key_authorization.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(self.key_authorization.encode("utf-8"))
        else:
            self.send_response(401)
            self.send_header("Content-Length", str(len(b"error")))
            self.end_headers()
            self.wfile.write(b"error")

        self.server.server_close()
        self.server.shutdown()

    # Disable logging in unittest
    def log_request(self, code: Union[int, str] = "-", size: Union[int, str] = "-") -> None:
        pass


def run_http_server(token: str, key_authorization: str) -> None:
    server_address = ("", 80)
    AcmeChallengeHTTPRequestHandler.token = token
    AcmeChallengeHTTPRequestHandler.key_authorization = key_authorization

    httpd = HTTPServer(server_address, AcmeChallengeHTTPRequestHandler)
    httpd.timeout = 5
    httpd.handle_request()


def acme_nonce() -> str:
    req = requests.head(f"{ROOT_URL}{ACME_ROOT}/new-nonce", timeout=10, verify="./tls_certificate.pem")
    return req.headers["Replay-Nonce"]


def create_sunet_token(priv_key: EllipticCurvePrivateKey, cert_der: bytes) -> str:
    header = {
        "alg": "ES256",
        "typ": "JWT",
        "url": "https://ca:8005/acme/new-authz",
        "x5c": [base64.b64encode(cert_der).decode("utf-8")],
    }
    payload = {
        "names": [os.environ["HOSTNAME"]],
        "nonce": acme_nonce(),
        "aud": "https://ca:8005/acme/new-authz",
        "iat": 1678536328,
        "exp": 1688536328,
        "crit": ["exp"],
    }
    signed_data = (
        to_base64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + to_base64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    )

    raw_signature = priv_key.sign(signed_data.encode("utf-8"), ECDSA(SHA256()))
    signature = to_base64url(convert_asn1_ec_signature(raw_signature, "secp256r1"))
    return f"{signed_data}.{signature}"


def create_payload(
    protected: Dict[str, Any], payload: Dict[str, Any], priv_key: EllipticCurvePrivateKey
) -> Dict[str, Any]:
    signed_data = (
        to_base64url(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
        + "."
        + to_base64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    )

    signature = to_base64url(priv_key.sign(signed_data.encode("utf-8"), ECDSA(SHA256())))
    acme_req = {
        "protected": to_base64url(json.dumps(protected, separators=(",", ":")).encode("utf-8")),
        "payload": to_base64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        "signature": signature,
    }
    return acme_req


def get_orders_jws(kid: str, priv_key: EllipticCurvePrivateKey, url: str) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}
    payload: Dict[str, str] = {}
    return create_payload(protected, payload, priv_key)


def revoke_cert_jws(
    kid: str, priv_key: EllipticCurvePrivateKey, url: str, cert: asn1_x509.Certificate
) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}
    payload: Dict[str, Union[str, int]] = {"certificate": to_base64url(cert.dump()), "reason": 4}
    return create_payload(protected, payload, priv_key)


def send_csr_jws(kid: str, priv_key: EllipticCurvePrivateKey, url: str) -> Dict[str, Any]:
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
    return create_payload(protected, payload, priv_key)


def new_authz_sunet_token_jws(kid: str, priv_key: EllipticCurvePrivateKey, cert_der: bytes) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": f"{ROOT_URL}{ACME_ROOT}/new-authz"}
    payload = {
        "token": create_sunet_token(priv_key, cert_der)
        # {"type": "dns", "value": "www.test1"},
    }
    return create_payload(protected, payload, priv_key)


def new_authz_jws(kid: str, priv_key: EllipticCurvePrivateKey) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": f"{ROOT_URL}{ACME_ROOT}/new-authz"}
    payload = {
        "identifier": {"type": "dns", "value": os.environ["HOSTNAME"]},
        # {"type": "dns", "value": "www.test1"},
    }
    return create_payload(protected, payload, priv_key)


def get_authz_jws(kid: str, priv_key: EllipticCurvePrivateKey, url: str) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}
    payload: Dict[str, str] = {}
    return create_payload(protected, payload, priv_key)


def new_order_jws(kid: str, priv_key: EllipticCurvePrivateKey) -> Dict[str, Any]:
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
    return create_payload(protected, payload, priv_key)


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
        to_base64url(json.dumps(inner_protected, separators=(",", ":")).encode("utf-8"))
        + "."
        + to_base64url(json.dumps(inner_payload, separators=(",", ":")).encode("utf-8"))
    )

    inner_signature = to_base64url(priv_key2.sign(inner_signed_data.encode("utf-8"), ECDSA(SHA256())))

    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": f"{ROOT_URL}{ACME_ROOT}/key-change"}
    payload = {
        "protected": to_base64url(json.dumps(inner_protected, separators=(",", ":")).encode("utf-8")),
        "payload": to_base64url(json.dumps(inner_payload, separators=(",", ":")).encode("utf-8")),
        "signature": inner_signature,
    }
    return create_payload(protected, payload, priv_key)


def create_update_account_jws(kid: str, priv_key: EllipticCurvePrivateKey) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "kid": kid, "nonce": nonce, "url": kid}
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:updated@example.org", "mailto:updated2@example.org"],
    }
    return create_payload(protected, payload, priv_key)


def create_new_account_jws(jwk: Dict[str, Any], priv_key: EllipticCurvePrivateKey) -> Dict[str, Any]:
    nonce = acme_nonce()
    protected = {"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": f"{ROOT_URL}{ACME_ROOT}/new-account"}
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:cert-admin@example.org", "mailto:cert-admin2@example.org"],
    }
    return create_payload(protected, payload, priv_key)


class TestAcme(unittest.TestCase):
    """
    Test our acme
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def test_acme_directory(self) -> None:
        acme_urls = ["newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"]

        req = requests.get(
            f"{ROOT_URL}{ACME_ROOT}/directory",
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        response_data = json.loads(req.text)

        for acme_url in acme_urls:
            self.assertTrue(acme_url in response_data)

            req = requests.post(
                response_data[acme_url],
                timeout=10,
                verify="./tls_certificate.pem",
            )
            self.assertTrue(req.status_code not in (200, 404))

    # Works but cant bind to port 80 due to test_acme() also binds to port 80
    #     def test_acme_dehydrated(self) -> None:
    #         acme_test_script = """from typing import Union
    # import threading
    # from http.server import BaseHTTPRequestHandler, HTTPServer
    # import time
    # import subprocess
    # import sys
    # import os
    #
    # class AcmeChallengeHTTPRequestHandler(BaseHTTPRequestHandler):
    #     def do_GET(self) -> None:
    #
    #         tokens = os.listdir("http_server")
    #         if len(tokens) != 1:
    #             print("ERROR: must have only one token in ./http_server")
    #             sys.exit(1)
    #
    #
    #         with open(f"http_server/{tokens[0]}", "rb") as f_data:
    #             key_auth = f_data.read()
    #
    #         self.send_response(200)
    #         self.send_header("Content-Length", str(len(key_auth)))
    #         self.end_headers()
    #
    #         self.wfile.write(key_auth)
    #         self.server.server_close()
    #         self.server.shutdown()
    #
    #
    # def run_http_server() -> None:
    #     server_address = ("", 80)
    #     httpd = HTTPServer(server_address, AcmeChallengeHTTPRequestHandler)
    #     httpd.timeout = 10
    #     httpd.handle_request()
    #
    #
    #
    # t = threading.Thread(target=run_http_server, daemon=True)
    # t.start()
    #
    # time.sleep(2)
    #
    # subprocess.call(["bash", "-c", "echo $HOSTNAME > domains.txt"])
    # subprocess.call(["bash", "-c", 'openssl req -subj "/C=SE/CN=my-web-server" -addext "subjectAltName = DNS:${HOSTNAME}" -new -newkey rsa:2048 -nodes -keyout csr_rsa.key -out csr_rsa.pem'])
    #
    # subprocess.call(["bash", "-c", "rm -rf http_server/ accounts/ && mkdir -p http_server/ && bash dehydrated --register --accept-terms && sleep 1 && bash dehydrated --signcsr csr_rsa.pem | grep -v '# CERT #' > chain.pem && sleep 1 && bash dehydrated --revoke chain.pem"])
    # """
    #
    #         dehydrated_patch = """diff --git a/dehydrated b/dehydrated
    # index a2bff40..fe8a3f4 100755
    # --- a/dehydrated
    # +++ b/dehydrated
    # @@ -350,6 +350,7 @@ load_config() {
    #    fi
    #
    #    # Preset
    # +  CA_PKCS11CA="https://ca:8005/acme/directory"
    #    CA_ZEROSSL="https://acme.zerossl.com/v2/DV90"
    #    CA_LETSENCRYPT="https://acme-v02.api.letsencrypt.org/directory"
    #    CA_LETSENCRYPT_TEST="https://acme-staging-v02.api.letsencrypt.org/directory"
    # @@ -357,16 +358,18 @@ load_config() {
    #    CA_BUYPASS_TEST="https://api.test4.buypass.no/acme/directory"
    #
    #    # Default values
    # -  CA="letsencrypt"
    # +  # CA="letsencrypt"
    # +  CA="pkcs11ca"
    #    OLDCA=
    #    CERTDIR=
    #    ALPNCERTDIR=
    #    ACCOUNTDIR=
    #    ACCOUNT_KEYSIZE="4096"
    # -  ACCOUNT_KEY_ALGO=rsa
    # +  # ACCOUNT_KEY_ALGO=rsa
    # +  ACCOUNT_KEY_ALGO=secp384r1
    #    CHALLENGETYPE="http-01"
    #    CONFIG_D=
    # -  CURL_OPTS=
    # +  CURL_OPTS=" -k "
    #    DOMAINS_D=
    #    DOMAINS_TXT=
    #    HOOK=
    # @@ -471,7 +474,9 @@ load_config() {
    #    fi
    #
    #    # Preset CAs
    # -  if [ "${CA}" = "letsencrypt" ]; then
    # +  if [ "${CA}" = "pkcs11ca" ]; then
    # +    CA="${CA_PKCS11CA}"
    # +  elif [ "${CA}" = "letsencrypt" ]; then
    #      CA="${CA_LETSENCRYPT}"
    #    elif [ "${CA}" = "letsencrypt-test" ]; then
    #      CA="${CA_LETSENCRYPT_TEST}"
    # @@ -529,7 +534,7 @@ load_config() {
    #    [[ -z "${ALPNCERTDIR}" ]] && ALPNCERTDIR="${BASEDIR}/alpn-certs"
    #    [[ -z "${CHAINCACHE}" ]] && CHAINCACHE="${BASEDIR}/chains"
    #    [[ -z "${DOMAINS_TXT}" ]] && DOMAINS_TXT="${BASEDIR}/domains.txt"
    # -  [[ -z "${WELLKNOWN}" ]] && WELLKNOWN="/var/www/dehydrated"
    # +  [[ -z "${WELLKNOWN}" ]] && WELLKNOWN="http_server"
    #    [[ -z "${LOCKFILE}" ]] && LOCKFILE="${BASEDIR}/lock"
    #    [[ -z "${OPENSSL_CNF}" ]] && OPENSSL_CNF="$("${OPENSSL}" version -d | cut -d\\" -f2)/openssl.cnf"
    #    [[ -n "${PARAM_LOCKFILE_SUFFIX:-}" ]] && LOCKFILE="${LOCKFILE}-${PARAM_LOCKFILE_SUFFIX}"
    # """
    #         subprocess.check_call(
    #             ["bash", "-c", "git clone https://github.com/dehydrated-io/dehydrated.git dehydrated_repo"]
    #         )
    #         with open("pkcs11_ca.patch", "wb") as f_data:
    #             f_data.write(dehydrated_patch.encode("utf-8"))
    #         with open("acme_test.py", "wb") as f_data:
    #             f_data.write(acme_test_script.encode("utf-8"))
    #         subprocess.check_call(["bash", "-c", "cd dehydrated_repo && git apply ../pkcs11_ca.patch && cd .."])
    #         subprocess.check_call(["bash", "-c", "cp dehydrated_repo/dehydrated ."])
    #         subprocess.check_call(["bash", "-c", "python3 acme_test.py"])

    def test_acme(self) -> None:
        """
        Test acme
        """

        request_headers = {"Content-Type": "application/jose+json"}

        priv_key = generate_private_key(SECP256R1())
        public_key = priv_key.public_key()

        jwk = pem_key_to_jwk(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
        # pub_key_pem1 = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
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
        response_data = json.loads(req.text)
        self.assertTrue("status" in response_data)

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
        key_authorization = f"{challenge['token']}.{to_base64url(jwk_thumbprint(jwk2))}"
        thread = threading.Thread(target=run_http_server, args=(challenge["token"], key_authorization), daemon=True)
        thread.start()

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
        issued_cert_asn1 = asn1_x509.Certificate()
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
        self.assertTrue(len(certs) > 1)

        for index in range(len(certs)):
            if len(certs[index]) < 3:
                continue

            data = ("-----BEGIN CERTIFICATE-----" + certs[index]).encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)

            cert_asn1 = asn1_x509.Certificate().load(data)
            _ = cert_asn1.native

            if index == 1:  # First cert in chain - the leaf
                issued_cert_asn1 = asn1_x509.Certificate().load(data)

        # Revoke cert
        acme_req = revoke_cert_jws(kid, priv_key2, f"{ROOT_URL}{ACME_ROOT}/revoke-cert", issued_cert_asn1)
        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/revoke-cert",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)

    def test_acme_pre_auth(self) -> None:
        """
        Test acme
        """

        request_headers = {"Content-Type": "application/jose+json"}

        priv_key2 = generate_private_key(SECP256R1())
        public_key2 = priv_key2.public_key()

        jwk = pem_key_to_jwk(public_key2.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
        # pub_key_pem1 = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        acme_req = create_new_account_jws(jwk, priv_key2)

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

        acme_req = create_new_account_jws(jwk, priv_key2)

        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/new-account",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)

        # Create pre authz
        acme_req = new_authz_jws(kid, priv_key2)
        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/new-authz",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 201)

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
        key_authorization = f"{challenge['token']}.{to_base64url(jwk_thumbprint(jwk))}"
        thread = threading.Thread(target=run_http_server, args=(challenge["token"], key_authorization), daemon=True)
        thread.start()

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
        issued_cert_asn1 = asn1_x509.Certificate()
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
        self.assertTrue(len(certs) > 1)

        for index in range(len(certs)):
            if len(certs[index]) < 3:
                continue

            data = ("-----BEGIN CERTIFICATE-----" + certs[index]).encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)

            cert_asn1 = asn1_x509.Certificate().load(data)
            _ = cert_asn1.native

            if index == 1:  # First cert in chain - the leaf
                issued_cert_asn1 = asn1_x509.Certificate().load(data)

        # Revoke cert
        acme_req = revoke_cert_jws(kid, priv_key2, f"{ROOT_URL}{ACME_ROOT}/revoke-cert", issued_cert_asn1)
        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/revoke-cert",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)

    def test_acme_pre_auth_sunet_token(self) -> None:
        """
        Test acme
        """

        request_headers = {"Content-Type": "application/jose+json"}

        issuer_priv_key = load_der_private_key(
            b"0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01"
            b"\x04 Y\x85Dy\xec\x92f^\xce\x14\xb5\xc9\xf2\x02\x06j\xa7E\xd1\xc2.&26\xa5a\x9c\xd9\xab\xb2\xd6\x86\xa1D"
            b"\x03B\x00\x04\xb5\xa1x\xd6>\xa5\xc7t\x11bj#\x9c/\xe7Gog\x92\xb4\xc2\xf5\xd5\xceQ\xfa\xceL?FW\x02\xfa"
            b"\xb8\x90\x8f\xba\x89\xfa\x1bf\xe8Xm\x13\x08\x97\xf5\x8a\x01\xb1;\xf8\xc4\xaf\x80Z\x178&k\xe5{\xce",
            password=None,
        )
        if not isinstance(issuer_priv_key, EllipticCurvePrivateKey):
            raise ValueError("Problem with private key")

        # issuer_priv_key = generate_private_key(SECP256R1())
        # if not isinstance(issuer_priv_key, EllipticCurvePrivateKey):
        #     raise ValueError("Problem with private key")
        # issuer_public_key = issuer_priv_key.public_key()
        # issuer_priv_key_pem = issuer_priv_key.private_bytes(
        #     Encoding.DER, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        # )
        # print("issuer_prib_key")
        # print(issuer_priv_key_pem)

        priv_key2 = generate_private_key(SECP256R1())
        if not isinstance(priv_key2, EllipticCurvePrivateKey):
            raise ValueError("Problem with private key")
        public_key2 = priv_key2.public_key()

        # priv_key2_pem = priv_key2.private_bytes(Encoding.DER, PrivateFormat.PKCS8,
        # encryption_algorithm=NoEncryption()) print(priv_key2_pem)

        jwk = pem_key_to_jwk(public_key2.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))

        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )

        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dummy-issuer-name")])
        # basic_contraints = x509.BasicConstraints(ca=True, path_length=None)

        # now = datetime.datetime.utcnow()
        # cert = (
        #     x509.CertificateBuilder()
        #     .subject_name(issuer_name)
        #     .issuer_name(issuer_name)
        #     .public_key(issuer_public_key)
        #     .serial_number(2000)
        #     .not_valid_before(now - datetime.timedelta(minutes=2))
        #     .not_valid_after(now + datetime.timedelta(days=10 * 365))
        #     .add_extension(basic_contraints, False)
        #     .add_extension(key_usage, False)
        #     .sign(issuer_priv_key, SHA256())
        # )
        # cert_der = cert.public_bytes(encoding=Encoding.DER)
        # print("issuer_cert")
        # print(cert.public_bytes(encoding=Encoding.PEM).decode("utf-8"))

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, os.environ["HOSTNAME"])])
        basic_contraints = x509.BasicConstraints(ca=True, path_length=None)

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer_name)
            .public_key(public_key2)
            .serial_number(secrets.randbelow(1000000000))
            .not_valid_before(now - datetime.timedelta(minutes=2))
            .not_valid_after(now + datetime.timedelta(days=10 * 365))
            .add_extension(basic_contraints, False)
            .add_extension(key_usage, False)
            .sign(issuer_priv_key, SHA256())
        )
        cert_der = cert.public_bytes(encoding=Encoding.DER)
        # print(cert.public_bytes(encoding=Encoding.PEM).decode("utf-8"))

        # pub_key_pem2 = public_key2.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        # print(pub_key_pem2)
        acme_req = create_new_account_jws(jwk, priv_key2)

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

        acme_req = create_new_account_jws(jwk, priv_key2)

        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/new-account",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)

        # Create pre authz
        acme_req = new_authz_sunet_token_jws(kid, priv_key2, cert_der)
        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/new-authz",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 201)

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
        self.assertTrue(response_data["status"] == "ready")

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
        issued_cert_asn1 = asn1_x509.Certificate()
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
        self.assertTrue(len(certs) > 1)

        for index in range(len(certs)):
            if len(certs[index]) < 3:
                continue

            data = ("-----BEGIN CERTIFICATE-----" + certs[index]).encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)

            cert_asn1 = asn1_x509.Certificate().load(data)
            _ = cert_asn1.native

            if index == 1:  # First cert in chain - the leaf
                issued_cert_asn1 = asn1_x509.Certificate().load(data)

        # Revoke cert
        acme_req = revoke_cert_jws(kid, priv_key2, f"{ROOT_URL}{ACME_ROOT}/revoke-cert", issued_cert_asn1)
        req = requests.post(
            f"{ROOT_URL}{ACME_ROOT}/revoke-cert",
            headers=request_headers,
            json=acme_req,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
