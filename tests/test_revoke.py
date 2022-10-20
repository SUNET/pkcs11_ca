"""
Test our revocation
"""
import unittest
import json
import os

import requests

from asn1crypto import pem as asn1_pem
from asn1crypto import crl as asn1_crl

# from asn1crypto import crl as asn1_crl
# from asn1crypto import pem as asn1_pem

from src.pkcs11_ca_service.asn1 import create_jwt_header_str, cert_revoked, crl_expired, cert_pem_serial_number
from .lib import get_cas, cdp_url

TEST_CSR1 = """-----BEGIN CERTIFICATE REQUEST-----
MIIC2DCCAcACAQAwgZIxCzAJBgNVBAYTAlNFMRMwEQYDVQQIDApTb21lLVN0YXRl
MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxLjAsBgNVBAMMJXRl
c3QtcmV2b2tlMTctZG9lcy1ub3QtZXhpc3Quc3VuZXQuc2UxGzAZBgkqhkiG9w0B
CQEWDHNvY0BzdW5ldC5zZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
APSlIOoqPWpQv8C7ytaiu/fZeXMIbEKgEypg3bpX5ps6bsTFCYmryR+8lH+YhFt5
25EtsPAcnt/oDeaQTevbbaYTy0pZgxcWpolAa3LV1PGpOR4T2B1e2lckRukim4wa
TBOkDcSGJ11RU/Oji7wpxN9Dsb8ThZ1HJj5Ay39zD/lZB0YK/pEnNc4diVey+p/P
3Aia6/4DbxZBUXvbRW4QX6mc0I81s0/KITYshVAL1CwxvahAc0SetTmHPqLMvX54
BC+cdQMdjVJ9MsI5dmeV5v8f/1r/S0yyQ6mnA76uFrmed/Ff8VYBiQBxAwgfpZkM
EdUQHQIrIVJP0QEN6i8i2x8CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBVwBdd
NBISrnvlj12WDI7Cb40u0GJkAzLGRa3Q60f2yUaRiLnTpUc8mdmOtSp5Y+pBpZZS
h472wzebTIt1MfaA1j9X1gpHBkm1besHPtX/Zr58Kvr7sCcGkVA7DobPxCwUzUEx
b0PLXomGhOoCu8Mmt9fnnm6ProUQm8EQ6MuIJSckeTFz1SDKF2/oMnn7x//ff9ns
SVP9cgbB7DN4CN92iFwcHMJqDM1V1AdtPkJAJmb9/6APmlEpvVlKOOt28Z0Q/b++
FCltA598ksWRvKdX/PRdxFmKx3AaJMVGJmsWgVPf7xzMCypXRvqdaQ9ithxCiVgn
CXG0k5gblEYXmZc/
-----END CERTIFICATE REQUEST-----
"""


class TestRevoke(unittest.TestCase):
    """
    Test our revocation
    """

    def test_revoke(self) -> None:
        """
        Test revoke
        """

        with open("trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()
        with open("trusted_keys/privkey1.key", "rb") as f_data:
            priv_key = f_data.read()

        # Sign a csr
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/sign_csr")

        all_cas = get_cas(pub_key, priv_key)
        data = json.loads(
            '{"pem": "'
            + TEST_CSR1.replace("\n", "\\n")
            + '"'
            + ","
            + '"ca_pem": '
            + '"'
            + all_cas[0].replace("\n", "\\n")
            + '"'
            + "}"
        )
        req = requests.post("http://localhost:8000/sign_csr", headers=request_headers, json=data, timeout=5)
        self.assertTrue(req.status_code == 200)

        cert = json.loads(req.text)["certificate"]

        # Revoke cert
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/revoke")

        data = json.loads('{"pem": "' + cert.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/revoke", headers=request_headers, json=data, timeout=5)
        self.assertTrue(req.status_code == 200)
        self.assertTrue(cert == json.loads(req.text)["revoked"])

        # Check CRL
        # Get CDP
        url = cdp_url(cert)
        req = requests.get(url, headers=request_headers, timeout=5)
        self.assertTrue(req.status_code == 200)
        data = req.content
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        curr_crl = asn1_crl.CertificateList.load(data)
        curr_crl_pem: str = asn1_pem.armor("X509 CRL", curr_crl.dump()).decode("utf-8")
        self.assertTrue(isinstance(curr_crl, asn1_crl.CertificateList))
        self.assertTrue(cert_revoked(cert_pem_serial_number(cert), curr_crl_pem))
        self.assertFalse(crl_expired(curr_crl_pem))

    def test_is_revoked(self) -> None:
        """
        Test revoke
        """

        with open("trusted_keys/pubkey1.pem", "rb") as file_data:
            pub_key = file_data.read()
        with open("trusted_keys/privkey1.key", "rb") as file_data:
            priv_key = file_data.read()

        # Create CA
        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm_test",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-revoke-22.sunet.se",
            "email_address": "soc@sunet.se",
        }

        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/ca")

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        data = json.loads('{"key_label": ' + '"' + new_key_label + '"' + "}")
        data["name_dict"] = name_dict
        # all_cas = get_cas(pub_key, priv_key)
        # dta["issuer_pem"] = all_cas[0]

        req = requests.post("http://localhost:8000/ca", headers=request_headers, json=data, timeout=5)
        self.assertTrue(req.status_code == 200)
        old_ca = json.loads(req.text)["certificate"]

        # Revoke CA
        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm_test",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-revoke-33.sunet.se",
            "email_address": "soc@sunet.se",
        }

        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/ca")

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        data = json.loads('{"key_label": ' + '"' + new_key_label + '"' + "}")
        data["name_dict"] = name_dict
        data["issuer_pem"] = old_ca

        req = requests.post("http://localhost:8000/ca", headers=request_headers, json=data, timeout=5)
        self.assertTrue(req.status_code == 200)
        curr_ca = json.loads(req.text)["certificate"]

        # Check revoked status
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/is_revoked")
        data = json.loads('{"pem": "' + curr_ca.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/is_revoked", headers=request_headers, json=data, timeout=5)
        self.assertTrue(req.status_code == 200)
        revoked = json.loads(req.text)["is_revoked"]
        self.assertTrue(revoked is False)

        # Revoke CA
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/revoke")

        data = json.loads('{"pem": "' + curr_ca.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/revoke", headers=request_headers, json=data, timeout=5)
        self.assertTrue(req.status_code == 200)

        # Check revoked status
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/is_revoked")
        data = json.loads('{"pem": "' + curr_ca.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/is_revoked", headers=request_headers, json=data, timeout=5)
        self.assertTrue(req.status_code == 200)
        revoked = json.loads(req.text)["is_revoked"]
        self.assertTrue(revoked is True)
