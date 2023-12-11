"""
Test our revocation
"""
import json
import os
import unittest

import requests
from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem

from src.pkcs11_ca_service.asn1 import cert_pem_serial_number, cert_revoked, create_jwt_header_str, crl_expired
from src.pkcs11_ca_service.config import ROOT_URL

from .lib import cdp_url, create_i_ca, verify_pkcs11_ca_tls_cert

ORGANIZATIONAL_UNIT_NAME = "SUNET Infrastructure"
REVOKE_ENDPOINT = "/revoke"
IS_REVOKED_ENDPOINT = "/is_revoked"


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

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm_test",
        "organization_name": "SUNET_revoke",
        "organizational_unit_name": ORGANIZATIONAL_UNIT_NAME,
        "common_name": "ca-test-revoke-47.sunet.se",
    }

    def test_revoke(self) -> None:
        """
        Test revoke
        """

        with open("data/trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()
        with open("data/trusted_keys/privkey1.key", "rb") as f_data:
            priv_key = f_data.read()

        # Sign a csr
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/sign_csr")}

        data = {"pem": TEST_CSR1, "ca_pem": create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)}

        req = requests.post(
            self.ca_url + "/sign_csr",
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)

        cert = json.loads(req.text)["certificate"]

        # Revoke cert
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + REVOKE_ENDPOINT)}

        data = {"pem": cert}
        req = requests.post(
            self.ca_url + REVOKE_ENDPOINT,
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)
        self.assertTrue(cert == json.loads(req.text)["revoked"])

        # Check CRL
        # Get CDP
        url = cdp_url(cert)
        req = requests.get(url, headers=request_headers, timeout=10, verify=verify_pkcs11_ca_tls_cert())
        self.assertTrue(req.status_code == 200)
        resp_data = req.content
        if asn1_pem.detect(resp_data):
            _, _, resp_data = asn1_pem.unarmor(resp_data)
        curr_crl = asn1_crl.CertificateList.load(resp_data)
        curr_crl_pem: str = asn1_pem.armor("X509 CRL", curr_crl.dump()).decode("utf-8")
        self.assertTrue(isinstance(curr_crl, asn1_crl.CertificateList))
        self.assertTrue(cert_revoked(cert_pem_serial_number(cert), curr_crl_pem))
        self.assertFalse(crl_expired(curr_crl_pem))

    def test_is_revoked(self) -> None:
        """
        Test revoke
        """

        with open("data/trusted_keys/pubkey1.pem", "rb") as file_data:
            pub_key = file_data.read()
        with open("data/trusted_keys/privkey1.key", "rb") as file_data:
            priv_key = file_data.read()

        # Create CA
        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm_test",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET",
            "organizational_unit_name": ORGANIZATIONAL_UNIT_NAME,
            "common_name": "ca-test-revoke-22.sunet.se",
        }

        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/ca")}

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        data = {"key_label": new_key_label, "name_dict": name_dict}

        req = requests.post(
            self.ca_url + "/ca", headers=request_headers, json=data, timeout=10, verify=verify_pkcs11_ca_tls_cert()
        )
        self.assertTrue(req.status_code == 200)
        old_ca = json.loads(req.text)["certificate"]

        # Revoke CA
        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm_test",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET",
            "organizational_unit_name": ORGANIZATIONAL_UNIT_NAME,
            "common_name": "ca-test-revoke-33.sunet.se",
        }

        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/ca")}

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)
        data = {"key_label": new_key_label, "name_dict": name_dict, "issuer_pem": old_ca}

        req = requests.post(
            self.ca_url + "/ca", headers=request_headers, json=data, timeout=10, verify=verify_pkcs11_ca_tls_cert()
        )
        self.assertTrue(req.status_code == 200)
        curr_ca = json.loads(req.text)["certificate"]

        # Check revoked status
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + IS_REVOKED_ENDPOINT)}
        data = {"pem": curr_ca}
        req = requests.post(
            self.ca_url + IS_REVOKED_ENDPOINT,
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)
        revoked = json.loads(req.text)["is_revoked"]
        self.assertTrue(revoked is False)

        # Revoke CA
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + REVOKE_ENDPOINT)}

        data = {"pem": curr_ca}
        req = requests.post(
            self.ca_url + REVOKE_ENDPOINT,
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)

        # Check revoked status
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + IS_REVOKED_ENDPOINT)}
        data = json.loads('{"pem": "' + curr_ca.replace("\n", "\\n") + '"' + "}")
        req = requests.post(
            self.ca_url + IS_REVOKED_ENDPOINT,
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)
        revoked = json.loads(req.text)["is_revoked"]
        self.assertTrue(revoked is True)
