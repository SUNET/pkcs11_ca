"""
Test our certificates
"""
import json
import os
import unittest

import requests
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509

from src.pkcs11_ca_service.asn1 import create_jwt_header_str
from src.pkcs11_ca_service.config import ROOT_URL

from .lib import create_i_ca


class TestCertificate(unittest.TestCase):
    """
    Test our certificates.
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm_test",
        "organization_name": "SUNET_cert",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test-certificate-48.sunet.se",
    }

    def test_certificate(self) -> None:
        """
        Search for certificates
        """

        with open("data/trusted_keys/privkey1.key", "rb") as f_data:
            priv_key = f_data.read()
        with open("data/trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()

        csr_pem = """-----BEGIN CERTIFICATE REQUEST-----
MIICsjCCAZoCAQAwbTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEmMCQGA1UEAwwddGVz
dC1jZXJ0LTM1LmNhLXRlc3Quc3VuZXQuc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDlsQXv/htfEAyLgklU/0ytP1MBaLQij+1Z+b9yzQUy0dzYfwcz
NyxjzBSRhM5Rz1GfEMmwSi/TsRD6UNgiho7nkUe0Yjo7gaEXKdfl1J98KcAQrm0u
oLLHezxbPH6cLDnoWDDBnkfMldMNAftshef38Ct0V3RFyzkhSoONudAYfi0+M7Y4
h1CPMvtne9QbB01e8sM8yP4x6VwL0NvLDl9HqFX0ALAsTbd8e+udx+K9fDUP/f7/
MXZrbfhZuH31eHpDcr9RQP1htp8IoBBC+45q7pX2VHp5mecQxLHghOHjDx1LERLE
Y3mykDdLsvC3d1A5uG4Gqjd3mI2RqMLZy1w1AgMBAAGgADANBgkqhkiG9w0BAQsF
AAOCAQEAHaS3QCN6XV6CPnXenJTmOG28FihZ3esbmwbqZk9AiSjB2rCuIwoiVWaz
ahKaw7Hmv+Mwo5k+hVnlo8zRwz8v+2caWJ3XKuljORDF3AP66i6XolYVxGASaS6W
cq7k24ygqQTJGcSGWKhStq3RniMste/waNFtfGJ6GForGJBWcCO1AvlesHnycnxw
lxodC+GWZuKdkBRWk4lWSFJpVMjCTnHL/qSOEoEdZ0Gam9yI8bRTtDprwIsXw8gK
IHuEGEoo1BdVvQEq/Jd6jpjjix68mxHQXc3tQBRRMoZVtf8izoNJRMJrqokT4x54
4afzNzZEQ9AI0J9WsJgFo26jNyOHUQ==
-----END CERTIFICATE REQUEST-----"""

        data = json.loads('{"pem": "' + csr_pem.replace("\n", "\\n") + '"' + "}")
        data["ca_pem"] = create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)

        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/sign_csr")}
        req = requests.post(
            self.ca_url + "/sign_csr", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 200)

        # Get ALL certificates, currently the database limits this to the last 20 issued by the PKCS11 CA
        request_headers = {
            "Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/search/certificate")
        }
        req = requests.get(
            self.ca_url + "/search/certificate", headers=request_headers, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 200)
        certs = json.loads(req.text)["certificates"]
        self.assertTrue(isinstance(certs, list))
        self.assertTrue(len(certs) > 0)

        # Search for certificates
        request_headers = {
            "Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/search/certificate")
        }
        data = json.loads('{"pem": ' + '"' + certs[0].replace("\n", "\\n") + '"' + "}")
        req = requests.post(
            self.ca_url + "/search/certificate",
            headers=request_headers,
            json=data,
            timeout=10,
            verify="./tls_certificate.pem",
        )
        self.assertTrue(req.status_code == 200)
        certs = json.loads(req.text)["certificates"]
        self.assertTrue(len(certs) == 1)

        cert_data = certs[0].encode("utf-8")
        if asn1_pem.detect(cert_data):
            _, _, cert_data = asn1_pem.unarmor(cert_data)
        self.assertTrue(isinstance(asn1_x509.Certificate.load(cert_data), asn1_x509.Certificate))
