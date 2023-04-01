"""
Test our ca
"""
import asyncio
import datetime
import json
import os
import unittest
from secrets import token_bytes
from typing import Tuple, Union

import requests
from asn1crypto import ocsp as asn1_ocsp
from python_x509_pkcs11.ocsp import certificate_ocsp_data, request

from src.pkcs11_ca_service.asn1 import create_jwt_header_str, ocsp_encode
from src.pkcs11_ca_service.config import ROOT_URL

from .lib import create_i_ca, verify_pkcs11_ca_tls_cert

OCSP_ENDPOINT = "/ocsp/"
REVOKE_ENDPOINT = "/revoke"

OCSP_DUMMY_DATA = b"\xad\xd0\x88DW\x96'\xce\xf4\"\xc6\xc77W\xc9\xefi\xa4[\x8b"

with open("data/trusted_keys/privkey1.key", "rb") as file_data:
    priv_key = file_data.read()
with open("data/trusted_keys/pubkey1.pem", "rb") as file_data:
    pub_key = file_data.read()


class TestOCSP(unittest.TestCase):
    """
    Test our OCSP
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm_test",
        "organization_name": "SUNET_ocsp",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test-ocsp-45.sunet.se",
    }

    def _ocsp_request(self, post: bool, url: str, ocsp_request_bytes: bytes) -> Tuple[bytes, asn1_ocsp.OCSPResponse]:
        if post is False:
            data = self._submit_req("GET", f"{url}{ocsp_encode(ocsp_request_bytes)}")
        else:
            data = self._submit_req("POST", url, ocsp_request_bytes)

        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        _ = ocsp_response.native
        return data, ocsp_response

    def _check_certs_in_req_and_resp(self, req: asn1_ocsp.OCSPRequest, resp: asn1_ocsp.OCSPResponse) -> None:
        self.assertTrue(
            len(resp["response_bytes"]["response"].native["tbs_response_data"]["responses"])
            == len(req["tbs_request"]["request_list"])
        )

        for index, _ in enumerate(resp["response_bytes"]["response"].native["tbs_response_data"]["responses"]):
            self.assertTrue(
                resp["response_bytes"]["response"].native["tbs_response_data"]["responses"][index]["cert_id"]
                == req["tbs_request"]["request_list"][index]["req_cert"].native
            )

    def _submit_req(self, method: str, url: str, data: Union[bytes, None] = None) -> bytes:
        if method == "GET":
            req = requests.get(url, timeout=10, verify=verify_pkcs11_ca_tls_cert())
        else:
            req = requests.post(url, data=data, timeout=10, verify=verify_pkcs11_ca_tls_cert())
        self.assertTrue(req.status_code == 200)
        self.assertTrue(len(req.content) > 0)
        self.assertTrue("content-type" in req.headers and req.headers["content-type"] == "application/ocsp-response")
        return req.content

    def _check_ok_cert(self, cert_pem: str, post: bool = False) -> None:
        i_n_h, i_n_k, serial, ocsp_url = certificate_ocsp_data(cert_pem)

        ocsp_request_bytes = asyncio.run(request([(i_n_h, i_n_k, serial)]))
        ocsp_request = asn1_ocsp.OCSPRequest().load(ocsp_request_bytes)
        self.assertTrue(isinstance(ocsp_request, asn1_ocsp.OCSPRequest))

        _, ocsp_response = self._ocsp_request(post, f"{ocsp_url}", ocsp_request_bytes)

        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response)
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "good"
        )

        # Ensure we support extended_revoke
        found = False
        for _, ext in enumerate(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"]
        ):
            if ext["extn_id"] == "extended_revoke":
                found = True
        self.assertTrue(found)

    def test_ocsp(self) -> None:
        """
        Test OCSP
        """

        ca_pem = create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)
        self._check_ok_cert(ca_pem)

        ca_pem = create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)
        self._check_ok_cert(ca_pem, True)

    def test_revoked_get(self, post: bool = False) -> None:
        """
        Test OCSP revoked
        """

        new_ca = create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)
        i_n_h, i_n_k, serial, ocsp_url = certificate_ocsp_data(new_ca)
        ocsp_request_bytes = asyncio.run(request([(i_n_h, i_n_k, serial)]))
        ocsp_request = asn1_ocsp.OCSPRequest().load(ocsp_request_bytes)
        self.assertTrue(isinstance(ocsp_request, asn1_ocsp.OCSPRequest))

        # Revoke cert
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + REVOKE_ENDPOINT)}

        data = json.loads('{"pem": "' + new_ca.replace("\n", "\\n") + '"' + "}")
        data["reason"] = 5
        req = requests.post(
            self.ca_url + REVOKE_ENDPOINT,
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)

        _, ocsp_response_rev = self._ocsp_request(post, f"{ocsp_url}", ocsp_request_bytes)

        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response_rev)
        self.assertTrue(
            ocsp_response_rev["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )
        self.assertTrue(
            isinstance(
                ocsp_response_rev["response_bytes"]["response"].native["tbs_response_data"]["responses"][0][
                    "cert_status"
                ]["revocation_time"],
                datetime.datetime,
            )
        )

    def test_revoked_post(self) -> None:
        """
        Test OCSP mixed get
        """

        self.test_revoked_get(True)

    def test_ocsp_fail(self) -> None:
        """
        Test OCSP fails
        """

        request_certs_data = [
            (
                b"R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc",
                OCSP_DUMMY_DATA,
                440320505043419981128735462508870123525487964711,
            )
        ]
        ocsp_request_bytes = asyncio.run(request(request_certs_data))

        # GET
        data, _ = self._ocsp_request(False, f"{self.ca_url}{OCSP_ENDPOINT}", ocsp_request_bytes)
        self.assertTrue(data == b"0\x03\n\x01\x06")

        # POST
        data, _ = self._ocsp_request(True, f"{self.ca_url}{OCSP_ENDPOINT}", ocsp_request_bytes)
        self.assertTrue(data == b"0\x03\n\x01\x06")

        # GET
        data = self._submit_req("GET", self.ca_url + OCSP_ENDPOINT + "/sldfsf!!#¤&%¤%YARSFdfvdfv")
        self.assertTrue(data == b"0")
        data = self._submit_req("GET", self.ca_url + OCSP_ENDPOINT + "/sdfsfas/sdfsdf/d")
        self.assertTrue(data == b"0")

        # POST
        data = self._submit_req("POST", self.ca_url + OCSP_ENDPOINT, OCSP_DUMMY_DATA)
        self.assertTrue(data == b"0")

    def test_ocsp_mixed_get(self, post: bool = False) -> None:
        """
        Test OCSP mixed get
        """

        new_ca = create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)
        i_n_h, i_n_k, serial, _ = certificate_ocsp_data(new_ca)

        request_certs_data = [
            (
                b"R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc",
                OCSP_DUMMY_DATA,
                440320505043419981128735462508870123525487964711,
            ),
            (i_n_h, i_n_k, serial),
        ]
        new_ca_ok = create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)
        i_n_h, i_n_k, serial, _ = certificate_ocsp_data(new_ca_ok)
        request_certs_data.append((i_n_h, i_n_k, serial))

        ocsp_request_bytes = asyncio.run(request(request_certs_data))
        ocsp_request = asn1_ocsp.OCSPRequest().load(ocsp_request_bytes)
        self.assertTrue(isinstance(ocsp_request, asn1_ocsp.OCSPRequest))

        # Revoke cert
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + REVOKE_ENDPOINT)}

        data = json.loads('{"pem": "' + new_ca.replace("\n", "\\n") + '"' + "}")
        data["reason"] = 5
        req = requests.post(
            self.ca_url + REVOKE_ENDPOINT,
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)

        _, ocsp_response_mix = self._ocsp_request(post, f"{self.ca_url}{OCSP_ENDPOINT}", ocsp_request_bytes)

        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response_mix)
        self.assertTrue(
            ocsp_response_mix["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "unknown"
        )
        self.assertTrue(
            ocsp_response_mix["response_bytes"]["response"].native["tbs_response_data"]["responses"][1]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )
        self.assertTrue(
            ocsp_response_mix["response_bytes"]["response"].native["tbs_response_data"]["responses"][2]["cert_status"]
            == "good"
        )

    def test_ocsp_mixed_post(self) -> None:
        """
        Test OCSP mixed get
        """

        self.test_ocsp_mixed_get(True)

    def test_ocsp_extensions_get(self, post: bool = False) -> None:
        """
        Test OCSP extensions get
        """

        new_ca = create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)
        i_n_h, i_n_k, serial, ocsp_url = certificate_ocsp_data(new_ca)

        nonce_val = token_bytes(32)
        nonce_ext = asn1_ocsp.TBSRequestExtension()
        nonce_ext["extn_id"] = asn1_ocsp.TBSRequestExtensionId("1.3.6.1.5.5.7.48.1.2")
        nonce_ext["extn_value"] = nonce_val
        extra_extensions = asn1_ocsp.TBSRequestExtensions()
        extra_extensions.append(nonce_ext)

        ocsp_request_bytes = asyncio.run(request([(i_n_h, i_n_k, serial)], extra_extensions=extra_extensions))
        ocsp_request = asn1_ocsp.OCSPRequest().load(ocsp_request_bytes)
        self.assertTrue(isinstance(ocsp_request, asn1_ocsp.OCSPRequest))

        _, ocsp_response_ext = self._ocsp_request(post, f"{ocsp_url}", ocsp_request_bytes)

        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response_ext)
        self.assertTrue(
            ocsp_response_ext["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"][0][
                "extn_value"
            ]
            == nonce_val
        )

        self.assertTrue(
            ocsp_response_ext["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "good"
        )

    def test_ocsp_extensions_post(self) -> None:
        """
        Test OCSP extensions post
        """

        self.test_ocsp_extensions_get(True)

    def test_ocsp_cert(self) -> None:
        """
        Test OCSP extensions
        """

        csr_pem = """-----BEGIN CERTIFICATE REQUEST-----
MIICsDCCAZgCAQAwazELMAkGA1UEBhMCU0UxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEkMCIGA1UEAwwbY2hl
Y2stb2NzcC50ZXN0LTU3LnN1bmV0LnNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAqZ7KLyarB001jU2E8tPY+jbs2FNBfQg5gebvWMxtap2UG2HQla+2
r3mKWAfmd5rn09Kb5PTvVvmFAuf7mALlsOw1Ppjo0nQeQG34FTQ2fmyO5Yr4q4sI
v7nZE1MtAFuwQBC0xxJ/aunf7T0I4VTKzik5UqmlztzPhdrhCASOAgcqOSYqdl8j
DQtKTk7F1VF21zOwivZ2375aBc6ztEvgLqSdsh4txFKYRwUm/slBgGEptsRO/ZnY
4lrfXuSDxAy7jRxWHyrLfur3I5tkVqYxBnFMCdjwDV3LPalKcNDim6n+52LhIWE+
39y4ynfPBYDpT/4NXWc71Pbrmr4GwuGp7wIDAQABoAAwDQYJKoZIhvcNAQELBQAD
ggEBAF3yXwXMKnc1ZKAtuuhyfXDE7s97qRy/iVoTEldrWmUcDhlfWdfZYBxpWp2e
R7rOJDrL2LbHMYEN+vIQsaow6z4kYcSmyEasNCD/4gms/VesCTOoWz0QP+59NtFe
w0+S7OGYDzBS+Wyo3W00R4nKMug1lhSCtOa9p3ibtPzx6U48Ch5whoedfzXY5z92
q2BvFe+gBHospMivm2m/laeMMu99EarJE8JgTnUDtQmZ/xxLBsPp9Xk78Bc1gU7u
1d2+gEBSgJ/cc3cagBWPPbdRaT4OmuOkIudq/zP6GqQKQ+8d7rLsFszdamTPv2v7
zu/HPacJI420g3IC4vMVHeZznEM=
-----END CERTIFICATE REQUEST-----
"""

        data = {"pem": csr_pem, "ca_pem": create_i_ca(self.ca_url, pub_key, priv_key, self.name_dict)}

        # Sign a csr
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/sign_csr")}

        req = requests.post(
            self.ca_url + "/sign_csr",
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)
        new_cert = json.loads(req.text)["certificate"]
        self._check_ok_cert(new_cert)
