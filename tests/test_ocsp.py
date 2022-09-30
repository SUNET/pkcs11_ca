"""
Test our ca
"""
import unittest
from typing import Union
import json
import asyncio
from secrets import token_bytes
import datetime

import requests
from asn1crypto import ocsp as asn1_ocsp

from python_x509_pkcs11.ocsp import certificate_ocsp_data, request

from src.pkcs11_ca_service.asn1 import create_jwt_header_str, ocsp_encode
from .lib import get_cas, create_i_ca

with open("trusted_keys/privkey1.key", "rb") as file_data:
    priv_key = file_data.read()
with open("trusted_keys/pubkey1.pem", "rb") as file_data:
    pub_key = file_data.read()


class TestOCSP(unittest.TestCase):
    """
    Test our OCSP
    """

    name_dict = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm_test",
        "organization_name": "SUNET_ocsp",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test-ocsp-45.sunet.se",
        "email_address": "soc@sunet.se",
    }

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
            req = requests.get(url)
        else:
            req = requests.post(url, data=data)
        self.assertTrue(req.status_code == 200)
        self.assertTrue(len(req.content) > 0)
        self.assertTrue("content-type" in req.headers and req.headers["content-type"] == "application/ocsp-response")
        return req.content

    def _check_ok_cert(self, cert_pem: str) -> None:
        i_n_h, i_n_k, serial, ocsp_url = certificate_ocsp_data(cert_pem)

        ocsp_request_bytes = asyncio.run(request([(i_n_h, i_n_k, serial)]))
        ocsp_request = asn1_ocsp.OCSPRequest().load(ocsp_request_bytes)
        self.assertTrue(isinstance(ocsp_request, asn1_ocsp.OCSPRequest))

        # GET
        data = self._submit_req("GET", ocsp_url + ocsp_encode(ocsp_request_bytes))
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
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

        # POST
        data = self._submit_req("POST", ocsp_url, ocsp_request_bytes)
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
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

        ca_pem = create_i_ca(pub_key, priv_key, self.name_dict)
        self._check_ok_cert(ca_pem)

    def test_revoked(self) -> None:
        """
        Test OCSP revoked
        """

        new_ca = create_i_ca(pub_key, priv_key, self.name_dict)
        i_n_h, i_n_k, serial, ocsp_url = certificate_ocsp_data(new_ca)
        ocsp_request_bytes = asyncio.run(request([(i_n_h, i_n_k, serial)]))
        ocsp_request = asn1_ocsp.OCSPRequest().load(ocsp_request_bytes)
        self.assertTrue(isinstance(ocsp_request, asn1_ocsp.OCSPRequest))

        # Revoke cert
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/revoke")

        data = json.loads('{"pem": "' + new_ca.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/revoke", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        # GET
        data = self._submit_req("GET", ocsp_url + ocsp_encode(ocsp_request_bytes))
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response)
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )
        self.assertTrue(
            isinstance(
                ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"][
                    "revocation_time"
                ],
                datetime.datetime,
            )
        )

        # POST
        data = self._submit_req("POST", ocsp_url, ocsp_request_bytes)
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response)
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )
        self.assertTrue(
            isinstance(
                ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"][
                    "revocation_time"
                ],
                datetime.datetime,
            )
        )

    def test_ocsp_fail(self) -> None:
        """
        Test OCSP fails
        """

        request_certs_data = [
            (
                b"R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc",
                b"\xad\xd0\x88DW\x96'\xce\xf4\"\xc6\xc77W\xc9\xefi\xa4[\x8b",
                440320505043419981128735462508870123525487964711,
            )
        ]
        ocsp_request_bytes = asyncio.run(request(request_certs_data))

        # GET
        data = self._submit_req("GET", "http://localhost:8000/ocsp/" + ocsp_encode(ocsp_request_bytes))
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(data == b"0\x03\n\x01\x06")

        # POST
        data = self._submit_req("POST", "http://localhost:8000/ocsp/", ocsp_request_bytes)
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self.assertTrue(data == b"0\x03\n\x01\x06")

        # GET
        data = self._submit_req("GET", "http://localhost:8000/ocsp/" + "sldfsf!!#¤&%¤%YARSFdfvdfv")
        self.assertTrue(data == b"0")
        data = self._submit_req("GET", "http://localhost:8000/ocsp/" + "sdfsfas/sdfsdf/d")
        self.assertTrue(data == b"0")

        # POST
        data = self._submit_req(
            "POST", "http://localhost:8000/ocsp/", b"\xad\xd0\x88DW\x96'\xce\xf4\"\xc6\xc77W\xc9\xefi\xa4[\x8b"
        )
        self.assertTrue(data == b"0")

    def test_ocsp_mixed(self) -> None:
        """
        Test OCSP mixed
        """

        new_ca = create_i_ca(pub_key, priv_key, self.name_dict)
        i_n_h, i_n_k, serial, _ = certificate_ocsp_data(new_ca)

        request_certs_data = [
            (
                b"R\x94\xca?\xac`\xf7i\x819\x14\x94\xa7\x085H\x84\xb4&\xcc",
                b"\xad\xd0\x88DW\x96'\xce\xf4\"\xc6\xc77W\xc9\xefi\xa4[\x8b",
                440320505043419981128735462508870123525487964711,
            ),
            (i_n_h, i_n_k, serial),
        ]
        new_ca_ok = create_i_ca(pub_key, priv_key, self.name_dict)
        i_n_h, i_n_k, serial, _ = certificate_ocsp_data(new_ca_ok)
        request_certs_data.append((i_n_h, i_n_k, serial))

        ocsp_request_bytes = asyncio.run(request(request_certs_data))
        ocsp_request = asn1_ocsp.OCSPRequest().load(ocsp_request_bytes)
        self.assertTrue(isinstance(ocsp_request, asn1_ocsp.OCSPRequest))

        # Revoke cert
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/revoke")

        data = json.loads('{"pem": "' + new_ca.replace("\n", "\\n") + '"' + "}")
        req = requests.post("http://localhost:8000/revoke", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)

        # GET
        data = self._submit_req("GET", "http://localhost:8000/ocsp/" + ocsp_encode(ocsp_request_bytes))
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response)
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "unknown"
        )

        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][1]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][2]["cert_status"]
            == "good"
        )

        # POST
        data = self._submit_req("POST", "http://localhost:8000/ocsp/", ocsp_request_bytes)
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response)
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "unknown"
        )

        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][1]["cert_status"][
                "revocation_reason"
            ]
            == "cessation_of_operation"
        )

        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][2]["cert_status"]
            == "good"
        )

    def test_ocsp_extensions(self) -> None:
        """
        Test OCSP extensions
        """

        new_ca = create_i_ca(pub_key, priv_key, self.name_dict)
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

        # GET
        data = self._submit_req("GET", ocsp_url + ocsp_encode(ocsp_request_bytes))
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response)
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"][0][
                "extn_value"
            ]
            == nonce_val
        )

        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "good"
        )

        # POST
        data = self._submit_req("POST", ocsp_url, ocsp_request_bytes)
        ocsp_response = asn1_ocsp.OCSPResponse().load(data)
        self.assertTrue(isinstance(ocsp_response, asn1_ocsp.OCSPResponse))
        self._check_certs_in_req_and_resp(ocsp_request, ocsp_response)
        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["response_extensions"][0][
                "extn_value"
            ]
            == nonce_val
        )

        self.assertTrue(
            ocsp_response["response_bytes"]["response"].native["tbs_response_data"]["responses"][0]["cert_status"]
            == "good"
        )

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

        cas = get_cas(pub_key, priv_key)

        # Sign a csr
        request_headers = {}
        request_headers["Authorization"] = create_jwt_header_str(pub_key, priv_key, "http://localhost:8000/sign_csr")

        data = json.loads(
            '{"pem": "'
            + csr_pem.replace("\n", "\\n")
            + '"'
            + ","
            + '"ca_pem": '
            + '"'
            + cas[-1].replace("\n", "\\n")
            + '"'
            + "}"
        )
        req = requests.post("http://localhost:8000/sign_csr", headers=request_headers, json=data)
        self.assertTrue(req.status_code == 200)
        new_cert = json.loads(req.text)["certificate"]
        self._check_ok_cert(new_cert)
