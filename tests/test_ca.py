"""
Test our ca
"""
import json
import os
import unittest
from typing import List

import requests
from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem
from asn1crypto import x509 as asn1_x509
from python_x509_pkcs11.ocsp import certificate_ocsp_data

from src.pkcs11_ca_service.asn1 import create_jwt_header_str
from src.pkcs11_ca_service.config import KEY_TYPES, ROOT_URL

from .lib import cdp_url, create_i_ca, verify_cert, verify_pkcs11_ca_tls_cert

with open("data/trusted_keys/privkey1.key", "rb") as file_data:
    priv_key = file_data.read()
with open("data/trusted_keys/pubkey1.pem", "rb") as file_data:
    pub_key = file_data.read()


class TestCa(unittest.TestCase):
    """
    Test our ca
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def get_single_ca(self, cas: List[str]) -> None:
        """Get single ca"""

        # Get a ca
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/search/ca")}

        data = json.loads('{"pem": ' + '"' + cas[-1].replace("\n", "\\n") + '"' + "}")
        req = requests.post(
            self.ca_url + "/search/ca",
            headers=request_headers,
            json=data,
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )
        self.assertTrue(req.status_code == 200)
        self.assertTrue(len(json.loads(req.text)["cas"]) == 1)

    def test_ca(self) -> None:
        """
        create ca
        """

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-13.sunet.se",
        }

        new_ca = create_i_ca(self.ca_url, pub_key, priv_key, name_dict)
        data = new_ca.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        self.assertTrue(isinstance(asn1_x509.Certificate.load(data), asn1_x509.Certificate))

        new_ca = create_i_ca(self.ca_url, pub_key, priv_key, name_dict)
        data = new_ca.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        self.assertTrue(isinstance(asn1_x509.Certificate.load(data), asn1_x509.Certificate))
        self.get_single_ca([new_ca])

    def test_root_ca(self) -> None:
        """
        create ca
        """

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-17.sunet.se",
        }

        new_key_label = hex(int.from_bytes(os.urandom(20), "big") >> 1)

        # Create a root ca
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/ca")}

        data = json.loads('{"key_label": ' + '"' + new_key_label[:-2] + '"' + "}")
        data["name_dict"] = name_dict

        req = requests.post(
            self.ca_url + "/ca", headers=request_headers, json=data, timeout=10, verify=verify_pkcs11_ca_tls_cert()
        )
        self.assertTrue(req.status_code == 200)

        data = json.loads(req.text)["certificate"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        cert_curr = asn1_x509.Certificate().load(data)
        self.assertTrue(isinstance(cert_curr, asn1_x509.Certificate))

        tbs = cert_curr["tbs_certificate"]
        for _, extension in enumerate(tbs["extensions"]):
            if extension["extn_id"].dotted == "2.5.29.14":
                ski = extension["extn_value"].native

        for _, extension in enumerate(tbs["extensions"]):
            if extension["extn_id"].dotted == "2.5.29.35":
                aki = extension["extn_value"].native["key_identifier"]
        self.assertTrue(ski == aki)

    def test_aia_and_cdp_ca(self) -> None:
        """
        create aia and cdp extensions ca
        """

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET_ca",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-20.sunet.se",
        }

        new_ca = create_i_ca(self.ca_url, pub_key, priv_key, name_dict)
        data = new_ca.encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        tbs = asn1_x509.Certificate().load(data)["tbs_certificate"]

        # AIA
        found_ca, found_ocsp = False, False
        for _, extension in enumerate(tbs["extensions"]):
            if extension["extn_id"].dotted == "1.3.6.1.5.5.7.1.1":
                for _, descr in enumerate(extension["extn_value"].native):
                    if descr["access_method"] == "ca_issuers":
                        self.assertTrue("/ca/" in descr["access_location"])
                        found_ca = True
                        url_ca = descr["access_location"]
                    elif descr["access_method"] == "ocsp":
                        self.assertTrue("/ocsp/" in descr["access_location"])
                        found_ocsp = True
        self.assertTrue(found_ca)
        self.assertTrue(found_ocsp)

        # Get AIA
        req = requests.get(url_ca, timeout=10, verify=verify_pkcs11_ca_tls_cert())
        self.assertTrue(req.status_code == 200)
        data = req.content
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        self.assertTrue(isinstance(asn1_x509.Certificate().load(data), asn1_x509.Certificate))

        # Get OCSP
        _, _, _, _ = certificate_ocsp_data(new_ca)

        # Get CDP
        url = cdp_url(new_ca)
        req = requests.get(url, timeout=10, verify=verify_pkcs11_ca_tls_cert())
        self.assertTrue(req.status_code == 200)
        data = req.content
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)
        self.assertTrue(isinstance(asn1_crl.CertificateList.load(data), asn1_crl.CertificateList))

    def test_ca_wrong_key_type(self) -> None:
        """
        create aia and cdp extensions ca
        """

        name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET_ca",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-21.sunet.se",
        }

        issuer_name_dict = {
            "country_name": "SE",
            "state_or_province_name": "Stockholm",
            "locality_name": "Stockholm_test",
            "organization_name": "SUNET_ca",
            "organizational_unit_name": "SUNET Infrastructure",
            "common_name": "ca-test-create-31.sunet.se",
        }

        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/ca")}

        data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
        data["name_dict"] = name_dict
        data["issuer_pem"] = create_i_ca(self.ca_url, pub_key, priv_key, issuer_name_dict)
        data["key_type"] = "dummy_not_exist"

        req = requests.post(
            self.ca_url + "/ca", headers=request_headers, json=data, timeout=10, verify=verify_pkcs11_ca_tls_cert()
        )
        self.assertTrue(req.status_code != 200)

    def test_ca_key_types(self) -> None:
        """
        create aia and cdp extensions ca
        """

        for key_type in KEY_TYPES:
            name_dict = {
                "country_name": "SE",
                "state_or_province_name": "Stockholm",
                "locality_name": "Stockholm_test",
                "organization_name": "SUNET_ca",
                "organizational_unit_name": "SUNET Infrastructure",
                "common_name": "ca-test-create-22-" + key_type + ".sunet.se",
            }
            issuer_name_dict = {
                "country_name": "SE",
                "state_or_province_name": "Stockholm",
                "locality_name": "Stockholm_test",
                "organization_name": "SUNET_ca",
                "organizational_unit_name": "SUNET Infrastructure",
                "common_name": "ca-test-create-32-" + key_type + ".sunet.se",
            }

            request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/ca")}

            data = json.loads('{"key_label": ' + '"' + hex(int.from_bytes(os.urandom(20), "big") >> 1) + '"' + "}")
            data["name_dict"] = name_dict
            data["issuer_pem"] = create_i_ca(self.ca_url, pub_key, priv_key, issuer_name_dict)
            data["key_type"] = key_type

            req = requests.post(
                self.ca_url + "/ca", headers=request_headers, json=data, timeout=10, verify=verify_pkcs11_ca_tls_cert()
            )
            self.assertTrue(req.status_code == 200)
            new_ca: str = json.loads(req.text)["certificate"]
            self.assertTrue(len(new_ca) > 9)

            data = new_ca.encode("utf-8")
            if asn1_pem.detect(data):
                _, _, data = asn1_pem.unarmor(data)
            self.assertTrue(isinstance(asn1_x509.Certificate.load(data), asn1_x509.Certificate))
            tbs = asn1_x509.Certificate().load(data)["tbs_certificate"]

            if "rsa_" in key_type:
                self.assertTrue(tbs["subject_public_key_info"]["algorithm"]["algorithm"].native == "rsa")
            elif "secp" in key_type:
                self.assertTrue(tbs["subject_public_key_info"]["algorithm"]["algorithm"].native == "ec")
                self.assertTrue(tbs["subject_public_key_info"]["algorithm"]["parameters"].native == key_type)
            elif key_type == "ed25519":
                self.assertTrue(tbs["subject_public_key_info"]["algorithm"]["algorithm"].native == "ed25519")
            elif key_type == "ed448":
                self.assertTrue(tbs["subject_public_key_info"]["algorithm"]["algorithm"].native == "ed448")

            verify_cert(new_ca)
