"""
Test our CRL creation
"""
import unittest
import json
import os

import requests
from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem

from src.pkcs11_ca_service.asn1 import create_jwt_header_str, crl_expired
from src.pkcs11_ca_service.config import ROOT_URL
from .lib import get_cas


class TestCrl(unittest.TestCase):
    """
    Test our crls
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def test_crl(self) -> None:
        """
        Test crls
        """

        with open("data/trusted_keys/pubkey1.pem", "rb") as f_data:
            pub_key = f_data.read()
        with open("data/trusted_keys/privkey1.key", "rb") as f_data:
            priv_key = f_data.read()

        # Get all CAs
        cas = get_cas(self.ca_url, pub_key, priv_key)

        # create a crl
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/crl")}

        data = json.loads('{"ca_pem": ' + '"' + cas[0].replace("\n", "\\n") + '"' + "}")
        req = requests.post(
            self.ca_url + "/crl", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 200)

        crl1 = json.loads(req.text)["crl"]
        data = json.loads(req.text)["crl"].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))

        # get the crl
        request_headers = {"Authorization": create_jwt_header_str(pub_key, priv_key, self.ca_url + "/search/crl")}

        data = json.loads('{"pem": ' + '"' + crl1.replace("\n", "\\n") + '"' + "}")
        req = requests.post(
            self.ca_url + "/search/crl", headers=request_headers, json=data, timeout=10, verify="./tls_certificate.pem"
        )
        self.assertTrue(req.status_code == 200)
        self.assertTrue(len(json.loads(req.text)["crls"]) == 1)

        data = json.loads(req.text)["crls"][0].encode("utf-8")
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))

        # Check if expired
        self.assertFalse(crl_expired(json.loads(req.text)["crls"][0]))
