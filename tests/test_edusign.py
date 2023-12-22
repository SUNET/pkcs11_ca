"""
Test our edusign module
"""
import datetime
import os
import unittest

import requests
from asn1crypto import crl as asn1_crl
from asn1crypto import pem as asn1_pem

from src.pkcs11_ca_service.config import ROOT_URL

from .lib import verify_pkcs11_ca_tls_cert


class TestEDUSIGN(unittest.TestCase):
    """
    Test our edusign
    """

    if "CA_URL" in os.environ:
        ca_url = os.environ["CA_URL"]
    else:
        ca_url = ROOT_URL

    def test_edusign_longterm_crl(self) -> None:
        """
        Test our longterm edusign CRL signed by the old CA.
        """

        req = requests.get(
            self.ca_url + "/edusign/longterm-crl",
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )

        self.assertTrue(req.status_code == 200)

        data = req.content
        if asn1_pem.detect(data):
            _, _, data = asn1_pem.unarmor(data)

        test_crl = asn1_crl.CertificateList.load(data)
        self.assertTrue(isinstance(test_crl, asn1_crl.CertificateList))

        crl_dict = test_crl.native

        # Ensure CRL is empty (no revoked certs)
        self.assertTrue(crl_dict["tbs_cert_list"]["revoked_certificates"] is None)

        # Ensure created before current time
        self.assertTrue(crl_dict["tbs_cert_list"]["this_update"] < (datetime.datetime.now(datetime.timezone.utc)))

        # Ensure next_update (valid until) is one year long
        self.assertTrue(
            crl_dict["tbs_cert_list"]["next_update"]
            > (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=359)).replace(microsecond=0)
        )

    def test_edusign_simple_healthcheck(self) -> None:
        """
        Test our simple healthcheck
        """

        req = requests.get(
            self.ca_url + "/edusign/simple_healthcheck",
            timeout=10,
            verify=verify_pkcs11_ca_tls_cert(),
        )

        # Ensure status 200 OK
        self.assertTrue(req.status_code == 200)
