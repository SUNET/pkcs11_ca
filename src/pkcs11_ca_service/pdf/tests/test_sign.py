import unittest
import requests

from pkcs11_ca_service.pdf.app import init_api
from pkcs11_ca_service.pdf.context import ContextRequest
from pkcs11_ca_service.pdf.routers.utils.pdf import sign, validate


class TestSign(unittest.TestCase):
    """ Test pdf signing """
    url = "http://localhost:8006"
    app = init_api()

    def test_sign(self) -> None:
        """
        Test sign
        """
        req = requests.post(
            url=self.url + "/pdf/sign",
            headers={"Content-Type": "application/json"},
            json="",
            timeout=10,
            verify=False,
        )
        assert req.status_code == 200

    def test_sign_pdf(self) -> None:
        """ Test signing of pdf """
        base64_pdf = ""
        signed_pdf_reply = sign(req= ContextRequest, transaction_id= "test", base64_pdf= base64_pdf, reason= "test", location="test")
        res = validate(req=ContextRequest, base64_pdf=signed_pdf_reply.data)
        assert res.valid_signature is True