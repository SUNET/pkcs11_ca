import logging
# from logging import Logger, getLogger
from fastapi import FastAPI
from typing import Optional
from pyhanko.sign import signers, SimpleSigner, timestamps
from pyhanko.keys import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from .context import ContextRequestRoute
from .router import pdf_router
from .exceptions import (
    RequestValidationError,
    validation_exception_handler,
    HTTPErrorDetail,
    http_error_detail_handler,
    unexpected_error_handler,
)


class PDFAPI(FastAPI):
    """PDF API"""

    def __init__(self,
                 service_name: str = "pdf_api",
                 timestamp_url: str = "http://ca_ca:8005/timestamp01"
                 ):
        self.service_name = service_name
        self.logger = logging.getLogger(self.service_name)
        self.logger.setLevel(logging.DEBUG)

        super().__init__()

        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        ch.setFormatter(formatter)

        self.logger.addHandler(ch)

        # self.logger_config: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"

        self.chain_path = "/app/ts_chain.pem"
        self.key_path = "/app/ts_priv"
        self.cert_path = "/app/ts_cert.pem"
        self.tst_client = timestamps.HTTPTimeStamper(
            url=timestamp_url,
        )

        self.logger.info(msg=f"chain_path: {self.chain_path}")
        self.logger.info(msg=f"cert_path: {self.cert_path}")
        self.logger.info(msg=f"key_path: {self.key_path}")

        self.cms_signer: Optional[SimpleSigner] = signers.SimpleSigner.load(
            key_file=self.key_path,
            cert_file=self.cert_path,
            # ca_chain_files=(self.chain_path),
            signature_mechanism=None)

        self.cert_pemder = load_cert_from_pemder(self.cert_path)

        self.validator_context = ValidationContext(
            trust_roots=[
                self.cert_pemder,
            ],
        )


def init_api(service_name: str = "pdf_api") -> PDFAPI:
    """init PDF_API"""
    app = PDFAPI(service_name=service_name)
    app.router.route_class = ContextRequestRoute

    # Routers
    app.include_router(pdf_router)

    # Exception handling
    app.add_exception_handler(RequestValidationError,
                              validation_exception_handler)
    app.add_exception_handler(
        HTTPErrorDetail, http_error_detail_handler)
    app.add_exception_handler(Exception, unexpected_error_handler)

    app.logger.info(msg="app running...")
    return app
