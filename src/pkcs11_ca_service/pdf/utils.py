""" PDF utils for signing and validating PDFs """
import base64
import binascii
import os
import sys
from io import BytesIO

from pyhanko.sign import signers
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.keys import load_cert_from_pemder
from .models import PDFSignReply, PDFValidateReply, PDFValidateData
from .context import ContextRequest


def sign(req: ContextRequest, transaction_id: str, base64_pdf: str) -> PDFSignReply:
    """sign a PDF"""

    req.app.logger.info(
        msg=f"Trying to sign the PDF, transaction_id: {transaction_id}"
    )
    pdf_writer = IncrementalPdfFileWriter(
        BytesIO(base64.b64decode(base64_pdf.encode("utf-8"), validate=True))
    )

    out = signers.sign_pdf(
        pdf_writer, signers.PdfSignatureMetadata(
            field_name='Signature1',
            location='Tidan',
            reason='Testing',
            use_pades_lta=True,
            embed_validation_info=False,
            # validation_context=ValidationContext(),
        ),
        signer=req.app.cms_signer,
    )
    print("out: ", out, file=sys.stdout)
    req.app.logger.debug(msg=f"out: {out}")

    req.app.logger.info(
        msg=f"Successfully signed the PDF, transaction_id: {transaction_id}"
    )

    signed_pdf_b64 = base64.b64encode(out.read()).decode("utf-8")

    return PDFSignReply(
        transaction_id=transaction_id,
        data=signed_pdf_b64,
        error="",
    )


def validate(req: ContextRequest, base64_pdf: str) -> PDFValidateReply:
    """validate a PDF"""

    req.app.logger.info(msg="Trying to validate the PDF")

    pdf = PdfFileReader(
        BytesIO(base64.b64decode(base64_pdf.encode("utf-8"), validate=True))
    )

    sig = pdf.embedded_signatures[0]
    status = validate_pdf_signature(sig, req.app.validator_context)

    return PDFValidateReply(
        data=PDFValidateData(
            valid=status.valid,
        ),
        error="",
    )
