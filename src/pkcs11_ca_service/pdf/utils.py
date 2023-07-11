""" PDF utils for signing and validating PDFs """
import base64
import binascii
import os
import sys

from pyhanko.sign import signers
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from .models import PDFSignReply, PDFValidateReply
from .context import ContextRequest


def base64_to_byte(base64_str: str, filename: str) -> None:
    """helper for open, convert base64 string to bytes"""
    try:
        unsigned_pdf_bytes = base64.b64decode(
            base64_str.encode("utf-8"), validate=True)
    except binascii.Error:
        return None

    with open(filename, "wb") as f_data:
        f_data.write(unsigned_pdf_bytes)

    return None


def sign(req: ContextRequest, transaction_id: str, base64_pdf: str) -> PDFSignReply:
    """sign a PDF"""

    unsigned_filename = f"unsigned_{transaction_id}.pdf"
    signed_filename = f"signed_{transaction_id}.pdf"

    # if os.path.exists(unsigned_filename) or os.path.exists(signed_filename):
    #    return PDFSignReply(
    #        transaction_id=transaction_id,
    #        data="",
    #        error="transaction_id already exists",
    #    )

    base64_to_byte(
        base64_str=base64_pdf, filename=unsigned_filename)

    req.app.logger.info(
        msg=f"Trying to sign the PDF, transaction_id: {transaction_id}"
    )
    with open(unsigned_filename, 'rb') as doc:
        w = IncrementalPdfFileWriter(doc)
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
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
        req.app.logger.info(msg=f"out: {out}")
   # subprocess.check_call(
   #     [
   #         "bash",
   #         "-c",
   #         """pyhanko sign addsig --no-strict-syntax --trust ts_chain.pem --timestamp-url http://ca_ca:8005/timestamp01 --field Signature1 --with-validation-info --use-pades pemder --key ts_priv --cert ts_cert.pem --no-pass """
   #         + f"{unsigned_filename} {signed_filename}",
   #     ]
   # )
    req.app.logger.info(
        msg=f"Successfully signed the PDF, transaction_id: {transaction_id}")

   # with open(signed_filename, "rb") as f_data:
   #     signed_pdf_bytes = f_data.read()

   # signed_pdf_b64 = base64.b64encode(signed_pdf_bytes).decode("utf-8")

   # print(
   #     f"Removing temporary disk files, transaction_id: {in_data.transaction_id}")
   # os.remove(signed_filename)
   # os.remove(unsigned_filename)

   # print(
   #     f"Sending the signed PDF back to client, transaction_id: {in_data.transaction_id}")
    return PDFSignReply(
        transaction_id=transaction_id,
        data="",
        error="",
    )


def validate() -> PDFValidateReply:
    """validate a PDF"""
