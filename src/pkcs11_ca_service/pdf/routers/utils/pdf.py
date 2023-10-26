"""pdf utils"""

import base64
from io import BytesIO
from typing import Optional

from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.crypt.api import PdfKeyNotAvailableError
from pkcs11_ca_service.pdf.models import PDFSignReply, PDFValidateReply
from pkcs11_ca_service.pdf.context import ContextRequest
from pkcs11_ca_service.common.helpers import unix_ts



def sign(req: ContextRequest, transaction_id: str, base64_pdf: str, reason: str, location: str) -> PDFSignReply:
    """sign a PDF"""

    req.app.logger.info(msg=f"Trying to sign the PDF, transaction_id: {transaction_id}")
    pdf_writer = IncrementalPdfFileWriter(input_stream=BytesIO(base64.urlsafe_b64decode(base64_pdf)), strict=False)

    pdf_writer.document_meta.keywords = [f"transaction_id:{transaction_id}"]

    signed_pdf = BytesIO()

    signature_meta = signers.PdfSignatureMetadata(
        field_name="Signature1",
        location=location,
        reason=reason,
        subfilter=SigSeedSubFilter.PADES,
        use_pades_lta=True,
        embed_validation_info=True,
        validation_context=req.app.validator_context,
    )

    try:
        signers.sign_pdf(
            pdf_writer,
            signature_meta=signature_meta,
            signer=req.app.simple_signer,
            output=signed_pdf,
            # timestamper=req.app.tst_client,
        )
    except PdfKeyNotAvailableError as _e:
        err_msg = f"ca_pdfsign: input pdf is encrypted, err: {_e}"

        req.app.logger.warn(err_msg)

        return PDFSignReply(
            transaction_id=transaction_id,
            data=None,
            create_ts=unix_ts(),
            error=err_msg,
        )

    base64_encoded = base64.b64encode(signed_pdf.getvalue()).decode("utf-8")

    req.app.logger.info(msg=f"Successfully signed the PDF, transaction_id: {transaction_id}")

    signed_pdf.close()

    return PDFSignReply(
        transaction_id=transaction_id,
        data=base64_encoded,
        create_ts=unix_ts(),
        error="",
    )


def get_transaction_id_from_keywords(req: ContextRequest, pdf: PdfFileReader) -> Optional[str]:
    """simple function to get transaction_id from a list of keywords"""
    for keyword in pdf.document_meta_view.keywords:
        entry = keyword.split(sep=":")
        if entry[0] == "transaction_id":
            req.app.logger.info(msg=f"found transaction_id: {entry[1]}")
            return entry[1]
    return None

def validate(req: ContextRequest, base64_pdf: str) -> PDFValidateReply:
    """validate a PDF"""

    req.app.logger.info(msg="Trying to validate the PDF")

    pdf = PdfFileReader(BytesIO(base64.b64decode(base64_pdf.encode("utf-8"), validate=True)))

    if len(pdf.embedded_signatures) == 0:
        return PDFValidateReply(error="No signature found")

    sig = pdf.embedded_signatures[0]
    status = validate_pdf_signature(
        embedded_sig=sig,
        signer_validation_context=req.app.validator_context,
    )

    transaction_id = get_transaction_id_from_keywords(req=req, pdf=pdf)

    req.app.logger.info(msg=f"status: {status}")

    # status_ltv = validate_pdf_ltv_signature(
    #    sig,
    #    RevocationInfoValidationType.PADES_LTA,
    #    validation_context_kwargs={'trust_roots': [req.app.cert_pemder]},
    # )

    # req.app.logger.info(msg=status_ltv.pretty_print_details())

    req.app.logger.info(msg="Successfully validate PDF")

    return PDFValidateReply(
        valid_signature=status.valid,
        transaction_id= transaction_id,
    )
