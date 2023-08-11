import base64
from io import BytesIO
from pkcs11_ca_service.common.helpers import unix_ts

from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pkcs11_ca_service.pdf.models import PDFSignReply, PDFValidateReply
from pkcs11_ca_service.pdf.context import ContextRequest


def sign(req: ContextRequest, transaction_id: str, base64_pdf: str, reason: str, location: str) -> PDFSignReply:
    """sign a PDF"""

    req.app.logger.info(msg=f"Trying to sign the PDF, transaction_id: {transaction_id}")
    pdf_writer = IncrementalPdfFileWriter(input_stream=BytesIO(base64.b64decode(base64_pdf)))

    f = BytesIO()

    signature_meta = signers.PdfSignatureMetadata(
        field_name="Signature1",
        location=location,
        reason=reason,
        subfilter=SigSeedSubFilter.PADES,
        use_pades_lta=True,
        embed_validation_info=True,
        validation_context=req.app.validator_context,
    )

    signers.sign_pdf(
        pdf_writer,
        signature_meta=signature_meta,
        signer=req.app.cms_signer,
        output=f,
        # timestamper=req.app.tst_client,
    )

    base64_encoded = base64.b64encode(f.getvalue()).decode("utf-8")

    req.app.logger.info(msg=f"Successfully signed the PDF, transaction_id: {transaction_id}")

    f.close()

    return PDFSignReply(
        transaction_id=transaction_id,
        data=base64_encoded,
        create_ts=unix_ts(),
        error="",
    )


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

    req.app.logger.info(msg=f"status: {status}")

    # status_ltv = validate_pdf_ltv_signature(
    #    sig,
    #    RevocationInfoValidationType.PADES_LTA,
    #    validation_context_kwargs={'trust_roots': [req.app.cert_pemder]},
    # )

    # req.app.logger.info(msg=status_ltv.pretty_print_details())

    req.app.logger.info(msg="Successfully validate PDF")

    return PDFValidateReply(
        valid=status.valid,
    )
