from typing import Any
from fastapi import APIRouter
from pkcs11_ca_service.pdf.routers.utils.pdf import sign, validate
from pkcs11_ca_service.pdf.models import PDFSignRequest, PDFSignReply, PDFValidateRequest, PDFValidateReply
from pkcs11_ca_service.pdf.exceptions import ErrorDetail
from pkcs11_ca_service.pdf.context import ContextRequest, ContextRequestRoute


pdf_router = APIRouter(
    route_class=ContextRequestRoute,
    prefix="/pdf",
    responses={
        400: {"description": "Bad request", "model": ErrorDetail},
        404: {"description": "Not found", "model": ErrorDetail},
        500: {"description": "Internal server error", "model": ErrorDetail},
    },
)


@pdf_router.post("/sign", response_model=PDFSignReply)
def endpoint_sign_pdf(req: ContextRequest, in_data: PDFSignRequest) -> Any:
    """ endpoint for signing a base64 encoded PDF """

    req.app.logger.info(
        f"Received a base64 PDF, transaction_id: {in_data.transaction_id}")

    reply = sign(req=req,
                 transaction_id=in_data.transaction_id,
                 base64_pdf=in_data.data,
                 reason=in_data.reason,
                 location=in_data.location,
                 )

    return reply


@pdf_router.post("/validate", response_model=PDFValidateReply)
def endpoint_validate_pdf(req: ContextRequest, in_data: PDFValidateRequest) -> Any:
    """ endpoint for validation of a base64 encoded PDF """

    req.app.logger.info("Validate a signed base64 PDF")

    reply = validate(req=req, base64_pdf=in_data.data)

    return reply
