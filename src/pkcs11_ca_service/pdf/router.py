"""Router for PDF signing and validation"""

from typing import Any
from fastapi import APIRouter
from .context import ContextRequest, ContextRequestRoute
from .utils import sign, validate
from .models import PDFSignRequest, PDFSignReply, PDFValidateRequest, PDFValidateReply, StatusReply
from .exceptions import ErrorDetail

status_router = APIRouter(route_class=ContextRequestRoute, prefix="/status")


@status_router.get("/healthy", response_model=StatusReply)
async def healthy(req: ContextRequest) -> Any:
    """Endpoint for status/healthy"""

    req.app.logger.info(msg="Check for healthy")

    reply = StatusReply(
        status="STATUS_OK",
    )

    return reply


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
def sign_pdf(req: ContextRequest, in_data: PDFSignRequest) -> Any:
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
def validate_pdf(req: ContextRequest, in_data: PDFValidateRequest) -> Any:
    """ endpoint for validation of a base64 encoded PDF """

    req.app.logger.info("Validate a signed base64 PDF")

    reply = validate(req=req, base64_pdf=in_data.data)

    return reply