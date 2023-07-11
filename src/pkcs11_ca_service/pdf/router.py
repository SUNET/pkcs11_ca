"""Router for PDF signing and validation"""

import os
import subprocess
from typing import Any
import uuid
from fastapi import APIRouter
from .context import ContextRequest, ContextRequestRoute
from .utils import base64_to_byte, sign
from .models import PDFSignRequest, PDFSignReply, PDFValidateRequest, PDFValidateReply
from .exceptions import ErrorDetail


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

    # create_ts = int(time.time())

    reply = sign(req=req, transaction_id=in_data.transaction_id,
                 base64_pdf=in_data.data)

    return reply


@pdf_router.post("/validate", response_model=PDFValidateReply)
def validate_pdf(req: ContextRequest, in_data: PDFValidateRequest) -> Any:
    """ endpoint for validation of a base64 encoded PDF """

    req.app.logger.info("Validate a signed base64 PDF")

    filename = f"validate_candidate_{str(uuid.uuid4())}.pdf"

    base64_to_byte(base64_str=in_data.data, filename=filename)

    output = subprocess.run([
        "bash",
        "-c",
        """pyhanko sign validate - -pretty-print""",
        + f"{filename}",
    ],
        check=True,
        capture_output=True,
        text=True,
    )

    os.remove(filename)

    print(f"output from validate: {output.stdout}")
    return PDFValidateReply(
        error="",
        message=output,
    )
