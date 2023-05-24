"""pdfsign module, FastAPI runs from here"""
import base64
import os
import secrets
import subprocess

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Create fastapi app
# Disable swagger and docs endpoints for now
app = FastAPI(docs_url=None, redoc_url=None)


class PDFInput(BaseModel):
    """Class to represent PDF and metadata matching from HTTP post data"""

    transaction_id: str
    pdf_b64_data: str


@app.post("/pdfsign01")
async def post_pdf(pdf_input: PDFInput) -> JSONResponse:
    """PDF fixme"""

    print("Received a PDF file")

    if len(pdf_input.pdf_b64_data) < 3:
        raise ValueError("Invalid PDF")

    pdf_bytes = base64.b64decode(pdf_input.pdf_b64_data, validate=True)
    filename = str(secrets.randbits(128))

    with open(f"{filename}.pdf", "wb") as f_data:
        f_data.write(pdf_bytes)

    print("Trying to sign the PDF")
    subprocess.check_call(
        [
            "bash",
            "-c",
            """pyhanko sign addsig --no-strict-syntax --trust ts_chain.pem --timestamp-url http://ca:8005/timestamp01 --field Signature1 --with-validation-info --use-pades pemder --key ts_priv --cert ts_cert.pem --no-pass """
            + f"{filename}.pdf signed_{filename}.pdf",
        ]
    )
    print("Successfully signed the PDF")

    with open(f"signed_{filename}.pdf", "rb") as f_data:
        signed_pdf_bytes = f_data.read()

    signed_pdf_b64 = base64.b64encode(signed_pdf_bytes).decode("utf-8")

    print("Removing temporary disk files")
    os.remove(f"signed_{filename}.pdf")
    os.remove(f"{filename}.pdf")

    print("Sending the signed PDF back to client")

    return JSONResponse(
        status_code=200, content={"transaction_id": pdf_input.transaction_id, "signed_pdf_b64_data": signed_pdf_b64}
    )
