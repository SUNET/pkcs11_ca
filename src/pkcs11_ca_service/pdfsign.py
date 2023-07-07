"""pdfsign module, FastAPI runs from here"""
import base64
import os
import subprocess
import time
from typing import Any

from fastapi import FastAPI, Response, status
from pydantic import BaseModel, validator

# Create fastapi app
# Disable swagger and docs endpoints for now
app = FastAPI(docs_url=None, redoc_url=None)


class PDFSignRequest(BaseModel):
    """Class to represent request"""

    transaction_id: str
    data: str


class PDFSignReply(BaseModel):
    """Class to represent reply"""

    transaction_id: str
    data: str
    error: str
    create_ts: int

    @validator("data")
    def data_len(cls, v: str) -> str:
        """validate data field by length"""
        if len(v) < 3:
            raise ValueError("data field needs to be of length 3 or greater")
        return v


@app.post("/pdfsign01", response_model=PDFSignReply)
async def post_pdf(in_data: PDFSignRequest, response: Response) -> Any:
    """PDF fixme"""

    print(f"Received a base64 PDF, transaction_id: {in_data.transaction_id}")

    unsigned_filename = f"unsigned_{in_data.transaction_id}.pdf"
    signed_filename = f"signed_{in_data.transaction_id}.pdf"

    create_ts = int(time.time())

    if os.path.exists(unsigned_filename) or os.path.exists(signed_filename):
        response.status_code = status.HTTP_204_NO_CONTENT
        return PDFSignReply(
            transaction_id=in_data.transaction_id,
            data="",
            create_ts=create_ts,
            error="transaction_id already exists",
        )

    unsigned_pdf_bytes = base64.b64decode(in_data.data, validate=True)
    with open(unsigned_filename, "wb") as f_data:
        f_data.write(unsigned_pdf_bytes)

    print(f"Trying to sign the PDF, transaction_id: {in_data.transaction_id}")
    subprocess.check_call(
        [
            "bash",
            "-c",
            """pyhanko sign addsig --no-strict-syntax --trust ts_chain.pem --timestamp-url http://ca_ca:8005/timestamp01 --field Signature1 --with-validation-info --use-pades pemder --key ts_priv --cert ts_cert.pem --no-pass """
            + f"{unsigned_filename} {signed_filename}",
        ]
    )
    print(
        f"Successfully signed the PDF, transaction_id: {in_data.transaction_id}")

    with open(signed_filename, "rb") as f_data:
        signed_pdf_bytes = f_data.read()

    signed_pdf_b64 = base64.b64encode(signed_pdf_bytes).decode("utf-8")

    print(
        f"Removing temporary disk files, transaction_id: {in_data.transaction_id}")
    os.remove(signed_filename)
    os.remove(unsigned_filename)

    print(
        f"Sending the signed PDF back to client, transaction_id: {in_data.transaction_id}")

    return PDFSignReply(
        transaction_id=in_data.transaction_id,
        data=signed_pdf_b64,
        create_ts=create_ts,
        error="",
    )
