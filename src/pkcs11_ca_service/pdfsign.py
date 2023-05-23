"""pdfsign module, FastAPI runs from here"""
import os
import secrets
import subprocess

from fastapi import FastAPI, HTTPException, Request, Response

# Create fastapi app
# Disable swagger and docs endpoints for now
app = FastAPI(docs_url=None, redoc_url=None)


@app.post("/pdfsign01")
async def post_pdf(request: Request) -> Response:
    """PDF fixme"""

    media_type = "application/pdf"

    content_type = request.headers.get("Content-type")
    if content_type is None or content_type != media_type:
        return Response(status_code=400, content=b"0", media_type=media_type)

    data = await request.body()
    print("Received a PDF file")

    filename = str(secrets.randbits(128))

    with open(f"{filename}.pdf", "wb") as f_data:
        f_data.write(data)

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

    print("Removing temporary disk files")
    os.remove(f"signed_{filename}.pdf")
    os.remove(f"{filename}.pdf")

    print("Sending the signed PDF back to client")

    # curl http://ca:8005/timestamp01 -H 'Content-Type: application/timestamp-query' -s -S --data-binary "@ts_req.tsq" -o "ts_req.tsr"
    # openssl ts -reply -in ts_req.tsr -token_out 2> /dev/null | openssl pkcs7 -inform der -print_certs 2> /dev/null | sed -n '/-----BEGIN/,/-----END/p' > timestamp_chain.pem
    # cat timestamp_chain.pem >> ts_chain.pem

    return Response(status_code=200, content=signed_pdf_bytes, media_type=media_type)
