"""Main module, FastAPI runs from here"""
import asyncio
import base64
import os
import subprocess
import sys
from typing import Dict, Optional, Union

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pkcs11.exceptions import NoSuchKey
from pydantic import BaseModel
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


async def pkcs11_startup() -> None:
    # Ensure pkcs11 env variables
    if (
        "PKCS11_BACKEND" not in os.environ
        or "PKCS11_MODULE" not in os.environ
        or "PKCS11_TOKEN" not in os.environ
        or "PKCS11_PIN" not in os.environ
    ):
        print("PKCS11_BACKEND, PKCS11_MODULE, PKCS11_TOKEN or PKCS11_PIN env variables is not set")
        sys.exit(1)

    # If SOFTHSM then create token if not exists
    if os.environ["PKCS11_BACKEND"] == "SOFTHSM":
        if not os.path.isdir("/var/lib/softhsm/tokens") or not os.listdir("/var/lib/softhsm/tokens"):
            subprocess.check_call(
                [
                    "softhsm2-util",
                    "--init-token",
                    "--slot",
                    "0",
                    "--label",
                    os.environ["PKCS11_TOKEN"],
                    "--pin",
                    os.environ["PKCS11_PIN"],
                    "--so-pin",
                    os.environ["PKCS11_PIN"],
                ]
            )


class PKCS11Request(BaseModel):
    key_label: Optional[str] = None
    key_type: Optional[str] = None
    data_b64: Optional[str] = None
    signature_b64: Optional[str] = None
    verify_signature: Optional[bool] = None
    public_key_b64: Optional[str] = None
    private_key_b64: Optional[str] = None
    cert_label: Optional[str] = None
    cert_pem: Optional[str] = None


loop = asyncio.get_running_loop()
startup_task = loop.create_task(pkcs11_startup())

# Create fastapi app
app = FastAPI()


@app.get("/pkcs11/simple_healthcheck")
async def get_pkcs11_simple_healthcheck() -> JSONResponse:
    _ = await PKCS11Session().sign(
        key_label="test_pkcs11_device_do_not_use",
        data=b"test_data",
        verify_signature=True,
        key_type="rsa_2048",
    )
    return JSONResponse({"status": "ok"})


@app.post("/pkcs11/import_certificate")
async def post_pkcs11_import_certificate(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if not isinstance(pkcs11_request.cert_label, str) or not isinstance(pkcs11_request.cert_pem, str):
        raise HTTPException(status_code=400, detail="Invalid request")

    await PKCS11Session().import_certificate(cert_label=pkcs11_request.cert_label, cert_pem=pkcs11_request.cert_pem)
    print("imported cert ok")
    return JSONResponse({"status": "ok"})


@app.post("/pkcs11/export_certificate")
async def post_pkcs11_export_certificate(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if not isinstance(pkcs11_request.cert_label, str):
        raise HTTPException(status_code=400, detail="Invalid request")

    cert = await PKCS11Session().export_certificate(cert_label=pkcs11_request.cert_label)
    print("exported cert ok")
    return JSONResponse({"status": "ok", "certificate": cert})


@app.post("/pkcs11/delete_certificate")
async def post_pkcs11_delete_certificate(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if not isinstance(pkcs11_request.cert_label, str):
        raise HTTPException(status_code=400, detail="Invalid request")

    await PKCS11Session().delete_certificate(cert_label=pkcs11_request.cert_label)
    print("deleted cert ok")
    return JSONResponse({"status": "ok"})


@app.post("/pkcs11/create_keypair")
async def post_pkcs11_create_keypair(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if not isinstance(pkcs11_request.key_label, str) or not isinstance(pkcs11_request.key_type, str):
        raise HTTPException(status_code=400, detail="Invalid request")

    spi, ski = await PKCS11Session().create_keypair(
        key_label=pkcs11_request.key_label, key_type=pkcs11_request.key_type
    )
    print("created keypair ok")
    return JSONResponse(
        {"status": "ok", "subjectPublicKeyInfo": spi, "subjectKeyIdentifier_b64": base64.b64encode(ski).decode("utf-8")}
    )


@app.post("/pkcs11/import_keypair")
async def post_pkcs11_import_keypair(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if (
        not isinstance(pkcs11_request.key_label, str)
        or not isinstance(pkcs11_request.key_type, str)
        or not isinstance(pkcs11_request.public_key_b64, str)
        or not isinstance(pkcs11_request.private_key_b64, str)
    ):
        raise HTTPException(status_code=400, detail="Invalid request")

    await PKCS11Session().import_keypair(
        public_key=base64.b64decode(pkcs11_request.public_key_b64),
        private_key=base64.b64decode(pkcs11_request.private_key_b64),
        key_label=pkcs11_request.key_label,
        key_type=pkcs11_request.key_type,
    )
    print("imported keypair ok")
    return JSONResponse({"status": "ok"})


@app.post("/pkcs11/key_labels")
async def post_pkcs11_key_labels(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    key_labels = await PKCS11Session().key_labels()
    print("key labels ok")
    return JSONResponse({"status": "ok", "key_labels": key_labels})


@app.post("/pkcs11/sign")
async def post_pkcs11_sign(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if (
        not isinstance(pkcs11_request.key_label, str)
        or not isinstance(pkcs11_request.key_type, str)
        or not isinstance(pkcs11_request.data_b64, str)
    ):
        raise HTTPException(status_code=400, detail="Invalid request")

    signature = await PKCS11Session().sign(
        key_label=pkcs11_request.key_label,
        data=base64.b64decode(pkcs11_request.data_b64),
        verify_signature=pkcs11_request.verify_signature,
        key_type=pkcs11_request.key_type,
    )
    print("signed data ok")
    return JSONResponse({"status": "ok", "signature_b64": base64.b64encode(signature).decode("utf-8")})


@app.post("/pkcs11/verify")
async def post_pkcs11_verify(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if (
        not isinstance(pkcs11_request.key_label, str)
        or not isinstance(pkcs11_request.key_type, str)
        or not isinstance(pkcs11_request.data_b64, str)
        or not isinstance(pkcs11_request.signature_b64, str)
    ):
        raise HTTPException(status_code=400, detail="Invalid request")

    verified = await PKCS11Session().verify(
        key_label=pkcs11_request.key_label,
        data=base64.b64decode(pkcs11_request.data_b64),
        signature=base64.b64decode(pkcs11_request.signature_b64),
        key_type=pkcs11_request.key_type,
    )
    print("verified signature ok")
    return JSONResponse({"status": "ok", "verified": verified})


@app.post("/pkcs11/delete_keypair")
async def post_pkcs11_delete_keypair(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if not isinstance(pkcs11_request.key_label, str) or not isinstance(pkcs11_request.key_type, str):
        raise HTTPException(status_code=400, detail="Invalid request")

    await PKCS11Session().delete_keypair(key_label=pkcs11_request.key_label, key_type=pkcs11_request.key_type)
    print("deleted keypair ok")
    return JSONResponse({"status": "ok"})


@app.post("/pkcs11/public_key_data")
async def post_pkcs11_public_key_data(request: Request, pkcs11_request: PKCS11Request) -> JSONResponse:
    if not isinstance(pkcs11_request.key_label, str) or not isinstance(pkcs11_request.key_type, str):
        raise HTTPException(status_code=400, detail="Invalid request")

    try:
        spi, ski = await PKCS11Session().public_key_data(
            key_label=pkcs11_request.key_label, key_type=pkcs11_request.key_type
        )
    except NoSuchKey:
        return JSONResponse({"status": "error", "detail": "NoSuchKey"})

    print("verified signature ok")
    return JSONResponse(
        {"status": "ok", "subjectPublicKeyInfo": spi, "subjectKeyIdentifier_b64": base64.b64encode(ski).decode("utf-8")}
    )
