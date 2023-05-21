"""Main module, FastAPI runs from here"""
import asyncio
import base64
import hashlib
import os
from secrets import token_bytes
from typing import Dict, Union

from asn1crypto import x509 as asn1_x509
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.background import BackgroundTasks
from fastapi.responses import JSONResponse
from pkcs11.exceptions import MultipleObjectsReturned
from python_x509_pkcs11.ca import create as create_ca
from python_x509_pkcs11.crl import create as create_crl
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

from .acme_lib import NoSuchKID, handle_acme_routes
from .asn1 import (
    aia_and_cdp_exts,
    cert_as_der,
    cert_pem_serial_number,
    crl_as_der,
    pem_cert_to_name_dict,
    public_key_pem_from_csr,
)
from .auth import authorized_by
from .base import InputObject, db_load_data_class
from .ca import Ca, CaInput
from .ca import search as ca_search
from .certificate import Certificate, CertificateInput
from .certificate import search as certificate_search
from .cmc import cmc_handle_request
from .config import ACME_ROOT, KEY_TYPES, PKCS11_SIGN_API_TOKEN, ROOT_URL
from .crl import Crl, CrlInput
from .crl import search as crl_search
from .csr import Csr, CsrInput
from .csr import search as csr_search
from .nonce import nonce_response
from .ocsp import ocsp_response
from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
from .pkcs11_sign import pkcs11_sign
from .public_key import PublicKey, PublicKeyInput
from .public_key import search as public_key_search
from .route_functions import (
    ca_request,
    crl_request,
    healthcheck,
    pkcs11_key_request,
    sign_csr,
)
from .startup import startup
from .timestamp import timestamp_handle_request

if "_" in os.environ and "sphinx-build" in os.environ["_"]:
    print("Running sphinx build")
else:
    loop = asyncio.get_running_loop()
    startup_task = loop.create_task(startup())

# Create fastapi app
# Disable swagger and docs endpoints for now
app = FastAPI(docs_url=None, redoc_url=None)


@app.get("/new-nonce")
async def get_new_nonce() -> Response:
    """Get new nonce, GET method.

    Returns:
    fastapi.Response
    """

    return nonce_response()


@app.head("/new-nonce")
async def head_new_nonce() -> Response:
    """Get new nonce, HEAD method.

    Returns:
    fastapi.Response
    """

    return nonce_response()


@app.get("/healthcheck")
async def get_healthcheck(request: Request) -> JSONResponse:
    """/healthcheck, GET method.

    Do a healthcheck. Sign some data.

    Parameters:
    request (fastapi.Request): The entire HTTP request.

    Returns:
    fastapi.responses.JSONResponse
    """

    _ = await authorized_by(request)
    return await healthcheck()


@app.get("/search/public_key")
async def get_public_key_search(request: Request) -> JSONResponse:
    """/search/public_key, GET method.

    Fetch all public keys.

    Parameters:
    request (fastapi.Request): The entire HTTP request.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await public_key_search(InputObject())


@app.post("/search/public_key")
async def post_public_key_search(request: Request, public_key_input: PublicKeyInput) -> JSONResponse:
    """/search/public_key, POST method.

    Fetch all public keys which matches the search pattern.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    public_key_input (PublicKeyInput): The search pattern.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await public_key_search(public_key_input)


@app.get("/search/ca")
async def get_ca_search(request: Request) -> JSONResponse:
    """/search/ca, GET method.

    Fetch all cas.

    Parameters:
    request (fastapi.Request): The entire HTTP request.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await ca_search(InputObject())


@app.post("/search/ca")
async def post_ca_search(request: Request, ca_input: CaInput) -> JSONResponse:
    """/search/ca, POST method.

    Fetch all cas which matches the search pattern.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    ca_input (CaInput): The search pattern.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await ca_search(ca_input)


@app.get("/search/crl")
async def get_crl_search(request: Request) -> JSONResponse:
    """/search/crl, GET method.

    Fetch all crls.

    Parameters:
    request (fastapi.Request): The entire HTTP request.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await crl_search(InputObject())


@app.post("/search/crl")
async def post_crl_search(request: Request, crl_input: CrlInput) -> JSONResponse:
    """/search/crl, POST method.

    Fetch all crls which matches the search pattern.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    crl_input (CrlInput): The search pattern.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await crl_search(crl_input)


@app.get("/search/csr")
async def get_csr_search(request: Request) -> JSONResponse:
    """/search/csr, GET method.

    Fetch all csrs.

    Parameters:
    request (fastapi.Request): The entire HTTP request.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await csr_search(InputObject())


@app.post("/search/csr")
async def post_csr_search(request: Request, csr_input: CsrInput) -> JSONResponse:
    """/search/csr, POST method.

    Fetch all csrs which matches the search pattern.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    csr_input (CsrInput): The search pattern.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await csr_search(csr_input)


@app.get("/search/certificate")
async def get_certificate_search(request: Request) -> JSONResponse:
    """/search/certificate, GET method.

    Fetch all certificates.

    Parameters:
    request (fastapi.Request): The entire HTTP request.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await certificate_search(InputObject())


@app.post("/search/certificate")
async def post_certificate_search(request: Request, certificate_input: CertificateInput) -> JSONResponse:
    """/search/certificate, POST method.

    Fetch all certificates which matches the search pattern.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    certificate_input (CertificateInput): The search pattern.

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)
    return await certificate_search(certificate_input)


@app.post("/public_key")
async def post_public_key(request: Request, public_key_input: PublicKeyInput) -> JSONResponse:
    """/public_key, POST method.

    Post/create a new public key.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    public_key_input (PublicKeyInput): The public key data.

    Returns:
    fastapi.responses.JSONResponse
    """

    auth_by = await authorized_by(request)

    if public_key_input.pem is None:
        return JSONResponse(
            status_code=400,
            content={"message": "must have 'pem' with the public key"},
        )

    # remove is_admin check
    is_admin = 0
    if isinstance(public_key_input.admin, int) and public_key_input.admin == 1:
        is_admin = 1

    # Save Public key for new CA
    public_key_obj = PublicKey({"pem": public_key_input.pem, "authorized_by": auth_by, "admin": is_admin})
    await public_key_obj.save()
    return JSONResponse(status_code=200, content={"public_key": public_key_obj.pem})


# # Redo this so CRLS are generated in the background and this fetches the last one
@app.post("/crl")
async def post_crl(request: Request, crl_input: CrlInput) -> JSONResponse:
    """/crl, POST method.

    Create a new crl.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    crl_input (CrlInput): The crl data.

    Returns:
    fastapi.responses.JSONResponse
    """

    auth_by = await authorized_by(request)
    if crl_input.ca_pem is None:
        return JSONResponse(
            status_code=400,
            content={"message": "must have 'ca_pem' with the CA to issue a CRL for"},
        )

    issuer_obj = await ca_request(CaInput(pem=crl_input.ca_pem))
    crl_pem = await crl_request(auth_by, issuer_obj)
    return JSONResponse(status_code=200, content={"crl": crl_pem})


# ALSO THE SAME FOR POST
# APPENDIX A
# https://www.ietf.org/rfc/rfc2560.txt


@app.post("/ocsp/")
async def post_ocsp(request: Request) -> Response:
    """/ocsp, POST method.

    Return an OCSP response.

    Parameters:
    request (fastapi.Request): The entire HTTP request.

    Returns:
    fastapi.Response
    """

    # WORK ON BETTER ERROR HANDLING
    ocsp_request = await request.body()
    try:
        ocsp_data = await ocsp_response(ocsp_request, encoded=False)
        return Response(status_code=200, content=ocsp_data, media_type="application/ocsp-response")
    except HTTPException:
        return Response(status_code=404, content='{"detail":"Not Found"}', media_type="application/json")


@app.get("/ocsp/{ocsp_path:path}")
async def get_ocsp(ocsp_path: str) -> Response:
    """/ocsp, GET method.

    Return an OCSP response.

    Parameters:
    ocsp_path (str): OCSP path.

    Returns:
    fastapi.Response
    """

    # WORK ON BETTER ERROR HANDLING
    path = ocsp_path.replace("/ocsp/", "").encode("utf-8")
    try:
        ocsp_data = await ocsp_response(path, encoded=True)
        return Response(status_code=200, content=ocsp_data, media_type="application/ocsp-response")
    except HTTPException:
        return Response(status_code=404, content='{"detail":"Not Found"}', media_type="application/json")


@app.get("/crl/{crl_path}")
async def get_crl(crl_path: str) -> Response:
    """/ca, GET method.

    Get a CRL.

    Parameters:
    crl_path (str): The unique CRL path.

    Returns:
    fastapi.Response
    """

    path = crl_path.replace("/crl/", "")
    try:
        issuer_obj = await ca_request(CaInput(path=path))
        # Set author as id 1 (first root ca) if the CRL is created due to the old crl expired
        # author is unknow due to no authentication so lets set the system as author.
        # Perhaps rethink this in the future
        crl_pem = await crl_request(1, issuer_obj)
        return Response(status_code=200, content=crl_as_der(crl_pem), media_type="application/pkix-crl")
    except HTTPException:
        return Response(status_code=404, content='{"detail":"Not Found"}', media_type="application/json")


@app.get("/ca/{ca_path}")
async def get_ca(ca_path: str) -> Response:
    """/ca, GET method.

    Get a ca.

    Parameters:
    ca_path (str): The unique CA path.

    Returns:
    fastapi.Response
    """

    path = ca_path.replace("/ca/", "")
    try:
        issuer_obj = await ca_request(CaInput(path=path))
        return Response(status_code=200, content=cert_as_der(issuer_obj.pem), media_type="application/pkcs7-mime")
    except HTTPException:
        return Response(status_code=404, content='{"detail":"Not Found"}', media_type="application/json")


@app.post("/ca")
async def post_ca(request: Request, ca_input: CaInput) -> JSONResponse:  # pylint: disable-msg=too-many-locals
    """/ca, POST method.

    Post/create a new ca.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    ca_input (CaInput): The ca data.

    Returns:
    fastapi.responses.JSONResponse
    """

    auth_by = await authorized_by(request)

    if ca_input.name_dict is None or ca_input.key_label is None:
        return JSONResponse(
            status_code=400,
            content={"message": "missing json dict key 'pem' with a csr and 'ca_pem' with the signing CA"},
        )

    if ca_input.key_type is None:
        key_type = "secp256r1"
    else:
        key_type = ca_input.key_type
    if key_type not in KEY_TYPES:
        return JSONResponse(
            status_code=400,
            content={"message": f"missing valid json dict key 'key_type', must be one of {KEY_TYPES}"},
        )

    issuer_pem: Union[Dict[str, str], None] = None
    issuer_key_label: Union[str, None] = None
    issuer_key_type: Union[str, None] = None
    extra_extensions: Union[asn1_x509.Extensions, None] = None

    # If this should not be a self-signed ca
    if ca_input.issuer_pem is not None:
        issuer_obj = await ca_request(CaInput(pem=ca_input.issuer_pem))

        issuer_pkcs11_key_obj = await pkcs11_key_request(Pkcs11KeyInput(serial=issuer_obj.pkcs11_key))
        issuer_key_label = issuer_pkcs11_key_obj.key_label
        issuer_key_type = issuer_pkcs11_key_obj.key_type
        issuer_pem = pem_cert_to_name_dict(issuer_obj.pem)

        # This will be an intermediate CA so get the AIA and CDP extensions for it
        extra_extensions = aia_and_cdp_exts(issuer_obj.path)

    try:
        ca_csr_pem, ca_pem = await create_ca(
            ca_input.key_label,
            ca_input.name_dict,
            signer_key_label=issuer_key_label,
            signer_key_type=issuer_key_type,
            signer_subject_name=issuer_pem,
            extra_extensions=extra_extensions,
            key_type=key_type,
        )
    except MultipleObjectsReturned:
        return JSONResponse(
            status_code=400,
            content={"message": f"key_label '{ca_input.key_label}' already exists"},
        )

    # Save Public key for new CA
    public_key_obj = PublicKey(
        {
            "pem": (await PKCS11Session.public_key_data(ca_input.key_label, key_type=key_type))[0],
            "authorized_by": auth_by,
        }
    )
    await public_key_obj.save()

    # Save pkcs11 key for new CA
    pkcs11_key_obj = Pkcs11Key(
        {
            "public_key": public_key_obj.serial,
            "key_label": ca_input.key_label,
            "key_type": key_type,
            "authorized_by": auth_by,
        }
    )
    await pkcs11_key_obj.save()

    # Save csr for new CA
    csr_obj = Csr({"pem": ca_csr_pem, "authorized_by": auth_by, "public_key": public_key_obj.serial})
    await csr_obj.save()

    # Save new CA
    if ca_input.issuer_pem is not None:
        ca_obj = Ca(
            {
                "pem": ca_pem,
                "authorized_by": auth_by,
                "pkcs11_key": pkcs11_key_obj.serial,
                "csr": csr_obj.serial,
                "serial_number": str(cert_pem_serial_number(ca_pem)),
                "issuer": issuer_obj.serial,
                "path": hashlib.sha256(token_bytes(256)).hexdigest(),
            }
        )
        await ca_obj.save()
    else:
        # Save new CA
        ca_obj = Ca(
            {
                "pem": ca_pem,
                "pkcs11_key": pkcs11_key_obj.serial,
                "authorized_by": auth_by,
                "csr": csr_obj.serial,
                "serial_number": str(cert_pem_serial_number(ca_pem)),
            }
        )
        # Cant know issuer before we know serial which is only after we call save()
        # so hack this when the field_set_to_serial parameter
        await ca_obj.save(field_set_to_serial="issuer")

    # Create an empty CRL for the CA
    await Crl(
        {
            "pem": await create_crl(
                ca_input.key_label, pem_cert_to_name_dict(ca_pem), key_type=pkcs11_key_obj.key_type
            ),
            "authorized_by": auth_by,
            "issuer": ca_obj.serial,
        }
    ).save()

    return JSONResponse(status_code=200, content={"certificate": ca_pem})


@app.post("/sign_csr")
async def post_sign_csr(request: Request, csr_input: CsrInput) -> JSONResponse:
    """/sign_csr, POST method.

    Post/create a new csr, will create and return certificate.

    If a cert has CA:TRUE then treat it as a normal cert since we dont have its private key

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    csr_input (CsrInput): The csr data.

    Returns:
    fastapi.responses.JSONResponse
    """

    auth_by = await authorized_by(request)

    if csr_input.pem is None or csr_input.ca_pem is None:
        return JSONResponse(
            status_code=400,
            content={"message": "missing json dict key 'pem' with a csr and 'ca_pem' with the signing CA"},
        )

    # Get public key from csr
    public_key_obj = PublicKey({"pem": public_key_pem_from_csr(csr_input.pem), "authorized_by": auth_by})
    await public_key_obj.save()

    # Save csr
    csr_obj = Csr({"pem": csr_input.pem, "authorized_by": auth_by, "public_key": public_key_obj.serial})
    await csr_obj.save()

    issuer_obj = await ca_request(CaInput(pem=csr_input.ca_pem))

    data_content = await sign_csr(auth_by, issuer_obj, csr_obj, public_key_obj)

    return JSONResponse(status_code=200, content={"certificate": data_content})


class RevokeInput(InputObject):
    """Class to represent revoke specification matching from HTTP post data"""

    pem: str
    reason: Union[int, None]


@app.post("/is_revoked")
async def is_revoked(request: Request, revoke_input: RevokeInput) -> JSONResponse:
    """/is_revoked, POST method.

    If a certificate/CA is revoked

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    revoke_input (PublicKeyInput): The revoke specification

    Returns:
    fastapi.responses.JSONResponse
    """

    await authorized_by(request)

    db_certificate_objs = await db_load_data_class(Certificate, CertificateInput(pem=revoke_input.pem))
    for obj in db_certificate_objs:
        if isinstance(obj, Certificate):
            revoked = await obj.is_revoked()
            return JSONResponse(
                status_code=200,
                content={"is_revoked": revoked},
            )
    db_ca_objs = await db_load_data_class(Ca, CaInput(pem=revoke_input.pem))
    for obj in db_ca_objs:
        if isinstance(obj, Ca):
            revoked = await obj.is_revoked()
            return JSONResponse(
                status_code=200,
                content={"is_revoked": revoked},
            )

    return JSONResponse(
        status_code=400,
        content={"message": "No such certificate or CA"},
    )


@app.post("/revoke")
async def post_revoke(request: Request, revoke_input: RevokeInput) -> JSONResponse:
    """/revoke, POST method.

    Revoke a certificate/CA as a CA is really just a certificate.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    revoke_input (PublicKeyInput): The revoke specification

    Returns:
    fastapi.responses.JSONResponse
    """

    auth_by = await authorized_by(request)

    db_certificate_objs = await db_load_data_class(Certificate, CertificateInput(pem=revoke_input.pem))
    for obj in db_certificate_objs:
        if isinstance(obj, Certificate):
            await obj.revoke(auth_by, revoke_input.reason)
            return JSONResponse(
                status_code=200,
                content={"revoked": revoke_input.pem},
            )
    db_ca_objs = await db_load_data_class(Ca, CaInput(pem=revoke_input.pem))
    for obj in db_ca_objs:
        if isinstance(obj, Ca):
            await obj.revoke(auth_by, revoke_input.reason)
            return JSONResponse(
                status_code=200,
                content={"revoked": revoke_input.pem},
            )

    return JSONResponse(
        status_code=400,
        content={"message": "No such certificate or CA"},
    )


@app.post("/pkcs11_sign")
async def post_pkcs11_sign(request: Request) -> JSONResponse:
    """/pkcs11_sign, POST method."""

    if (
        "Authorization" not in request.headers
        or "Bearer " not in request.headers["Authorization"]
        or base64.b64decode(request.headers["Authorization"].split("Bearer ", maxsplit=1)[1])
        != PKCS11_SIGN_API_TOKEN.encode("utf-8")
    ):
        return JSONResponse(
            status_code=401,
            content={"message": "Missing valid authorization token"},
        )

    data = await request.json()
    return await pkcs11_sign(data)


@app.post("/cmc01")
async def post_cmc(request: Request) -> Response:
    """CMC fixme"""

    content_type = request.headers.get("Content-type")
    if content_type is None or content_type != "application/pkcs7-mime":
        return Response(status_code=400, content=b"0", media_type="application/pkcs7-mime")

    data = await request.body()
    print("cmc req for debugging")
    print(data.hex())
    try:
        data_content = await cmc_handle_request(data)
        return Response(status_code=200, content=data_content, media_type="application/pkcs7-mime")
    except (ValueError, TypeError):
        return Response(status_code=400, content=b"0", media_type="application/pkcs7-mime")


@app.post("/timestamp")
async def post_timestamp(request: Request) -> Response:
    """Timestamp fixme"""

    content_type = request.headers.get("Content-type")
    if content_type is None or content_type != "application/timestamp-query":
        return Response(status_code=400, content=b"0", media_type="application/timestamp-reply")

    data = await request.body()
    print("timestamp req for debugging")
    print(data.hex())
    try:
        data_content = await timestamp_handle_request(data)
        return Response(status_code=200, content=data_content, media_type="application/timestamp-reply")
    except (ValueError, TypeError) as e:
        raise e
        return Response(status_code=400, content=b"0", media_type="application/timestamp-reply")


acme_endpoints = [
    "new-account",
    "acct/{id}",
    "orders/{id}",
    "key-change",
    "new-order",
    "order/{id}",
    "new-authz",
    "authz/{id}",
    "chall/{id}",
    "order/{id}/finalize",
    "cert/{id}",
    "revoke-cert",
]

for acme_endpoint in acme_endpoints:

    @app.post(f"{ACME_ROOT}/{acme_endpoint}")  # pylint: disable=cell-var-from-loop
    async def post_acme_routes(request: Request, background_tasks: BackgroundTasks) -> Response:
        """Handle all acme endpoints except for /directory endpoint

        Parameters:
        request (Request): The http request
        background_tasks (BackgroundTasks): The list of background task to append to, for example executing challenges

        Returns:
        Response
        """

        try:
            return await handle_acme_routes(request, background_tasks)
        except (InvalidSignature, NoSuchKID) as exc:
            raise HTTPException(status_code=401, detail="Invalid jws signature or kid") from exc
        except (ValueError, IndexError, KeyError) as exc:
            raise HTTPException(status_code=400, detail="Non valid jws or url") from exc


@app.get(ACME_ROOT + "/directory")
async def get_acme_directory() -> JSONResponse:
    """ACME GET directory endpoint

    Returns:
    Response
    """

    paths = ["new-nonce", "new-account", "new-order", "new-authz", "revoke-cert", "key-change"]
    directory: Dict[str, str] = {}

    for path in paths:
        index = (
            path.split("-", maxsplit=1)[0]
            + path.split("-", maxsplit=1)[1][0].upper()
            + path.split("-", maxsplit=1)[1][1:]
        )
        directory[index] = ROOT_URL + ACME_ROOT + "/" + path
    return JSONResponse(status_code=200, content=directory)


@app.get(ACME_ROOT + "/new-nonce")
async def get_acme_new_nonce() -> Response:
    """ACME GET new-nonce endpoint

    Returns:
    Response
    """

    return nonce_response(204)


@app.head(ACME_ROOT + "/new-nonce")
async def head_acme_new_nonce() -> Response:
    """ACME HEAD new-nonce endpoint

    Returns:
    Response
    """

    return nonce_response(200)
