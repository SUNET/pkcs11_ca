from typing import Union, List
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import sys

from .base import db_load_data_class, db_load_all_data_class
from .csr import Csr, CsrInput
from .certificate import Certificate
from .crl import Crl, CrlInput
from .ca import Ca, CaInput
from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
from .public_key import PublicKey, PublicKeyInput
from .startup import startup
from .asn1 import public_key_pem_from_csr, pem_cert_to_name_dict
from .nonce import generate_nonce, hash_nonce, nonces
from .auth import authorized_by
from .config import ROOT_CA_KEY_LABEL, ROOT_CA_NAME_DICT

from python_x509_pkcs11.crl import create as create_crl
from python_x509_pkcs11.csr import sign_csr

from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from python_x509_pkcs11.ca import create as create


import asyncio

loop = asyncio.get_running_loop()
loop.create_task(startup())

# Create fastapi app
app = FastAPI()


# c,k = ca.new_ca()
# ca.save_ca(c,k)

## GET HTTP ##
# @app.get("/" + config.ca_info_common_name + ".crl")
# def crl_file():
#    return get_path.crl_file()

# # Special for compatibility
# @app.get("/crl2")
# async def sign_csr_file(): # request):
#     #data = await request.body()

#     d = await crl.Crl().create()
#     return fastapi.Response(status_code=200,
#                             content=d,
#                             media_type="application/x-pem-file")


@app.head("/new_nonce")
async def head_new_nonce() -> Response:
    new_nonce = generate_nonce()
    nonces.append(hash_nonce(new_nonce))
    response = Response()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Replay-Nonce"] = new_nonce
    return response


@app.get("/new_nonce")
async def get_new_nonce() -> Response:
    response = Response()
    new_nonce = generate_nonce()
    nonces.append(hash_nonce(new_nonce))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Replay-Nonce"] = new_nonce
    return response


# Redo this so CRLS can be fetched by perhaps the CAs common name
@app.get("/public_key")
async def get_public_key(request: Request) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    public_key_objs: List[PublicKey] = []
    public_key_pems: List[str] = []

    db_public_key_objs = await db_load_all_data_class(PublicKey)
    for obj in db_public_key_objs:
        if isinstance(obj, PublicKey):
            public_key_objs.append(obj)

    for public_key in public_key_objs:
        public_key_pems.append(public_key.pem)

    return JSONResponse(status_code=200, content={"public_keys": public_key_pems})


@app.post("/public_key")
async def post_public_key(request: Request, public_key_input: PublicKeyInput) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    if public_key_input.pem is None:
        return JSONResponse(
            status_code=400,
            content={"message": "must have 'pem' with the public key"},
        )

    is_admin = 0
    if isinstance(public_key_input.admin, int) and public_key_input.admin == 1:
        is_admin = 1
    
    # Save Public key for new CA
    public_key_obj = PublicKey({"pem": public_key_input.pem, "authorized_by": auth_by, "admin": is_admin})
    await public_key_obj.save()
    return JSONResponse(status_code=200, content={"public_key": public_key_obj.pem})


# Redo this so CRLS can be fetched by perhaps the CAs common name
@app.get("/crl")
async def get_crl(request: Request) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    crl_objs: List[Crl] = []
    crl_pems: List[str] = []

    db_crl_objs = await db_load_all_data_class(Crl)
    for obj in db_crl_objs:
        if isinstance(obj, Crl):
            crl_objs.append(obj)

    for crl in crl_objs:
        crl_pems.append(crl.pem)

    return JSONResponse(status_code=200, content={"crls": crl_pems})


# Redo this so CRLS are generated in the background and this fetches the last one
@app.post("/crl")
async def post_crl(request: Request, crl_input: CrlInput) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    if crl_input.ca_pem is None:
        return JSONResponse(
            status_code=400,
            content={"message": "must have 'ca_pem' with the CA to issue a CRL for"},
        )

    issuer_objs = await db_load_data_class(Ca, CaInput(pem=crl_input.ca_pem))
    if not issuer_objs:
        return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})
    issuer_obj = issuer_objs[0]
    if not isinstance(issuer_obj, Ca):
        return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})

    issuer_pkcs11_key_objs = await db_load_data_class(
        Pkcs11Key, Pkcs11KeyInput(serial=issuer_obj.pkcs11_key)
    )
    if not issuer_pkcs11_key_objs:
        return JSONResponse(
            status_code=400, content={"message": "CA to sign with has no pkcs11 key"}
        )
    issuer_pkcs11_key_obj = issuer_pkcs11_key_objs[0]
    if not isinstance(issuer_pkcs11_key_obj, Pkcs11Key):
        return JSONResponse(
            status_code=400, content={"message": "CA to sign with has no pkcs11 key"}
        )

    crl_pem = await create_crl(
        issuer_pkcs11_key_obj.key_label, pem_cert_to_name_dict(issuer_obj.pem)
    )

    crl_obj = Crl(
        {
            "pem": crl_pem,
            "authorized_by": auth_by,
            "issuer": issuer_obj.serial,
        }
    )
    crl_obj.save()

    return JSONResponse(status_code=200, content={"crl": crl_pem})


# @app.get("/crl")
# def get_crl() -> str:
# return create("test_4", root_ca_name_dict)

## POST HTTP ##
# @app.post("/has_csr")
# def has_csr(c: csr.Csr):
#    return post_path.has_csr(c)

# @app.post("/has_issued_cert")
# def has_issued_cert(c: cert.CertInput):
#    return post_path.has_issued_cert(c)

# @app.post("/add_public_key")
# async def post_sign_csr(request: Request, public_key_input: PublicKeyInput) -> JSONResponse:
#     auth_by, auth_error = await authorized_by(request)
#     if auth_error is not None or auth_by < 1:
#         return auth_error

#     new_public_key = PublicKey(
#         {"pem": public_key_pem_from_csr(csr_input.pem),
#          "authorized_by": auth_by}
#     )
#     await new_public_key.save()


@app.get("/ca")
async def get_ca(request: Request) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    ca_objs: List[Ca] = []
    ca_pems: List[str] = []

    db_ca_objs = await db_load_all_data_class(Ca)
    for obj in db_ca_objs:
        if isinstance(obj, Ca):
            ca_objs.append(obj)

    for ca in ca_objs:
        ca_pems.append(ca.pem)

    return JSONResponse(status_code=200, content={"cas": ca_pems})


@app.post("/ca")
async def post_ca(request: Request, ca_input: CaInput) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    if ca_input.name_dict is None or ca_input.key_label is None:
        return JSONResponse(
            status_code=400,
            content={
                "message": "must have json dict with key 'pem' with a csr and 'ca_pem' with the signing CA"
            },
        )

    signer_key_label: Union[str, None] = None

    # If this should not be a selfsigned ca
    if ca_input.issuer_pem is not None:
        issuer_objs = await db_load_data_class(Ca, CaInput(pem=ca_input.issuer_pem))
        if not issuer_objs:
            return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})
        issuer_obj = issuer_objs[0]
        if not isinstance(issuer_obj, Ca):
            return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})

        issuer_pkcs11_key_objs = await db_load_data_class(
            Pkcs11Key, Pkcs11KeyInput(serial=issuer_obj.pkcs11_key)
        )
        if not issuer_pkcs11_key_objs:
            return JSONResponse(
                status_code=400, content={"message": "CA to sign with has no pkcs11 key"}
            )
        issuer_pkcs11_key_obj = issuer_pkcs11_key_objs[0]
        if not isinstance(issuer_pkcs11_key_obj, Pkcs11Key):
            return JSONResponse(
                status_code=400, content={"message": "CA to sign with has no pkcs11 key"}
            )
        signer_key_label = issuer_pkcs11_key_obj.key_label

    ca_csr_pem, ca_pem = await create(
        ca_input.key_label,
        ca_input.name_dict,
        ca_input.key_size,
        signer_key_label=signer_key_label,
    )

    # Save Public key for new CA
    public_key_pem, identifier = await PKCS11Session.public_key_data(ca_input.key_label)
    public_key_obj = PublicKey({"pem": public_key_pem, "authorized_by": auth_by})
    await public_key_obj.save()

    # Save pkcs11 key for new CA
    pkcs11_key_obj = Pkcs11Key(
        {
            "public_key": public_key_obj.serial,
            "key_label": ca_input.key_label,
            "authorized_by": auth_by,
        }
    )
    await pkcs11_key_obj.save()

    # Save csr for new CA
    csr_obj = Csr(
        {"pem": ca_csr_pem, "authorized_by": auth_by, "public_key": public_key_obj.serial}
    )
    await csr_obj.save()

    # Save new CA
    if ca_input.issuer_pem is not None:
        ca_obj = Ca(
            {
                "pem": ca_pem,
                "authorized_by": auth_by,
                "pkcs11_key": pkcs11_key_obj.serial,
                "csr": csr_obj.serial,
                "issuer": issuer_obj.serial,
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
            }
        )
        # Cant know issuer before we know serial which is only after we call save() so hack this when the field_set_to_serial parameter
        await ca_obj.save(field_set_to_serial="issuer")

    return JSONResponse(status_code=200, content={"certificate": ca_pem})


# FIXME allow request to specify which CA to sign with, perhaps the CAs pem or the CAs pub_key pem
# Perhaps a 'replaced_by' field for CAs and/or error message trying to use a revoked/old CA to sign with
@app.post("/sign_csr")
async def post_sign_csr(request: Request, csr_input: CsrInput) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    if csr_input.pem is None or csr_input.ca_pem is None:
        return JSONResponse(
            status_code=400,
            content={
                "message": "must have json dict with key 'pem' with a csr and 'ca_pem' with the signing CA"
            },
        )

    # Get public key from csr
    public_key_obj = PublicKey(
        {"pem": public_key_pem_from_csr(csr_input.pem), "authorized_by": auth_by}
    )
    await public_key_obj.save()

    # Save csr
    csr_obj = Csr(
        {"pem": csr_input.pem, "authorized_by": auth_by, "public_key": public_key_obj.serial}
    )
    await csr_obj.save()

    # Get CA to sign csr with
    ca_input_obj = CaInput(pem=csr_input.ca_pem)
    ca_objs = await db_load_data_class(Ca, ca_input_obj)
    if not ca_objs:
        return JSONResponse(status_code=400, content={"message": "No such CA"})
    ca_obj = ca_objs[0]
    if not isinstance(ca_obj, Ca):
        return JSONResponse(status_code=400, content={"message": "No such CA"})

    # Get pkcs11 and its key label to sign the csr with from the CA
    pkcs11_key_input_obj = Pkcs11KeyInput(serial=ca_obj.pkcs11_key)
    pkcs11_key_objs = await db_load_data_class(Pkcs11Key, pkcs11_key_input_obj)
    if not pkcs11_key_objs:
        return JSONResponse(status_code=400, content={"message": "No such CA"})
    pkcs11_key_obj = pkcs11_key_objs[0]
    if not isinstance(pkcs11_key_obj, Pkcs11Key):
        return JSONResponse(status_code=400, content={"message": "CA has no pkcs11 key"})

    # Sign csr
    cert_pem = await sign_csr(
        pkcs11_key_obj.key_label, pem_cert_to_name_dict(ca_obj.pem), csr_obj.pem
    )

    # Save cert
    cert_obj = Certificate(
        {
            "pem": cert_pem,
            "authorized_by": auth_by,
            "csr": csr_obj.serial,
            "public_key": public_key_obj.serial,
            "issuer": ca_obj.serial,
        }
    )
    await cert_obj.save()

    # Return cert
    return JSONResponse(status_code=200, content={"certificate": cert_obj.pem})


# Special for compatibility
# @app.post("/sign_csr_file")
# async def sign_csr_file(request: fastapi.Request):
#    return await post_path.sign_csr_file(request)

# @app.post("/revoke")
# def revoke(c: cert.Cert):
#    return post_path.revoke(c)
