"""Main module, FastAPI runs from here"""
from typing import Union
import asyncio

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from python_x509_pkcs11.crl import create as create_crl
from python_x509_pkcs11.csr import sign_csr
from python_x509_pkcs11.ca import create as create_ca

from .base import db_load_data_class, InputObject
from .csr import Csr, CsrInput, search as csr_search
from .certificate import Certificate, CertificateInput, search as certificate_search
from .crl import Crl, CrlInput, search as crl_search
from .ca import Ca, CaInput, search as ca_search
from .pkcs11_key import Pkcs11Key, Pkcs11KeyInput
from .public_key import PublicKey, PublicKeyInput, search as public_key_search
from .startup import startup
from .asn1 import public_key_pem_from_csr, pem_cert_to_name_dict
from .nonce import nonce_response
from .auth import authorized_by


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


@app.get("/new_nonce")
async def get_new_nonce() -> Response:
    """Get new nonce, GET method.

    Returns:
    fastapi.Response
    """

    return nonce_response()


@app.head("/new_nonce")
async def head_new_nonce() -> Response:
    """Get new nonce, HEAD method.

    Returns:
    fastapi.Response
    """

    return nonce_response()


# DO THIS IN BASE OUTSIDE OF CLAss SEND CLASS TYPE AND INPUTOBJECT AS ARG not in publickey as now
# try:
#    for cls in load_db_data_classes():
# app.post("/search/" + cls.db_table_name)(cls.search)


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


# except Exception as e:
#    print(e)


# @app.post("/public_key")
# async def post_public_key(request: Request, public_key_input: PublicKeyInput) -> JSONResponse:


# # for data_object in data_objects():

# Dynamicly create search/DB_CLASS, t.ex. search/PublicKey
# for all DB classes with ClassInput for all
# Example
# @app.post("/search/public_key")
# async def post_search(request: Request,
# input_obj: PublicKey (or atleast input_obj: InputObj abstract class) -> Response:

# # Write this in auth
# # raise HTTPException(status_code=401, detail="Unauthorized token.")
# # So we only need to write auth_by = await authorized_by(request)
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

    Post/create a new crl.

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

    issuer_objs = await db_load_data_class(Ca, CaInput(pem=crl_input.ca_pem))
    if not issuer_objs:
        return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})
    issuer_obj = issuer_objs[0]
    if not isinstance(issuer_obj, Ca):
        return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})

    issuer_pkcs11_key_objs = await db_load_data_class(Pkcs11Key, Pkcs11KeyInput(serial=issuer_obj.pkcs11_key))
    if not issuer_pkcs11_key_objs:
        return JSONResponse(status_code=400, content={"message": "CA to sign with has no pkcs11 key"})
    issuer_pkcs11_key_obj = issuer_pkcs11_key_objs[0]
    if not isinstance(issuer_pkcs11_key_obj, Pkcs11Key):
        return JSONResponse(status_code=400, content={"message": "CA to sign with has no pkcs11 key"})

    crl_pem = await create_crl(issuer_pkcs11_key_obj.key_label, pem_cert_to_name_dict(issuer_obj.pem))

    crl_obj = Crl(
        {
            "pem": crl_pem,
            "authorized_by": auth_by,
            "issuer": issuer_obj.serial,
        }
    )
    await crl_obj.save()

    return JSONResponse(status_code=200, content={"crl": crl_pem})


@app.post("/ca")
async def post_ca(request: Request, ca_input: CaInput) -> JSONResponse:
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

    signer_key_label: Union[str, None] = None

    # If this should not be a selfsigned ca
    if ca_input.issuer_pem is not None:
        issuer_objs = await db_load_data_class(Ca, CaInput(pem=ca_input.issuer_pem))
        if not issuer_objs:
            return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})
        issuer_obj = issuer_objs[0]
        if not isinstance(issuer_obj, Ca):
            return JSONResponse(status_code=400, content={"message": "No such CA to sign with"})

        issuer_pkcs11_key_objs = await db_load_data_class(Pkcs11Key, Pkcs11KeyInput(serial=issuer_obj.pkcs11_key))
        if not issuer_pkcs11_key_objs:
            return JSONResponse(status_code=400, content={"message": "CA to sign with has no pkcs11 key"})
        issuer_pkcs11_key_obj = issuer_pkcs11_key_objs[0]
        if not isinstance(issuer_pkcs11_key_obj, Pkcs11Key):
            return JSONResponse(status_code=400, content={"message": "CA to sign with has no pkcs11 key"})
        signer_key_label = issuer_pkcs11_key_obj.key_label

    ca_csr_pem, ca_pem = await create_ca(
        ca_input.key_label,
        ca_input.name_dict,
        ca_input.key_size,
        signer_key_label=signer_key_label,
    )

    # Save Public key for new CA
    public_key_pem, _ = await PKCS11Session.public_key_data(ca_input.key_label)
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
        # Cant know issuer before we know serial which is only after we call save()
        # so hack this when the field_set_to_serial parameter
        await ca_obj.save(field_set_to_serial="issuer")

    return JSONResponse(status_code=200, content={"certificate": ca_pem})


@app.post("/sign_csr")
async def post_sign_csr(request: Request, csr_input: CsrInput) -> JSONResponse:
    """/sign_csr, POST method.

    Post/create a new csr, will create and return certificate.

    Parameters:
    request (fastapi.Request): The entire HTTP request.
    csr_input (CrlInput): The csr data.

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
    cert_pem = await sign_csr(pkcs11_key_obj.key_label, pem_cert_to_name_dict(ca_obj.pem), csr_obj.pem)

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
