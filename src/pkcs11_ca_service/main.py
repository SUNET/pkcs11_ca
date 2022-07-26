from typing import Union
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import sys

from .base import db_load_data_class
from .csr import Csr, CsrInput
from .certificate import Certificate
from .public_key import PublicKey, PublicKeyInput
from .startup import startup
from .asn1 import public_key_pem_from_csr
from .nonce import generate_nonce, hash_nonce, nonces
from .auth import authorized_by
from .config import ROOT_CA_KEY_LABEL, ROOT_CA_NAME_DICT

from python_x509_pkcs11.crl import create as create_crl
from python_x509_pkcs11.csr import sign_csr

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
    return head_new_nonce()


@app.post("/public_key")
async def post_public_key(request: Request) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    p_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+1TSL9l6b5uleqVVkS22
1xf9C7OqR9jxR1IqAxJkESuuSeldyPL1F4jFA65p13EaPFnLLVuG5RAa6wSjT07B
GXIjmmd3aY6JkPcJaKn/TMzxFaYO4KHYraOHaI4o3AxmQsCd35dAy9h2Zj74/uTV
Yq58BVNuFwYe/sbm1AOCQCri/4ZpI3VB4u7425maQ4At+twYGMC6VF+gApoEbZvE
Il5khkUZLXu/3AsJ234YFpdvocT855xPXriZrne5faS6breercjr9lslaVNaLcRw
VSeUCBermXzHt3t/vF2fsXG6f5JCZJDKJw0GyaL+l/pDqvnL9o8GMbWlRbAgPv59
tQIDAQAB
-----END PUBLIC KEY-----
"""
    a = PublicKeyInput(pem=p_key)

    p_key_obj = PublicKey({"pem": p_key})
    p_key_obj.set_references({"authorized_by": auth_by})
    await p_key_obj.save()
    p2_key_objs = await db_load_data_class(PublicKey, a)
    p2_key_obj = p2_key_objs[0]

    csr_pem = """-----BEGIN CERTIFICATE REQUEST-----
MIIDJTCCAg0CAQAwgZwxCzAJBgNVBAYTAlNFMRIwEAYDVQQIDAlTdG9ja2hvbG0x
EjAQBgNVBAcMCVN0b2NraG9sbTEOMAwGA1UECgwFU1VORVQxHTAbBgNVBAsMFFNV
TkVUIEluZnJhc3RydWN0dXJlMRkwFwYDVQQDDBBjYS10ZXN0LnN1bmV0LnNlMRsw
GQYJKoZIhvcNAQkBFgxzb2NAc3VuZXQuc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDhqvb34vQ0WUVM4VLUgXSrim0tYrL3dU18Wy2FKYGSxyS9YLTQ
X30XDLx0oQlf2Zs267sPXixuemgXgtzstflhYveyZ6RR13zHyqdMw1iaffyaQtrQ
LMAFKTEzx8ZEpDR0og1iQkKk62phnLsvyUq0g0xiUMjSYwTeq1vwiR4U9nqkJiDC
BHKNG/XH0nDrFx/1D1s28XVejFXpB8g0OiLOZyKWd90k932gySXCGMirwL+lCk2H
9ctpbwUA53Q+kwAUyJTzknTSSEch5bSMwX+3FVRHeBmMDYbcZ/c2gtLHNUF5YI+p
v5QZzNwZt/t0GXfEyd5xX0DSmGKPHe45JUyPAgMBAAGgQzAfBgkqhkiG9w0BCQ4x
EjAQMA4GA1UdDwEB/wQEAwIBhjAgBgkqhkiG9w0BCQ4xEzARMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGhYVybB34e09tolj0mwQu7L298MnB9q
+m5qS7TWeI5cLU7vucmxfpd67ocL2ce0BgaKfsjvmP2vRo+jgjLHeEtnl+3cWG3x
lJ+y8PlwkeZMfzK0Rj+X+r3pcxLfTtRaLH20m1PlqXr5Pd4kuDM2SruCCeNiMhDF
a8X+BYfbRunWY3rjfcIQnFs5QpcNwwORk+NHC9SHXTBA4Jbo+sdhE0IorcjWJkZX
KZfuzkMivRr5+GOQYK5xiKc0mqaFzg5uZ1KUXTAWbVAHWGkktXDlpvFBrCNJciKh
WOuWRK+vlgQ76Gi6sLkXIiFiyQ/deiUzwmgNNNbQ2mScYpK7lfF0zdk=
-----END CERTIFICATE REQUEST-----
"""
    b = CsrInput(pem=csr_pem)
    csr_obj = Csr({"pem": csr_pem})
    p_key3 = PublicKey({"pem": public_key_pem_from_csr(csr_obj.pem)})
    p_key3.set_references({"authorized_by": auth_by})
    await p_key3.save()
    csr_obj.set_references({"authorized_by": auth_by, "public_key": p_key3.serial})
    await csr_obj.save()
    csr2_objs = await db_load_data_class(Csr, b)
    csr2_obj = csr2_objs[0]

    return JSONResponse(status_code=200, content={"message": "test ok"})


@app.post("/crl")
async def post_crl(request: Request) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    # FIXME
    ROOT_CA_NAME_DICT = {
        "country_name": "SE",
        "state_or_province_name": "Stockholm",
        "locality_name": "Stockholm",
        "organization_name": "SUNET",
        "organizational_unit_name": "SUNET Infrastructure",
        "common_name": "ca-test.sunet.se",
        "email_address": "soc@sunet.se",
    }

    crl_pem = await create_crl("my_ROOT_CA_key_label", ROOT_CA_NAME_DICT)
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


# FIXME allow request to specify which CA to sign with, perhaps the CAs pem or the CAs pub_key pem
# Perhaps a 'replaced_by' field for CAs and/or error message trying to use a revoked/old CA to sign with
@app.post("/sign_csr")
async def post_sign_csr(request: Request, csr_input: CsrInput) -> JSONResponse:
    auth_by, auth_error = await authorized_by(request)
    if auth_error is not None or auth_by < 1:
        return auth_error

    if csr_input.pem is None:
        return JSONResponse(
            status_code=400, content={"message": "must have json dict with key 'pem' with a csr"}
        )

    public_key_obj = PublicKey(
        {"pem": public_key_pem_from_csr(csr_input.pem), "authorized_by": auth_by}
    )
    await public_key_obj.save()

    csr_obj = Csr(
        {"pem": csr_input.pem, "authorized_by": auth_by, "public_key": public_key_obj.serial}
    )
    await csr_obj.save()

    cert_pem = await sign_csr(ROOT_CA_KEY_LABEL, ROOT_CA_NAME_DICT, csr_obj.pem)
    cert_obj = Certificate(
        {
            "pem": cert_pem,
            "authorized_by": auth_by,
            "csr": csr_obj.serial,
            "public_key": public_key_obj.serial,
            "issuer": 1,
        }
    )
    await cert_obj.save()
    return JSONResponse(status_code=200, content={"certificate": cert_obj.pem})


# Special for compatibility
# @app.post("/sign_csr_file")
# async def sign_csr_file(request: fastapi.Request):
#    return await post_path.sign_csr_file(request)

# @app.post("/revoke")
# def revoke(c: cert.Cert):
#    return post_path.revoke(c)
