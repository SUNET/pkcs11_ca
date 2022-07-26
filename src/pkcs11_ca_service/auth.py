from typing import Tuple, Union
import json

from fastapi.responses import JSONResponse
from fastapi import Request
import jwt

from .public_key import PublicKey, PublicKeyInput
from .base import db_load_data_class
from .asn1 import jwk_key_to_pem, from_base64url
from .config import JWT_ALGOS
from .nonce import verify_nonce


async def _pub_key_from_db(pem: str) -> Tuple[str, int, Union[JSONResponse, None]]:
    pub_key_input = PublicKeyInput(pem=pem)
    pub_key_obj_list = await db_load_data_class(PublicKey, pub_key_input)
    if not pub_key_obj_list:
        print("Rejecting pub key not in DB")
        return (
            "",
            -1,
            JSONResponse(
                status_code=401, content={"message": "public key not registered"}
            ),
        )

    pub_key_vars = vars(pub_key_obj_list[0])

    if "admin" not in pub_key_vars:
        return (
            "",
            -1,
            JSONResponse(status_code=401, content={"message": "public key invalid"}),
        )
    pub_key_admin: int = pub_key_vars["admin"]
    if pub_key_admin != 1:
        print("Rejecting non admin pub key")
        return (
            "",
            -1,
            JSONResponse(
                status_code=401, content={"message": "public key is not admin"}
            ),
        )

    if "pem" not in pub_key_vars or "authorized_by" not in pub_key_vars:
        return (
            "",
            -1,
            JSONResponse(status_code=401, content={"message": "public key invalid"}),
        )
    pub_key_pem: str = pub_key_vars["pem"]
    auth_by: int = pub_key_vars["authorized_by"]
    return pub_key_pem, auth_by, None


async def _token_from_headers(request: Request) -> Tuple[bool, str]:
    if "Authorization" not in request.headers:
        return False, ""

    token = request.headers["Authorization"].strip()
    if token.startswith("Bearer "):
        token = token.split("Bearer ")[1]
    return True, token


async def _validate_token(
    request: Request,
) -> Tuple[int, str, Union[JSONResponse, None]]:
    has_token, token = await _token_from_headers(request)
    if not has_token:
        return (
            -1,
            "",
            JSONResponse(status_code=401, content={"message": "missing token"}),
        )

    # Load jwt public key from DB
    try:
        decoded_jwt = jwt.decode(
            token, algorithms=JWT_ALGOS, options={"verify_signature": False}
        )
    except BaseException as exeption:  # pylint: disable=broad-except
        print(exeption)
        return (
            -1,
            "",
            JSONResponse(status_code=401, content={"message": "token invalid"}),
        )
    pub_key_pem, auth_by, auth_error = await _pub_key_from_db(
        jwk_key_to_pem(decoded_jwt)
    )
    if auth_error is not None or auth_by < 1:
        return -1, "", auth_error

    # Verify signature with public key from db
    try:
        decoded_jwt = jwt.decode(
            token, key=pub_key_pem.encode("utf-8"), algorithms=JWT_ALGOS
        )
    except BaseException as exeption:  # pylint: disable=broad-except
        print(exeption)
        return (
            -1,
            "",
            JSONResponse(
                status_code=401, content={"message": "token signature invalid"}
            ),
        )
    print("Verified signature with public key")

    return auth_by, token, None


async def _validate_url(request: Request, token: str) -> Union[JSONResponse, None]:
    # https://ietf-wg-acme.github.io/acme/circle-test/draft-ietf-acme-acme.html#request-url-integrity
    jwt_header_decoded = json.loads(from_base64url(token.split(".")[0]))
    if "url" not in jwt_header_decoded:
        return JSONResponse(
            status_code=401, content={"message": "url missing in token"}
        )

    if jwt_header_decoded["url"] == str(request.url):
        print("Verified url in token")
        return None
    return JSONResponse(
        status_code=401, content={"message": "url in token verification failed"}
    )


async def _validate_nonce(token: str) -> Union[JSONResponse, None]:
    jwt_header_decoded = json.loads(from_base64url(token.split(".")[0]))
    if "nonce" not in jwt_header_decoded:
        return JSONResponse(
            status_code=401, content={"message": "nonce missing in token"}
        )

    if await verify_nonce(jwt_header_decoded["nonce"]):
        print("Verified nonce in token")
        return None
    return JSONResponse(
        status_code=401, content={"message": "nonce in token verification failed"}
    )


async def _authorized_by(request: Request) -> Tuple[int, Union[JSONResponse, None]]:
    auth_by, token, auth_error = await _validate_token(request)
    if auth_error is not None or auth_by < 1:
        return -1, auth_error

    auth_error = await _validate_url(request, token)
    if auth_error is not None:
        return -1, auth_error

    auth_error = await _validate_nonce(token)
    if auth_error is not None:
        return -1, auth_error

    return auth_by, None


async def authorized_by(request: Request) -> Tuple[int, Union[JSONResponse, None]]:
    try:
        return await _authorized_by(request)
    except BaseException as exeption:  # pylint: disable=broad-except
        print(exeption)
        return -1, JSONResponse(
            status_code=401, content={"message": "authorization failed"}
        )
