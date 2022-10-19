"""Module  which handle the authorization"""

from typing import Tuple
import json

from fastapi import HTTPException
from fastapi import Request
import jwt

from .public_key import PublicKey, PublicKeyInput
from .base import db_load_data_class
from .asn1 import jwk_key_to_pem, from_base64url
from .config import JWT_ALGOS
from .nonce import verify_nonce


async def _pub_key_from_db(pem: str) -> Tuple[str, int]:
    pub_key_input = PublicKeyInput(pem=pem)
    pub_keys = await db_load_data_class(PublicKey, pub_key_input)
    if not pub_keys:
        raise HTTPException(status_code=401, detail="public key not registered")

    pub_key = pub_keys[0]
    if not isinstance(pub_key, PublicKey):
        raise HTTPException(status_code=401, detail="public key not registered")

    if pub_key.admin != 1:
        raise HTTPException(status_code=401, detail="public key is non admin")

    if pub_key.serial < 1:
        raise HTTPException(status_code=401, detail="public key is invalid")

    return pub_key.pem, pub_key.serial


async def _token_from_headers(request: Request) -> str:
    if "Authorization" not in request.headers:
        raise HTTPException(status_code=401, detail="token missing")

    token: str = request.headers["Authorization"].strip()
    if token.startswith("Bearer "):
        token = token.replace("Bearer ", "")
    return token


async def _validate_token(request: Request) -> Tuple[int, str]:
    token = await _token_from_headers(request)

    # Load jwt public key from DB
    try:
        decoded_jwt = jwt.decode(token, algorithms=JWT_ALGOS, options={"verify_signature": False})
    except BaseException as exception:
        # Log this
        print(exception)
        raise HTTPException(status_code=401, detail="token invalid") from exception

    pub_key_pem, auth_by = await _pub_key_from_db(jwk_key_to_pem(decoded_jwt))

    # Verify signature with public key from db
    try:
        decoded_jwt = jwt.decode(token, key=pub_key_pem, algorithms=JWT_ALGOS)
    except BaseException as exception:
        # Log this
        print(exception)
        raise HTTPException(status_code=401, detail="token invalid signature") from exception

    return auth_by, token


async def _validate_url(request: Request, token: str) -> None:
    # https://ietf-wg-acme.github.io/acme/circle-test/draft-ietf-acme-acme.html#request-url-integrity
    jwt_header_decoded = json.loads(from_base64url(token.split(".")[0]))
    if "url" not in jwt_header_decoded:
        raise HTTPException(status_code=401, detail="url missing in token")

    if jwt_header_decoded["url"] != str(request.url):
        raise HTTPException(status_code=401, detail="url in token verification failed")


async def _validate_nonce(token: str) -> None:
    jwt_header_decoded = json.loads(from_base64url(token.split(".")[0]))
    if "nonce" not in jwt_header_decoded:
        raise HTTPException(status_code=401, detail="nonce missing in token")

    if not await verify_nonce(jwt_header_decoded["nonce"]):
        raise HTTPException(status_code=401, detail="nonce in token verification failed")


async def _authorized_by(request: Request) -> int:
    auth_by, token = await _validate_token(request)

    # Must be after token signature validate
    await _validate_url(request, token)

    # Must be after token signature validate
    await _validate_nonce(token)

    return auth_by


# Write this
# raise HTTPException(status_code=401, detail="Unauthorized token.")
async def authorized_by(request: Request) -> int:
    """Authorize a request to to our http server.

    Returns the ID of the public key in DB whoch was used to authorize the request.

    Parameters:
    request (fastapi.Request): The entire HTTP request which we can extract the JWT and nonce from.

    Returns:
    int
    """

    try:
        return await _authorized_by(request)
    except HTTPException as exception:
        print(exception)
        raise exception
    except BaseException as exception:
        # Log this important error
        print(exception)
        raise HTTPException(status_code=401, detail="token verification failed") from exception
