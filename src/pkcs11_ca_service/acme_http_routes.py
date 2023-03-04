from typing import Any, Dict, List
import json

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi import HTTPException

from .acme_account import AcmeAccount, AcmeAccountInput
from .acme_lib import (
    validate_jws,
    pem_from_jws,
    account_exists,
    key_change_response,
    update_account_response,
    existing_account_response,
    new_account_response,
    account_id_from_kid,
)
from .asn1 import from_base64url


async def acme_key_change(request: Request) -> JSONResponse:
    input_data = await request.json()

    if not isinstance(input_data, dict):
        raise HTTPException(status_code=400, detail="Non valid jws")

    # Ensure valid jwt
    await validate_jws(input_data, str(request.url))
    protected = json.loads(from_base64url(input_data["protected"]).decode("utf-8"))
    account = await account_exists(AcmeAccountInput(id=account_id_from_kid(protected["kid"])))

    if account is None:
        return JSONResponse(
            status_code=401,
            content="Unauthorized",  # fixme
            media_type="application/json",
        )

    return await key_change_response(account, input_data)


async def acme_update_account(request: Request) -> JSONResponse:
    input_data = await request.json()

    if not isinstance(input_data, dict):
        raise HTTPException(status_code=400, detail="Non valid jws")

    # Ensure valid jwt
    await validate_jws(input_data, str(request.url))
    protected = json.loads(from_base64url(input_data["protected"]).decode("utf-8"))
    account = await account_exists(AcmeAccountInput(id=account_id_from_kid(protected["kid"])))

    if account is None:
        return JSONResponse(
            status_code=401,
            content="Unauthorized",  # fixme
            media_type="application/json",
        )

    return await update_account_response(account, input_data)


async def acme_new_account(request: Request) -> JSONResponse:
    input_data = await request.json()

    if not isinstance(input_data, dict):
        raise HTTPException(status_code=400, detail="Non valid jws")

    # Ensure valid jwt
    await validate_jws(input_data, str(request.url))

    public_key_pem = pem_from_jws(input_data)

    # If account exists
    existing_account = await account_exists(AcmeAccountInput(public_key_pem=public_key_pem))
    if existing_account is not None:
        return await existing_account_response(existing_account)

    return await new_account_response(input_data, public_key_pem)
