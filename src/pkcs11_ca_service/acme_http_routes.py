from typing import Any, Dict, List
import json

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from fastapi import HTTPException
from fastapi.background import BackgroundTasks

from .acme_account import AcmeAccount, AcmeAccountInput
from .acme_lib import (
    validate_jws,
    pem_from_jws,
    account_exists,
    revoke_cert_response,
    cert_response,
    finalize_order_response,
    chall_response,
    authz_response,
    order_response,
    new_order_response,
    key_change_response,
    orders_response,
    update_account_response,
    existing_account_response,
    new_account_response,
    account_id_from_kid,
)
from .asn1 import from_base64url


async def acme_revoke_cert(request: Request) -> Response:
    input_data = await request.json()

    if not isinstance(input_data, dict):
        raise HTTPException(status_code=400, detail="Non valid jws")

    return await revoke_cert_response(input_data, str(request.url))


async def acme_cert(request: Request) -> Response:
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

    return await cert_response(account, input_data)


async def acme_finalize_order(request: Request) -> JSONResponse:
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

    return await finalize_order_response(account, input_data)


async def acme_chall(request: Request, background_tasks: BackgroundTasks) -> JSONResponse:
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

    return await chall_response(account, input_data, background_tasks)


async def acme_authz(request: Request) -> JSONResponse:
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

    return await authz_response(account, input_data)


async def acme_order(request: Request) -> JSONResponse:
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

    return await order_response(account, input_data)


async def acme_new_order(request: Request) -> JSONResponse:
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

    return await new_order_response(account, input_data)


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


async def acme_orders(request: Request) -> JSONResponse:
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

    return await orders_response(account, input_data)


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
