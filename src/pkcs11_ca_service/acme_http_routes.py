from typing import Any, Dict, List
import json

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi import HTTPException

from .acme_account import AcmeAccount, existing_account_response
from .acme_lib import random_string, validate_jws, pem_from_jws, public_key_exists
from .nonce import generate_nonce
from .config import ROOT_URL, ACME_ROOT
from .asn1 import from_base64url, to_base64url, jwk_key_to_pem
from .public_key import PublicKey, PublicKeyInput


async def acme_new_account(request: Request) -> JSONResponse:
    input_data = await request.json()
    print("acme_data")
    print(input_data)

    if not isinstance(input_data, dict):
        raise HTTPException(status_code=400, detail="Non valid jws")

    # Ensure valid jwt
    validate_jws(input_data, str(request.url))

    public_key_pem = pem_from_jws(input_data)

    # If account exists
    existing_account = await public_key_exists(public_key_pem)
    if existing_account is not None:
        return await existing_account_response(existing_account)

    encoded_contacts: List[str] = []
    contacts: List[str] = []

    payload = json.loads(from_base64url(input_data["payload"]).decode("utf-8"))
    if "contact" in payload:
        req_contacts = payload["contact"]
        if isinstance(req_contacts, list):
            for entry in req_contacts:
                if isinstance(entry, str):
                    encoded_contacts.append(to_base64url(entry.encode("utf-8")))
                    contacts.append(entry)

    # Generate account_id
    account_id = random_string()
    response_data = {
        "status": "valid",
        "contact": contacts,
        "orders": f"{ROOT_URL}{ACME_ROOT}/acct/{account_id}/orders",
    }

    acme_account_obj = AcmeAccount(
        {
            "public_key_pem": public_key_pem,
            "status": "valid",
            "id": account_id,
            "contact": ",".join(encoded_contacts),
            "authorized_by": 1,  # FIXME
        }
    )
    await acme_account_obj.save()

    return JSONResponse(
        status_code=201,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/acct/{account_id}"},
        content=response_data,
        media_type="application/json",
    )
