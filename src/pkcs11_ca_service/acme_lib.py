from typing import Any, Dict, Union, List
from secrets import token_bytes
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

from fastapi.responses import JSONResponse
from fastapi import HTTPException

from .base import db_load_data_class
from .acme_account import AcmeAccount, AcmeAccountInput
from .nonce import generate_nonce, verify_nonce
from .asn1 import to_base64url, from_base64url, jwk_key_to_pem
from .config import ACME_ROOT, ROOT_URL


class NoSuchKID(Exception):
    """Class to handle no such kid"""

    def __init__(self, message: str = "No such KID") -> None:
        self.message = message
        super().__init__(self.message)


def random_string() -> str:
    """Generate a random string, only base64url chars

    Returns:
    str
    """

    return to_base64url(token_bytes(64).strip(b"="))


def account_id_from_kid(kid: str) -> str:
    return kid.replace(ROOT_URL, "").replace(ACME_ROOT, "").replace("/acct/", "")


async def account_exists(acme_account_input: AcmeAccountInput) -> Union[AcmeAccount, None]:
    """If exists the return the account"""
    db_certificate_objs = await db_load_data_class(AcmeAccount, acme_account_input)
    for obj in db_certificate_objs:
        if isinstance(obj, AcmeAccount):
            return obj
    return None


async def key_change_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    if "protected" not in payload or "payload" not in payload:
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    inner_protected = json.loads(from_base64url(payload["protected"]).decode("utf-8"))
    inner_payload = json.loads(from_base64url(payload["payload"]).decode("utf-8"))
    inner_signature = payload["signature"]

    if (
        not isinstance(inner_protected, dict)
        or not isinstance(inner_payload, dict)
        or not isinstance(inner_signature, str)
    ):
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    if "jwk" not in inner_protected or "url" not in inner_protected or "alg" not in inner_protected:
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    inner_signed_data = (
        to_base64url(json.dumps(inner_protected).encode("utf-8"))
        + "."
        + to_base64url(json.dumps(inner_payload).encode("utf-8"))
    )

    validate_jwk(inner_protected["jwk"], inner_protected["alg"], inner_signed_data, inner_signature)
    inner_signer_public_key_data = jwk_key_to_pem(inner_protected["jwk"])

    outer_account = await account_exists(AcmeAccountInput(id=account_id_from_kid(protected["kid"])))
    if outer_account is None:
        raise HTTPException(status_code=401, detail="No such account")

    if "account" not in inner_payload or "oldKey" not in inner_payload or "alg" not in inner_protected["jwk"]:
        raise HTTPException(status_code=400, detail="Non valid inner jws")
    inner_account = inner_payload["account"]
    inner_old_key = inner_payload["oldKey"]
    inner_jwk_alg = inner_protected["jwk"]["alg"]

    if not isinstance(inner_account, str) or not isinstance(inner_old_key, dict) or not isinstance(inner_jwk_alg, str):
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    inner_old_public_key_pem = jwk_key_to_pem(inner_old_key)
    if outer_account.public_key_pem != inner_old_public_key_pem:
        raise HTTPException(status_code=400, detail="oldkey and account key are not matching")

    if protected["kid"] != inner_account:
        raise HTTPException(status_code=400, detail="kid and account payload are not matching")

    if inner_protected["alg"] != inner_jwk_alg:
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    outer_account.public_key_pem = inner_signer_public_key_data
    await outer_account.update()

    response_data = {
        "status": account.status,
        "contact": account.contact_as_list(),
        "orders": f"{protected['kid']}/orders",
    }

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": protected["url"]},
        content=response_data,
        media_type="application/json",
    )


async def update_account_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))
    encoded_contacts: List[str] = []

    if "contact" in payload:
        req_contacts = payload["contact"]
        if isinstance(req_contacts, list):
            for entry in req_contacts:
                if isinstance(entry, str):
                    encoded_contacts.append(to_base64url(entry.encode("utf-8")))
            account.contact = ",".join(encoded_contacts)

    if "status" in payload:
        status = payload["status"]
        if status == "deactivated":
            account.status = "deactivated"

    await account.update()

    response_data = {
        "status": account.status,
        "contact": account.contact_as_list(),
        "orders": f"{protected['url']}/orders",
    }

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": protected["url"]},
        content=response_data,
        media_type="application/json",
    )


async def existing_account_response(account: AcmeAccount) -> JSONResponse:
    response_data = {
        "status": account.status,
        "contact": account.contact_as_list(),
        "orders": f"{ROOT_URL}{ACME_ROOT}/acct/{account.id}/orders",
    }

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/acct/{account.id}"},
        content=response_data,
        media_type="application/json",
    )


async def new_account_response(input_data: Dict[str, Any], public_key_pem: str) -> JSONResponse:
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


def pem_from_jws(jws: Dict[str, Any]) -> str:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    return jwk_key_to_pem(protected["jwk"])


def validate_signature(signer_public_key_data: str, data: str, signature: str) -> None:
    # Load the signers public key
    signer_public_key = serialization.load_pem_public_key(signer_public_key_data.encode("utf-8"))
    if not isinstance(signer_public_key, EllipticCurvePublicKey) and not isinstance(
        signer_public_key, Ed25519PublicKey
    ):
        raise HTTPException(status_code=400, detail="Non valid key in jwk")

    if isinstance(signer_public_key, EllipticCurvePublicKey):
        if signer_public_key.curve.name != "secp256r1":
            raise HTTPException(status_code=400, detail="Non valid key in jwk")

        signer_public_key.verify(from_base64url(signature), data.encode("utf-8"), ECDSA(SHA256()))
    else:
        signer_public_key.verify(from_base64url(signature), data.encode("utf-8"))


async def validate_kid(kid: str, signed_data: str, signature: str) -> None:
    account = await account_exists(AcmeAccountInput(id=account_id_from_kid(kid)))
    if account is None:
        raise NoSuchKID(kid)

    validate_signature(account.public_key_pem, signed_data, signature)


def validate_jwk(jwk: Dict[str, Any], alg: str, signed_data: str, signature: str) -> None:
    if jwk["alg"] not in ["ES256", "EdDSA"]:
        raise HTTPException(status_code=400, detail="Non valid alg in jwk")

    jwk_alg = jwk["alg"]

    # Verify alg
    if not isinstance(jwk_alg, str) or alg != jwk_alg:
        raise HTTPException(status_code=400, detail="Non valid jwk in jws")

    signer_public_key_data = jwk_key_to_pem(jwk)
    validate_signature(signer_public_key_data, signed_data, signature)


async def _validate_jws(input_data: Dict[str, Any], request_url: str) -> None:
    # Fixme error handling
    if "protected" not in input_data or "payload" not in input_data or "signature" not in input_data:
        raise HTTPException(status_code=400, detail="Non valid jws0")

    protected = json.loads(from_base64url(input_data["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(input_data["payload"]).decode("utf-8"))
    signature = input_data["signature"]
    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )
    # print("protected")
    # print(protected)
    # print("payload")
    # print(payload)

    if not isinstance(protected, dict) or not isinstance(payload, dict) or not isinstance(signature, str):
        raise HTTPException(status_code=400, detail="Non valid jws1")

    alg = protected["alg"]
    nonce = protected["nonce"]
    url = protected["url"]

    if not isinstance(alg, str) or not isinstance(nonce, str) or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Non valid jws2")

    # Verify url
    print(url)
    print(request_url)
    if url != request_url:
        raise HTTPException(status_code=400, detail="Client request url did not match jws url")

    # Verify nonce
    if not await verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="No such nonce in jws")

    if "jwk" in protected and "kid" in protected:
        raise HTTPException(status_code=400, detail="Non valid jws3")

    if url == f"{ROOT_URL}{ACME_ROOT}/new-account":
        if "jwk" not in protected:
            raise HTTPException(status_code=400, detail="Non valid jwk in jws")
    else:
        if "kid" not in protected:
            raise HTTPException(status_code=400, detail="Non valid kid in jws")

    # Validate JWK OR KID
    if "jwk" in protected:
        jwk = protected["jwk"]
        if not isinstance(jwk, dict):
            raise HTTPException(status_code=400, detail="Non valid jwk in jws")
        validate_jwk(jwk, alg, signed_data, signature)
    elif "kid" in protected:
        kid = protected["kid"]
        if not isinstance(kid, str):
            raise HTTPException(status_code=400, detail="Non valid kid in jws")
        await validate_kid(kid, signed_data, signature)
    else:
        raise HTTPException(status_code=400, detail="Missing either jwk or kid in jws")


async def validate_jws(input_data: Dict[str, Any], request_url: str) -> None:
    try:
        await _validate_jws(input_data, request_url)
    except (InvalidSignature, NoSuchKID):
        raise HTTPException(status_code=401, detail="Invalid jws signature or kid")
    except (ValueError, IndexError, KeyError):
        raise HTTPException(status_code=400, detail="Non valid jws")
