from typing import Any, Dict, Union, List
from secrets import token_bytes
import datetime
import json
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256

from fastapi.responses import JSONResponse
from fastapi import HTTPException
import requests

from .base import db_load_data_class
from .acme_authorization import AcmeAuthorization, AcmeAuthorizationInput, challenges_from_list
from .acme_account import AcmeAccount, AcmeAccountInput, contact_from_payload
from .acme_order import AcmeOrder, AcmeOrderInput, identifiers_from_order, authorizations_from_list
from .nonce import generate_nonce, verify_nonce
from .asn1 import to_base64url, from_base64url, jwk_key_to_pem
from .config import ACME_ROOT, ROOT_URL, ACME_IDENTIFIER_TYPES


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


async def authz_exists(acme_authz_input: AcmeAuthorizationInput) -> Union[AcmeAuthorization, None]:
    """If exists the return the authorization"""
    db_acme_authz_objs = await db_load_data_class(AcmeAuthorization, acme_authz_input)
    for obj in db_acme_authz_objs:
        if isinstance(obj, AcmeAuthorization):
            return obj
    return None


async def account_exists(acme_account_input: AcmeAccountInput) -> Union[AcmeAccount, None]:
    """If exists the return the account"""
    db_acme_account_objs = await db_load_data_class(AcmeAccount, acme_account_input)
    for obj in db_acme_account_objs:
        if isinstance(obj, AcmeAccount):
            return obj
    return None


async def execute_challenge(kid: str, authz: AcmeAuthorization, challenge: Dict[str, str]) -> bool:
    identifier = json.loads(from_base64url(authz.identifier))
    hash_module = hashlib.sha256()
    hash_module.update(f"{ROOT_URL}{ACME_ROOT}/acct/{kid}".encode("utf-8"))
    key_authorization = f"{challenge['token']}.{to_base64url(hash_module.digest())}"

    if challenge["type"] == "http-01":
        req = requests.get(
            f"http://{identifier['value']}/.well-known/acme-challenge/{challenge['token']}", verify=False, timeout=3
        )

        if req.status_code == 200 and len(req.text) < 500 and key_authorization in req.text:
            print("chall OKKK")
            return True

    return False


async def chall_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    if isinstance(payload, dict) and payload == {}:
        execute = True
    else:
        execute = False

    challenge_url: str = protected["url"]
    orders: List[AcmeOrder] = []
    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(account=account.serial))
    for obj in db_acme_order_objs:
        if isinstance(obj, AcmeOrder):
            orders.append(obj)

    for order in orders:
        for authz in order.authorizations_as_list():
            db_acme_authz_objs = await db_load_data_class(
                AcmeAuthorization, AcmeAuthorizationInput(id=authz.replace(f"{ROOT_URL}{ACME_ROOT}/authz/", ""))
            )
            for authz_obj in db_acme_authz_objs:
                if not isinstance(authz_obj, AcmeAuthorization):
                    raise HTTPException(status_code=401, detail="Non valid challenge")

                for challenge in authz_obj.challenges_as_list():
                    if challenge["url"] == challenge_url:
                        if execute:
                            print("executing chall")
                            await execute_challenge(account.id, authz_obj, challenge)
                        return JSONResponse(
                            status_code=200,
                            headers={"Replay-Nonce": generate_nonce()},
                            content=challenge,
                            media_type="application/json",
                        )

    raise HTTPException(status_code=401, detail="Non valid challenge")


async def authz_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    # payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    authz_id: str = protected["url"]
    authz_id = authz_id.replace(f"{ROOT_URL}{ACME_ROOT}/authz/", "")

    authz = await authz_exists(AcmeAuthorizationInput(id=authz_id))
    if authz is None:
        raise HTTPException(status_code=401, detail="Non valid authz")

    response_data = {
        "status": authz.status,
        "expires": authz.expires,
        "identifier": json.loads(from_base64url(authz.identifier)),
        "challenges": authz.challenges_as_list(),
    }

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce()},
        content=response_data,
        media_type="application/json",
    )


async def order_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    # payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    # Ensure correct account access the orders list
    order_id: str = protected["url"].replace(f"{ROOT_URL}{ACME_ROOT}/order/", "")

    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(account=account.serial))
    for order in db_acme_order_objs:
        if not isinstance(order, AcmeOrder):
            raise HTTPException(status_code=401, detail="Non valid order")

        if order.id != order_id:
            continue

        response_data = {
            "status": order.status,
            "expires": order.expires,
            "notBefore": order.not_before,
            "notAfter": order.not_after,
            "identifiers": order.identifiers_as_list(),
            "authorizations": order.authorizations_as_list(),
            "finalize": order.finalize,
        }

        return JSONResponse(
            status_code=200,
            headers={"Replay-Nonce": generate_nonce()},
            content=response_data,
            media_type="application/json",
        )
    raise HTTPException(status_code=401, detail="Non valid order")


async def new_order_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    # protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    request_not_before: Union[str, None] = None
    request_not_after: Union[str, None] = None

    if "notBefore" in payload:
        not_before = payload["notBefore"]
        if not isinstance(not_before, str):
            raise HTTPException(status_code=400, detail="Non valid notBefore")
        _request_not_before = datetime.datetime.fromisoformat(not_before)
        if _request_not_before.tzinfo is None:
            request_not_before = (
                datetime.datetime.fromisoformat(not_before)
                .astimezone(datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        else:
            request_not_before = _request_not_before.strftime("%Y-%m-%dT%H:%M:%SZ")

    if "notAfter" in payload:
        not_after = payload["notAfter"]
        if not isinstance(not_after, str):
            raise HTTPException(status_code=400, detail="Non valid notAfter")
        _request_not_after = datetime.datetime.fromisoformat(not_after)
        if _request_not_after.tzinfo is None:
            request_not_after = (
                datetime.datetime.fromisoformat(not_after)
                .astimezone(datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        else:
            request_not_after = _request_not_after.strftime("%Y-%m-%dT%H:%M:%SZ")

    new_order = AcmeOrder(
        {
            "account": account.serial,
            "id": random_string(),
            "status": "pending",
            "expires": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "identifiers": identifiers_from_order(payload),
            "not_before": request_not_before
            if request_not_before is not None
            else (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 3)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "not_after": request_not_after
            if request_not_after is not None
            else (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 3)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "authorizations": "",
            "finalize": "",
            "certificate": "",
        }
    )
    new_order_serial = await new_order.save()

    new_order.finalize = f"{ROOT_URL}{ACME_ROOT}/order/{new_order.id}/finalize"

    authorizations: List[str] = []
    for identifier in new_order.identifiers_as_list():
        if identifier["type"] not in ACME_IDENTIFIER_TYPES:
            raise HTTPException(status_code=400, detail="Non valid identifier type")

        auth_id = random_string()
        authorizations.append(f"{ROOT_URL}{ACME_ROOT}/authz/{auth_id}")

        challenges: List[Dict[str, str]] = [  # FIXME add DNS challenge
            {
                "type": "http-01",
                "url": f"{ROOT_URL}{ACME_ROOT}/chall/{random_string()}",
                "status": "pending",
                "token": random_string(),
            }
        ]
        new_authorization = AcmeAuthorization(
            {
                "acme_order": new_order_serial,
                "id": auth_id,
                "status": "pending",
                "expires": new_order.expires,
                "identifier": to_base64url(json.dumps(identifier).encode("utf-8")),
                "challenges": challenges_from_list(challenges),
                "wildcard": 1 if "*" in identifier["value"] else 0,
            }
        )
        # Save new auth to database
        await new_authorization.save()

    new_order.authorizations = authorizations_from_list(authorizations)

    # Save new order to database
    await new_order.update()

    response_data = {
        "status": new_order.status,
        "expires": new_order.expires,
        "notBefore": new_order.not_before,
        "notAfter": new_order.not_after,
        "identifiers": new_order.identifiers_as_list(),
        "authorizations": new_order.authorizations_as_list(),
        "finalize": new_order.finalize,
    }

    return JSONResponse(
        status_code=201,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/order/{new_order.id}"},
        content=response_data,
        media_type="application/json",
    )


async def key_change_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:  # FIXME not overwrite key??
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    inner_protected = json.loads(from_base64url(payload["protected"]).decode("utf-8"))
    inner_payload = json.loads(from_base64url(payload["payload"]).decode("utf-8"))
    inner_signature = payload["signature"]

    if (
        not isinstance(inner_protected, dict)
        or not isinstance(inner_payload, dict)
        or not isinstance(inner_signature, str)
    ):
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    inner_signed_data = (
        to_base64url(json.dumps(inner_protected).encode("utf-8"))
        + "."
        + to_base64url(json.dumps(inner_payload).encode("utf-8"))
    )

    if "jwk" not in inner_protected or "url" not in inner_protected or "alg" not in inner_protected:
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    validate_jwk(inner_protected["jwk"], inner_protected["alg"], inner_signed_data, inner_signature)
    inner_signer_public_key_data = jwk_key_to_pem(inner_protected["jwk"])

    inner_account = inner_payload["account"]
    inner_old_key = inner_payload["oldKey"]
    inner_jwk_alg = inner_protected["jwk"]["alg"]
    inner_alg = inner_protected["alg"]
    inner_url = inner_protected["url"]

    if (
        not isinstance(inner_account, str)
        or not isinstance(inner_old_key, dict)
        or not isinstance(inner_jwk_alg, str)
        or not isinstance(inner_alg, str)
        or not isinstance(inner_url, str)
    ):
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    if inner_url != protected["url"]:
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    inner_old_public_key_pem = jwk_key_to_pem(inner_old_key)
    if account.public_key_pem != inner_old_public_key_pem:
        raise HTTPException(status_code=400, detail="oldkey and account key are not matching")

    if protected["kid"] != inner_account:
        raise HTTPException(status_code=400, detail="kid and account payload are not matching")

    if inner_alg != inner_jwk_alg:
        raise HTTPException(status_code=400, detail="Non valid inner jws")

    account.public_key_pem = inner_signer_public_key_data
    await account.update()

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


async def orders_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    # payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    # Ensure correct account access the orders list
    url: str = protected["url"].replace(f"{ROOT_URL}{ACME_ROOT}/orders/", "")
    order_account = await account_exists(AcmeAccountInput(id=url))
    if order_account is None or order_account.id != account.id:
        raise HTTPException(status_code=401, detail="Non valid orders")

    orders: List[str] = []
    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(account=account.serial))
    for order in db_acme_order_objs:
        if isinstance(order, AcmeOrder):
            orders.append(f"{ROOT_URL}{ACME_ROOT}/order/{order.id}")

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce()},
        content={"orders": orders},
        media_type="application/json",
    )


async def update_account_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))
    encoded_contacts: List[str] = []

    # Update contact if contact is in payload
    account.contact = contact_from_payload(payload)

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
    payload = json.loads(from_base64url(input_data["payload"]).decode("utf-8"))

    # Generate account_id
    account_id = random_string()

    acme_account_obj = AcmeAccount(
        {
            "public_key_pem": public_key_pem,
            "status": "valid",
            "id": account_id,
            "contact": contact_from_payload(payload),
            "authorized_by": 1,  # FIXME
        }
    )
    await acme_account_obj.save()

    response_data = {
        "status": acme_account_obj.status,
        "contact": acme_account_obj.contact_as_list(),
        "orders": f"{ROOT_URL}{ACME_ROOT}/orders/{account_id}",
    }

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
    if account is None or account.status == "deactivated":  # FIXME special error for deactivated
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
    # if "protected" not in input_data or "payload" not in input_data or "signature" not in input_data:
    #     raise HTTPException(status_code=400, detail="Non valid jws0")

    protected = json.loads(from_base64url(input_data["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(input_data["payload"]).decode("utf-8"))
    signature = input_data["signature"]

    if not isinstance(protected, dict) or not isinstance(payload, dict) or not isinstance(signature, str):
        raise HTTPException(status_code=400, detail="Non valid jws222")

    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )
    # print("protected")
    # print(protected)
    # print("payload")
    # print(payload)

    alg = protected["alg"]
    nonce = protected["nonce"]
    url = protected["url"]

    if not isinstance(alg, str) or not isinstance(nonce, str) or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Non valid jws2")

    # Verify url
    # print(url)
    # print(request_url)
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
    await _validate_jws(input_data, request_url)
