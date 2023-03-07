from typing import Any, Dict, Union, List
from secrets import token_bytes
import datetime
import json
import hashlib
import time

from asn1crypto import csr as asn1_csr
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256

from python_x509_pkcs11.csr import sign_csr as pkcs11_sign_csr

from fastapi.responses import JSONResponse
from fastapi import HTTPException, Response
import requests

from .base import db_load_data_class
from .acme_authorization import AcmeAuthorization, AcmeAuthorizationInput, challenges_from_list
from .acme_account import AcmeAccount, AcmeAccountInput, contact_from_payload
from .acme_order import AcmeOrder, AcmeOrderInput, identifiers_from_order, authorizations_from_list
from .nonce import generate_nonce, verify_nonce
from .public_key import PublicKey
from .pkcs11_key import Pkcs11KeyInput, Pkcs11Key
from .ca import CaInput
from .csr import Csr
from .certificate import Certificate, CertificateInput
from .route_functions import ca_request
from .asn1 import (
    to_base64url,
    from_base64url,
    jwk_key_to_pem,
    public_key_pem_from_csr,
    cert_pem_serial_number,
    aia_and_cdp_exts,
    pem_cert_verify_signature,
)
from .config import (
    ACME_ROOT,
    ROOT_URL,
    ACME_IDENTIFIER_TYPES,
    ACME_SIGNER_KEY_TYPE,
    ACME_SIGNER_NAME_DICT,
    ACME_SIGNER_KEY_LABEL,
)


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
    """If exists then return the authorization"""
    db_acme_authz_objs = await db_load_data_class(AcmeAuthorization, acme_authz_input)
    for obj in db_acme_authz_objs:
        if isinstance(obj, AcmeAuthorization):
            return obj
    return None


async def account_exists(acme_account_input: AcmeAccountInput) -> Union[AcmeAccount, None]:
    """If exists then return the account"""
    db_acme_account_objs = await db_load_data_class(AcmeAccount, acme_account_input)
    for obj in db_acme_account_objs:
        if isinstance(obj, AcmeAccount):
            return obj
    return None


async def execute_challenge(kid: str, order: AcmeOrder, authz: AcmeAuthorization, challenge: Dict[str, str]) -> None:
    identifier = json.loads(from_base64url(authz.identifier))
    hash_module = hashlib.sha256()
    hash_module.update(f"{ROOT_URL}{ACME_ROOT}/acct/{kid}".encode("utf-8"))
    key_authorization = f"{challenge['token']}.{to_base64url(hash_module.digest())}"
    challenges = authz.challenges_as_list()

    authz.status = "processing"
    await authz.update()

    chall_success = False

    if challenge["type"] == "http-01":
        req = requests.get(
            f"http://{identifier['value']}/.well-known/acme-challenge/{challenge['token']}", verify=False, timeout=3
        )

        if req.status_code == 200 and key_authorization in req.text:
            chall_success = True
        else:
            time.sleep(5)
            req = requests.get(
                f"http://{identifier['value']}/.well-known/acme-challenge/{challenge['token']}", verify=False, timeout=3
            )

            if req.status_code == 200 and key_authorization in req.text:
                chall_success = True

        if chall_success:
            for chall in challenges:
                if chall["token"] == challenge["token"]:
                    chall["status"] = "valid"
                    chall["validated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            authz.challenges = challenges_from_list(challenges)
            authz.status = "valid"
            await authz.update()

            for order_auth_data in order.authorizations_as_list():
                order_auth = await authz_exists(
                    AcmeAuthorizationInput(id=order_auth_data.replace(f"{ROOT_URL}{ACME_ROOT}/authz/", ""))
                )
                if not isinstance(order_auth, AcmeAuthorization) or order_auth.status != "valid":
                    break
            else:
                order.status = "ready"
                await order.update()


async def sign_cert(csr: asn1_csr.CertificationRequest, order: AcmeOrder) -> None:
    csr_pem = asn1_pem.armor("CERTIFICATE REQUEST", csr.dump()).decode("utf-8")

    pkcs11_key = (await db_load_data_class(Pkcs11Key, Pkcs11KeyInput(key_label=ACME_SIGNER_KEY_LABEL)))[0]
    if not isinstance(pkcs11_key, Pkcs11Key):
        raise HTTPException(status_code=400, detail="Non valid acme signer ca")

    issuer = await ca_request(CaInput(pkcs11_key=pkcs11_key.serial))
    extra_extensions = aia_and_cdp_exts(issuer.path)

    # Get public key from csr
    public_key_obj = PublicKey({"pem": public_key_pem_from_csr(csr_pem), "authorized_by": 1})
    await public_key_obj.save()

    # Save csr
    csr_obj = Csr({"pem": csr_pem, "authorized_by": 1, "public_key": public_key_obj.serial})
    await csr_obj.save()

    cert_pem = await pkcs11_sign_csr(
        ACME_SIGNER_KEY_LABEL,
        ACME_SIGNER_NAME_DICT,
        csr_pem,
        key_type=ACME_SIGNER_KEY_TYPE,
        extra_extensions=extra_extensions,
    )

    # Save cert
    cert_obj = Certificate(
        {
            "pem": cert_pem,
            "authorized_by": 1,
            "csr": csr_obj.serial,
            "serial_number": str(cert_pem_serial_number(cert_pem)),
            "public_key": public_key_obj.serial,
            "issuer": issuer.serial,
        }
    )
    await cert_obj.save()

    order.certificate = f"{ROOT_URL}{ACME_ROOT}/cert/{random_string()}"
    order.issued_certificate = cert_pem
    order.status = "valid"
    await order.update()


def validate_csr(csr: asn1_csr.CertificationRequest, order: AcmeOrder) -> None:
    subject = csr["certification_request_info"]["subject"].native

    sans: List[str] = []
    csr_exts = csr["certification_request_info"]["attributes"].native
    for csr_ext in csr_exts:
        if csr_ext["type"] == "extension_request":
            for exts in csr_ext["values"]:
                for ext in exts:
                    if ext["extn_id"] == "subject_alt_name":
                        for san in ext["extn_value"]:
                            sans.append(san)

    if "common_name" not in subject or len(sans) == 0:
        raise HTTPException(status_code=400, detail="Non valid csr")

    identifiers: List[str] = []
    for ident in order.identifiers_as_list():
        if ident["type"] == "dns":
            identifiers.append(ident["value"])

    # Check all identifiers
    for identifier in identifiers:
        if identifier not in sans and identifier != subject["common_name"]:
            raise HTTPException(status_code=400, detail="csr not matching identifier")

    # Check all subject alternative names
    for san in sans:
        if san not in identifiers and san != subject["common_name"]:
            raise HTTPException(status_code=400, detail="csr not matching identifier")


async def revoke_cert_response(jws: Dict[str, Any], request_url: str) -> Response:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))
    reason: Union[int, None] = None

    if "signature" not in jws:
        raise HTTPException(status_code=400, detail="invalid request")
    signature = jws["signature"]
    if not isinstance(signature, str) or not isinstance(protected, dict) or not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid request")

    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )

    if "certificate" not in payload:
        raise HTTPException(status_code=400, detail="Certificate missing")
    certificate: str = payload["certificate"]
    if not isinstance(certificate, str):
        raise HTTPException(status_code=400, detail="Certificate missing")

    asn1_certificate = asn1_x509.Certificate().load(from_base64url(certificate))
    cert_pem: str = asn1_pem.armor("CERTIFICATE", asn1_certificate.dump()).decode("utf-8")

    if "reason" in payload:
        reason = payload["reason"]
    if not isinstance(reason, int) or reason not in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]:
        raise HTTPException(status_code=400, detail="Invalid reason")

    # Verify signature
    if "kid" in protected:
        # Ensure valid jwt
        await validate_jws(jws, request_url)
        account = await account_exists(AcmeAccountInput(id=account_id_from_kid(protected["kid"])))
        if account is None:
            raise HTTPException(status_code=401, detail="No such account")

        order = (await db_load_data_class(AcmeOrder, AcmeOrderInput(issued_certificate=cert_pem)))[0]
        if not isinstance(order, AcmeOrder):
            raise HTTPException(status_code=401, detail="Non valid cert to revoke")

        if order.issued_certificate != cert_pem or order.account != account.serial:
            raise HTTPException(status_code=401, detail="Non valid cert to revoke")

    elif "jwk" in protected:
        pem_cert_verify_signature(cert_pem, from_base64url(signature), signed_data.encode("utf-8"))
        order = (await db_load_data_class(AcmeOrder, AcmeOrderInput(issued_certificate=cert_pem)))[0]
        if not isinstance(order, AcmeOrder):
            raise HTTPException(status_code=401, detail="Non valid cert to revoke")

        if order.issued_certificate != cert_pem:
            raise HTTPException(status_code=401, detail="Non valid cert to revoke")
    else:
        raise HTTPException(status_code=401, detail="No such account")

    cert = (await db_load_data_class(Certificate, CertificateInput(pem=cert_pem)))[0]
    if not isinstance(cert, Certificate):
        raise HTTPException(status_code=401, detail="Non valid cert to revoke")

    # Revoke cert
    await cert.revoke(1, reason)
    print("Revoked cert from acme revoke request")

    return Response(headers={"Replay-Nonce": generate_nonce()})


async def cert_response(account: AcmeAccount, jws: Dict[str, Any]) -> Response:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    cert_id: str = protected["url"]

    order: AcmeOrder
    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(account=account.serial))
    for obj in db_acme_order_objs:
        if not isinstance(obj, AcmeOrder):
            raise HTTPException(status_code=401, detail="Non valid order")

        if obj.certificate == cert_id:
            order = obj
            break
    else:
        raise HTTPException(status_code=401, detail="Non valid order")

    pkcs11_key = (await db_load_data_class(Pkcs11Key, Pkcs11KeyInput(key_label=ACME_SIGNER_KEY_LABEL)))[0]
    if not isinstance(pkcs11_key, Pkcs11Key):
        raise HTTPException(status_code=400, detail="Non valid acme signer ca")

    issuer = await ca_request(CaInput(pkcs11_key=pkcs11_key.serial))

    return Response(content=f"{order.issued_certificate}{issuer.pem}", media_type="application/pem-certificate-chain")


async def finalize_order_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    order_id: str = protected["url"]
    order_id = order_id.replace(f"{ROOT_URL}{ACME_ROOT}/order/", "").replace("/finalize", "")

    order: AcmeOrder
    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(id=order_id))
    for obj in db_acme_order_objs:
        if not isinstance(obj, AcmeOrder):
            raise HTTPException(status_code=401, detail="Non valid order")

        if obj.id == order_id:
            order = obj
            break
    else:
        raise HTTPException(status_code=401, detail="Non valid order")

    if order.status != "ready":
        raise HTTPException(status_code=403, detail="orderNotReady")  # Fixme handle error better see rfc

    if "csr" not in payload:
        raise HTTPException(status_code=400, detail="Non valid csr")

    csr = payload["csr"]
    if not isinstance(csr, str):
        raise HTTPException(status_code=400, detail="Non valid csr")

    csr_req = asn1_csr.CertificationRequest().load(from_base64url(csr))
    _ = csr_req.native  # Ensure valid csr format

    validate_csr(csr_req, order)

    # Set status as processing since csr was valid
    order.status = "prccessing"
    await order.update()

    await sign_cert(csr_req, order)

    response_data = {
        "status": order.status,
        "expires": order.expires,
        "notBefore": order.not_before,
        "notAfter": order.not_after,
        "identifiers": order.identifiers_as_list(),
        "authorizations": order.authorizations_as_list(),
        "finalize": order.finalize,
    }
    if order.status == "valid":
        response_data["certificate"] = order.certificate

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce()},
        content=response_data,
        media_type="application/json",
    )


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
                    raise HTTPException(status_code=400, detail="Non valid challenge")

                for challenge in authz_obj.challenges_as_list():
                    if challenge["url"] == challenge_url:
                        if execute:
                            print("executing chall")  # fixme run in background thread
                            await execute_challenge(account.id, order, authz_obj, challenge)
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

    if authz.status == "pending":
        headers = {"Replay-Nonce": generate_nonce(), "Retry-After": "10"}
    else:
        headers = {"Replay-Nonce": generate_nonce()}

    return JSONResponse(
        status_code=200,
        headers=headers,
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
        if order.status == "valid":
            response_data["certificate"] = order.certificate

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
            "issued_certificate": "",
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
    if "protected" not in input_data or "payload" not in input_data or "signature" not in input_data:
        raise HTTPException(status_code=400, detail="Non valid jws")

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
        raise HTTPException(status_code=400, detail="Non valid jws")

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
