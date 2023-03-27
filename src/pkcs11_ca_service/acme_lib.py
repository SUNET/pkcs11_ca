"""ACME lib module

Handle the ACME requests

FIXME: handle and check for expired acme objects
"""
from typing import Any, Dict, Union, List
from secrets import token_bytes
import datetime
import json
import time
import base64

from asn1crypto import csr as asn1_csr
from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

from cryptography.exceptions import InvalidSignature

from python_x509_pkcs11.csr import sign_csr as pkcs11_sign_csr

from fastapi.responses import JSONResponse
from fastapi import HTTPException, Response, Request
from fastapi.background import BackgroundTasks

import requests
from requests.exceptions import (
    ConnectionError as requestsConnectionError,
    ConnectTimeout as requestsConnectTimeout,
)
from .base import db_load_data_class
from .acme_authorization import AcmeAuthorization, AcmeAuthorizationInput, challenges_from_list
from .acme_account import AcmeAccount, AcmeAccountInput, contact_from_payload
from .acme_order import AcmeOrder, AcmeOrderInput, authorizations_from_list, identifiers_from_payload
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
    jwk_thumbprint,
    pem_key_to_jwk,
    cert_from_der,
    cert_issued_by_ca,
    public_key_verify_signature,
)
from .config import (
    ACME_ROOT,
    ROOT_URL,
    ACME_IDENTIFIER_TYPES,
    ACME_SIGNER_KEY_TYPE,
    ACME_SIGNER_NAME_DICT,
    ACME_SIGNER_KEY_LABEL,
    ACME_SUNET_TRUSTED_SIGNERS,
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


def is_expired(expiry_date: str) -> bool:
    """If the current date is past the expiry date

    Parameters:
    expiry_date (str): The expiry date as string in %Y-%m-%dT%H:%M:%SZ

    Returns:
    bool
    """

    curr_datetime = datetime.datetime.now(datetime.timezone.utc)
    expire_datetime = datetime.datetime.strptime(expiry_date, "%Y-%m-%dT%H:%M:%SZ").astimezone(tz=datetime.timezone.utc)

    if curr_datetime >= expire_datetime:
        return True
    return False


def account_id_from_kid(kid: str) -> str:
    """Get the account id from the acme KID by only keeping the id part.
    Example KID: 'https://acme-server/path-to-acme/acct/djXYss-mx-L0wy3V47OBoNkLiyOQNUObz'

    Parameters:
    kid (str): The acme KID.

    Returns:
    str
    """

    return kid.replace(ROOT_URL, "").replace(ACME_ROOT, "").replace("/acct/", "")


async def account_authzs(acme_authz_input: AcmeAuthorizationInput) -> List[AcmeAuthorization]:
    """All acme authorizations for the account

    Parameters:
    acme_authz_input (AcmeAuthorizationInput): The AcmeAuthorizationInput for the DB search.

    Returns:
    Union[AcmeAuthorization, None]
    """

    authzs: List[AcmeAuthorization] = []
    db_acme_authz_objs = await db_load_data_class(AcmeAuthorization, acme_authz_input)
    for obj in db_acme_authz_objs:
        if isinstance(obj, AcmeAuthorization):
            authzs.append(obj)

    return authzs


async def account_exists(acme_account_input: AcmeAccountInput) -> Union[AcmeAccount, None]:
    """If the acme account exists (in DB)

    Parameters:
    acme_account_input (AcmeAccountInput): The AcmeAccountInput for the DB search.

    Returns:
    Union[AcmeAccount, None]
    """

    db_acme_account_objs = await db_load_data_class(AcmeAccount, acme_account_input)
    for obj in db_acme_account_objs:
        if isinstance(obj, AcmeAccount):
            return obj
    return None


def http_01_challenge(url: str, token: str, key_authorization: str) -> bool:
    """Execute the http-01 ACME challenge, return true if successful, false if failed
    Retry 5 times each after 5 seconds if the challenge fails.

    Parameters:
    url (str): The challenge's URL
    token (str): The challenge's token
    key_authorization (str): The challenge's key_authorization

    Returns:
    bool

    """

    for _ in range(3):
        try:
            req = requests.get(f"http://{url}/.well-known/acme-challenge/{token}", timeout=3)
            if req is not None and req.status_code == 200 and key_authorization in req.text:
                return True
            return False

        except (requestsConnectionError, requestsConnectTimeout):
            print(f"(1) Failed to connect to ACME challenge at " f"http://{url}/.well-known/acme-challenge/{token}")

        time.sleep(3)

    return False


async def execute_challenge(
    public_key_pem: str, order: AcmeOrder, authz: AcmeAuthorization, challenge: Dict[str, str]
) -> None:
    """Execute the acme challenge.

    Parameters:
    public_key_pem (str): The acme accounts public key in PEM form.
    order (AcmeOrder): The acme order for this challenge.
    authz (AcmeAuthorization): The acme AcmeAuthorization for this challenge.
    challenge (Dict[str, Any]): The challenge.
    """

    identifier = json.loads(from_base64url(authz.identifier))
    thumbprint_jwk = jwk_thumbprint(pem_key_to_jwk(public_key_pem))
    key_authorization = f"{challenge['token']}.{to_base64url(thumbprint_jwk)}"
    challenges = authz.challenges_as_list()

    authz.status = "processing"
    await authz.update()

    if challenge["type"] == "http-01":
        if not http_01_challenge(identifier["value"], challenge["token"], key_authorization):
            return
    else:
        raise ValueError("Invalid challenge type")

    # Challenge was successful
    for chall in challenges:
        if chall["token"] == challenge["token"]:
            chall["status"] = "valid"
            chall["validated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    authz.challenges = challenges_from_list(challenges)
    authz.status = "valid"
    await authz.update()

    # Update order if all authz for the order are valid now due to the challenge was successful
    for order_auth_data in order.authorizations_as_list():
        order_auths = await account_authzs(
            AcmeAuthorizationInput(id=order_auth_data.replace(f"{ROOT_URL}{ACME_ROOT}/authz/", ""))
        )
        if len(order_auths) == 0 or order_auths[0].status != "valid":
            break
    else:
        order.status = "ready"
        await order.update()


async def sign_cert(csr: asn1_csr.CertificationRequest, order: AcmeOrder) -> None:
    """Sign the validated csr into a certificate.

    Parameters:
    csr (asn1crypto.csr.CertificationRequest): The csr.
    order (AcmeOrder): The acme order for this request.
    """

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


def validate_csr(csr: asn1_csr.CertificationRequest, order: AcmeOrder) -> None:  # pylint: disable=too-many-branches
    """Validate a csr to its orders identifications.

    Parameters:
    csr (asn1crypto.csr.CertificationRequest): The csr.
    order (AcmeOrder): The acme order for this request.
    """

    subject = csr["certification_request_info"]["subject"].native

    sans: List[str] = []
    csr_exts = csr["certification_request_info"]["attributes"].native
    for csr_ext in csr_exts:  # pylint: disable=too-many-nested-blocks
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


async def _check_revoke_jwk(signature: str, signed_data: str, cert_pem: str) -> None:
    pem_cert_verify_signature(cert_pem, from_base64url(signature), signed_data.encode("utf-8"))
    order = (await db_load_data_class(AcmeOrder, AcmeOrderInput(issued_certificate=cert_pem)))[0]
    if not isinstance(order, AcmeOrder):
        raise HTTPException(status_code=401, detail="Non valid cert to revoke")

    # Check if the acme account is deactivated
    account = await account_exists(AcmeAccountInput(serial=order.account))
    if account is None:
        raise HTTPException(status_code=401, detail="No such account")

    if account.status == "deactivated":
        raise HTTPException(status_code=401, detail="Unauthorized")

    if order.issued_certificate != cert_pem:
        raise HTTPException(status_code=401, detail="Non valid cert to revoke")


async def _check_revoke_kid(jws: Dict[str, Any], request_url: str, protected: Dict[str, Any], cert_pem: str) -> None:
    # Ensure valid jwt
    await validate_jws(jws, request_url)
    account = await account_exists(AcmeAccountInput(id=account_id_from_kid(protected["kid"])))
    if account is None:
        raise HTTPException(status_code=401, detail="No such account")

    # Check if the acme account is deactivated
    if account.status == "deactivated":
        raise HTTPException(status_code=401, detail="Unauthorized")

    order = (await db_load_data_class(AcmeOrder, AcmeOrderInput(issued_certificate=cert_pem)))[0]
    if not isinstance(order, AcmeOrder):
        raise HTTPException(status_code=401, detail="Non valid cert to revoke")

    if order.issued_certificate != cert_pem or order.account != account.serial:
        raise HTTPException(status_code=401, detail="Non valid cert to revoke")


async def revoke_cert_response(jws: Dict[str, Any], request_url: str) -> Response:
    """Revoke an acme issued cert.
    Authorization can be normal acme or the JWS being signed by the certs private key.

    Parameters:
    jws (Dict[str, Any]): The JWS.
    request_url (str): The request url.

    Returns:
    fastapi.responses.Response
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))
    reason: Union[int, None] = None

    if "signature" not in jws:
        raise HTTPException(status_code=400, detail="invalid request")
    signature = jws["signature"]
    if not isinstance(signature, str) or not isinstance(protected, dict) or not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid request")

    signed_data = jws["protected"] + "." + jws["payload"]

    # Get certificate from request
    if "certificate" not in payload:
        raise HTTPException(status_code=400, detail="Certificate missing")
    certificate: str = payload["certificate"]
    if not isinstance(certificate, str):
        raise HTTPException(status_code=400, detail="Certificate missing")

    asn1_certificate = asn1_x509.Certificate().load(from_base64url(certificate))
    cert_pem: str = asn1_pem.armor("CERTIFICATE", asn1_certificate.dump()).decode("utf-8")

    if "reason" in payload:
        reason = payload["reason"]
    if isinstance(reason, int) and reason not in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]:  # 7 not here
        raise HTTPException(status_code=400, detail="Invalid reason")

    # Verify using normal acme auth
    if "kid" in protected:
        await _check_revoke_kid(jws, request_url, protected, cert_pem)

    # Verify it's the certificate private key that has signed the request
    elif "jwk" in protected:
        await _check_revoke_jwk(signature, signed_data, cert_pem)
    else:
        raise HTTPException(status_code=401, detail="No such account")

    # Get cert from DB
    cert = (await db_load_data_class(Certificate, CertificateInput(pem=cert_pem)))[0]
    if not isinstance(cert, Certificate):
        raise HTTPException(status_code=401, detail="Non valid cert to revoke")

    # Revoke cert
    await cert.revoke(1, reason)

    return Response(headers={"Replay-Nonce": generate_nonce()})


async def cert_response(account: AcmeAccount, jws: Dict[str, Any]) -> Response:
    """Fetch the issued certificate.
    The certs issuer is included, it's a chain.

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.Response
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    cert_id: str = protected["url"]

    order: AcmeOrder
    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(account=account.serial))
    for obj in db_acme_order_objs:
        if not isinstance(obj, AcmeOrder):
            raise HTTPException(status_code=401, detail="Non valid order")

        if obj.certificate == cert_id and obj.status == "valid":
            order = obj
            break
    else:
        raise HTTPException(status_code=401, detail="Non valid order")

    return Response(content=f"{order.issued_certificate}", media_type="application/pem-certificate-chain")


async def finalize_order_response(_: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    """Finalize the order by sending a csr which the acme CA will sign
     as long as it conforms to the orders identifiers

    Parameters:
    _ (AcmeAccount): The acme account that made this request. Here for uniformity with the other ACME functions
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

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

    if is_expired(order.expires):
        order.status = "invalid"
        await order.update()
        raise HTTPException(status_code=401, detail="order has expired")  # Fixme handle error better see rfc

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
    order.status = "processing"
    await order.update()

    await sign_cert(csr_req, order)

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce()},
        content=order.response_data(),
        media_type="application/json",
    )


async def chall_response(  # pylint: disable=too-many-branches
    account: AcmeAccount, jws: Dict[str, Any], background_tasks: BackgroundTasks
) -> JSONResponse:
    """List or execute the acme challenge

    The challenge will be executed if the payload is an empty json dict '{}'
    by the server immediately after the http request finishes

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.
    background_tasks (fastapi.background.BackgroundTasks):
    The list of background tasks which will execute the challenge.

    Returns:
    fastapi.responses.JSONResponse
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    if jws["payload"] == "":  # Here since some clients sends "" instead of "{}"
        payload = {"just_info": "just_info"}
    else:
        payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    # Should we execute the challenge or is the client just listing it
    execute = isinstance(payload, dict) and not bool(payload)

    challenge_url: str = protected["url"]
    orders: List[AcmeOrder] = []
    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(account=account.serial))
    for obj in db_acme_order_objs:
        if isinstance(obj, AcmeOrder):
            orders.append(obj)

    for order in orders:  # pylint: disable=too-many-nested-blocks
        for authz in order.authorizations_as_list():
            db_acme_authz_objs = await db_load_data_class(
                AcmeAuthorization, AcmeAuthorizationInput(id=authz.replace(f"{ROOT_URL}{ACME_ROOT}/authz/", ""))
            )
            for authz_obj in db_acme_authz_objs:
                if not isinstance(authz_obj, AcmeAuthorization):
                    raise HTTPException(status_code=400, detail="Non valid challenge")

                for challenge in authz_obj.challenges_as_list():
                    if challenge["url"] == challenge_url:
                        # Check expired
                        if is_expired(order.expires):
                            order.status = "invalid"
                            await order.update()
                        if is_expired(authz_obj.expires):
                            authz_obj.status = "expired"
                            await authz_obj.update()

                        # Execute the challenge if the client requested it, and it's not expired
                        if execute and order.status == "pending" and authz_obj.status == "pending":
                            background_tasks.add_task(
                                execute_challenge, account.public_key_pem, order, authz_obj, challenge
                            )

                        return JSONResponse(
                            status_code=200,
                            headers={"Replay-Nonce": generate_nonce()},
                            content=challenge,
                            media_type="application/json",
                        )

    raise HTTPException(status_code=401, detail="Non valid challenge")


async def authz_response(_: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    """List the acme authorization

    Parameters:
    _ (AcmeAccount): The acme account that made this request. Here for uniformity with the other ACME functions
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))

    authz_id: str = protected["url"]
    authz_id = authz_id.replace(f"{ROOT_URL}{ACME_ROOT}/authz/", "")

    authzs = await account_authzs(AcmeAuthorizationInput(id=authz_id))
    if len(authzs) != 1:
        raise HTTPException(status_code=401, detail="Non valid authz")

    # Check if the authz has expired
    if is_expired(authzs[0].expires):
        authzs[0].status = "expired"
        await authzs[0].update()

    if authzs[0].status == "pending":
        headers = {"Replay-Nonce": generate_nonce(), "Retry-After": "10"}
    else:
        headers = {"Replay-Nonce": generate_nonce()}

    return JSONResponse(
        status_code=200,
        headers=headers,
        content=authzs[0].response_data(),
        media_type="application/json",
    )


async def sunet_acme_authz(account: AcmeAccount, token: str) -> JSONResponse:
    """A SUNET type challenge ACME pre-authorization

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

    response_data: Dict[str, Any] = {}
    token_parts = token.split(".")
    if len(token_parts) != 3:
        raise HTTPException(status_code=400, detail="Invalid token for sunet acme authz")

    header = json.loads(from_base64url(token_parts[0]))
    payload = json.loads(from_base64url(token_parts[1]))
    signature = token_parts[2]

    if (
        "x5c" not in header
        or "alg" not in header
        or "typ" not in header
        or "url" not in header
        or "names" not in payload
        or "nonce" not in payload
    ):
        raise HTTPException(status_code=400, detail="Invalid token for sunet acme authz")

    x5c = header["x5c"]
    alg = header["alg"]
    typ = header["typ"]
    url = header["url"]
    names = payload["names"]
    nonce = payload["nonce"]
    if (
        not isinstance(x5c, list)
        or len(x5c) == 0
        or not isinstance(alg, str)
        or not isinstance(typ, str)
        or not isinstance(url, str)
        or not isinstance(names, list)
        or not isinstance(nonce, str)
    ):
        raise HTTPException(status_code=400, detail="Invalid token for sunet acme authz")

    encoded_cert = x5c[0]
    if not isinstance(encoded_cert, str):
        raise HTTPException(status_code=400, detail="Invalid token for sunet acme authz")

    cert_pem = cert_from_der(base64.b64decode(encoded_cert.encode("utf-8")))

    # Verify token signature
    try:
        pem_cert_verify_signature(
            cert_pem,
            from_base64url(token_parts[2]),
            f"{token_parts[0]}.{token_parts[1]}".encode("utf-8"),
        )
    except (InvalidSignature, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Token signature invalid") from exc

    # Verify cert or certs CA is in config file
    for config_cert in ACME_SUNET_TRUSTED_SIGNERS:
        config_cert = config_cert.strip() + "\n"
        if config_cert == cert_pem or cert_issued_by_ca(cert_pem, config_cert):
            break
    else:
        raise HTTPException(status_code=401, detail="Cert was not a trusted cert or signed by trusted CA")

    auth_id = random_string()
    first_authorization: Union[AcmeAuthorization, None] = None

    for index, name in enumerate(names):
        if not isinstance(name, str):
            raise HTTPException(status_code=400, detail="Invalid dns name")

        if index == 0:
            curr_auth_id = auth_id
        else:
            curr_auth_id = random_string()

        challenges: List[Dict[str, str]] = [
            {
                "type": "http-01",  # FIXME change this to x-sunet-01
                "url": f"{ROOT_URL}{ACME_ROOT}/chall/{random_string()}",
                "status": "valid",
                "validated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ]

        new_authorization = AcmeAuthorization(
            {
                "account": account.serial,
                "id": curr_auth_id,
                "status": "valid",
                "expires": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "identifier": to_base64url(json.dumps({"type": "signature", "value": name}).encode("utf-8")),
                "challenges": challenges_from_list(challenges),
                "wildcard": 1 if "*" in name else 0,
            }
        )
        # Save new auth to database
        await new_authorization.save()

        if index == 0:
            first_authorization = new_authorization

    headers = {"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/authz/{auth_id}"}

    if first_authorization is None:
        raise HTTPException(status_code=400, detail="Could not create authz")

    return JSONResponse(
        status_code=201,
        headers=headers,
        content=first_authorization.response_data(),
        media_type="application/json",
    )


async def new_authz_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    """An ACME pre-authorization

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    if "token" in payload:
        token = payload["token"]
        if isinstance(token, str):
            return await sunet_acme_authz(account, token)
        raise HTTPException(status_code=400, detail="Missing valid token for sunet acme authz")

    if "identifier" not in payload:
        raise HTTPException(status_code=400, detail="Missing identifier")

    identifier = payload["identifier"]
    if not isinstance(identifier, dict) or "type" not in identifier or "value" not in identifier:
        raise HTTPException(status_code=400, detail="Missing valid identifier")

    identifier_type = identifier["type"]
    identifier_value = identifier["value"]
    if (
        not isinstance(identifier_type, str)
        or not isinstance(identifier_value, str)
        or identifier_type not in ACME_IDENTIFIER_TYPES
    ):
        raise HTTPException(status_code=400, detail="Missing valid identifier")

    if "*" in identifier_value:
        raise HTTPException(status_code=400, detail="Cannot pre auth wildcard")

    auth_id = random_string()
    challenges: List[Dict[str, str]] = []  # FIXME add DNS challenge

    if identifier_type == "dns":
        challenges.append(
            {
                "type": "http-01",
                "url": f"{ROOT_URL}{ACME_ROOT}/chall/{random_string()}",
                "status": "pending",
                "token": random_string(),
            }
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported identifier type")

    new_authorization = AcmeAuthorization(
        {
            "account": account.serial,
            "id": auth_id,
            "status": "pending",
            "expires": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "identifier": to_base64url(
                json.dumps({"type": identifier_type, "value": identifier_value}).encode("utf-8")
            ),
            "challenges": challenges_from_list(challenges),
            "wildcard": 1 if "*" in identifier["value"] else 0,
        }
    )
    # Save new auth to database
    await new_authorization.save()

    headers = {"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/authz/{new_authorization.id}"}

    return JSONResponse(
        status_code=201,
        headers=headers,
        content=new_authorization.response_data(),
        media_type="application/json",
    )


async def order_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    """List the acme order

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))

    # Ensure correct account access the orders list
    order_id: str = protected["url"].replace(f"{ROOT_URL}{ACME_ROOT}/order/", "")

    db_acme_order_objs = await db_load_data_class(AcmeOrder, AcmeOrderInput(account=account.serial))
    for order in db_acme_order_objs:
        if not isinstance(order, AcmeOrder):
            raise HTTPException(status_code=401, detail="Non valid order")

        if order.id != order_id:
            continue

        # Check if order has expired
        if is_expired(order.expires):
            order.status = "invalid"
            await order.update()

        return JSONResponse(
            status_code=200,
            headers={"Replay-Nonce": generate_nonce()},
            content=order.response_data(),
            media_type="application/json",
        )
    raise HTTPException(status_code=401, detail="Non valid order")


async def new_order_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    """Create a new acme order

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

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
            "status": "ready",  # Changed to pending below if pending challenges exists for the order
            "expires": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "identifiers": identifiers_from_payload(payload),
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
            "issued_certificate": random_string(),
        }
    )
    await new_order.save()

    new_order.finalize = f"{ROOT_URL}{ACME_ROOT}/order/{new_order.id}/finalize"

    pre_authzs = await account_authzs(AcmeAuthorizationInput(account=account.serial))

    authorizations: List[str] = []
    for identifier in new_order.identifiers_as_list():
        if identifier["type"] not in ACME_IDENTIFIER_TYPES:
            raise HTTPException(status_code=400, detail="Non valid identifier type")

        auth_id = random_string()

        # Get a pre auth if exists
        found_identifier = False

        # x-sunet-01
        for pre_authz in pre_authzs:
            if (
                pre_authz.identifier_as_dict()["type"] == "signature"
                and pre_authz.identifier_as_dict()["value"] == identifier["value"]
                and pre_authz.status == "valid"
                and not is_expired(pre_authz.expires)
            ):
                found_identifier = True
                authorizations.append(f"{ROOT_URL}{ACME_ROOT}/authz/{pre_authz.id}")
                break
        if found_identifier:
            continue

        for pre_authz in pre_authzs:
            if (
                pre_authz.identifier_as_dict()["type"] == identifier["type"]
                and pre_authz.identifier_as_dict()["value"] == identifier["value"]
                and pre_authz.status == "pending"
                and not is_expired(pre_authz.expires)
            ):
                found_identifier = True
                new_order.status = "pending"
                authorizations.append(f"{ROOT_URL}{ACME_ROOT}/authz/{pre_authz.id}")
                break
        if found_identifier:
            continue

        challenges: List[Dict[str, str]] = []  # FIXME add DNS challenge

        if identifier["type"] == "dns":
            challenges.append(
                {
                    "type": "http-01",
                    "url": f"{ROOT_URL}{ACME_ROOT}/chall/{random_string()}",
                    "status": "pending",
                    "token": random_string(),
                }
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported identifier type")

        new_order.status = "pending"
        authorizations.append(f"{ROOT_URL}{ACME_ROOT}/authz/{auth_id}")
        new_authorization = AcmeAuthorization(
            {
                "account": account.serial,
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

    return JSONResponse(
        status_code=201,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/order/{new_order.id}"},
        content=new_order.response_data(),
        media_type="application/json",
    )


async def orders_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    """List acme orders

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))

    # Ensure correct account access the orders list
    account_id: str = protected["url"].replace(f"{ROOT_URL}{ACME_ROOT}/orders/", "")
    order_account = await account_exists(AcmeAccountInput(id=account_id))
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


async def key_change_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:  # FIXME not overwrite key??
    """Change key for the acme account

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

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

    inner_signed_data = payload["protected"] + "." + payload["payload"]

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

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": protected["url"]},
        content=account.response_data(),
        media_type="application/json",
    )


async def update_account_response(account: AcmeAccount, jws: Dict[str, Any]) -> JSONResponse:
    """Update the acme account

    Parameters:
    account (AcmeAccount): The acme account that made this request.
    jws (Dict[str, Any): The JWS.

    Returns:
    fastapi.responses.JSONResponse
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    # Update contact if contact is in payload
    if "contact" in payload:
        account.contact = contact_from_payload(payload)

    if "status" in payload:
        status = payload["status"]
        if isinstance(status, str) and status == "deactivated":
            account.status = "deactivated"

    await account.update()

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": protected["url"]},
        content=account.response_data(),
        media_type="application/json",
    )


async def existing_account_response(account: AcmeAccount) -> JSONResponse:
    """List an existing acme account

    Parameters:
    account (AcmeAccount): The acme account class object.

    Returns:
    fastapi.responses.JSONResponse
    """

    return JSONResponse(
        status_code=200,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/acct/{account.id}"},
        content=account.response_data(),
        media_type="application/json",
    )


async def new_account_response(jws: Dict[str, Any], request_url: str) -> JSONResponse:
    """Create a new acme account

    Parameters:
    jws (Dict[str, Any): The ACME jws

    Returns:
    fastapi.responses.JSONResponse
    """

    payload = json.loads(from_base64url(jws["payload"]).decode("utf-8"))

    # Ensure valid jwt
    await validate_jws(jws, request_url)

    public_key_pem = pem_from_jws(jws)

    # If account exists
    existing_account = await account_exists(AcmeAccountInput(public_key_pem=public_key_pem))
    if existing_account is not None:
        return await existing_account_response(existing_account)

    # onlyReturnExisting for an unknown account
    if (
        "onlyReturnExisting" in payload
        and isinstance(payload["onlyReturnExisting"], bool)
        and payload["onlyReturnExisting"]
    ):
        return JSONResponse(
            status_code=400,
            headers={"Replay-Nonce": generate_nonce()},
            content={"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "No such account"},
        )

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
    # Save account to DB
    await acme_account_obj.save()

    return JSONResponse(
        status_code=201,
        headers={"Replay-Nonce": generate_nonce(), "Location": f"{ROOT_URL}{ACME_ROOT}/acct/{account_id}"},
        content=acme_account_obj.response_data(),
        media_type="application/json",
    )


def pem_from_jws(jws: Dict[str, Any]) -> str:
    """Get a public key in PEM form from a JWS.

    Parameters:
    jws (Dict[str, Any): The JWS.

    Returns:
    str
    """

    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    return jwk_key_to_pem(protected["jwk"])


def validate_signature(signer_public_key_data: str, signature: str, signed_data: str) -> None:
    """Validate a signature
    Raises cryptography.exceptions.InvalidSignature or fastapi.HTTPException if failed

    Parameters:
    signer_public_key_data (str): Public key in PEM form
    signature (str): The signature in base64url form.
    signed_data (str): The signed data in base64url form.
    """

    return public_key_verify_signature(signer_public_key_data, from_base64url(signature), signed_data.encode("utf-8"))


async def validate_kid(kid: str, signed_data: str, signature: str) -> None:
    """Validate an acme KID signature
    Raises cryptography.exceptions.InvalidSignature or fastapi.HTTPException if KID not exists.

    Parameters:
    kid (str): The acme KID.
    signed_data (str): The signed data in base64url form.
    signature (str): The signature in base64url form.
    """

    account = await account_exists(AcmeAccountInput(id=account_id_from_kid(kid)))
    if account is None or account.status == "deactivated":  # FIXME special error for deactivated
        raise NoSuchKID(kid)

    validate_signature(account.public_key_pem, signature, signed_data)


def validate_jwk(jwk: Dict[str, Any], alg: str, signed_data: str, signature: str) -> None:
    """Validate a JWK signature to the specified alg

    Parameters:
    jwk (Dict[str, Any]): The JWK.
    alg (str): The signature algorithm.
    signed_data (str): The signed data in base64url form.
    signature (str): The signature in base64url form.

    Returns:
    fastapi.Response
    """

    if alg not in ["RS256", "ES256", "ES384", "ES512", "EdDSA"]:
        raise HTTPException(status_code=400, detail="Non valid alg in jwk")

    signer_public_key_data = jwk_key_to_pem(jwk)
    validate_signature(signer_public_key_data, signature, signed_data)


async def validate_jws(input_data: Dict[str, Any], request_url: str) -> None:  # pylint: disable=too-many-branches
    """Validate an acme JWS by either acme KID or JWK.
    Also validates url, nonce and alg according to acme

    Parameters:
    input_data (Dict[str, Any]): The JWS.
    request_url (str): The request url.

    Returns:
    fastapi.Response
    """

    if "protected" not in input_data or "payload" not in input_data or "signature" not in input_data:
        raise HTTPException(status_code=400, detail="Non valid jws")

    protected = json.loads(from_base64url(input_data["protected"]).decode("utf-8"))
    if input_data["payload"] == "":
        payload = {}
    else:
        payload = json.loads(from_base64url(input_data["payload"]).decode("utf-8"))
    signature = input_data["signature"]

    if not isinstance(protected, dict) or not isinstance(payload, dict) or not isinstance(signature, str):
        raise HTTPException(status_code=400, detail="Non valid jws")

    signed_data = input_data["protected"] + "." + input_data["payload"]

    alg = protected["alg"]
    nonce = protected["nonce"]
    url = protected["url"]

    if not isinstance(alg, str) or not isinstance(nonce, str) or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Non valid jws")

    if url != request_url:
        raise HTTPException(status_code=400, detail="Client request url did not match jws url")

    # Verify nonce
    if not await verify_nonce(nonce):
        raise HTTPException(status_code=400, detail="No such nonce in jws")

    # Cant have both jwk and kid
    if "jwk" in protected and "kid" in protected:
        raise HTTPException(status_code=400, detail="Non valid jws")

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


async def handle_acme_routes(  # pylint: disable=too-many-return-statements,too-many-branches
    request: Request, background_tasks: BackgroundTasks
) -> Response:
    """All acme routes except new-nonce and directory are handled from here.

    Parameters:
    request (fastapi.Request): The http request.
    background_tasks (fastapi.background.BackgroundTasks): A background to be run after the http request has finished.

    Returns:
    fastapi.Response
    """

    request_url = str(request.url)

    try:
        input_data = await request.json()
    except json.decoder.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid json") from exc

    if not isinstance(input_data, dict):
        raise HTTPException(status_code=400, detail="Non valid jws")

    if request_url == f"{ROOT_URL}{ACME_ROOT}/new-account":
        return await new_account_response(input_data, request_url)

    # Revoke cert does its own auth
    if request_url == f"{ROOT_URL}{ACME_ROOT}/revoke-cert":
        return await revoke_cert_response(input_data, request_url)

    # Ensure valid jwt and account exists - Thus a valid acme request
    await validate_jws(input_data, request_url)
    protected = json.loads(from_base64url(input_data["protected"]).decode("utf-8"))
    account = await account_exists(AcmeAccountInput(id=account_id_from_kid(protected["kid"])))
    if account is None:
        return JSONResponse(status_code=401, content="Unauthorized", media_type="application/json")  # fixme

    # Check if the acme account is deactivated
    if account.status == "deactivated":
        return JSONResponse(status_code=401, content="Unauthorized", media_type="application/json")  # fixme

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/acct/"):
        return await update_account_response(account, input_data)

    if request_url == f"{ROOT_URL}{ACME_ROOT}/key-change":
        return await key_change_response(account, input_data)

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/orders/"):
        return await orders_response(account, input_data)

    if request_url == f"{ROOT_URL}{ACME_ROOT}/new-order":
        return await new_order_response(account, input_data)

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/order/") and request_url.endswith("/finalize"):
        return await finalize_order_response(account, input_data)

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/order/"):
        return await order_response(account, input_data)

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/new-authz"):
        return await new_authz_response(account, input_data)

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/authz/"):
        return await authz_response(account, input_data)

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/chall/"):
        return await chall_response(account, input_data, background_tasks)

    if request_url.startswith(f"{ROOT_URL}{ACME_ROOT}/cert/"):
        return await cert_response(account, input_data)

    raise HTTPException(status_code=404)
