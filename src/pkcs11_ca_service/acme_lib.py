from typing import Any, Dict, Union
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
from .nonce import generate_nonce
from .asn1 import to_base64url, from_base64url, jwk_key_to_pem
from .config import ACME_ROOT


def random_string() -> str:
    """Generate a random string, only base64url chars

    Returns:
    str
    """

    return to_base64url(token_bytes(64).strip(b"="))


async def public_key_exists(public_key_pem: str) -> Union[Dict[str, Any], None]:
    """If exists the return the account"""
    db_certificate_objs = await db_load_data_class(AcmeAccount, AcmeAccountInput(public_key_pem=public_key_pem))
    for obj in db_certificate_objs:
        if isinstance(obj, AcmeAccount):
            if public_key_pem == vars(obj)["public_key_pem"]:
                return vars(obj)
    return None


def pem_from_jws(jws: Dict[str, Any]) -> str:
    protected = json.loads(from_base64url(jws["protected"]).decode("utf-8"))
    return jwk_key_to_pem(protected["jwk"])


def validate_signature(signer_public_key_data: str, data: str, signature: str) -> None:
    # Load the signers public key
    signer_public_key = serialization.load_pem_public_key(signer_public_key_data.encode("utf-8"))
    if not isinstance(signer_public_key, EllipticCurvePublicKey) and not isinstance(
        signer_public_key, Ed25519PublicKey
    ):
        print("non valid key in jwk22 fixme")
        raise HTTPException(status_code=400, detail="Non valid key in jwk")

    if isinstance(signer_public_key, EllipticCurvePublicKey):
        if signer_public_key.curve.name != "secp256r1":
            print("wrong ec key")
            raise HTTPException(status_code=400, detail="Non valid key in jwk")

        signer_public_key.verify(from_base64url(signature), data.encode("utf-8"), ECDSA(SHA256()))
    else:
        signer_public_key.verify(from_base64url(signature), data.encode("utf-8"))


def validate_kid(kid: str, alg: str, signed_data: str, signature: str) -> None:
    pass


def validate_jwk(jwk: Dict[str, Any], alg: str, signed_data: str, signature: str) -> None:
    if jwk["alg"] not in ["ES256", "EdDSA"]:
        raise HTTPException(status_code=400, detail="Non valid alg in jwk")

    jwk_alg = jwk["alg"]

    if not isinstance(jwk_alg, str) or alg != jwk_alg:
        raise HTTPException(status_code=400, detail="Non valid jwk in jws")

    signer_public_key_data = jwk_key_to_pem(jwk)
    validate_signature(signer_public_key_data, signed_data, signature)


def _validate_jws(input_data: Dict[str, Any], request_url: str) -> None:
    # Fixme error handling
    if "protected" not in input_data or "payload" not in input_data or "signature" not in input_data:
        raise HTTPException(status_code=400, detail="Non valid jws0")

    protected = json.loads(from_base64url(input_data["protected"]).decode("utf-8"))
    payload = json.loads(from_base64url(input_data["payload"]).decode("utf-8"))
    signature = input_data["signature"]
    signed_data = (
        to_base64url(json.dumps(protected).encode("utf-8")) + "." + to_base64url(json.dumps(payload).encode("utf-8"))
    )
    print("protected")
    print(type(protected))
    print(protected)
    print("payload")
    print(type(payload))
    print(payload)

    if not isinstance(protected, dict) or not isinstance(payload, dict) or not isinstance(signature, str):
        raise HTTPException(status_code=400, detail="Non valid jws1")

    alg = protected["alg"]
    nonce = protected["nonce"]
    url = protected["url"]

    if not isinstance(alg, str) or not isinstance(nonce, str) or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Non valid jws2")

    if url != request_url:
        raise HTTPException(status_code=400, detail="Client request url did not match jws url")

    if "jwk" in protected and "kid" in protected:
        raise HTTPException(status_code=400, detail="Non valid jws3")

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
        validate_kid(kid, alg, signed_data, signature)
    else:
        raise HTTPException(status_code=400, detail="Missing either jwk or kid in jws")


def validate_jws(input_data: Dict[str, Any], request_url: str) -> None:
    try:
        _validate_jws(input_data, request_url)
    except InvalidSignature:
        raise HTTPException(status_code=401, detail="Invalid jws signature")
    except (ValueError, IndexError, KeyError):
        raise HTTPException(status_code=400, detail="Non valid jws")
