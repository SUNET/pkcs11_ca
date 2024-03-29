"""Module which handle nonces"""
import hashlib
from secrets import token_bytes
from typing import List

from fastapi import Response

from .asn1 import from_base64url, to_base64url

# https://docs.python.org/3/library/secrets.html
# https://datatracker.ietf.org/doc/html/rfc8555#section-6.5.1


# FIXME store in DB and clear DB nonces on application startup

nonces: List[str] = []


def _generate_nonce() -> str:
    """Generate a nonce, will be base64url encoded.

    Returns:
    str
    """

    return to_base64url(token_bytes(64).strip(b"="))


def hash_nonce(nonce_base64url: str) -> str:
    """Hash a nonce, we store nonces hashed by sha256 for the same reason as hashing passwords.

    Parameters:
    nonce_base64url (str): base64url encoded nonce to be hashed.

    Returns:
    str
    """

    nonce_decoded = from_base64url(nonce_base64url)
    return hashlib.sha256(nonce_decoded).hexdigest()


async def verify_nonce(nonce: str) -> bool:
    """Verify a nonce, if verified then delete it from the list of nonces.

    Parameters:
    nonce (str): base64url encoded nonce to be verified.

    Returns:
    bool
    """

    hashed_nonce = hash_nonce(nonce)
    if hashed_nonce in nonces:
        nonces.remove(hashed_nonce)
        return True
    return False


def generate_nonce() -> str:
    """Generate, store and returns a nonce

    Returns:
    str
    """

    new_nonce = _generate_nonce()
    nonces.append(hash_nonce(new_nonce))
    return new_nonce


def nonce_response(status_code: int = 200) -> Response:
    """Create HTTP response containing a new nonce.

    Returns:
    fastapi.Response
    """

    new_nonce = generate_nonce()

    response = Response()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Replay-Nonce"] = new_nonce
    response.status_code = status_code
    return response
