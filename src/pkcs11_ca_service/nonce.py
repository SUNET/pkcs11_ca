from typing import List
from secrets import token_bytes
import hashlib

from .asn1 import to_base64url, from_base64url

# https://docs.python.org/3/library/secrets.html
# https://datatracker.ietf.org/doc/html/rfc8555#section-6.5.1

# We store nonces hashed by sha256 for the same reason as hashing passwords

nonces: List[str] = []


def generate_nonce() -> str:
    return to_base64url(token_bytes(64).strip(b"="))


def hash_nonce(nonce_base64url: str) -> str:
    nonce_decoded = from_base64url(nonce_base64url)
    return hashlib.sha256(nonce_decoded).hexdigest()


async def verify_nonce(nonce: str) -> bool:
    hashed_nonce = hash_nonce(nonce)
    if hashed_nonce not in nonces:
        return False
    nonces.remove(hashed_nonce)
    return True
