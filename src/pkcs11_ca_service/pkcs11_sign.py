"""Module to handle /pkcs11_sign endpoint"""
import base64
from typing import List, Dict, Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse
import jsonschema
from pkcs11.exceptions import NoSuchKey
from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from openapi_schema_validator import validate as openapi_validate

request_schema = {
    "$id": "https://localhost/request.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Request",
    "type": "object",
    "properties": {
        "meta": {
            "type": "object",
            "properties": {
                "version": {"type": "integer", "minimum": 1},
                "encoding": {"type": "string"},
                "key_label": {"type": "string"},
                "key_type": {"type": "string"},
            },
            "required": ["version", "encoding", "key_label", "key_type"],
        },
        "documents": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "data": {"type": "string"}},
                "required": ["id", "data"],
            },
            "minItems": 1,
        },
    },
    "required": ["meta", "documents"],
}

response_schema = {
    "$id": "https://localhost/response.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Response",
    "type": "object",
    "properties": {
        "meta": {
            "type": "object",
            "properties": {
                "version": {"type": "integer", "minimum": 1},
                "encoding": {"type": "string"},
                "signer_public_key": {"type": "string"},
                "signature_algorithm": {"type": "string"},
            },
            "required": ["version", "encoding", "signer_public_key", "signature_algorithm"],
        },
        "signature_values": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "signature": {"type": "string"}},
                "required": ["id", "signature"],
            },
            "minItems": 1,
        },
    },
    "required": ["meta", "signature_values"],
}


def validate_input(request: dict[str, Any]) -> None:
    """Validate the json input with our schema, raises HTTP error 400 if invalid

    Parameters:
    request (Dict[str, Any]): The input.

    Returns:
    None
    """

    try:
        openapi_validate(request, request_schema)  # type: ignore
    except jsonschema.exceptions.ValidationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid schema try '{request_schema}'") from exc

    key_types = ["secp256r1", "secp384r1", "secp384r1", "ed25519"]
    if request["meta"]["key_type"] not in key_types:
        raise HTTPException(
            status_code=400, detail=f"key_type '{request['meta']['key_type']}' must be one of {key_types}"
        )


async def pkcs11_sign(request: Dict[str, Any]) -> JSONResponse:
    """Sign input data in the request schema format using a key in a pkcs11 device.
    Raises HTTP error if operation or data formats failed/invalid.

    Parameters:
    request (Dict[str, Any]): The input data.

    Returns:
    fastapi.responses.JSONResponse
    """

    result: Dict[str, Any] = {}
    signed_data: List[Dict[str, str]] = []

    # Validate input
    validate_input(request)

    # Get or create pkcs11 key
    try:
        signer_public_key, _ = await PKCS11Session.public_key_data(
            request["meta"]["key_label"], request["meta"]["key_type"]
        )
    except NoSuchKey:
        signer_public_key, _ = await PKCS11Session.create_keypair(
            request["meta"]["key_label"], request["meta"]["key_type"]
        )
        print(f"Created pkcs11 key label:{request['meta']['key_label']} type:{request['meta']['key_type']}")

    # Sign data entries
    for data in request["documents"]:
        signature: bytes = await PKCS11Session.sign(
            key_label=request["meta"]["key_label"],
            data=base64.b64decode(data["data"]),
            verify_signature=False,
            key_type=request["meta"]["key_type"],
        )
        signed_data.append({"id": data["id"], "signature": base64.b64encode(signature).decode("utf-8")})

    # Create response data
    result["meta"] = {}
    result["meta"]["version"] = 1
    result["meta"]["encoding"] = "base64"
    result["meta"]["signer_public_key"] = signer_public_key

    if request["meta"]["key_type"] == "secp256r1":
        result["meta"]["signature_algorithm"] = "sha256_ecdsa"
    elif request["meta"]["key_type"] == "secp384r1":
        result["meta"]["signature_algorithm"] = "sha384_ecdsa"
    elif request["meta"]["key_type"] == "secp521r1":
        result["meta"]["signature_algorithm"] = "sha512_ecdsa"
    else:
        result["meta"]["signature_algorithm"] = "ed25519"

    result["signature_values"] = signed_data

    try:
        openapi_validate(result, response_schema)  # type: ignore
    except jsonschema.exceptions.ValidationError as exc:
        raise HTTPException(status_code=500, detail=f"Error creating valid with schema '{response_schema}'") from exc

    return JSONResponse(status_code=200, content=result)
