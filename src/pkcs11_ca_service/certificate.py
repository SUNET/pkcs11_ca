"""Module to handle certificates"""
from typing import Union, Dict, List
from fastapi.responses import JSONResponse
from .base import DataClassObject, InputObject, db_load_data_class
from .asn1 import pem_to_sha256_fingerprint, not_before_not_after_from_cert

from .error import WrongDataType


class CertificateInput(InputObject):
    """Class to represent certificate matching from HTTP post data """

    pem: Union[str, None]
    fingerprint: Union[str, None]


class Certificate(DataClassObject):
    """Class to represent a certificate"""

    db_table_name = "certificate"
    db_fields = {
        "public_key": int,
        "pem": str,
        "csr": int,
        "issuer": int,  # pylint:disable=duplicate-code
        "authorized_by": int,
        "fingerprint": str,
        "not_before": str,  # pylint:disable=duplicate-code
        "not_after": str,
        "created": str,
    }
    db_reference_fields = {
        "public_key": "public_key(serial)",
        "csr": "csr(serial)",
        "issuer": "ca(serial)",
        "authorized_by": "public_key(serial)",
    }
    db_unique_fields = ["pem", "fingerprint"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)
        if not isinstance(pem, str):  # pylint:disable=duplicate-code
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem

        self.fingerprint = pem_to_sha256_fingerprint(self.pem)
        self.not_before, self.not_after = not_before_not_after_from_cert(self.pem)


async def search(input_object: InputObject) -> JSONResponse:
    """Get certificates matching the input_object pattern(s).
    Returns a fastAPI json response with a list of the certificates.

    Parameters:
    input_object (InputObject): The search pattern data.

    Returns:
    fastapi.responses.JSONResponse
    """

    certificate_objs: List[Certificate] = []
    certificate_pems: List[str] = []

    db_certificate_objs = await db_load_data_class(Certificate, input_object)
    for obj in db_certificate_objs:
        if isinstance(obj, Certificate):
            certificate_objs.append(obj)

    for certificate in certificate_objs:
        certificate_pems.append(certificate.pem)

    return JSONResponse(status_code=200, content={"certificates": certificate_pems})
