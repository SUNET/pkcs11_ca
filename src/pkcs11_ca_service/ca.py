"""Module to handle certificate authorities"""
from typing import Dict, Union, List
import hashlib
from secrets import token_bytes

from fastapi.responses import JSONResponse
from fastapi import HTTPException
from python_x509_pkcs11.crl import create as create_crl

from .crl import Crl
from .asn1 import pem_cert_to_name_dict
from .base import DataClassObject, DataBaseObject, InputObject, db_load_data_class
from .asn1 import pem_to_sha256_fingerprint, not_before_not_after_from_cert, cert_pem_serial_number, cert_revoked
from .error import WrongDataType


class CaInput(InputObject):
    """Class to represent ca matching from HTTP post data"""

    name_dict: Union[Dict[str, str], None]
    pem: Union[str, None]
    key_label: Union[str, None]
    key_type: Union[str, None] = None
    issuer_pem: Union[str, None]
    path: Union[str, None] = None
    pkcs11_key: Union[int, None] = None


class Ca(DataClassObject):
    """Class to represent a certificate authority"""

    db: DataBaseObject

    db_table_name = "ca"
    db_fields = {
        "pem": str,
        "csr": int,
        "issuer": int,
        "pkcs11_key": int,
        "authorized_by": int,
        "path": str,
        "fingerprint": str,
        "not_before": str,
        "not_after": str,
        "created": str,
    }
    db_reference_fields = {
        "pkcs11_key": "pkcs11_key(serial)",
        "csr": "csr(serial)",
        "authorized_by": "public_key(serial)",
    }
    db_unique_fields = ["pem", "pkcs11_key", "fingerprint", "path"]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__(kwargs)
        pem = kwargs.get("pem", None)
        if not isinstance(pem, str):
            raise WrongDataType("'pem', must be a 'str'")
        self.pem = pem

        pkcs11_key = kwargs.get("pkcs11_key", None)
        if not isinstance(pkcs11_key, int):
            raise WrongDataType("'pkcs11_key', must be a 'int'")
        self.pkcs11_key = pkcs11_key

        self.fingerprint = pem_to_sha256_fingerprint(self.pem)
        self.not_before, self.not_after = not_before_not_after_from_cert(self.pem)

        self.path = hashlib.sha256(token_bytes(256)).hexdigest()

    async def revoke(self, auth_by: int) -> None:
        """Revoke the certificate authority
        https://github.com/wbond/asn1crypto/blob/b5f03e6f9797c691a3b812a5bb1acade3a1f4eeb/asn1crypto/crl.py#L97

        Parameters:
        auth_by (int): The revoker public key DB id

        Returns:
        str
        """

        issuer = vars(self).get("issuer")
        if issuer is None or issuer < 1:
            raise HTTPException(status_code=400, detail="Cannot revoke a non existing ca.")

        revoke_data = await self.db.revoke_data_for_ca(issuer)
        curr_crl = revoke_data["crl"]
        ca_pem = revoke_data["ca"]
        key_label = revoke_data["key_label"]
        key_type = revoke_data["key_type"]

        crl_pem: str = await create_crl(
            key_label,
            pem_cert_to_name_dict(ca_pem),
            old_crl_pem=curr_crl,
            serial_number=cert_pem_serial_number(self.pem),
            reason=5,
            key_type=key_type,
        )
        crl_obj = Crl(
            {
                "pem": crl_pem,
                "issuer": issuer,
                "authorized_by": auth_by,
            }
        )
        await crl_obj.save()

        print("Revoked CA, serial " + str(self.serial))

    async def is_revoked(self) -> bool:
        """If CA has been revoked

        Returns:
        bool
        """

        issuer = vars(self).get("issuer")
        if issuer is None or issuer < 1:
            raise HTTPException(status_code=400, detail="Cannot revoke a non existing CA.")

        revoke_data = await self.db.revoke_data_for_ca(issuer)
        ca_pem: str = self.pem

        while True:
            ca_issuer = int(revoke_data["ca_issuer"])
            crl_pem = revoke_data["crl"]
            ca_serial = int(revoke_data["ca_serial"])

            if cert_revoked(cert_pem_serial_number(ca_pem), crl_pem):
                return True

            if ca_issuer == ca_serial:
                return False

            ca_pem = revoke_data["ca"]
            revoke_data = await self.db.revoke_data_for_ca(ca_issuer)


async def search(input_object: InputObject) -> JSONResponse:
    """Get cas matching the input_object pattern(s).
    Returns a fastAPI json response with a list of the cas.

    Parameters:
    input_object (InputObject): The search pattern data.

    Returns:
    fastapi.responses.JSONResponse
    """

    ca_objs: List[Ca] = []
    ca_pems: List[str] = []

    db_ca_objs = await db_load_data_class(Ca, input_object)
    for obj in db_ca_objs:
        if isinstance(obj, Ca):
            ca_objs.append(obj)

    for c_a in ca_objs:
        ca_pems.append(c_a.pem)

    return JSONResponse(status_code=200, content={"cas": ca_pems})
