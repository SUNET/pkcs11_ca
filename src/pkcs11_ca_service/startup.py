"""Startup module"""
import os
import subprocess
import sys
from importlib import import_module
from typing import Dict, List, Type, Union

from pkcs11.exceptions import NoSuchKey
from python_x509_pkcs11.pkcs11_handle import PKCS11Session

from .base import DataBaseObject, DataClassObject
from .ca import CaInput
from .config import (
    ACME_SIGNER_KEY_LABEL,
    CMC_CERT_ISSUING_KEY_LABEL,
    CMC_ROOT_KEY_LABEL,
    CMC_SIGNING_KEY_LABEL,
    DB_MODULE,
    DB_TABLE_MODULES,
    PKCS11_BACKEND,
    ROOT_CA_KEY_LABEL,
    ROOT_CA_KEY_TYPE,
    TIMESTAMP_CERT_KEY_LABEL,
    TIMESTAMP_ROOT_KEY_LABEL,
    TIMESTAMP_SIGNING_KEY_LABEL,
)
from .pkcs11_key import Pkcs11KeyInput
from .route_functions import ca_request, pkcs11_key_request


def _load_db_data_classes() -> List[DataClassObject]:
    db_data_classes: List[DataClassObject] = []

    for module_name in DB_TABLE_MODULES:
        try:
            db_data_module = import_module("." + module_name, "src.pkcs11_ca_service")
        except ModuleNotFoundError:
            db_data_module = import_module("." + module_name, "pkcs11_ca_service")

        class_name = module_name[0].upper() + module_name[1:]
        if "_" in class_name:
            index = class_name.index("_")
            class_name = class_name[:index] + class_name[index + 1].upper() + class_name[index + 2 :]
        db_data_classes.append(getattr(db_data_module, class_name))
    return db_data_classes


def _load_db_module() -> DataBaseObject:
    try:
        module = import_module("." + DB_MODULE, "src.pkcs11_ca_service")
    except ModuleNotFoundError:
        module = import_module("." + DB_MODULE, "pkcs11_ca_service")
    class_name = DB_MODULE[0].upper() + DB_MODULE[1:].replace("_db", "DB")

    # Instance the DB class to ensure abstract methods are implemented
    db_obj = object.__new__(getattr(module, class_name))
    if not isinstance(db_obj, DataBaseObject):
        print(f"Error loading {class_name}")
        sys.exit(1)

    # Set pkcs11 session
    db_obj.pkcs11_session = PKCS11Session()

    # Set db object
    DataClassObject.db = db_obj
    return db_obj


async def _db_startup(db_obj: DataBaseObject, db_data_classes: List[DataClassObject]) -> bool:
    tables: List[str] = []
    fields: List[Dict[str, Union[Type[str], Type[int]]]] = []
    reference_fields: List[Dict[str, str]] = []
    unique_fields: List[List[str]] = []

    # Allow DB to startup
    for db_data_class in db_data_classes:
        tables.append(db_data_class.db_table_name)
        fields.append(db_data_class.db_fields)
        reference_fields.append(db_data_class.db_reference_fields)
        unique_fields.append(db_data_class.db_unique_fields)

    return await db_obj.startup(tables, fields, reference_fields, unique_fields)


async def _pkcs11_check() -> bool:
    # Ensure pkcs11 env variables
    if "PKCS11_MODULE" not in os.environ or "PKCS11_TOKEN" not in os.environ or "PKCS11_PIN" not in os.environ:
        print("PKCS11_MODULE, PKCS11_TOKEN or PKCS11_PIN env variables is not set")
        sys.exit(1)

    # If SOFTHSM then create token if not exists
    if PKCS11_BACKEND == "SOFTHSM":
        if not os.path.isdir("/var/lib/softhsm/tokens") or not os.listdir("/var/lib/softhsm/tokens"):
            subprocess.check_call(
                [
                    "softhsm2-util",
                    "--init-token",
                    "--slot",
                    "0",
                    "--label",
                    os.environ["PKCS11_TOKEN"],
                    "--pin",
                    os.environ["PKCS11_PIN"],
                    "--so-pin",
                    os.environ["PKCS11_PIN"],
                ]
            )

    print("PKCS11 check OK", flush=True)
    return True


async def _pkcs11_startup(db_obj: DataBaseObject) -> bool:
    try:
        _, _ = await db_obj.pkcs11_session.public_key_data(ROOT_CA_KEY_LABEL, key_type=ROOT_CA_KEY_TYPE)
    except NoSuchKey:
        print(f"Could not find pkcs11 key {ROOT_CA_KEY_LABEL} for root ca", flush=True)
        print("You should probably empty and reset the DB since we lost the root ca key", flush=True)
        return False

    print("PKCS11 startup OK", flush=True)
    return True


async def write_root_certs_to_disk() -> None:
    """Write global root cers to file for easy access"""

    for cert in [
        ACME_SIGNER_KEY_LABEL,
        CMC_ROOT_KEY_LABEL,
        CMC_SIGNING_KEY_LABEL,
        CMC_CERT_ISSUING_KEY_LABEL,
        TIMESTAMP_ROOT_KEY_LABEL,
        TIMESTAMP_SIGNING_KEY_LABEL,
        TIMESTAMP_CERT_KEY_LABEL,
    ]:
        cert_pkcs11_key = await pkcs11_key_request(Pkcs11KeyInput(key_label=cert))
        cert_obj = await ca_request(CaInput(pkcs11_key=cert_pkcs11_key.serial))

        if os.path.isfile(f"/etc/pkcs11_ca/ca_root_certs/{cert}.crt"):
            with open(f"/etc/pkcs11_ca/ca_root_certs/{cert}.crt", encoding="utf-8") as cert_file:
                cert_data = cert_file.read()
            if cert_data.strip() != cert_obj.pem.strip():
                print(f"ERROR: Cert for pkcs11 key {cert} is not the same as /etc/pkcs11_ca/ca_root_certs/{cert}.crt")
                sys.exit(1)

            continue

        with open(f"/etc/pkcs11_ca/ca_root_certs/{cert}.crt", "w", encoding="utf-8") as cert_file:
            cert_file.write(cert_obj.pem + "\n")


async def startup() -> None:
    """Startup main function

    Returns:
    None
    """

    # Check pkcs11
    if not await _pkcs11_check():
        sys.exit(1)

    db_obj = _load_db_module()
    db_data_classes = _load_db_data_classes()

    # Check DB
    if not await _db_startup(db_obj, db_data_classes):
        sys.exit(1)

    # Check pkcs11 with database
    if not await _pkcs11_startup(db_obj):
        sys.exit(1)

    await write_root_certs_to_disk()
