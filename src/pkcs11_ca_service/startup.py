from typing import Dict, List, Union, Type
from importlib import import_module

from python_x509_pkcs11.pkcs11_handle import PKCS11Session

# from .base import DataClassObject, DataBaseObject, db_data_classes, db_classes
from .base import DataClassObject, DataBaseObject  # db_data_classes, db_classes
from .config import DB_TABLE_MODULES, DB_MODULE, ROOT_CA_KEY_LABEL


def load_db_data_modules() -> List[DataClassObject]:
    db_data_classes: List[DataClassObject] = []

    for module_name in DB_TABLE_MODULES:
        try:
            db_data_module = import_module("." + module_name, "src.pkcs11_ca_service")
        except ModuleNotFoundError:
            db_data_module = import_module("." + module_name, "pkcs11_ca_service")

        class_name = module_name[0].upper() + module_name[1:]
        if "_" in class_name:
            index = class_name.index("_")
            class_name = (
                class_name[:index] + class_name[index + 1].upper() + class_name[index + 2 :]
            )
        db_data_classes.append(getattr(db_data_module, class_name))
    return db_data_classes


def load_db_module() -> DataBaseObject:
    try:
        module = import_module("." + DB_MODULE, "src.pkcs11_ca_service")
    except ModuleNotFoundError:
        module = import_module("." + DB_MODULE, "pkcs11_ca_service")
    class_name = DB_MODULE[0].upper() + DB_MODULE[1:].replace("_db", "DB")

    # Instance the DB class to ensure abstractmethods are implemented
    db_obj: DataBaseObject = object.__new__(getattr(module, class_name))

    # Set pkcs11 session
    db_obj.pkcs11_session = PKCS11Session()

    # Set db object
    DataClassObject.db = db_obj
    return db_obj


async def db_init(db_obj: DataBaseObject, db_data_classes: List[DataClassObject]) -> None:
    tables: List[str] = []
    fields: List[Dict[str, Union[Type[str], Type[int]]]] = []
    reference_fields: List[Dict[str, str]] = []
    unique_fields: List[List[str]] = []

    for db_data_class in db_data_classes:
        tables.append(db_data_class.db_table_name)
        fields.append(db_data_class.db_fields)
        reference_fields.append(db_data_class.db_reference_fields)
        unique_fields.append(db_data_class.db_unique_fields)

    await db_obj.init(tables, fields, reference_fields, unique_fields)


async def pkcs11_init(db_obj: DataBaseObject) -> None:
    _, _ = await db_obj.pkcs11_session.public_key_data(ROOT_CA_KEY_LABEL)
    print("PKCS11 Session OK")


async def startup() -> None:
    db_obj = load_db_module()
    db_data_classes = load_db_data_modules()

    await db_init(db_obj, db_data_classes)
    await pkcs11_init(db_obj)
