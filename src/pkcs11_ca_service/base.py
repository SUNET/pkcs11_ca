"""Base file which contains the abstract base classes"""

from __future__ import annotations
from typing import Union, Dict, List, Type
from abc import ABC, abstractmethod
import datetime

from pydantic import BaseModel
from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from .validate import validate_input_string


class DataBaseObject(ABC):
    """Abstract base class for database classes"""

    pkcs11_session: PKCS11Session

    @classmethod
    @abstractmethod
    async def delete(cls, table_name: str, unique_field: str, data: Union[str, int]) -> None:
        """Delete data object in DB.

        Parameters:
        table_name (str): Name of the DB table.
        unique_field (str): Name of a unique_field.
        data (Union[str, int]): The data in the unique field to delete.

        Returns:
        None
        """

    @classmethod
    @abstractmethod
    async def save(
        cls,
        table_name: str,
        fields: Dict[str, Union[str, int]],
        unique_fields: List[str],
    ) -> int:
        """Save data object in DB. Return the DB ID for the data object.

        Parameters:
        table_name (str): Name of the DB table.
        fields (Dict[str, Union[str, int]]): Data for the fields.
        unique_fields (List[str]): Data for the unique fields.

        Returns:
        int
        """

    @classmethod
    @abstractmethod
    async def update(
        cls,
        table_name: str,
        fields: Dict[str, Union[str, int]],
        unique_fields: List[str],
    ) -> None:
        """Update data object in DB.

        Parameters:
        table_name (str): Name of the DB table.
        fields (Dict[str, Union[str, int]]): Data for the fields.
        unique_fields (List[str]): Data for the unique fields.

        Returns:
        None
        """

    @classmethod
    @abstractmethod
    async def load(
        cls,
        table_name: str,
        input_search: Dict[str, Union[str, int]],
        fields: List[str],
        unique_fields: List[str],
    ) -> List[Dict[str, Union[str, int]]]:
        """Load data objects from DB, returns a list of dict with fields as keys

        Parameters:
        table_name (str): Name of the DB table.
        input_search (Dict[str, Union[str, int]]): Data to_search for.
        fields (List[str]): Fields to retrieve.
        unique_fields (List[str]): Data for the unique fields.

        Returns:
        List[Dict[str, Union[str, int]]]
        """

    @classmethod
    @abstractmethod
    async def revoke_data_for_ca(cls, ca_serial: int) -> Dict[str, str]:
        """Get last CRL for an CA

        Parameters:
        pem (str): The database row serial for the CA

        Returns:
        Dict[str, str]
        """

    @classmethod
    @abstractmethod
    async def startup(
        cls,
        tables: List[str],
        fields: List[Dict[str, Union[Type[str], Type[int]]]],
        reference_fields: List[Dict[str, str]],
        unique_fields: List[List[str]],
    ) -> bool:
        """Startup for the database.
        Creates all tables, create and insert the root ca and healthcheck PKCS11 key,
        if not exists and loads trusted admin keys, return true if DB startup ok

        Parameters:
        tables (List[str]): Table names.
        fields (List[Dict[str, Union[Type[str], Type[int]]]]): Fields and their data type.
        reference_fields (List[Dict[str, str]]): Reference field names and their references.
        unique_fields (List[List[str]]): Unique field names.

        Returns:
        bool
        """


class InputObject(BaseModel):
    """FastAPI input object for HTTP post data"""

    def __init__(self, **data: Union[str, int]) -> None:
        for _, (key, value) in enumerate(data.items()):
            if isinstance(value, str) and isinstance(key, str):
                # Fix pem whitespaces
                if "pem" in key:
                    data[key] = value.strip() + "\n"

                # Validate input data
                # Raises 400 status code if invalid
                validate_input_string(value)

        super().__init__(**data)


class DataClassObject(ABC):
    """Abstract base class for data classes"""

    db: DataBaseObject

    db_table_name: str
    db_fields: Dict[str, Union[Type[str], Type[int]]]
    db_reference_fields: Dict[str, str]
    db_unique_fields: List[str]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__()
        self.serial = -1
        self.authorized_by = -1
        self.created = str(datetime.datetime.utcnow())

        for key, value in kwargs.items():
            setattr(self, key, value)

    def db_data(self) -> Dict[str, Union[str, int]]:
        """Gather only the data vars matching the DB fields.

        Returns:
        Dict[str, Union[str, int]]
        """

        data = {}
        class_data = vars(self)
        for key in class_data:
            if key in self.db_fields:
                data[key] = class_data[key]
        return data

    async def save(self, field_set_to_serial: Union[str, None] = None) -> int:
        """Save data object to its database. Return its serial/ID.

        Parameters:
        field_set_to_serial (Union[str, None] = None): Set a field to its serial/ID field.
        For example if CA is a root CA then set its 'issuer' to its own 'serial' number

        Returns:
        int
        """

        if field_set_to_serial is not None:
            setattr(self, field_set_to_serial, 1)

        serial = await self.db.save(self.db_table_name, self.db_data(), self.db_unique_fields)
        print("Saved into " + self.db_table_name + ", serial " + str(serial))
        self.serial = serial

        if field_set_to_serial is not None:
            setattr(self, field_set_to_serial, serial)
            await self.db.update(self.db_table_name, self.db_data(), self.db_unique_fields)
        return serial

    async def delete(self) -> None:
        """Delete data object from its database.

        Returns:
        None
        """

        unique_field = self.db_unique_fields[0]
        await self.db.delete(self.db_table_name, unique_field, self.db_data()[unique_field])
        print(
            "Deleted from " + self.db_table_name + ", WHERE " + unique_field + " = " + str(self.db_data()[unique_field])
        )


async def db_load_data_class(db_data_class: Type[DataClassObject], input_object: InputObject) -> List[DataClassObject]:
    """Load data objects from search data from its data fields in DB.

    Parameters:
    db_data_class (Type[DataClassObject]): Which class the object will be.
    input_object (InputObject): Object with search data.

    Returns:
    int
    """

    input_vars: Dict[str, Union[str, int]] = {}

    for key, value in vars(input_object).items():
        if value is not None and (key in db_data_class.db_fields.keys() or key == "serial"):
            input_vars[key] = value

    value_dict_list = await DataClassObject.db.load(
        db_data_class.db_table_name,
        input_vars,
        ["serial"] + list(db_data_class.db_fields.keys()),
        db_data_class.db_unique_fields,
    )

    ret: List[DataClassObject] = []
    for value_dict in value_dict_list:

        class_obj = db_data_class(value_dict)
        for name, value in value_dict.items():
            setattr(class_obj, name, value)
        ret.append(class_obj)
    return ret
