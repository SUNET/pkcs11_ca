from __future__ import annotations
from typing import Union, Dict, List, Type
from abc import ABC, abstractmethod
import datetime

from pydantic import BaseModel
from python_x509_pkcs11.pkcs11_handle import PKCS11Session


class DataBaseObject(ABC):

    pkcs11_session: PKCS11Session

    @classmethod
    @abstractmethod
    async def delete(cls, table_name: str, unique_field: str, data: Union[str, int]) -> None:
        pass

    @classmethod
    @abstractmethod
    async def save(
        cls,
        table_name: str,
        fields: Dict[str, Union[str, int]],
        unique_fields: List[str],
    ) -> int:
        pass

    @classmethod
    @abstractmethod
    async def load(
        cls,
        input_search: Dict[str, Union[str, int]],
        fields: List[str],
        unique_fields: List[str],
        table_name: str,
    ) -> List[Dict[str, Union[str, int]]]:
        pass

    # Creates all tables, create and insert the root ca if not exists and loads trusted admin keys
    @classmethod
    @abstractmethod
    async def init(
        cls,
        tables: List[str],
        fields: List[Dict[str, Union[Type[str], Type[int]]]],
        reference_fields: List[Dict[str, str]],
        unique_fields: List[List[str]],
    ) -> None:
        pass


class InputObject(BaseModel):
    pass


class DataClassObject(ABC):

    db: DataBaseObject

    db_table_name: str
    db_fields: Dict[str, Union[Type[str], Type[int]]]
    db_reference_fields: Dict[str, str]
    db_unique_fields: List[str]

    def __init__(self, kwargs: Dict[str, Union[str, int]]) -> None:
        super().__init__()
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.serial = -1
        self.created = str(datetime.datetime.utcnow())

    def set_references(self, kwargs: Dict[str, int]) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)

    def db_data(self) -> Dict[str, Union[str, int]]:
        data = {}
        class_data = vars(self)
        for key in class_data:
            if key in self.db_fields:
                data[key] = class_data[key]
        return data

    async def save(self) -> int:
        serial = await self.db.save(self.db_table_name, self.db_data(), self.db_unique_fields)
        print("Saved into " + self.db_table_name + ", serial " + str(serial))
        self.serial = serial
        return serial

    async def delete(self) -> None:
        unique_field = self.db_unique_fields[0]
        self.db.delete(self.db_table_name, unique_field, self.db_data()[unique_field])
        print(
            "Deleted from "
            + self.db_table_name
            + ", WHERE "
            + unique_field
            + " = "
            + str(self.db_data()[unique_field])
        )


async def db_load_data_class(
    db_data_class: Type[DataClassObject], input_object: InputObject
) -> List[DataClassObject]:

    input_vars: Dict[str, Union[str, int]] = {}
    for key, value in vars(input_object).items():
        if value is not None:
            input_vars[key] = value

    value_dict_list = await DataClassObject.db.load(
        input_vars,
        ["serial"] + list(db_data_class.db_fields.keys()),
        db_data_class.db_unique_fields,
        db_data_class.db_table_name,
    )

    ret: List[DataClassObject] = []
    for value_dict in value_dict_list:

        class_obj = db_data_class(value_dict)
        for name, value in value_dict.items():
            setattr(class_obj, name, value)
        ret.append(class_obj)
    return ret
