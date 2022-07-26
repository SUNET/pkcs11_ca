"""
Module which handlas database actions
"""

from __future__ import annotations
from typing import Dict, Union, List, Tuple, Type
import datetime
import os

from asyncpg import create_pool
from asyncpg.pool import Pool

from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from python_x509_pkcs11.root_ca import create as create_root_ca

from .config import (
    ROOT_CA_NAME_DICT,
    ROOT_CA_KEY_LABEL,
    ROOT_CA_EXPIRE,
    ROOT_CA_KEY_SIZE,
    ROOT_ADMIN_KEYS_FOLDER,
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_PORT,
    DB_DATABASE,
    DB_TIMEOUT,
)
from .error import WrongDataType
from .asn1 import (
    pem_to_sha1_fingerprint,
    pem_to_sha256_fingerprint,
    public_key_info_to_pem,
)
from .base import DataBaseObject


class PostgresDB(DataBaseObject):

    pool: Pool

    @classmethod
    async def delete(
        cls, table_name: str, unique_field: str, data: Union[str, int]
    ) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():
                query = "DELETE FROM " + table_name + " WHERE " + unique_field + " = $1"
                await conn.execute(
                    query,
                    data,
                )

    @classmethod
    async def save(
        cls,
        fields: Dict[str, Union[str, int]],
        table_name: str,
        unique_fields: List[str],
    ) -> int:
        serial: int
        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                query = (
                    "SELECT serial from "
                    + table_name
                    + " WHERE "
                    + unique_fields[0]
                    + " = $1"
                )
                rows = await conn.fetch(query, fields[unique_fields[0]])
                if rows:
                    serial = rows[0][0]
                    if not isinstance(serial, int):
                        raise WrongDataType("Currently only supports 'int' as serial")
                    return serial

                args = ()
                query = "INSERT INTO " + table_name + "("
                for key in fields:
                    query += key + ","
                query = query[:-1] + ") VALUES ("

                for index, key in enumerate(fields):
                    query += "$" + str(index + 1) + ","
                    args = args + (fields[key],)  # type: ignore
                query = query[:-1] + ") RETURNING serial"
                rows = await conn.fetch(query, *args)
                serial = rows[0][0]

        return serial

    @classmethod
    def _rows_to_class_objects(
        cls, rows: List[Tuple[str, int]], fields: List[str]
    ) -> List[Dict[str, Union[str, int]]]:

        ret: List[Dict[str, Union[str, int]]] = []
        for row in rows:
            value_dict: Dict[str, Union[str, int]] = {}
            for index, field in enumerate(fields):
                value_dict[field] = row[index]
            ret.append(value_dict)
        return ret

    @classmethod
    async def load(
        cls,
        input_search: Dict[str, Union[str, int]],
        fields: List[str],
        unique_fields: List[str],
        table_name: str,
    ) -> List[Dict[str, Union[str, int]]]:

        search: Dict[str, Union[str, int]] = {}
        for key in input_search:
            if key in unique_fields:
                search[key] = input_search[key]
                break
        if not search:
            search = input_search

        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                fields_list: List[Dict[str, Union[str, int]]] = []
                for key in search:
                    query = "SELECT "
                    for field in fields:
                        query += field + ","
                    query = (
                        query[:-1] + " FROM " + table_name + " WHERE " + key + " = $1"
                    )
                    rows = await conn.fetch(query, search[key])
                    fields_list += cls._rows_to_class_objects(rows, fields)
        return fields_list

    @classmethod
    async def _drop_all_tables(cls, tables: List[str]) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():
                for table in reversed(tables):
                    query = "DROP TABLE IF EXISTS " + table
                    await conn.execute(query)
                    print(query)

    @classmethod
    async def _init_table(
        cls,
        table: str,
        fields: Dict[str, Union[Type[str], Type[int]]],
        reference_fields: Dict[str, str],
        unique_fields: List[str],
    ) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                query = (
                    "CREATE TABLE IF NOT EXISTS "
                    + table
                    + " (serial BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                )

                for field in fields:
                    query += " " + field + " "

                    if fields[field] == int:
                        query += "BIGINT "
                    elif fields[field] == str:
                        query += "TEXT "
                    else:
                        raise WrongDataType(
                            "Currently only supports 'int' and 'str' database field types"
                        )

                    if field in unique_fields:
                        query += "UNIQUE "

                    query += "NOT NULL "

                    if field in reference_fields:
                        query += " REFERENCES " + reference_fields[field]
                    query += ","
                query = query[:-1] + ")"
                await conn.execute(query)
                print(query)

    @classmethod
    async def _load_trusted_keys(cls, classes_info: Dict[str, List[str]]) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                for key_file in os.listdir(ROOT_ADMIN_KEYS_FOLDER):
                    if not key_file.endswith(".pem"):
                        continue

                    with open(
                        ROOT_ADMIN_KEYS_FOLDER + "/" + key_file, "rb"
                    ) as file_data:
                        key_pem = file_data.read().decode("utf-8")
                    print(
                        "Saved admin key "
                        + ROOT_ADMIN_KEYS_FOLDER
                        + "/"
                        + key_file
                        + " into DB"
                    )

                    query = cls._insert_root_item_query(
                        classes_info["public_key"], "public_key"
                    )
                    await conn.execute(
                        query,
                        *(
                            key_pem,
                            key_file,
                            1,
                            1,
                            pem_to_sha1_fingerprint(key_pem),
                            str(datetime.datetime.utcnow()),
                        ),
                    )

    @classmethod
    async def init(
        cls,
        tables: List[str],
        fields: List[Dict[str, Union[Type[str], Type[int]]]],
        reference_fields: List[Dict[str, str]],
        unique_fields: List[List[str]],
    ) -> None:

        pool = await create_pool(
            dsn="postgres://"
            + DB_USER
            + ":"
            + DB_PASSWORD
            + "@"
            + DB_HOST
            + ":"
            + DB_PORT
            + "/"
            + DB_DATABASE,
            min_size=5,
            max_size=50,
            command_timeout=DB_TIMEOUT,
        )
        cls.pool = pool

        classes_info: Dict[str, List[str]] = {}
        await cls._check_db()

        # Remove me, just here for easy testing
        await cls._drop_all_tables(tables)

        for index, table in enumerate(tables):
            await cls._init_table(
                table, fields[index], reference_fields[index], unique_fields[index]
            )
            classes_info[table] = list(fields[index].keys())

        if not await cls._has_root_ca():
            await cls._insert_root_ca(classes_info)

        await cls._load_trusted_keys(classes_info)

    # Rewrite this code so its future proof
    @classmethod
    async def _check_db(cls) -> None:
        async with cls.pool.acquire() as conn:
            query = "SELECT serial FROM ca WHERE serial = issuer"
            rows = await conn.fetch(query)

    # Rewrite this code so its future proof
    @classmethod
    async def _has_root_ca(cls) -> bool:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():
                query = "SELECT serial FROM ca WHERE serial = issuer"
                rows = await conn.fetch(query)
                if rows:
                    return True
        return False

    @classmethod
    def _insert_root_item_query(cls, fields: List[str], table_name: str) -> str:
        query = "INSERT INTO " + table_name + " ("
        for attr in fields:
            query += attr + ","
        query = query[:-1] + ") VALUES ("

        for index, attr in enumerate(fields):
            query += "$" + str(index + 1) + ","
        query = query[:-1] + ")"
        return query

    @classmethod
    async def _insert_root_ca(cls, classes_info: Dict[str, List[str]]) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                not_before = datetime.datetime.now(
                    datetime.timezone.utc
                ) - datetime.timedelta(minutes=2)
                not_after = not_before + datetime.timedelta(ROOT_CA_EXPIRE)

                root_ca_csr_pem, root_ca_pem = await create_root_ca(
                    ROOT_CA_KEY_LABEL,
                    ROOT_CA_NAME_DICT,
                    ROOT_CA_KEY_SIZE,
                    not_before=not_before,
                    not_after=not_after,
                )
                public_key_info, identifier = await PKCS11Session.public_key_data(
                    ROOT_CA_KEY_LABEL
                )
                public_key_pem = public_key_info_to_pem(public_key_info)

                # Insert into 'public_key' table
                query = cls._insert_root_item_query(
                    classes_info["public_key"], "public_key"
                )
                await conn.execute(
                    query,
                    *(
                        public_key_pem,
                        "root_ca",
                        1,
                        1,
                        identifier.hex(),
                        str(datetime.datetime.utcnow()),
                    ),
                )

            # Insert into 'csr' table
            query = cls._insert_root_item_query(classes_info["csr"], "csr")
            await conn.execute(
                query,
                *(1, root_ca_csr_pem, 1, str(datetime.datetime.utcnow())),
            )

            # Insert into 'ca' table
            query = cls._insert_root_item_query(classes_info["ca"], "ca")
            await conn.execute(
                query,
                *(
                    1,
                    ROOT_CA_KEY_LABEL,
                    root_ca_pem,
                    1,
                    1,
                    1,
                    pem_to_sha256_fingerprint(root_ca_pem),
                    str(not_before),
                    str(not_after),
                    str(datetime.datetime.utcnow()),
                ),
            )
