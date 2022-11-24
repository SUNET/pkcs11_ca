"""
Module which handles database queries
"""

from __future__ import annotations
from typing import Dict, Union, List, Tuple, Type
import datetime
import hashlib
from secrets import token_bytes
import os
from time import sleep

from asyncpg.exceptions import UndefinedTableError
from asyncpg import create_pool
from asyncpg.pool import Pool
from python_x509_pkcs11.pkcs11_handle import PKCS11Session
from python_x509_pkcs11.ca import create as create_ca
from python_x509_pkcs11.crl import create as create_crl
from pkcs11.exceptions import MultipleObjectsReturned

from .asn1 import this_update_next_update_from_crl

# asyncpg is safe from sql injections when using parameterized queries
# https://github.com/MagicStack/asyncpg/issues/822

from .config import (
    HEALTHCHECK_KEY_LABEL,
    HEALTHCHECK_KEY_TYPE,
    ROOT_CA_NAME_DICT,
    ROOT_CA_KEY_LABEL,
    ROOT_CA_KEY_TYPE,
    ROOT_CA_EXPIRE,
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
    public_key_pem_to_sha1_fingerprint,
    pem_to_sha256_fingerprint,
)
from .base import DataBaseObject


class PostgresDB(DataBaseObject):
    """Class to use with Postgres DB"""

    pool: Pool

    @classmethod
    async def delete(cls, table_name: str, unique_field: str, data: Union[str, int]) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():
                query = "DELETE FROM " + table_name + " WHERE " + unique_field + " = $1"
                await conn.execute(query, data)

    @classmethod
    async def update(
        cls,
        table_name: str,
        fields: Dict[str, Union[str, int]],
        unique_fields: List[str],
    ) -> None:

        if not fields:
            raise WrongDataType("Cant update DB row, 'fields' dict was empty")

        async with cls.pool.acquire() as conn:
            async with conn.transaction():
                args = ()
                query = "UPDATE " + table_name + " SET "
                for index, key in enumerate(fields):
                    query += key + " = $" + str(index + 1) + ","
                    args = args + (fields[key],)  # type: ignore
                query = query[:-1] + " WHERE " + unique_fields[0] + " = $" + str(len(fields) + 1)
                args = args + (fields[unique_fields[0]],)  # type: ignore
                await conn.fetch(query, *args)

    @classmethod
    async def save(
        cls,
        table_name: str,
        fields: Dict[str, Union[str, int]],
        unique_fields: List[str],
    ) -> int:
        serial: int
        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                query = "SELECT serial from " + table_name + " WHERE " + unique_fields[0] + " = $1"
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
    def _rows_to_class_objects(cls, rows: List[Tuple[str, int]], fields: List[str]) -> List[Dict[str, Union[str, int]]]:

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
        table_name: str,
        input_search: Dict[str, Union[str, int]],
        fields: List[str],
        unique_fields: List[str],
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

                # If search argument exists
                if input_search:
                    for key in search:
                        query = "SELECT "
                        for field in fields:
                            query += field + ","
                        query = query[:-1] + " FROM " + table_name + " WHERE " + key + " = $1"
                        rows = await conn.fetch(query, search[key])
                        fields_list += cls._rows_to_class_objects(rows, fields)

                # If no search argument exists
                else:
                    query = "SELECT "
                    for field in fields:
                        query += field + ","
                    query = query[:-1] + " FROM " + table_name + " ORDER BY serial DESC LIMIT 10"
                    rows = await conn.fetch(query)
                    fields_list += cls._rows_to_class_objects(rows, fields)

        return fields_list

    @classmethod
    async def _drop_all_tables(cls, tables: List[str]) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():
                for table in reversed(tables):
                    query = "DROP TABLE IF EXISTS " + table + " CASCADE"
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
                    "CREATE TABLE IF NOT EXISTS " + table + " (serial BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                )

                for field in fields:
                    query += " " + field + " "

                    if fields[field] == int:
                        query += "BIGINT "
                    elif fields[field] == str:
                        query += "TEXT "
                    else:
                        raise WrongDataType("Currently only supports 'int' and 'str' database field types")

                    if field in unique_fields:
                        if not (fields[field] == str and field == "pem"):
                            query += "UNIQUE "

                    query += "NOT NULL "

                    if field in reference_fields:
                        query += " REFERENCES " + reference_fields[field]
                    query += ","
                query = query[:-1] + ")"
                await conn.execute(query)

                # Set 'pem' fields index to index its md5 hash instead of its value
                # This prevents weird index bug with large strings which PEM fields can be
                for field in fields:
                    if field in unique_fields and fields[field] == str and field == "pem":
                        query = (
                            "CREATE UNIQUE INDEX " + table + "_" + field + "_key ON " + table + "(md5(" + field + "))"
                        )
                        await conn.execute(query)

    @classmethod
    async def _load_trusted_keys(cls, classes_info: Dict[str, List[str]]) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                for key_file in os.listdir(ROOT_ADMIN_KEYS_FOLDER):
                    if not (key_file.endswith(".pem") or key_file.endswith(".pub")):
                        continue

                    with open(ROOT_ADMIN_KEYS_FOLDER + "/" + key_file, encoding="utf-8") as file_data:
                        key_pem = file_data.read()
                    key_pem = key_pem.strip() + "\n"  # Fix whitespaces for pem key

                    # If exist the skip
                    query = "SELECT pem FROM public_key WHERE pem = $1"
                    rows = await conn.fetch(query, key_pem)
                    if rows:
                        print(f"Key {ROOT_ADMIN_KEYS_FOLDER}/{key_file} already exist in DB, skipping")
                        continue

                    query = cls._insert_root_item_query(classes_info["public_key"], "public_key")
                    await conn.execute(
                        query,
                        *(
                            key_pem,
                            key_file,
                            1,
                            1,
                            public_key_pem_to_sha1_fingerprint(key_pem),
                            str(datetime.datetime.utcnow()),
                        ),
                    )
                    print("Saved admin key " + ROOT_ADMIN_KEYS_FOLDER + "/" + key_file + " into DB")

    @classmethod
    async def revoke_data_for_ca(cls, ca_serial: int) -> Dict[str, str]:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():

                query = (
                    "SELECT crl.pem, ca.pem, ca.issuer, ca.serial FROM crl INNER JOIN ca ON crl.issuer = ca.serial "
                    + "WHERE ca.serial = $1 ORDER BY crl.serial DESC LIMIT 1"
                )
                rows = await conn.fetch(query, ca_serial)
                crl: str = rows[0][0]
                cert_auth: str = rows[0][1]
                cert_auth_issuer: str = str(rows[0][2])
                cert_serial: str = str(rows[0][3])

                query = (
                    "SELECT pkcs11_key.key_label,pkcs11_key.key_type from pkcs11_key INNER JOIN ca "
                    + "ON ca.pkcs11_key = pkcs11_key.serial WHERE ca.serial = $1"
                )
                rows = await conn.fetch(query, ca_serial)
                key_label: str = rows[0][0]
                key_type: str = rows[0][1]

                ret: Dict[str, str] = {
                    "crl": crl,
                    "ca": cert_auth,
                    "ca_issuer": cert_auth_issuer,
                    "ca_serial": cert_serial,
                    "key_label": key_label,
                    "key_type": key_type,
                }

                return ret

    @classmethod
    async def startup(
        cls,
        tables: List[str],
        fields: List[Dict[str, Union[Type[str], Type[int]]]],
        reference_fields: List[Dict[str, str]],
        unique_fields: List[List[str]],
    ) -> bool:

        for _ in range(5):
            try:
                sleep(1)
                cls.pool = await create_pool(
                    dsn="postgres://" + DB_USER + ":" + DB_PASSWORD + "@" + DB_HOST + ":" + DB_PORT + "/" + DB_DATABASE,
                    min_size=5,
                    max_size=50,
                    command_timeout=DB_TIMEOUT,
                )
                break
            except:  # pylint: disable=bare-except
                print("Failed to connect to DB, please fix", flush=True)
                print(
                    "postgres://"
                    + DB_USER
                    + ":"
                    + "password_redacted"
                    + "@"
                    + DB_HOST
                    + ":"
                    + DB_PORT
                    + "/"
                    + DB_DATABASE,
                    flush=True,
                )
        else:
            return False

        classes_info: Dict[str, List[str]] = {}
        for index, table in enumerate(tables):
            classes_info[table] = list(fields[index].keys())

        # Remove me, just here for easy testing
        # await cls._drop_all_tables(tables)

        # Create the tables and root ca and healthcheck key
        if not await cls._check_db():
            for index, table in enumerate(tables):
                await cls._init_table(table, fields[index], reference_fields[index], unique_fields[index])
            await cls._insert_root_ca(classes_info)
            await cls._insert_healthcheck_key(classes_info)

        # Load trusted keys
        await cls._load_trusted_keys(classes_info)

        print("DB startup OK")
        return True

    # Rewrite this code so its future-proof
    @classmethod
    async def _check_db(cls) -> bool:
        async with cls.pool.acquire() as conn:
            try:
                query = "SELECT serial FROM ca ORDER BY serial DESC LIMIT 1"
                rows = await conn.fetch(query)
                if rows:
                    return True
                return False

            except UndefinedTableError:
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
                not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
                not_after = not_before + datetime.timedelta(ROOT_CA_EXPIRE)

                root_ca_csr_pem, root_ca_pem = await create_ca(
                    ROOT_CA_KEY_LABEL,
                    ROOT_CA_NAME_DICT,
                    not_before=not_before,
                    not_after=not_after,
                    key_type=ROOT_CA_KEY_TYPE,
                )

                public_key_pem, identifier = await PKCS11Session.public_key_data(
                    ROOT_CA_KEY_LABEL, key_type=ROOT_CA_KEY_TYPE
                )

                # Insert into 'public_key' table
                query = cls._insert_root_item_query(classes_info["public_key"], "public_key")
                await conn.execute(
                    query,
                    public_key_pem,
                    "root_ca",
                    1,
                    1,
                    identifier.hex(),
                    str(datetime.datetime.utcnow()),
                )

                # Insert into 'pkcs11_key' table
                query = cls._insert_root_item_query(classes_info["pkcs11_key"], "pkcs11_key")
                await conn.execute(
                    query,
                    1,
                    ROOT_CA_KEY_LABEL,
                    ROOT_CA_KEY_TYPE,
                    1,
                    str(datetime.datetime.utcnow()),
                )

                # Insert into 'csr' table
                query = cls._insert_root_item_query(classes_info["csr"], "csr")
                await conn.execute(query, 1, root_ca_csr_pem, 1, str(datetime.datetime.utcnow()))

                # Insert into 'ca' table
                query = cls._insert_root_item_query(classes_info["ca"], "ca")
                await conn.execute(
                    query,
                    root_ca_pem,
                    1,
                    1,
                    1,
                    1,
                    hashlib.sha256(token_bytes(256)).hexdigest(),
                    pem_to_sha256_fingerprint(root_ca_pem),
                    str(not_before),
                    str(not_after),
                    str(datetime.datetime.utcnow()),
                )

                # Create CRL for root CA
                crl_pem = await create_crl(ROOT_CA_KEY_LABEL, ROOT_CA_NAME_DICT, key_type=ROOT_CA_KEY_TYPE)
                this_update, next_update = this_update_next_update_from_crl(crl_pem)
                query = cls._insert_root_item_query(classes_info["crl"], "crl")
                await conn.execute(
                    query,
                    crl_pem,
                    1,
                    1,
                    this_update,
                    next_update,
                    str(datetime.datetime.utcnow()),
                )
                print("Created first ever root CA", flush=True)

    @classmethod
    async def _insert_healthcheck_key(cls, classes_info: Dict[str, List[str]]) -> None:
        async with cls.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    public_key_pem, identifier = await PKCS11Session.create_keypair(
                        HEALTHCHECK_KEY_LABEL, key_type=HEALTHCHECK_KEY_TYPE
                    )
                except MultipleObjectsReturned:
                    public_key_pem, identifier = await PKCS11Session.public_key_data(
                        HEALTHCHECK_KEY_LABEL, key_type=HEALTHCHECK_KEY_TYPE
                    )

                # Insert into 'public_key' table
                query = cls._insert_root_item_query(classes_info["public_key"], "public_key")
                await conn.execute(
                    query,
                    public_key_pem,
                    "healthcheck",
                    0,  # not an admin key
                    1,
                    identifier.hex(),
                    str(datetime.datetime.utcnow()),
                )
                # Insert into 'pkcs11_key' table
                query = cls._insert_root_item_query(classes_info["pkcs11_key"], "pkcs11_key")
                await conn.execute(
                    query,
                    2,
                    HEALTHCHECK_KEY_LABEL,
                    HEALTHCHECK_KEY_TYPE,
                    1,
                    str(datetime.datetime.utcnow()),
                )
                print("Created healthcheck PKCS11 key", flush=True)
