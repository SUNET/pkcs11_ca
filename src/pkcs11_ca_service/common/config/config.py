"""config"""

from typing import Any, Mapping, Optional
from pydantic import BaseModel
import yaml


class CA(BaseModel):
    """CA config class"""
    url: str = "http://ca:8005"
    dns_name: str = "ca"


class Pkcs11(BaseModel):
    """Pkcs11 config class"""
    sign_api_token: str = "xyz"
    token: str = "my_test_token_1"
    pin: str = "1234"
    module: str = "/usr/lib/softhsm/libsofthsm2.so"


class Postgres(BaseModel):
    """Postgres config class"""
    host: str = "postgres"
    user: str = "pkcs11_testuser1"
    password: str = "DBUserPassword"
    port: str = "5432"
    database: str = "pkcs11_testdb1"
    timeout: str = "5"


class PDFSign(BaseModel):
    """PDFSign config class"""
    chain_path: str = "/app/ts_chain.pem"
    key_path: str = "/app/ts_priv"
    cert_path: str = "/app/ts_cert.pem"


class Config(CA, Pkcs11, Postgres, PDFSign):
    """Config class"""
    acme_root: str = "/acme"


def load_config(test_config: Optional[Mapping[str, Any]] = None,):
    if test_config:
        return
    with open(file="config.yaml",encoding="UTF-8", mode="r") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)