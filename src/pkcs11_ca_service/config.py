"""Config module"""

# Must be one of ["LUNAHSM", "SOFTHSM"]
PKCS11_BACKEND = "SOFTHSM"

if PKCS11_BACKEND == "LUNAHSM":
    KEY_TYPES = ["secp256r1", "secp384r1", "secp521r1", "rsa_2048", "rsa_4096"]
else:
    KEY_TYPES = ["ed25519", "ed448", "secp256r1", "secp384r1", "secp521r1", "rsa_2048", "rsa_4096"]

# Folder for the initial trusted pub_keys
ROOT_ADMIN_KEYS_FOLDER = "trusted_keys"

ROOT_URL = "http://localhost:8005"

DB_MODULE = "postgres_db"
# Table order is important: for example 'ca' dependes on 'public_key' so it comes after
DB_TABLE_MODULES = ["public_key", "pkcs11_key", "csr", "ca", "certificate", "crl"]

# https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/src/Microsoft.IdentityModel.Tokens/JsonWebKeyECTypes.cs#L40
JWT_ALGOS = ["EdDSA", "ES256", "ES384", "ES512", "PS256", "PS512"]

HEALTHCHECK_KEY_LABEL = "pkcs11_ca_service_healthcheck"
HEALTHCHECK_KEY_TYPE = "secp256r1"  # Must be in KEY_TYPES above

ROOT_CA_KEY_LABEL = "my_ROOT_CA_key_label"
ROOT_CA_KEY_TYPE = "secp256r1"  # Must be in KEY_TYPES above

ROOT_CA_EXPIRE = 365 * 15
ROOT_CA_NAME_DICT = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test.sunet.se",
    "email_address": "soc@sunet.se",
}

CSR_EXPIRE_DATE = 365 * 1

DB_HOST = "postgres"
DB_USER = "pkcs11_testuser1"
DB_PASSWORD = "DBUserPassword"
DB_PORT = "5432"
DB_DATABASE = "pkcs11_testdb1"
DB_TIMEOUT = "5"
