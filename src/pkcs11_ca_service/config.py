# Folder for the initial trusted pub_keys
ROOT_ADMIN_KEYS_FOLDER = "trusted_pub_keys"

DB_MODULE = "postgres_db"
# Table order is important: for example 'ca' dependes on 'public_key' so it comes after
DB_TABLE_MODULES = ["public_key", "pkcs11_key", "csr", "ca", "certificate", "crl"]

# https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/src/Microsoft.IdentityModel.Tokens/JsonWebKeyECTypes.cs#L40
JWT_ALGOS = ["PS256", "PS384", "PS512", "ES256", "ES384", "ES521"]

ROOT_CA_KEY_LABEL = "my_ROOT_CA_key_label"
ROOT_CA_KEY_SIZE = 2048
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

DB_HOST = "localhost"
DB_USER = "pkcs11_testuser1"
DB_PASSWORD = "DBUserPassword"
DB_PORT = "5432"
DB_DATABASE = "pkcs11_testdb1"
DB_TIMEOUT = "5"
