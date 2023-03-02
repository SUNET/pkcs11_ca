"""Config module"""
import os

# Must be one of ["LUNAHSM", "SOFTHSM"]
PKCS11_BACKEND = "SOFTHSM"

if PKCS11_BACKEND == "LUNAHSM":
    KEY_TYPES = ["secp256r1", "secp384r1", "secp521r1", "rsa_2048", "rsa_4096"]
else:
    KEY_TYPES = ["ed25519", "ed448", "secp256r1", "secp384r1", "secp521r1", "rsa_2048", "rsa_4096"]

ACME_ROOT = "/acme"

# Folder for the initial trusted pub_keys
ROOT_ADMIN_KEYS_FOLDER = "trusted_keys"

DB_MODULE = "postgres_db"
# Table order is important: for example 'ca' depends on 'public_key' so it comes after
DB_TABLE_MODULES = [
    "public_key",
    "pkcs11_key",
    "csr",
    "ca",
    "certificate",
    "crl",
    "acme_account",
]

# https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/src/Microsoft.IdentityModel.Tokens/JsonWebKeyECTypes.cs#L40
JWT_ALGOS = ["EdDSA", "ES256", "ES384", "ES512", "PS256", "PS512"]

HEALTHCHECK_KEY_LABEL = "pkcs11_ca_service_healthcheck_103"
HEALTHCHECK_KEY_TYPE = "secp256r1"  # Must be in KEY_TYPES above

ROOT_CA_KEY_LABEL = "my_ROOT_CA_key_label_103"
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

CMC_ROOT_KEY_LABEL = "cmc_root_test3"
CMC_SIGNING_KEY_LABEL = "cmc_signer_test3"
CMC_CERT_ISSUING_KEY_LABEL = "cmc_issuer_test3"
CMC_KEYS_TYPE = "secp256r1"  # Must be in KEY_TYPES above
CMC_EXPIRE = 365 * 15

CMC_ROOT_NAME_DICT = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test-cmc3-root.sunet.se",
    "email_address": "soc@sunet.se",
}
CMC_SIGNING_NAME_DICT = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test-cmc3-signer.sunet.se",
    "email_address": "soc@sunet.se",
}
CMC_CERT_ISSUING_NAME_DICT = {
    "country_name": "SE",
    "state_or_province_name": "Stockholm",
    "locality_name": "Stockholm",
    "organization_name": "SUNET",
    "organizational_unit_name": "SUNET Infrastructure",
    "common_name": "ca-test-cmc3-issuer.sunet.se",
    "email_address": "soc@sunet.se",
}

CMC_REQUEST_CERTS = [
    """-----BEGIN CERTIFICATE-----
MIIBJDCByqADAgECAgRhfDUqMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMMD1Rlc3Qg
Q01DIENsaWVudDAeFw0yMTEwMjkxNzUzNDZaFw0yNjEwMjkxNzUzNDZaMBoxGDAW
BgNVBAMMD1Rlc3QgQ01DIENsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BJuWGZFY9U8KD8RsIALCJYElSH4GgI6/nY6L5RTPGdYl5xzF2yYKRlFQBNVbB359
HBmaVuhuKbTkLiKsTTy0qRMwCgYIKoZIzj0EAwIDSQAwRgIhAIitbkx60TsqHZbH
k9ko+ojFQ3XWJ0zTaKGQcfglrTU/AiEAjJs3LuO1F6GxDjgpLVVp+u750rVCwsUJ
zIqw8k4ytIY=
-----END CERTIFICATE-----""",
]

CSR_EXPIRE_DATE = 365 * 1

ROOT_URL = os.environ["CA_URL"]
PKCS11_SIGN_API_TOKEN = os.environ["PKCS11_SIGN_API_TOKEN"]
