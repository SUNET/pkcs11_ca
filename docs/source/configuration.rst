Configuration
=============

.. note::

   The PKCS11 CA currently has two types of configurations.

   | Environment variables such as hostname and database url.
   | The config file with options such as allowed signing algorithms.

Environment variables
---------------------

Default variables are located the top of `deploy.sh <https://github.com/SUNET/pkcs11_ca/blob/main/deploy.sh>`_.

.. code-block:: bash

   # The URL and DNS name for the PKCS11 CA
   export CA_URL="https://ca:8005"
   export CA_DNS_NAME="ca"

   # The ACME root endpoint
   export ACME_ROOT="/acme" # no trailing /

   # The API token for the PKCS11 raw signature endpoint
   export PKCS11_SIGN_API_TOKEN="xyz"

   # PKCS11 token and pin
   export PKCS11_TOKEN="my_test_token_1"
   export PKCS11_PIN="1234"

   # Path to PKCS11 library, SOFTHSM on ubuntu/debian as default
   export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

   # Database configs
   export POSTGRES_HOST="postgres"
   export POSTGRES_USER="pkcs11_testuser1"
   export POSTGRES_PASSWORD="DBUserPassword"
   export POSTGRES_PORT="5432"
   export POSTGRES_DATABASE="pkcs11_testdb1"
   export POSTGRES_TIMEOUT="5"


Config file
-----------

Default options are located at `src/pkcs11_ca_service/config.py <https://github.com/SUNET/pkcs11_ca/blob/main/src/pkcs11_ca_service/config.py>`_.
Its a python file which enables logic for the options such as *if* option A then option B.

.. code-block:: python

   """Config module"""
   import os

   # The PKCS11 backend, must be one of ["LUNAHSM", "SOFTHSM"]
   PKCS11_BACKEND = "SOFTHSM"

   # LUNAHSM does not support EdDSA yet.
   if PKCS11_BACKEND == "LUNAHSM":
       KEY_TYPES = ["secp256r1", "secp384r1", "secp521r1", "rsa_2048", "rsa_4096"]
   else:
       KEY_TYPES = ["ed25519", "ed448", "secp256r1", "secp384r1", "secp521r1", "rsa_2048", "rsa_4096"]

   # Folder for the initial trusted pub_keys
   ROOT_ADMIN_KEYS_FOLDER = "trusted_keys"

   # Which database module to use
   DB_MODULE = "postgres_db"
   # Table order is important: for example 'ca' depends on 'public_key' so it must come after
   DB_TABLE_MODULES = [
       "public_key",
       "pkcs11_key",
       "csr",
       "ca",
       "certificate",
       "crl",
       "acme_account",
       "acme_order",
       "acme_authorization",
   ]

   # Allowed JWT signing algos
   JWT_ALGOS = ["EdDSA", "ES256", "ES384", "ES512", "PS256", "PS512"]

   # Docker healthcheck key label and type.
   HEALTHCHECK_KEY_LABEL = "pkcs11_ca_service_healthcheck_103"
   HEALTHCHECK_KEY_TYPE = "secp256r1"  # Must be in KEY_TYPES above

   # Initial ROOT CA to be created at first run
   ROOT_CA_KEY_LABEL = "my_ROOT_CA_key_label_103"
   ROOT_CA_KEY_TYPE = "secp256r1"  # Must be in KEY_TYPES above

   # The initial ROOT CA's expire date and subject/issuer name
   ROOT_CA_EXPIRE = 365 * 15
   ROOT_CA_NAME_DICT = {
       "country_name": "SE",
       "state_or_province_name": "Stockholm",
       "locality_name": "Stockholm",
       "organization_name": "SUNET",
       "organizational_unit_name": "SUNET Infrastructure",
       "common_name": "ca-test.sunet.se",
   }

   # The CMC ROOT cert is the root of all CMC certs
   # The CMC SIGNING cert is the CA which signs the CMC responses
   # The CMC CERT ISSUING is the CA which signs (and creates) the certs requested by CMC requests.

   # A CMC response is signed by the CMC SIGNING CA and
   # the CMC response contains the new cert issued by the CMC CERT ISSUING CA
   CMC_ROOT_KEY_LABEL = "cmc_root_test3"
   CMC_SIGNING_KEY_LABEL = "cmc_signer_test3"
   CMC_CERT_ISSUING_KEY_LABEL = "cmc_issuer_test3"
   CMC_KEYS_TYPE = "secp256r1"  # Must be in KEY_TYPES above
   CMC_EXPIRE = 365 * 15

   # The CMC CA's subjects/issuers
   CMC_ROOT_NAME_DICT = {
       "country_name": "SE",
       "state_or_province_name": "Stockholm",
       "locality_name": "Stockholm",
       "organization_name": "SUNET",
       "organizational_unit_name": "SUNET Infrastructure",
       "common_name": "ca-test-cmc3-root.sunet.se",
   }
   CMC_SIGNING_NAME_DICT = {
       "country_name": "SE",
       "state_or_province_name": "Stockholm",
       "locality_name": "Stockholm",
       "organization_name": "SUNET",
       "organizational_unit_name": "SUNET Infrastructure",
       "common_name": "ca-test-cmc3-signer.sunet.se",
   }
   CMC_CERT_ISSUING_NAME_DICT = {
       "country_name": "SE",
       "state_or_province_name": "Stockholm",
       "locality_name": "Stockholm",
       "organization_name": "SUNET",
       "organizational_unit_name": "SUNET Infrastructure",
       "common_name": "ca-test-cmc3-issuer.sunet.se",
   }

   # The certs which are allowed to send CMC requests to the PKCS11 CA, signature check.
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

   # Default CSR expire date.
   CSR_EXPIRE_DATE = 365 * 1

   # ROOT_URL and PKCS11_SIGN_API_TOKEN is taken from the corresponding environment variables
   ROOT_URL = os.environ["CA_URL"]
   PKCS11_SIGN_API_TOKEN = os.environ["PKCS11_SIGN_API_TOKEN"]

   # ACME settings
   # The ACME root url endpoint
   ACME_ROOT = os.environ["ACME_ROOT"]

   # The allowed ACME identifier types
   # Remove 'signature' if not using the SUNET ACME signature challenge.
   ACME_IDENTIFIER_TYPES = ["dns", "signature"]

   # The ACME cert issuer CA. It is a root CA.
   ACME_SIGNER_NAME_DICT = {
       "country_name": "SE",
       "state_or_province_name": "Stockholm",
       "locality_name": "Stockholm",
       "organization_name": "SUNET",
       "organizational_unit_name": "SUNET Infrastructure",
       "common_name": "acme_signer.sunet.se",
   }
   ACME_SIGNER_KEY_LABEL = "acme_root_test3"
   ACME_SIGNER_KEY_TYPE = "secp256r1"

   # The expiry date for the ACME CA.
   ACME_SIGNER_EXPIRE = 365 * 15

   # The trusted certs and issuers for the SUNET ACME signature challenge.
   # Set and empty list if not using the SUNET ACME signature challenge.
   ACME_SUNET_TRUSTED_SIGNERS = [
       """-----BEGIN CERTIFICATE-----
   MIIBRDCB66ADAgECAgIH0DAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFkdW1teS1p
   c3N1ZXItbmFtZTAeFw0yMzAzMTExNjU4NDlaFw0zMzAzMDgxNzAwNDlaMBwxGjAY
   BgNVBAMMEWR1bW15LWlzc3Vlci1uYW1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
   QgAEtaF41j6lx3QRYmojnC/nR29nkrTC9dXOUfrOTD9GVwL6uJCPuon6G2boWG0T
   CJf1igGxO/jEr4BaFzgma+V7zqMdMBswDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMC
   AYYwCgYIKoZIzj0EAwIDSAAwRQIhAKKdU1WvRVApCYXR7jDwt0A+FDIUkF8i5Jkx
   JOvOkFmuAiAAi7tZG8mz4lh5+Z/BihVKZ308MQAlZJE+hQ7BvA4IwQ==
   -----END CERTIFICATE-----""",
   ]
