FIXME = "create crl at startup if not exist"
FIXME2 = "check db connection at startup"

valid_dns_names = ["sunet.se"]

DB_HOST = "localhost"
DB_USER = "ca_service_test1"
DB_PASSWORD = "CHANGEME"
DB_PORT = "5432"
DB_DATABASE = "ca_service_test1_db"
DB_TIMEOUT = "3"

ca_certfile = "ca.crt"
ca_keyfile = "ca.key"
ca_keyfile_password = "CHANGEME"
ca_expire_date = 365*2 # in days

ca_info_country_name = "SE"
ca_info_state_or_province_name = "Stockholm"
ca_info_locality_name = "Stockholm"
ca_info_organization_name = "SUNET"
ca_info_organizational_unit_name = "SUNET Infrastructure"
ca_info_common_name = "ca-test.sunet.se"
ca_info_email_address = "soc@sunet.se"

csr_keyfile = "csr.key"
csr_csrfile = "csr.pem"
csr_privatekeyfile_password = "CHANGEME"


