# TODO: lookup extract RSA sig from GPG sig, should be possible so we can sign with current gpg yubikey signs
# Check, create and insert root ca in main.py not in postgres.py


### Docker setup, will start at bool
# docker network create pkcs11_ca_service_network
# sudo mkdir -p /app_db
# sudo mkdir -p /app_softhsm && sudo chown 1500 /app_softhsm

## For the postgres database
# docker pull postgres:latest
# docker run --name pkcs11_ca_service_postgres --net pkcs11_ca_service_network --restart always -d -v /app_db:/var/lib/postgresql/data -e POSTGRES_DB=pkcs11_testdb1 -e POSTGRES_USER=pkcs11_testuser1 -e POSTGRES_PASSWORD=DBUserPassword postgres
# docker stop/start pkcs11_ca_service_postgres

# Run the code CA server and run unittests
bash dev-run.sh
