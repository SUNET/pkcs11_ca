#!/bin/bash

# For production replace the selfsigned TLS cert with your cert at ./data/tls_certificate.pem

# Ensure ENV vars are set
if [ -z "$CA_URL" ]
then
    echo "Set ENV CA_URL"
    echo """
Try with default ENV vars

export CA_URL="https://ca:8005"
export CA_DNS_NAME="ca"

export PKCS11_SIGN_API_TOKEN="xyz"

export PKCS11_TOKEN=my_test_token_1
export PKCS11_PIN=1234
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

export POSTGRES_HOST="postgres"
export POSTGRES_USER="pkcs11_testuser1"
export POSTGRES_PASSWORD="DBUserPassword"
export POSTGRES_PORT="5432"
export POSTGRES_DATABASE="pkcs11_testdb1"
export POSTGRES_TIMEOUT="5"
"""
    exit 1
fi

if [ -z "$PKCS11_SIGN_API_TOKEN" ]
then
    echo "Set ENV PKCS11_SIGN_API_TOKEN"
    exit 1
fi
if [ -z "$CA_DNS_NAME" ]
then
    echo "Set ENV CA_DNS_NAME"
    exit 1
fi

# PKCS11
if [ -z "$PKCS11_TOKEN" ]
then
    echo "Set ENV PKCS11_TOKEN"
    exit 1
fi
if [ -z "$PKCS11_PIN" ]
then
    echo "Set ENV PKCS11_PIN"
    exit 1
fi
if [ -z "$PKCS11_MODULE" ]
then
    echo "Set ENV PKCS11_MODULE"
    exit 1
fi

# POSTGRES
if [ -z "$POSTGRES_HOST" ]
then
    echo "Set ENV POSTGRES_HOST"
    exit 1
fi
if [ -z "$POSTGRES_PORT" ]
then
    echo "Set ENV POSTGRES_PORT"
    exit 1
fi
if [ -z "$POSTGRES_DATABASE" ]
then
    echo "Set ENV POSTGRES_DATABASE"
    exit 1
fi
if [ -z "$POSTGRES_USER" ]
then
    echo "Set ENV POSTGRES_USER"
    exit 1
fi
if [ -z "$POSTGRES_PASSWORD" ]
then
    echo "Set ENV POSTGRES_PASSWORD"
    exit 1
fi
if [ -z "$POSTGRES_TIMEOUT" ]
then
    echo "Set ENV POSTGRES_TIMEOUT"
    exit 1
fi


# Check docker
which openssl > /dev/null
if [ $? -ne 0 ]
then
    echo "openssl not found, install with sudo apt-get install openssl"
    exit 1
fi

# Generate trusted keys
mkdir -p data/trusted_keys
if [ ! -f data/trusted_keys/privkey1.key ]
then
    openssl genrsa -out data/trusted_keys/privkey1.key 4096
    openssl rsa -in data/trusted_keys/privkey1.key -pubout -out data/trusted_keys/pubkey1.pem

    openssl genrsa -out data/trusted_keys/privkey2.key 4096
    openssl rsa -in data/trusted_keys/privkey2.key -pubout -out data/trusted_keys/pubkey2.pem

    openssl genrsa -out data/trusted_keys/privkey3.key 2048
    openssl rsa -in data/trusted_keys/privkey3.key -pubout -out data/trusted_keys/pubkey3.pem

    openssl ecparam -name prime256v1 -genkey -noout -out data/trusted_keys/privkey4.key
    openssl ec -in data/trusted_keys/privkey4.key -pubout -out data/trusted_keys/pubkey4.pem

    openssl ecparam -name secp384r1 -genkey -noout -out data/trusted_keys/privkey5.key
    openssl ec -in data/trusted_keys/privkey5.key -pubout -out data/trusted_keys/pubkey5.pem

    openssl ecparam -name secp521r1 -genkey -noout -out data/trusted_keys/privkey6.key
    openssl ec -in data/trusted_keys/privkey6.key -pubout -out data/trusted_keys/pubkey6.pem

    openssl genpkey -algorithm ed25519 -out data/trusted_keys/privkey7.key
    openssl pkey -in data/trusted_keys/privkey7.key -pubout -out data/trusted_keys/pubkey7.pem

    openssl genpkey -algorithm ed448 -out data/trusted_keys/privkey8.key
    openssl pkey -in data/trusted_keys/privkey8.key -pubout -out data/trusted_keys/pubkey8.pem

    openssl genpkey -algorithm ed25519 -out data/trusted_keys/privkey9.key
    openssl pkey -in data/trusted_keys/privkey9.key -pubout -out data/trusted_keys/pubkey9.pem

    openssl genpkey -algorithm ed448 -out data/trusted_keys/privkey10.key
    openssl pkey -in data/trusted_keys/privkey10.key -pubout -out data/trusted_keys/pubkey10.pem

    chmod 644 data/trusted_keys/privkey*.key

    # Add the tls cert and key
    openssl ecparam -name prime256v1 -genkey -noout -out data/tls_key.key
    python3 -c '
import sys
from src.pkcs11_ca_service.config import ROOT_URL

if ROOT_URL not in ["https://ca:8005", "https://ca:443", "https://ca"]:
  sys.exit(1)
'
    if [ $? -eq 0 ]
    then
        openssl req -subj "/C=SE/CN=${CA_DNS_NAME}" -addext "subjectAltName = DNS:${CA_DNS_NAME}" -new -x509 -key data/tls_key.key -out data/tls_certificate.pem -days 1026
    else
        openssl req -subj "/C=SE/CN=${CA_DNS_NAME}" -addext "subjectAltName = DNS:${CA_DNS_NAME}" -addext "subjectAltName = DNS:localhost" -new -x509 -key data/tls_key.key -out data/tls_certificate.pem -days 1026
    fi

    chmod 644 data/tls_key*.key
fi

# Check docker
which docker > /dev/null
if [ $? -ne 0 ]
then
    echo "docker not found, install with sudo apt-get install docker.io"
    echo "sudo usermod -a -G docker $USER"
    echo "logout and in now for docker group to work"
    exit 1
fi

# Check python3
which python3 > /dev/null
if [ $? -ne 0 ]
then
    echo "python3 not found, install with sudo apt-get install python3"
    exit 1
fi

# Check docker-compose
which docker-compose > /dev/null
if [ $? -ne 0 ]
then
    echo "docker-compose not found, install with pip3 install docker-compose"
    exit 1
fi

# Check code
echo "Checking code package"

which mypy > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/tmp src/pkcs11_ca_service/*.py
else
    echo "mypy is not installed, skipping..."
    echo "Dont forget to install types-requests"
fi

which black > /dev/null
if [ $? -eq 0 ]
then
    black --line-length 120 src/pkcs11_ca_service/*.py
else
    echo "black is not installed, skipping..."
fi

which pylint > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    pylint --max-line-length 120 src/pkcs11_ca_service/*.py
else
    echo "pylint is not installed, skipping..."
fi

which mypy > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/tmp tests/*.py
fi

which black > /dev/null
if [ $? -eq 0 ]
then
    black --line-length 120 tests/*.py
fi

which pylint > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    pylint --max-line-length 120 tests/*.py
fi

echo "Using 'sudo' to set correct directory ownership"
# Remove git create folder files
sudo rm -f data/hsm_tokens/.empty
sudo rm -f data/db_data/.empty
sudo mkdir -p data/hsm_tokens data/db_data
sudo chown -R $USER data/hsm_tokens data/db_data/
docker-compose build || exit 1
sudo chown -R 1500 data/hsm_tokens
sudo chown -R 999 data/db_data

docker-compose -f docker-compose.yml up -d || exit 1

# Allow container to startup
sleep 3
# Run test container
echo -e "Running tests\n"
sleep 2

python3 -c '
import sys
from src.pkcs11_ca_service.config import ROOT_URL

if ROOT_URL not in ["https://ca:8005", "https://ca:443", "https://ca"]:
  sys.exit(1)
'
if [ $? -eq 0 ]
then
    docker run --env "CA_URL=${CA_URL}" --env "PKCS11_SIGN_API_TOKEN=${PKCS11_SIGN_API_TOKEN}" --network pkcs11_ca_default pkcs11_ca_test1 || exit 1
    echo -e "\nService ONLINE at https://localhost:8005 and at ${CA_URL} inside the docker network pkcs11_ca_default"
    echo -e "Note that the service listens on 0.0.0.0 so will be exposed to the public if its port is open"
else
    docker run --env "CA_URL=${CA_URL}" --env "PKCS11_SIGN_API_TOKEN=${PKCS11_SIGN_API_TOKEN}" --network host pkcs11_ca_test1 || exit 1
    echo -e "\nService ONLINE at ${CA_URL}"
fi

# Show 'docker ps' output
echo -e "\n"
docker ps
