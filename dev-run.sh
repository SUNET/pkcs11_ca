#!/bin/bash

# PKCS11
if [ -z "$PKCS11_TOKEN" ]
then
    echo "Set ENV PKCS11_TOKEN"
    echo """
Try with default ENV vars

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
which docker > /dev/null
if [ $? -ne 0 ]
then
    echo "docker not found, install with sudo apt-get install docker.io"
    echo "sudo usermod -a -G docker $USER"
    echo "logout and in now for docker group to work"
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
    mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null src/pkcs11_ca_service/*.py
else
    echo "mypy is not installed, skipping..."
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
    pylint --max-line-length 120 src/pkcs11_ca_service/*.py
else
    echo "pylint is not installed, skipping..."
fi

which mypy > /dev/null
if [ $? -eq 0 ]
then
    mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null tests/*.py
fi

which black > /dev/null
if [ $? -eq 0 ]
then
    black --line-length 120 tests/*.py
fi

which pylint > /dev/null
if [ $? -eq 0 ]
then
    pylint --max-line-length 120 tests/*.py
fi

mkdir -p data/hsm_tokens data/db_data
sudo chown -R $USER data/hsm_tokens data/db_data/
docker-compose build || exit 1
sudo chown -R 1500 data/hsm_tokens
sudo chown -R 999 data/db_data
docker-compose -f docker-compose.yml up -d || exit 1


# Allow container to startup
sleep 5

echo "Running tests"
python3 -m unittest || exit 1

echo -e "\nService ONLINE at 0.0.0.0:8000"
