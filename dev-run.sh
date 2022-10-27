#!/bin/bash

# Check docker
which docker > /dev/null || (echo "docker not found, install with sudo apt-get install docker.io" \
				 && echo "sudo usermod -a -G docker $USER" \
				 && echo "logout and in now for docker group to work" \
				 && exit 1)


# Check docker-compose
which docker-compose > /dev/null || (echo "docker-compose not found, install with pip3 install docker-compose" \
					 && exit 1)

# Check code
echo "Checking code package"
(which mypy > /dev/null \
    && mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null src/pkcs11_ca_service/*.py) || exit 1
(which black > /dev/null \
    && black --line-length 120 src/pkcs11_ca_service/*.py) || exit 1
(which pylint > /dev/null \
    && pylint --max-line-length 120 src/pkcs11_ca_service/*.py) || exit 1

# Check tests
echo "Checking code tests"
(which mypy > /dev/null \
     && mypy --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null tests/*.py) || exit 1
(which black > /dev/null \
    && black --line-length 120 tests/*.py) || exit 1
(which pylint > /dev/null \
      && pylint --max-line-length 120 tests/*.py) || exit 1

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
