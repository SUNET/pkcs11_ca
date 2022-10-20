#!/bin/bash

# Check docker
which docker > /dev/null || (echo "docker not found, install with sudo apt-get install docker.io" \
				 && echo "sudo usermod -a -G docker $USER" \
				 && echo "logout and in now for docker group to work" \
				 && exit 1)


# Create folder volume for softhsm tokens
if [ ! -d "/app_softhsm" ]; then
    echo "ERROR: /app_softhsm does not exist"
    echo "Run:"
    echo "sudo mkdir /app_softhsm"
    echo "sudo chown 1500 /app_softhsm"
    exit 1
fi

# Create network if not exist
docker network ls | grep pkcs11_ca_service_network > /dev/null \
    || (docker network create pkcs11_ca_service_network && echo -e "\nCreated docker network\n")

# Create postgres if not exists
docker ps --all | grep pkcs11_ca_service_postgres > /dev/null \
    || (docker pull postgres:15.0-bullseye@sha256:b1e2423776b4acc769a18e6a166e6103b22575be1d2ff2ae1b55500a5298b2d4 \
	&& docker run \
		  --name pkcs11_ca_service_postgres \
		  --net pkcs11_ca_service_network \
		  --restart always \
		  -d \
		  -v /app_db:/var/lib/postgresql/data \
		  -e POSTGRES_DB=pkcs11_testdb1 \
		  -e POSTGRES_USER=pkcs11_testuser1 \
		  -e POSTGRES_PASSWORD=DBUserPassword \
		  postgres \
		  && echo -e "\nStarted postgres container\n" \
    )

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

# Stop old container, build and run the new one
docker build -t pkcs11_ca_service_http . && echo "Built new http container"
docker ps --all | grep pkcs11_ca_service_http > /dev/null \
    && (docker stop pkcs11_ca_service_http ; docker rm pkcs11_ca_service_http ; echo -e "\nStopped and deleted old http container\n")
docker run \
       --name pkcs11_ca_service_http \
       --net pkcs11_ca_service_network \
       --restart always \
       --security-opt no-new-privileges \
       --cap-drop all \
       --read-only \
       --memory 256m \
       --cpus 2.75 \
       --mount type=tmpfs,target=/dev/shm,readonly=true \
       -v /app_softhsm:/var/lib/softhsm/tokens \
       -p 8000:8000 \
       -d \
       pkcs11_ca_service_http \
       && echo -e "\nStarted http container\n"

# Allow http container to startup
sleep 2

echo "Running tests"
python3 -m unittest || exit 1

echo -e "\nService ONLINE at 0.0.0.0:8000"
