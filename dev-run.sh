#!/bin/bash

echo "Checking package"
mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null src/pkcs11_ca_service/*.py || exit 1
black --line-length 120 src/pkcs11_ca_service/*.py || exit 1
pylint --max-line-length 120 src/pkcs11_ca_service/*.py || exit 1

echo "Checking tests"
mypy --strict --namespace-packages --ignore-missing-imports --cache-dir=/dev/null tests/*.py || exit 1
black --line-length 120 tests/*.py || exit 1
pylint --max-line-length 120 tests/*.py || exit 1

# Stop old container, build and run the new one
docker build -t pkcs11_ca_service_http .
docker stop /pkcs11_ca_service_http
docker rm /pkcs11_ca_service_http
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
       pkcs11_ca_service_http

sleep 2
echo "Running tests"
python3 -m unittest

