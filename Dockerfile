# FROM debian:stable-slim
FROM debian:latest


 RUN apt-get update \
     && apt-get install -y python3-pip \
     python3-dev \
     uvicorn \
     python3-fastapi \
     softhsm python3-jwt \
     python3-asyncpg \
     python3-requests \
     softhsm2

#RUN apk update && apk add softhsm py3-pip gcc py3-dev

RUN pip3 install python_x509_pkcs11

RUN useradd pkcs11_ca_service

RUN usermod -a -G softhsm pkcs11_ca_service


# Remove dev stuff
RUN apt-get remove gcc wget curl python3-dev -y && apt-get autoremove -y

COPY . /app
 
EXPOSE 8000/tcp

LABEL version="1.01"
LABEL description="pkcs11_ca_service container"

USER pkcs11_ca_service
WORKDIR /app

ENV PKCS11_TOKEN="my_test_token_1"
ENV PKCS11_PIN="1234"
ENV PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

RUN softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

# --security-opt seccomp:unconfined

CMD ["uvicorn", "src.pkcs11_ca_service.main:app", "--host", "0.0.0.0", "--workers", "1", "--header", "server:pkcs11_ca_service"]
