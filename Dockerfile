FROM debian:stable-20221004-slim@sha256:a4912461baca94ca557af4e779857867a25e0215d157d2dc04f148811e7877f8

MAINTAINER victor@sunet.se

EXPOSE 8000/tcp

LABEL version="1.01"
LABEL description="pkcs11_ca_service container"

WORKDIR /app

RUN mkdir -p /app
COPY ./requirements.txt /app/requirements.txt

RUN apt-get update \
    && apt-get install -y \
    python3-pip \
    python3-dev \
    softhsm2 \
    python3 \
    && pip3 install -r requirements.txt \
    && apt-get remove -y \
    gcc \
    curl \
    wget \
    python3-pip \
    python3-dev \
    && apt-get autoremove -y

# Remove setuid and setgid
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true

RUN useradd pkcs11_ca_service -u 1500 -s /usr/sbin/nologin
RUN usermod -a -G softhsm pkcs11_ca_service

COPY ./src /app/src
COPY ./tests /app/tests
COPY ./trusted_keys /app/trusted_keys
COPY ./healthcheck.sh /app/healthcheck.sh
COPY ./healthcheck.py /app/healthcheck.py

USER pkcs11_ca_service

ENV PKCS11_TOKEN="my_test_token_1"
ENV PKCS11_PIN="1234"
ENV PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

RUN softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

HEALTHCHECK --interval=30s --timeout=5s --retries=1 --start-period=5s \
    CMD sh healthcheck.sh || exit 1

ENTRYPOINT ["uvicorn", "src.pkcs11_ca_service.main:app", "--host", "0.0.0.0", "--workers", "1", "--header", "server:pkcs11_ca_service"]
