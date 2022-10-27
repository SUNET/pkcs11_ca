FROM debian:bullseye-20221024-slim@sha256:76cdda8fe5eb597ef5e712e4c9a9f5f1fb119e69f353daaa7bd6d0f6e66e541d

MAINTAINER victor@sunet.se

EXPOSE 8000/tcp

# Metadata
LABEL version="1.02"
LABEL description="pkcs11_ca_service container"

# Set work dir
WORKDIR /app

# Copy the requirement.txt file needed to install deps
COPY ./requirements.txt /app/requirements.txt

# Install deps
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

# Add user and add to softhsm group
RUN useradd pkcs11_ca_service -u 1500 -s /usr/sbin/nologin
RUN usermod -a -G softhsm pkcs11_ca_service

# Copy files
COPY ./src /app/src
COPY ./tests /app/tests
COPY ./data/trusted_keys /app/trusted_keys
COPY ./data/healthcheck.sh /app/healthcheck.sh
COPY ./data/healthcheck.py /app/healthcheck.py

# Run as user
USER pkcs11_ca_service

# Set env variables now during build
ENV PKCS11_TOKEN="my_test_token_1"
ENV PKCS11_PIN="1234"
ENV PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

RUN softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=15s --retries=1 --start-period=30s \
    CMD sh healthcheck.sh || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

ENTRYPOINT ["uvicorn", "src.pkcs11_ca_service.main:app", "--host", "0.0.0.0", "--workers", "1", "--header", "server:pkcs11_ca_service"]