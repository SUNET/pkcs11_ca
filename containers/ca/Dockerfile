FROM debian:bookworm-20230703-slim@sha256:01bd742e2c269abf94e2fefb47b08b5b61c9a880b993417d23a1d0bd9fa60dc4

MAINTAINER victor@sunet.se

EXPOSE 8005/tcp

# Metadata
LABEL version="1.03"
LABEL description="pkcs11_ca web"

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
    build-essential \
    opensc \
    wget \
    swig \
    libz-dev \
    dnsutils \
    mercurial \
    python3-venv \
    && python3 -m venv .venv && . .venv/bin/activate \
    && pip3 install --require-hashes -r requirements.txt \
    && apt-get remove -y \
    wget \
    curl \
    gcc \
    python3-pip \
    python3-dev \
    && apt-get autoremove -y

# Remove setuid and setgid
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true

# Add user and add to softhsm group
RUN useradd pkcs11_ca -u 1500 -s /usr/sbin/nologin
RUN usermod -a -G softhsm pkcs11_ca

# Copy files
COPY ./src /app/src
COPY ./tests /app/tests
COPY ./data/trusted_keys /app/trusted_keys
COPY ./containers/healthcheck.sh /app/healthcheck.sh
COPY ./containers/healthcheck.py /app/healthcheck.py
COPY ./containers/logging.json /app/logging.json
COPY ./data/tls_certificate.pem /app/tls_certificate.pem
COPY ./data/tls_key.key /app/tls_key.key

# HSM stuff
# WORKDIR /usr/src/luna-client
# COPY ./data/luna-client-7.4 /usr/src/luna-client
# RUN ./deb.sh
# WORKDIR /
# RUN rm -rf /usr/src/luna-client
# COPY ./data/web_container/entrypoint.sh /entrypoint.sh
# RUN chmod a+rx /entrypoint.sh
# COPY ./cert /usr/safenet/lunaclient/cert
# COPY ./50-ha-slot.conf /etc/Chrystoki.conf.d/50-ha-slot.conf

# WORKDIR /app

# Run as user
USER pkcs11_ca

# Set env variables now during build
# ENV PKCS11_TOKEN="my_test_token_1"
# ENV PKCS11_PIN="1234"
# ENV PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"

# RUN softhsm2-util --init-token --slot 0 --label $PKCS11_TOKEN --pin $PKCS11_PIN --so-pin $PKCS11_PIN

# Add healthcheck
HEALTHCHECK --interval=120s --timeout=15s --retries=1 --start-period=30s \
    CMD sh '. .venv/bin/activate && healthcheck.sh' || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

# ENTRYPOINT ["uvicorn", "src.pkcs11_ca_service.main:app", "--ssl-keyfile", "tls_key.key", "--ssl-certfile", "tls_certificate.pem", "--ssl-version", "2", "--log-config", "./logging.json", "--host", "0.0.0.0", "--port", "8005", "--workers", "1", "--header", "server:pkcs11_ca"]
# ENTRYPOINT ["uvicorn", "src.pkcs11_ca_service.main:app", "--log-config", "./logging.json", "--host", "0.0.0.0", "--port", "8005", "--workers", "1", "--header", "server:pkcs11_ca"]

CMD sh -c '. .venv/bin/activate && uvicorn src.pkcs11_ca_service.main:app --ssl-keyfile tls_key.key --ssl-certfile tls_certificate.pem --ssl-version 2 --log-config ./logging.json --host 0.0.0.0 --port 8005 --workers 1 --header server:pkcs11_ca'