FROM debian:bookworm-20231120-slim@sha256:93ff361288a7c365614a5791efa3633ce4224542afb6b53a1790330a8e52fc7d

MAINTAINER victor@sunet.se

EXPOSE 8080/tcp

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
# COPY ./data/trusted_keys /app/trusted_keys
# COPY ./containers/healthcheck.sh /app/healthcheck.sh
# COPY ./containers/healthcheck.py /app/healthcheck.py
COPY ./containers/logging.json /app/logging.json
# COPY ./data/tls_certificate.pem /app/tls_certificate.pem
# COPY ./data/tls_key.key /app/tls_key.key

# WORKDIR /app

# COPY ./data/pkcs11_handle.py /app/.venv/lib/python3.11/site-packages/python_x509_pkcs11/pkcs11_handle.py
COPY ./containers/simple_healthcheck.py /app/simple_healthcheck.py


# Run as user
USER pkcs11_ca

# Add healthcheck
HEALTHCHECK --interval=120s --timeout=15s --retries=1 --start-period=30s \
     CMD sh -c '. .venv/bin/activate && python3 simple_healthcheck.py' || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

# CMD sh -c '. .venv/bin/activate && uvicorn src.remote_pkcs11_ca_service.main:app --ssl-keyfile tls_key.key --ssl-certfile tls_certificate.pem --ssl-version 2 --log-config ./logging.json --host 0.0.0.0 --port 443 --workers 1 --header server:remote_pkcs11_ca'

CMD sh -c '. .venv/bin/activate && uvicorn src.remote_pkcs11_ca_service.main:app --log-config ./logging.json --host 0.0.0.0 --port 8080 --workers 1 --header server:remote_pkcs11_ca'
