FROM debian:bullseye-20221205-slim@sha256:cb1452ab51eb89a3a8b7cea58536558c809b2e4e8f687eb61e6ea4bde353f60d

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
    opensc \
    wget \
    build-essential \
    libz-dev \
    mercurial \
    swig \
    dnsutils \
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
RUN useradd pkcs11_ca -u 1500 -s /usr/sbin/nologin
RUN usermod -a -G softhsm pkcs11_ca

# Copy files
COPY ./src /app/src
COPY ./tests /app/tests
COPY ./data/trusted_keys /app/trusted_keys
COPY ./data/healthcheck.sh /app/healthcheck.sh
COPY ./data/healthcheck.py /app/healthcheck.py
COPY ./data/logging.json /app/logging.json

# Run as user
USER pkcs11_ca

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=15s --retries=1 --start-period=30s \
    CMD sh healthcheck.sh || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

ENTRYPOINT ["uvicorn", "src.pkcs11_ca_service.main:app", "--log-config", "./logging.json", "--host", "0.0.0.0", "--port", "8005", "--workers", "1", "--header", "server:pkcs11_ca"]

