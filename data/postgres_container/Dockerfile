FROM debian:bullseye-20221205-slim@sha256:cb1452ab51eb89a3a8b7cea58536558c809b2e4e8f687eb61e6ea4bde353f60d

MAINTAINER victor@sunet.se

EXPOSE 8000/tcp

# Metadata
LABEL version="1.02"
LABEL description="pkcs11_ca postgres"

# Set work dir
WORKDIR /var/lib/postgresql/data


# Install deps
RUN apt-get update \
    && apt-get install -y \
    postgresql
    && apt-get remove -y \
    gcc \
    curl \
    wget \
    python3-pip \
    python3-dev \
    && apt-get autoremove -y

# Remove setuid and setgid
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true

# COPY ./data/healthcheck.sh /healthcheck.sh
# COPY ./data/healthcheck.py /healthcheck.py

# Run as user
USER postgres

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=15s --retries=1 --start-period=30s \
    CMD sh healthcheck.sh || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

#ENTRYPOINT ["sleep", "300"]
ENTRYPOINT["/usr/bin/pg_ctlcluster", "start"]
# ENTRYPOINT ["uvicorn", "src.pkcs11_ca_service.main:app", "--host", "0.0.0.0", "--workers", "1", "--header", "server:pkcs11_ca"]
