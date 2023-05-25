FROM debian:bullseye-20230502-slim@sha256:249d9dc1b57918b203e45f647ea675cd940de5942863f35c979e5d926f024a7e

# Metadata
LABEL version="1.03"
LABEL description="pkcs11_ca postgres"

# Set work dir
WORKDIR /var/lib/postgresql/data


# Install deps
RUN apt-get update \
    && apt-get install -y \
    postgresql \
    && apt-get remove -y \
    gcc \
    curl \
    wget \
    python3-pip \
    python3-dev \
    && apt-get autoremove -y

# Remove setuid and setgid
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true

# COPY ./containers/healthcheck.sh /healthcheck.sh
# COPY ./containers/healthcheck.py /healthcheck.py

# Run as user
USER postgres

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=15s --retries=1 --start-period=30s \
    CMD sh healthcheck.sh || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

# ENTRYPOINT ["sleep", "300"]
ENTRYPOINT ["/usr/bin/pg_ctlcluster", "start"]
