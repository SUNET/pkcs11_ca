FROM debian:bookworm-20231009-slim@sha256:ceffa8e71bafc0190f915774b9696a0b6cb6262d1df5f64028b570ca4055ba83

MAINTAINER victor@sunet.se

# Metadata
LABEL version="1.03"
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

# COPY ./containers/healthcheck.sh /healthcheck.sh
# COPY ./containers/healthcheck.py /healthcheck.py

# Run as user
USER postgres

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=15s --retries=1 --start-period=30s \
    CMD sh healthcheck.sh || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

# ENTRYPOINT ["sleep", "300"]
ENTRYPOINT["/usr/bin/pg_ctlcluster", "start"]
