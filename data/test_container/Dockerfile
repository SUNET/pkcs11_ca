FROM debian:bullseye-20230208-slim@sha256:40febe8053827d8342f93978c541956ed0ac858016953e704939d276f62c83a3

MAINTAINER victor@sunet.se

# Metadata
LABEL version="1.03"
LABEL description="pkcs11_ca test1"

# Set work dir
WORKDIR /app

# Copy the requirement.txt file needed to install deps
COPY ./requirements.txt /app/requirements.txt


# Install deps
RUN apt-get update \
    && apt-get install -y \
    python3-pip \
    netcat \
    dnsutils \
    && pip3 install -r /app/requirements.txt \
    && apt-get autoremove -y
    

# Remove setuid and setgid
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; || true

# Add user and add to softhsm group
RUN useradd pkcs11_ca_test1 -u 1501 -s /usr/sbin/nologin


COPY ./src /app/src
COPY ./tests /app/tests
COPY ./data/trusted_keys /app/data/trusted_keys
COPY ./data/healthcheck.sh /app/healthcheck.sh
COPY ./data/healthcheck.py /app/healthcheck.py
COPY ./data/tls_certificate.pem /app/tls_certificate.pem

RUN chown -R pkcs11_ca_test1 /app

# Run as user
USER pkcs11_ca_test1

# Add healthcheck
# HEALTHCHECK --interval=30s --timeout=15s --retries=1 --start-period=30s \
#     CMD sh healthcheck.sh || bash -c 'kill -s 15 1 && (sleep 7; kill -s 9 1)'

# ENTRYPOINT ["sleep", "300"]
ENTRYPOINT ["python3", "-m", "unittest"]
