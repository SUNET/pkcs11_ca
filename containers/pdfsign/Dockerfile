FROM debian:stable

RUN mkdir -p /opt/sunet/pkcs11


RUN addgroup --system sunet && adduser --system --shell /bin/false --ingroup sunet sunet

env DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y \
    python3-pip \
    netcat-traditional \
    dnsutils \
    git \
    openssl \
    vim-tiny \
    emacs-nox \
    bsdmainutils \
    curl \
    python3-venv \
    iputils-ping \
    procps \
    net-tools \
    bind9-host \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/sunet && chown sunet: /var/log/sunet && chmod 770 /var/log/sunet

WORKDIR /opt/sunet

COPY src ./src
COPY containers/logging.json .
COPY data/pdfsign/ts_chain.pem .
COPY data/pdfsign/ts_cert.pem .
COPY data/pdfsign/ts_priv .
COPY containers/pdfsign/start.sh /
COPY requirements.txt ./

EXPOSE 8080

HEALTHCHECK --interval=27s CMD curl --max-time 20 http://localhost:8080/status/healthy | grep -q STATUS_OK

ENTRYPOINT [ "/bin/bash"]

CMD [ "/start.sh" ]