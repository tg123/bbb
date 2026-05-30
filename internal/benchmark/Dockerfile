# Image for the benchmark Compose service. It bundles the client tools the
# benchmark compares (bbb is built from the repo at run time, plus
# py-bbb/boostedblob and azcopy) together with the certificate tooling. The
# Azurite emulator itself runs as its own Compose service (see
# docker-compose.yaml), so it is not installed here.
FROM golang:1.26-trixie

ENV DEBIAN_FRONTEND=noninteractive

# openssl + ca-certificates: local CA for the emulator's TLS endpoint.
# python3 + venv: py-bbb (boostedblob) and the SAS generator for azcopy.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl openssl python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# py-bbb (boostedblob) and azure-storage-blob (used to mint the azcopy SAS),
# installed into a venv so they stay isolated from the system Python.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir boostedblob azure-storage-blob

# azcopy.
RUN curl -sSL -o /tmp/azcopy.tar.gz https://aka.ms/downloadazcopy-v10-linux \
    && tar -xzf /tmp/azcopy.tar.gz -C /tmp \
    && cp /tmp/azcopy_linux_amd64_*/azcopy /usr/local/bin/azcopy \
    && rm -rf /tmp/azcopy.tar.gz /tmp/azcopy_linux_amd64_* \
    && azcopy --version

WORKDIR /src
