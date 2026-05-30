# Image for the benchmark Compose service. It bundles every tool the benchmark
# compares (bbb is built from the repo at run time, plus py-bbb/boostedblob and
# azcopy) together with the Azurite emulator and the certificate tooling, so the
# whole benchmark runs inside the container without touching the host.
FROM golang:1.26-trixie

ENV DEBIAN_FRONTEND=noninteractive

# openssl + ca-certificates: local CA for the emulator's TLS endpoint.
# nodejs + npm: Azurite.
# python3 + venv: py-bbb (boostedblob) and the SAS generator for azcopy.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl openssl nodejs npm python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Azurite emulator.
RUN npm install -g azurite

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
