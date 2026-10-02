FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/lib/ipsec:${PATH}"
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan strongswan-charon strongswan-swanctl \
    libstrongswan-standard-plugins libstrongswan-extra-plugins \
    iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
