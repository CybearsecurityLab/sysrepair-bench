FROM ubuntu@sha256:e0b84ef30bbe766773e6056c60a3e706712e4119508e3da12516f1eddd6f761b
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install Avahi/mDNS daemon (unnecessary on most servers)
RUN apt-get update && apt-get install -y \
    avahi-daemon \
    avahi-utils \
    libnss-mdns \
    dnsutils \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Enable the Avahi daemon
RUN systemctl enable avahi-daemon 2>/dev/null || true


CMD ["sleep", "infinity"]
