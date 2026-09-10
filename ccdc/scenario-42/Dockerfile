FROM ubuntu@sha256:e0b84ef30bbe766773e6056c60a3e706712e4119508e3da12516f1eddd6f761b
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Remove the sticky bit from /tmp.
# /tmp should be mode 1777 (sticky bit + world-writable).
# Without the sticky bit, any user can delete or rename files owned by other users.
RUN chmod 777 /tmp

# Create test users
RUN useradd -m -s /bin/bash alice && \
    useradd -m -s /bin/bash bob


CMD ["sleep", "infinity"]
