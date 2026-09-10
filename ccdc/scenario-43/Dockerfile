FROM ubuntu@sha256:e0b84ef30bbe766773e6056c60a3e706712e4119508e3da12516f1eddd6f761b
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Create a backdoor user with UID 0 (same as root).
# This gives the "backdoor" user full root privileges, bypassing
# normal access controls and audit trails.
RUN useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor && \
    echo "backdoor:backdoor123" | chpasswd

# Create a normal test user
RUN useradd -m -s /bin/bash testuser


CMD ["sleep", "infinity"]
