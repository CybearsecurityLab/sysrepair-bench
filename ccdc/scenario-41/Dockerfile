FROM ubuntu@sha256:e0b84ef30bbe766773e6056c60a3e706712e4119508e3da12516f1eddd6f761b
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Set SUID bit on python3 and perl interpreters.
# This allows any local user to execute scripts with root privileges,
# enabling trivial privilege escalation.
RUN chmod u+s /usr/bin/python3* /usr/bin/perl

# Create a non-root test user
RUN useradd -m -s /bin/bash testuser


CMD ["sleep", "infinity"]
