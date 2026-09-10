FROM ubuntu@sha256:e0b84ef30bbe766773e6056c60a3e706712e4119508e3da12516f1eddd6f761b
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Basic system with no auditd installed or configured
# This violates CIS benchmarks requiring system auditing
RUN apt-get update && apt-get install -y \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Ensure auditd is not installed (default state - no audit framework)
# No audit rules, no logging of security-relevant events


CMD ["sleep", "infinity"]
