FROM --platform=linux/amd64 apache/superset@sha256:ca32ff641daca7447edfe78345e1abbc3b278895b1d4a245e69e28020e3310b7

# Apache Superset 2.0.0 — CVE-2023-27524: Hardcoded default SECRET_KEY.
# The default SECRET_KEY used to sign Flask sessions is publicly known.
# An attacker can forge a valid session cookie granting admin access without
# any credentials.

USER root

# Debian 11 reached EOL: bullseye-security packages were removed from the live
# mirror (404) and have not been ingested into archive.debian.org. snapshot pins
# the point-in-time state, as in the vulnhub suite. The date must be AT OR AFTER
# the pinned base image, or apt refuses to downgrade.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20260901T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20260901T000000Z bullseye-security main\n' > /etc/apt/sources.list && \
    rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Vulnerable default config — ships with a known SECRET_KEY
RUN echo "SECRET_KEY = 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET'" >> /app/pythonpath/superset_config.py


EXPOSE 8088

# Boot Superset (which signs Flask sessions with the vulnerable default
# SECRET_KEY loaded at startup) in the background, then hold the container open
# with `exec sleep infinity` so gunicorn is never PID 1. Paired with the
# `.preserve-cmd` marker. SECRET_KEY is read only at process start, so editing
# superset_config.py without restarting Superset leaves the running process
# trusting cookies forged with the old key - the not-restarted case is real.
CMD ["bash", "-c", "/usr/bin/run-server.sh >/tmp/superset.log 2>&1 & exec sleep infinity"]
