FROM --platform=linux/amd64 memcached@sha256:db45886d2d48f143be64f2d46407e224b0b61df3b0056b9d5b03e8bc6a7cd74e

# Memcached 1.6.17 started with the default command listens on UDP port 11211,
# enabling a ~50,000x DDoS amplification attack (CVE-2018-1000115 / CWE-406).
# The vulnerable state: UDP enabled, listening on all interfaces.

USER root

# Debian 11 reached EOL: bullseye-security packages were removed from the live
# mirror (404) and have not been ingested into archive.debian.org. snapshot pins
# the point-in-time state, as in the vulnhub suite. The date must be AT OR AFTER
# the pinned base image, or apt refuses to downgrade.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20260901T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20260901T000000Z bullseye-security main\n' > /etc/apt/sources.list && \
    rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        netcat-openbsd \
        && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 11211/tcp
EXPOSE 11211/udp

# Vulnerable state: UDP listener EXPLICITLY enabled (-U 11211). memcached 1.6.x
# ships with UDP OFF by default (-U 0), so the bare `memcached -u memcache`
# command is NOT vulnerable — the amplification port must be turned on to
# recreate CVE-2018-1000115.
# Boot wrapper (paired with .preserve-cmd): start memcached in the BACKGROUND
# then exec `sleep infinity` so PID 1 is the sleep and restarting memcached
# cannot kill the container, which makes the "fixed but not restarted" case
# detectable. NOT a bare foreground CMD.
CMD ["/bin/bash","-c","memcached -u memcache -l 0.0.0.0 -p 11211 -U 11211 & exec sleep infinity"]
