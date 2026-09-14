FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917

ENV DEBIAN_FRONTEND=noninteractive
# Debian 11 reached EOL: bullseye-security packages were removed from the live
# mirror and have not been ingested into archive.debian.org. snapshot pins the
# point-in-time state so this image rebuilds with the versions it was built on.
# The date must be AT OR AFTER the pinned base image (2026-08-24); an earlier
# snapshot offers older packages than the base already carries and apt fails with
# "held broken packages" rather than downgrading.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20260901T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20260901T000000Z bullseye-security main\n' > /etc/apt/sources.list

RUN apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y knockd && apt-get clean && rm -rf /var/lib/apt/lists/*

# Insecure knockd config (VULNERABLE)
RUN echo "[options]" > /etc/knockd.conf && \
    echo "    logfile = /var/log/knockd.log" >> /etc/knockd.conf && \
    echo "" >> /etc/knockd.conf && \
    echo "[openSSH]" >> /etc/knockd.conf && \
    echo "    sequence = 1000,2000,3000" >> /etc/knockd.conf && \
    echo "    seq_timeout = 30" >> /etc/knockd.conf && \
    echo "    command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT" >> /etc/knockd.conf && \
    echo "    tcpflags = syn" >> /etc/knockd.conf


# Boot wrapper: start knockd in the background, then hand PID 1 to sleep so a
# solution can restart knockd without killing the container (see .preserve-cmd).
CMD ["/bin/bash", "-c", "knockd & exec sleep infinity"]
