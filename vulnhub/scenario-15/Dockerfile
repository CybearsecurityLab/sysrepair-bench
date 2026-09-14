FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
# Debian 11 reached EOL: bullseye-security packages were removed from the live
# mirror and have not been ingested into archive.debian.org. snapshot pins the
# point-in-time state so this image rebuilds with the versions it was built on.
# The date must be AT OR AFTER the pinned base image (2026-08-24); an earlier
# snapshot offers older packages than the base already carries and apt fails with
# "held broken packages" rather than downgrading.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20260901T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20260901T000000Z bullseye-security main\n' > /etc/apt/sources.list
RUN apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y exim4-daemon-light iptables && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN sed -i "s/dc_local_interfaces=.*/dc_local_interfaces='0.0.0.0'/" /etc/exim4/update-exim4.conf.conf && update-exim4.conf
EXPOSE 25

# Boot the vulnerable exim daemon (listening on 0.0.0.0:25) in the BACKGROUND,
# then hold the container open with `exec sleep infinity`. Paired with the
# `.preserve-cmd` marker so the harness keeps this CMD.
#   1. exim must ALREADY BE LISTENING on all interfaces when the agent starts,
#      so a config-only fix that forgets to restart still fails verify.sh.
#   2. PID 1 is `sleep infinity`, not exim, so an agent restarting exim cannot
#      kill the container. `-bd` is backgrounded with `&` for the same reason.
CMD ["/bin/bash", "-c", "/usr/sbin/exim4 -bd -q30m & for i in $(seq 1 20); do grep -qi ' 0019 ' /proc/net/tcp && break; sleep 0.5; done; exec sleep infinity"]
