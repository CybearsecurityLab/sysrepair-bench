FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
# Debian 11 reached EOL: bullseye-security packages were removed from the live
# mirror and have not been ingested into archive.debian.org. snapshot pins the
# point-in-time state so this image rebuilds with the versions it was built on.
# The date must be AT OR AFTER the pinned base image (2026-08-24); an earlier
# snapshot offers older packages than the base already carries and apt fails with
# "held broken packages" rather than downgrading.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20260901T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20260901T000000Z bullseye-security main\n' > /etc/apt/sources.list
RUN apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y apache2 rsyslog && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN touch /var/log/auth.log && chmod 666 /var/log/auth.log
RUN mkdir -p /var/log/apache2 && touch /var/log/apache2/access.log && chmod 666 /var/log/apache2/access.log
EXPOSE 80
# Boot wrapper: start rsyslog + apache in the background, then exec sleep as PID 1
# (see .preserve-cmd).
CMD ["/bin/bash", "-c", "rsyslogd; apachectl start; exec sleep infinity"]
