FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917

ENV DEBIAN_FRONTEND=noninteractive
# Debian 11 reached EOL: bullseye-security packages were removed from the live
# mirror and have not been ingested into archive.debian.org. snapshot pins the
# point-in-time state so this image rebuilds with the versions it was built on.
# The date must be AT OR AFTER the pinned base image (2026-08-24); an earlier
# snapshot offers older packages than the base already carries and apt fails with
# "held broken packages" rather than downgrading.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20260901T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20260901T000000Z bullseye-security main\n' > /etc/apt/sources.list

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y apache2 openssl ssl-cert && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Generate self-signed certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/apache-selfsigned.key \
    -out /etc/ssl/certs/apache-selfsigned.crt \
    -subj "/CN=localhost"

RUN a2enmod ssl

# Configure SSL with DEPRECATED protocols (VULNERABLE)
RUN printf '<VirtualHost *:443>\n\
    ServerName localhost\n\
    SSLEngine on\n\
    SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt\n\
    SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key\n\
    SSLProtocol all\n\
    SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW\n\
    DocumentRoot /var/www/html\n\
</VirtualHost>\n' > /etc/apache2/sites-available/default-ssl.conf

RUN a2ensite default-ssl

EXPOSE 80 443

# Boot the vulnerable apache (SSLProtocol all, weak ciphers on :443) then hold
# the container open with `exec sleep infinity`. Paired with `.preserve-cmd`.
#   1. httpd must ALREADY be serving TLS when the agent starts, so a config-only
#      fix that never restarts apache still fails verify.sh.
#   2. PID 1 is `sleep infinity`, not httpd, so restarting apache cannot kill
#      the container.
CMD ["/bin/bash", "-c", "apachectl start && exec sleep infinity"]
