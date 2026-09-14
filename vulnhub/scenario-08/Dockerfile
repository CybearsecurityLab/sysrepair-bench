FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
# Debian 11 reached EOL: bullseye-security packages were removed from the live
# mirror and have not been ingested into archive.debian.org. snapshot pins the
# point-in-time state so this image rebuilds with the versions it was built on.
# The date must be AT OR AFTER the pinned base image (2026-08-24); an earlier
# snapshot offers older packages than the base already carries and apt fails with
# "held broken packages" rather than downgrading.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20260901T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20260901T000000Z bullseye-security main\n' > /etc/apt/sources.list
RUN apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y apache2 libapache2-mod-php php php-mysql mariadb-server && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN service mariadb start && \
    mysql -e "CREATE DATABASE wordpress;" && \
    mysql -e "CREATE TABLE wordpress.wp_users (ID INT PRIMARY KEY, user_login VARCHAR(60), user_pass VARCHAR(255), user_email VARCHAR(100));" && \
    mysql -e "INSERT INTO wordpress.wp_users VALUES (1, 'admin', '\$P\$BhWEqSH2qDK3BNeQSa12wD3G7Z1wp4/', 'admin@local.host');" && \
    mysql -e "INSERT INTO wordpress.wp_users VALUES (2, 'editor', '\$P\$BVXxf.YpxRwQY6miGkfRdkjox3v3N7/', 'editor@local.host');" && \
    service mariadb stop
EXPOSE 80
# Boot MariaDB (holding the weak wp_users hashes) + apache, then hold the
# container open. Paired with .preserve-cmd so the DB is live for verify.sh to
# query and PID 1 stays `sleep infinity`. (The hashes are data read per query,
# so the fix needs no restart - but the DB must be up.)
CMD ["/bin/bash", "-c", "service mariadb start && apachectl start && exec sleep infinity"]
