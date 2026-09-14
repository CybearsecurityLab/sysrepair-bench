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
    apt-get install -y mariadb-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure MySQL with NO secure_file_priv (VULNERABLE)
RUN echo "[mysqld]\nsecure_file_priv=" >> /etc/mysql/mariadb.conf.d/99-vulnerable.cnf

RUN service mariadb start && \
    mysql -e "CREATE DATABASE webapp;" && \
    mysql -e "CREATE USER 'webuser'@'localhost' IDENTIFIED BY 'webpass';" && \
    mysql -e "GRANT ALL ON webapp.* TO 'webuser'@'localhost';" && \
    mysql -e "GRANT FILE ON *.* TO 'webuser'@'localhost';" && \
    service mariadb stop

EXPOSE 3306

# Boot MariaDB (with secure_file_priv unset) in the background, wait for the
# socket, then hold the container open. Paired with .preserve-cmd so:
#   1. the DB is ALREADY running with the unrestricted config when the agent
#      starts - secure_file_priv is a start-up-only variable, so a config edit
#      that never restarts mariadb still fails verify.sh;
#   2. PID 1 is `sleep infinity`, not mysqld, so restarting the DB cannot kill
#      the container.
CMD ["/bin/bash", "-c", "mysqld_safe & for i in $(seq 1 60); do [ -S /run/mysqld/mysqld.sock ] && break; sleep 0.5; done; exec sleep infinity"]
