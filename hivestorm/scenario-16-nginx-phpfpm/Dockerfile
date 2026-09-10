# Hivestorm scenario-16 — Debian 12 + nginx + PHP-FPM free-roam.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 16 --seed $RANDOM \
#     --out hivestorm/scenario-16-nginx-phpfpm/build/roles.json \
#     --render-task hivestorm/scenario-16-nginx-phpfpm/task.md
#   docker build hivestorm/scenario-16-nginx-phpfpm
#
# Scored surface: nginx location/fastcgi config, php.ini toggles, pool user,
# PHP-FPM socket perms, sshd/account hygiene.

FROM debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

ARG DEBIAN_FRONTEND=noninteractive

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh /usr/local/sbin/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
 && chmod 0755 /usr/local/sbin/seed.sh \
 && /usr/local/sbin/seed.sh \
 && rm -f /usr/local/sbin/seed.sh

EXPOSE 22 80

CMD ["/usr/local/sbin/hs-start.sh"]
