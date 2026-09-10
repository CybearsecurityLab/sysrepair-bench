# Hivestorm HS21 — Ubuntu 18.04 + Samba free-roam scenario.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 07 --seed $RANDOM \
#       --out hivestorm/scenario-07-ubuntu1804-samba/build/roles.json \
#       --render-task hivestorm/scenario-07-ubuntu1804-samba/task.md
#   docker build hivestorm/scenario-07-ubuntu1804-samba

FROM ubuntu@sha256:dca176c9663a7ba4c1f0e710986f5a25e672842963d95b960191e2d9f7185ebe

ARG DEBIAN_FRONTEND=noninteractive

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh /usr/local/sbin/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
 && chmod 0755 /usr/local/sbin/seed.sh \
 && /usr/local/sbin/seed.sh \
 && rm -f /usr/local/sbin/seed.sh

EXPOSE 22 139 445

CMD ["/usr/local/sbin/hs-start.sh"]
