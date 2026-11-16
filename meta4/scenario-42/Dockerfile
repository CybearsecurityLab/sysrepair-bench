FROM --platform=linux/amd64 couchdb@sha256:2c96232290fe0414177909bdb8c30224af32c2f8f7031d868fb832ffaac6cc4f

# CouchDB 3.2.1 with the default/known Erlang distribution cookie "monster"
# (CVE-2022-24706).  An attacker who knows the cookie connects to EPMD (4369)
# and the distribution port and runs arbitrary Erlang terms => unauthenticated
# RCE as the couchdb user.
#
# NOTE (scenario fix): the upstream couchdb:3.2.1 image does NOT actually ship
# "-setcookie monster" in vm.args (the file has no -setcookie line at all, so
# Erlang auto-generates a random, non-guessable cookie) and does NOT run a
# distributed node by default (no -name => no EPMD, no distribution port).  The
# original Dockerfile's conditional sed matched nothing, so the built image was
# NOT vulnerable.  We now explicitly bake the vulnerable state: the known
# "monster" cookie AND a distributed node name (as a real clustered CouchDB
# deployment runs), which together expose the CVE-2022-24706 attack surface.

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

# CouchDB 3.x refuses to boot without an admin ("No Admin Account Found"), so an
# admin is required merely to run the node.  The cookie — not this credential —
# is the vulnerability under test.
RUN printf '\n[admins]\nadmin = adminpw\n' > /opt/couchdb/etc/local.d/admin.ini

# Bake the vulnerable Erlang distribution: known cookie + distributed node name.
RUN { grep -qE '^-setcookie' /opt/couchdb/etc/vm.args \
        && sed -i 's/^-setcookie .*/-setcookie monster/' /opt/couchdb/etc/vm.args \
        || echo '-setcookie monster' >> /opt/couchdb/etc/vm.args; } && \
    grep -qE '^-name' /opt/couchdb/etc/vm.args \
        || echo '-name couchdb@127.0.0.1' >> /opt/couchdb/etc/vm.args && \
    grep -q monster /opt/couchdb/etc/vm.args && \
    chown -R couchdb:couchdb /opt/couchdb/etc

EXPOSE 5984 4369 9100

# Boot wrapper (paired with .preserve-cmd).  $1 is /bin/bash so the image
# entrypoint skips its couchdb setup and execs this wrapper; we start couchdb
# ourselves (backgrounded, as the couchdb user) so the daemon is already running
# with the monster cookie when the agent starts, and PID 1 stays sleep infinity
# so restarting couchdb never kills the container.  The fix must change the
# cookie AND restart couchdb for the new cookie to take effect.
CMD ["/bin/bash", "-c", "chown -R couchdb:couchdb /opt/couchdb/etc /opt/couchdb/data 2>/dev/null; gosu couchdb /opt/couchdb/bin/couchdb >/tmp/couchdb.log 2>&1 & for i in $(seq 1 60); do [ \"$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5984/_up 2>/dev/null)\" = 200 ] && break; sleep 1; done; exec sleep infinity"]
