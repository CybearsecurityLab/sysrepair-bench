FROM --platform=linux/amd64 quay.io/minio/minio@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2

# MinIO public bucket — anonymous read access (misconfig).
# A bucket is created with public anonymous download policy,
# allowing anyone to read its contents without authentication.

ENV MINIO_ROOT_USER=minioadmin
ENV MINIO_ROOT_PASSWORD=minioadmin

USER root
RUN microdnf install -y curl || apk add --no-cache curl 2>/dev/null || true

# The vulnerable state is SEEDED AT BUILD TIME, not at container boot. Seeding at
# boot raced the grader: under load MinIO could answer its health check before
# the bucket and its anonymous policy existed, so an untouched host read as
# "anonymous access denied". Baking the state into the image means it is present
# the moment MinIO serves its first request.
#
# The data dir is /srv/minio, not /data: the base image declares /data a VOLUME,
# and anything written there during the build is discarded.
#
# Every step fails the build loudly (no `2>/dev/null || true`), and the build
# asserts the precondition itself: an anonymous GET of the secret must return 200.
RUN set -eu; \
    mkdir -p /srv/minio; \
    minio server /srv/minio --address 127.0.0.1:9000 >/tmp/minio-build.log 2>&1 & \
    up=0; for i in $(seq 1 60); do \
        if curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null; then up=1; break; fi; \
        sleep 1; \
    done; \
    [ "$up" = 1 ] || { cat /tmp/minio-build.log; echo "MinIO did not start during build" >&2; exit 1; }; \
    mc alias set local http://127.0.0.1:9000 minioadmin minioadmin; \
    mc mb local/testbucket; \
    echo "SECRET_DATA: aws_access_key_id=AKIAIOSFODNN7EXAMPLE" | mc pipe local/testbucket/secret.txt; \
    mc anonymous set download local/testbucket; \
    code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9000/testbucket/secret.txt); \
    [ "$code" = 200 ] || { echo "precondition not met: anonymous GET returned $code, expected 200" >&2; exit 1; }; \
    mc admin service stop local || true; \
    for i in $(seq 1 30); do curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null || break; sleep 1; done; \
    rm -f /tmp/minio-build.log

RUN cat > /opt/start.sh <<'BASH'
#!/bin/sh
# Boot wrapper (see .preserve-cmd): MinIO serves the pre-seeded data dir, whose
# testbucket already carries the public download policy, and PID 1 becomes
# `sleep infinity` so a solution that restarts MinIO cannot kill the container.
minio server /srv/minio --console-address ":9001" &
exec sleep infinity
BASH
RUN chmod +x /opt/start.sh


EXPOSE 9000 9001
ENTRYPOINT ["/opt/start.sh"]
