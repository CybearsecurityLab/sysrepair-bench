FROM --platform=linux/amd64 localstack/localstack@sha256:73698e485240939490134aadd7e429ac87ff068cd5ad09f5de8ccb76727c13e1

# AWS SNS Open Topic (misconfig)
# The SNS topic "app-debug-events" publishes internal debug data and has an
# open access policy allowing any authenticated AWS principal to subscribe.
# This lets unauthorized accounts receive sensitive debug payloads.

USER root

COPY init-sns-open-topic.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 4566

# Boot LocalStack via a wrapper that keeps PID 1 as `sleep infinity`.
ENTRYPOINT []
CMD ["/opt/start.sh"]
