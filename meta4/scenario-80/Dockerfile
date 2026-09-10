FROM --platform=linux/amd64 localstack/localstack@sha256:73698e485240939490134aadd7e429ac87ff068cd5ad09f5de8ccb76727c13e1

# AWS IAM Policy Version Rollback (design flaw)
# An IAM managed policy has multiple versions: v1 is restrictive (default)
# but v2 grants full admin ("*:*"). Any principal with iam:SetDefaultPolicyVersion
# can silently escalate to admin by switching the default back to v2.

USER root

COPY init-iam-policy-rollback.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 4566

# Boot LocalStack via a wrapper that keeps PID 1 as `sleep infinity`.
ENTRYPOINT []
CMD ["/opt/start.sh"]
