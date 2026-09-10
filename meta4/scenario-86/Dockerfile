FROM --platform=linux/amd64 hashicorp/vault@sha256:4ae5db972c9959e344dc64493b4684f75692ce4f8431177f358c66e6905244fd

# HashiCorp Vault 1.13.3 with a file backend and no seal stanza.
# Secrets are written to disk unencrypted — any OS-level read of /vault/data
# exposes plaintext secret material, bypassing Vault's access controls.

USER root

RUN apk add --no-cache bash curl coreutils

RUN mkdir -p /vault/data /vault/config && chmod 755 /vault/data

COPY vault.hcl /vault/config/vault.hcl

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 8200

ENV VAULT_ADDR=http://127.0.0.1:8200

# Boot Vault via a wrapper that keeps PID 1 as `sleep infinity`.
ENTRYPOINT []
CMD ["/opt/start.sh"]
