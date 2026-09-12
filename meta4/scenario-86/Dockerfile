FROM --platform=linux/amd64 hashicorp/vault@sha256:820bd0930e073d2e07248b4d19b2b05abd32713bfebeef594bfd9720a044a266

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
