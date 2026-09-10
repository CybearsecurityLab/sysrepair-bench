FROM --platform=linux/amd64 debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

# S7comm simulator listening on 0.0.0.0:102 with no authentication.
# The Siemens S7 protocol has no native auth — any client can read/write PLC memory.
# Remediation: iptables restrict port 102 to engineering workstation IP.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        iptables iproute2 netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY s7_server.py /opt/s7_server.py

EXPOSE 102

# Boot wrapper (see .preserve-cmd): start the S7 simulator in the BACKGROUND
# then exec `sleep infinity` so PID 1 is the wrapper, keeping the vulnerable
# service listening while a solution's firewall rules cannot kill the container.
CMD ["/bin/bash", "-c", "python3 /opt/s7_server.py & exec sleep infinity"]
