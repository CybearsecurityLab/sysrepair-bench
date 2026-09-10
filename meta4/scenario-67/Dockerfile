FROM --platform=linux/amd64 debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

# BACnet/IP server on UDP 0.0.0.0:47808 with no authentication.
# Building automation protocol with no native auth — a protocol design flaw.
# Remediation: iptables restrict UDP 47808 to BMS subnet.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        iptables iproute2 netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY bacnet_server.py /opt/bacnet_server.py

EXPOSE 47808/udp

# Boot wrapper (see .preserve-cmd): start the BACnet simulator in the BACKGROUND
# then exec `sleep infinity` so PID 1 is the wrapper, keeping the vulnerable
# service listening while a solution's firewall rules cannot kill the container.
CMD ["/bin/bash", "-c", "python3 /opt/bacnet_server.py & exec sleep infinity"]
