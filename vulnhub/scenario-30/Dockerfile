FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y libcap2-bin python3 findutils && apt-get clean && rm -rf /var/lib/apt/lists/*
# Set dangerous capabilities (VULNERABLE)
RUN setcap cap_dac_read_search+ep /usr/bin/python3.7 2>/dev/null; \
    setcap cap_setuid+ep /usr/bin/find 2>/dev/null; true
CMD ["/bin/bash"]
