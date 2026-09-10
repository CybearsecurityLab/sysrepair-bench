FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y sudo gawk tar nmap findutils && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash bob && echo 'bob:bob123' | chpasswd
# Dangerous sudoers entries (VULNERABLE)
RUN echo "bob ALL=(root) NOPASSWD: /usr/bin/awk" >> /etc/sudoers && \
    echo "bob ALL=(root) NOPASSWD: /bin/tar" >> /etc/sudoers && \
    echo "bob ALL=(root) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers && \
    echo "bob ALL=(root) NOPASSWD: /usr/bin/find" >> /etc/sudoers
CMD ["/bin/bash"]
