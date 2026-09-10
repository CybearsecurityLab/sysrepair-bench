FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y screen && apt-get clean && rm -rf /var/lib/apt/lists/*
# Set SUID bit on screen (VULNERABLE)
RUN chmod u+s /usr/bin/screen
CMD ["/bin/bash"]
