FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y exim4-daemon-light && apt-get clean && rm -rf /var/lib/apt/lists/*
# Set SUID bit (VULNERABLE)
RUN chmod u+s /usr/sbin/exim4
EXPOSE 25
CMD ["/usr/sbin/exim4", "-bd", "-q30m"]
