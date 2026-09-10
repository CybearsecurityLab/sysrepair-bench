FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y gcc && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN printf '#include <stdlib.h>\nint main() { system("curl http://localhost/status"); return 0; }' > /tmp/statuscheck.c && \
    gcc -o /usr/local/bin/statuscheck /tmp/statuscheck.c && \
    chmod u+s /usr/local/bin/statuscheck && rm /tmp/statuscheck.c
CMD ["/bin/bash"]
