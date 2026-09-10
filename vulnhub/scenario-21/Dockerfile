FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y cron && apt-get clean && rm -rf /var/lib/apt/lists/*
# Root cron executes from /tmp (VULNERABLE)
RUN printf '#!/bin/bash\necho "cleanup" > /dev/null' > /tmp/cleanup.sh && chmod 755 /tmp/cleanup.sh
RUN echo "* * * * * root /tmp/cleanup.sh" > /etc/cron.d/vulnerable-cleanup
# Boot wrapper: start the cron daemon, then exec sleep as PID 1 (see .preserve-cmd).
CMD ["/bin/bash", "-c", "cron; exec sleep infinity"]
