FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN mkdir -p /tmp/staging /var/tmp/staging && chmod 777 /tmp/staging /var/tmp/staging
RUN printf '#!/bin/bash\necho "exploit"' > /tmp/staging/exploit.sh && chmod 755 /tmp/staging/exploit.sh
CMD ["/bin/bash"]
