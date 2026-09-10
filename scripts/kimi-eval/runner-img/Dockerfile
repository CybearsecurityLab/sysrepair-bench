FROM ubuntu@sha256:281c5745f657873d78e5531fc5ba8575f46ab7769b94550ac99543f122679986
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bash coreutils curl && rm -rf /var/lib/apt/lists/*
COPY bin/kimi /usr/local/bin/kimi
RUN chmod +x /usr/local/bin/kimi
ENV HOME=/root
WORKDIR /work
