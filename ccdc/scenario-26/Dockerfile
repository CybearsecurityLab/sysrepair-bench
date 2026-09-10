FROM ubuntu@sha256:e0b84ef30bbe766773e6056c60a3e706712e4119508e3da12516f1eddd6f761b
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    ncat \
    hydra \
    john \
    nikto \
    procps \
    curl \
    wget \
    iputils-ping \
    iproute2 \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*


CMD ["sleep", "infinity"]
