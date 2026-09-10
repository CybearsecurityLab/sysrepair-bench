FROM ubuntu@sha256:e0b84ef30bbe766773e6056c60a3e706712e4119508e3da12516f1eddd6f761b
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    redis-server \
    redis-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Configure Redis insecurely: bind to all interfaces with no authentication
RUN sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf && \
    sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf

# Ensure no requirepass is set (remove any existing requirepass line)
RUN sed -i '/^requirepass/d' /etc/redis/redis.conf

# Entrypoint: boot the vulnerable Redis, then hold the container open with
# `exec sleep infinity` (paired with the `.preserve-cmd` marker). `exec` keeps
# PID 1 stable, so an agent restarting redis-server cannot kill the container,
# and Redis is already listening on 0.0.0.0 with no auth when the agent starts.
RUN printf '#!/bin/bash\nredis-server /etc/redis/redis.conf --daemonize yes\nexec sleep infinity\n' > /entrypoint.sh && \
    chmod +x /entrypoint.sh


CMD ["/entrypoint.sh"]
