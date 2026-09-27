FROM --platform=linux/amd64 debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

# Postfix 3.7 ships with default bare-LF handling that allows SMTP smuggling.
# An attacker can inject additional email messages past SPF/DKIM checks by
# embedding bare newlines (LF without CR) in the message body.

RUN apt-get update && \
    apt-get install -y --no-install-recommends postfix curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# The noninteractive install leaves no /etc/mailname (which mydestination
# references) and no alias database, so every local recipient fails with
# "451 4.3.0 Temporary lookup failure": no message is ever queued, the smuggling
# probe reads as blocked, and legitimate mail is refused on an untouched host.
RUN echo localhost > /etc/mailname && newaliases


EXPOSE 25

# Boot wrapper (see .preserve-cmd): start the Postfix master in the BACKGROUND
# (`postfix start` daemonizes) then exec `sleep infinity` so PID 1 is the
# wrapper. The vulnerable SMTP service is already listening on :25 when the agent
# starts, and a solution that reloads/restarts Postfix cannot kill the container.
CMD ["/bin/bash", "-c", "postfix start && exec sleep infinity"]
