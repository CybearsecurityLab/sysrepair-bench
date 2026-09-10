FROM --platform=linux/amd64 roundcube/roundcubemail@sha256:244dc88b1e6dcfe2122d4b484230dd988c78857d8767c9798bcadd7a9b0371ca

# Roundcube 1.6.3 is vulnerable to stored XSS via SVG elements embedded in
# HTML emails (CVE-2023-5631). This version cannot be replaced by upgrade;
# compensating controls (CSP headers, SVG stripping) are required.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*


COPY apache2-preserve /usr/local/bin/apache2-preserve
RUN chmod +x /usr/local/bin/apache2-preserve

EXPOSE 80

# Boot wrapper (see .preserve-cmd): the command name starts with "apache2" so the
# image ENTRYPOINT still runs its first-boot docroot setup, then execs this
# wrapper, which starts Apache in the BACKGROUND and execs `sleep infinity` so
# PID 1 is the wrapper. Roundcube (no CSP header) is already serving on :80 when
# the agent starts, and reloading/restarting Apache cannot kill the container.
CMD ["apache2-preserve"]
