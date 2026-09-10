FROM --platform=linux/amd64 rancher/k3s@sha256:47d01d1f6b7f10c9f3a929e6c3dca332fb65a3986881c2fb27ff079a995bd14d

# K8s Network Security misconfiguration: internal service exposed via NodePort
# (30000+) making it reachable from outside the cluster on all node IPs,
# rather than being restricted to ClusterIP (cluster-internal only).

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
# rancher/k3s ships NO /etc/passwd, so `docker exec -u root` fails with
# "unable to find user root: no matching entries in passwd file".
# inspect's sandbox-tool injection execs as root, so every k3s scenario
# errored out unscored in a real eval while the gate runner passed them --
# it does not exec as a named user. Found only by running the harness.
RUN echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd \
 && echo 'root:x:0:' > /etc/group \
 && chmod +x /opt/start.sh

EXPOSE 6443

ENTRYPOINT []
CMD ["/opt/start.sh"]
