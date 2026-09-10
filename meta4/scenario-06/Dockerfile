FROM --platform=linux/amd64 maven@sha256:37a94a4fe3b52627748d66c095d013a17d67478bc0594236eca55c8aef33ddaa AS build

# Spring Cloud Function 3.2.2 SpEL injection — CVE-2022-22963.
# The routing function evaluates the spring.cloud.function.routing-expression
# HTTP header as a SpEL expression without sandboxing, yielding unauth RCE.
#
# This builds a real Spring Boot + Spring Cloud Function app exposing
# /functionRouter with two bean functions (uppercase, reverse). The
# routing-expression header is the exploit surface.

WORKDIR /src
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src src
RUN mvn package -DskipTests -B

# ---------- runtime ----------
FROM --platform=linux/amd64 eclipse-temurin@sha256:01f14fc6a7240137b0a0b13de7a17afcc6983b46e7c42389ce1e00e6319d3bed
COPY --from=build /src/target/scf-demo.jar /opt/app/app.jar

EXPOSE 8080

# .preserve-cmd: boot the app in the BACKGROUND (vulnerable JVM already running
# when the agent starts, so "swapped jars but never restarted" is detectable)
# and keep PID 1 as `sleep infinity` so restarting the app cannot kill the
# container. App output -> /var/log/app.log.
CMD ["/bin/bash","-c","java -jar /opt/app/app.jar >/var/log/app.log 2>&1 & exec sleep infinity"]
