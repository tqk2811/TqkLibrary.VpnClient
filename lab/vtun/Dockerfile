# vtund 3.0.4 (apt) server image for the V.11 live lab. vtun is the legacy "VTun" tunnel daemon by Maxim Krasnyansky.
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    vtun iproute2 iputils-ping tcpdump procps net-tools >/dev/null \
    && rm -rf /var/lib/apt/lists/*
RUN vtund -h 2>&1 | head -1 || true
