# =====================================================================
# lab/wireguard — WireGuard server bằng wireguard-go (USERSPACE) +
# wireguard-tools (`wg`/`wg show`). Validate LIVE driver V.3 WireGuard
# của TqkLibrary (Drivers.WireGuard / protocol WireGuard) — Noise_IKpsk2
# + data type-4 + rekey + cookie, interop với `wg` thật.
#
# Vì sao wireguard-go (KHÔNG kernel module): VM host KHÔNG có module
# `wireguard` (modprobe cần sudo password — không passwordless). userspace
# wireguard-go CHỈ cần /dev/net/tun + NET_ADMIN trong netns container ⇒
# AN TOÀN (không phá mạng VM, không cần kernel module), đúng pattern
# lab ikev2-native (NET_ADMIN trong netns, KHÔNG host-net/privileged-host).
#
# `wg show` cho phép quan sát interop: `latest handshake`, `transfer:
# X received, Y sent` — bằng chứng handshake + data 2 chiều với client.
# =====================================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools \
        wireguard-go \
        iproute2 \
        iptables \
        iputils-ping \
        socat \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# WireGuard data plane UDP/51820 (mặc định). KHÔNG publish ra ngoài: test nội bộ bridge.
EXPOSE 51820/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
