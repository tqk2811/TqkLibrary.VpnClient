# =====================================================================
# lab/openvpn — OpenVPN community server (tự host) để VALIDATE LIVE driver
# V.2 OpenVPN của TqkLibrary (Drivers.OpenVpn / protocol OpenVpn): interop
# thật, có kiểm soát cipher/transport/mode (khác VPN Gate chỉ UDP/CBC NCP-less).
#
# Vì sao container (KHÔNG host-net/privileged-host) — giống lab ikev2/wireguard:
#   - OpenVPN tạo TUN/TAP trong netns container (CHỈ cần /dev/net/tun + NET_ADMIN),
#     KHÔNG đụng mạng VM, KHÔNG cần kernel module riêng.
#   - 2 container cùng bridge 'labnet' -> client gửi gói OpenVPN (UDP/TCP) tới
#     server qua tên service. KHÔNG publish cổng ra ngoài: test nội bộ bridge.
#
# Server sinh CA + server-cert + client-cert (easy-rsa) lúc khởi động, build
# config theo biến môi trường (PROTO=udp|tcp, DEV=tun|tap, CIPHER=AES-256-GCM...),
# rồi viết file .ovpn INLINE (ca/cert/key) ra volume chung /shared để demo .NET
# đọc qua --vpn /shared/client.ovpn (driver tự nạp cert/key inline).
# =====================================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openvpn \
        easy-rsa \
        openssl \
        iproute2 \
        iptables \
        iputils-ping \
        socat \
        tcpdump \
        python3 \
        dnsmasq \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# OpenVPN mặc định UDP/1194 (ta dùng 1194). KHÔNG publish ra ngoài: test nội bộ bridge.
EXPOSE 1194/udp 1194/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
