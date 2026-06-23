# =====================================================================
# lab/sstp-pppd — SSTP server bằng pppd CHUẨN (sorz/sstp-server, Python) + radvd.
#
# Mục đích: validate LIVE P1.1 (IPv6-over-PPP / SLAAC) cho client SSTP của repo.
# Vì accel-ppp trong lab bị HỎNG PPP network-phase (không bao giờ gửi IPCP
# ConfReq, ProtoRej mọi gói NCP của client — lỗi FSM userspace accel-ppp),
# ta dựng setup MỚI riêng dùng pppd CHUẨN (FSM khác accel-ppp) để chứng minh
# client repo đúng end-to-end và lấy được IPv6 global qua RA/SLAAC trên ppp.
#
# crypto binding: sstp-server CHỈ verify khi có sstp-pppd-plugin.so. Ở đây
# KHÔNG cài plugin ⇒ server BỎ QUA crypto binding (client vẫn gửi, server
# accept Call-Connected). Đủ để validate PPP network-phase + IPv6.
#
# An toàn: chạy BRIDGED (KHÔNG host-net, KHÔNG privileged). Chỉ cần NET_ADMIN
# (tạo ppp interface trong netns container) + NET_RAW (radvd gửi ICMPv6 RA) +
# /dev/ppp. SSTP là TLS/TCP thuần ⇒ không cần IPsec/strongSwan.
# =====================================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ppp \
        radvd \
        openssl \
        iproute2 \
        iptables \
        tcpdump \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# sstp-server (sorz) yêu cầu Python 3.12+ — Ubuntu 24.04 có sẵn 3.12.
# Cài trong venv (PEP 668: Ubuntu 24.04 chặn pip vào system Python).
RUN python3 -m venv /opt/sstp \
    && /opt/sstp/bin/pip install --no-cache-dir sstp-server

# pppd options dùng chung cho mọi phiên SSTP (sstp-server truyền qua --pppd-config).
COPY options.sstpd /etc/ppp/options.sstpd
# chap-secrets: user 'vpn' pass 'vpn', mọi IP ('*').
COPY chap-secrets /etc/ppp/chap-secrets
# Hook IPv6: khi IPV6CP lên, pppd chạy /etc/ppp/ipv6-up.d/* → cấu hình + (re)start radvd
# trên interface ppp động để quảng bá prefix global ULA fd00:dead:beef::/64 (SLAAC).
COPY ipv6-up.sh /etc/ppp/ipv6-up.d/00-radvd
COPY ipv6-down.sh /etc/ppp/ipv6-down.d/00-radvd
COPY radvd.conf.tmpl /etc/radvd.conf.tmpl
COPY entrypoint.sh /entrypoint.sh

RUN chmod 600 /etc/ppp/chap-secrets \
    && chmod +x /etc/ppp/ipv6-up.d/00-radvd /etc/ppp/ipv6-down.d/00-radvd /entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["/entrypoint.sh"]
