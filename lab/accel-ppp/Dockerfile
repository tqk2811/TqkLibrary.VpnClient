# accel-ppp trên ubuntu:24.04 — SSTP + L2TP + PPTP, BẬT IPv6 (RA/SLAAC trên ppp).
#
# ⚠️ BẢN NHÁP: gói `accel-ppp` có trong universe của Ubuntu 24.04 (kiểm tra lại tên
#    gói/phiên bản lúc build: `apt-cache policy accel-ppp`). Nếu apt không có hoặc
#    bản quá cũ thiếu module sstp/ipv6, phải build từ source accel-ppp
#    (https://github.com/accel-ppp/accel-ppp) — xem ghi chú "NÂNG CAO" cuối file.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      accel-ppp \
      openssl \
      iproute2 \
      iputils-ping \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Thư mục cert SSTP (mount volume ở compose để persist).
RUN mkdir -p /etc/accel-ppp/certs

COPY accel-ppp.conf /etc/accel-ppp.conf
COPY chap-secrets   /etc/ppp/chap-secrets
COPY entrypoint.sh  /usr/local/bin/entrypoint.sh
RUN chmod 600 /etc/ppp/chap-secrets \
 && chmod +x /usr/local/bin/entrypoint.sh

# SSTP 443/tcp, PPTP 1723/tcp, L2TP 1701/udp (network_mode: host nên EXPOSE chỉ mang tính tài liệu)
EXPOSE 443/tcp 1723/tcp 1701/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ---------------------------------------------------------------------
# NÂNG CAO — nếu apt không có accel-ppp đủ tính năng, build từ source:
#   apt-get install -y build-essential cmake gcc linux-headers-generic \
#       libpcre3-dev libssl-dev liblua5.3-dev pkg-config git
#   git clone https://github.com/accel-ppp/accel-ppp /tmp/accel
#   cmake -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE \
#         -DCMAKE_INSTALL_PREFIX=/usr -DKDIR=... -DLUA=TRUE /tmp/accel && make && make install
#   (đường dẫn binary/khởi động có thể khác: /usr/sbin/accel-pppd)
# ---------------------------------------------------------------------
