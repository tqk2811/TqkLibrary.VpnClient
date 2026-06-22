# strongSwan trên ubuntu:24.04 — IKEv1 PSK cho L2TP/IPsec (transport mode) + IKEv2.
#
# ⚠️ BẢN NHÁP: có thể thay bằng image dựng sẵn (vd `strongx509/strongswan`,
#    hoặc `hwdsl2/ipsec-vpn-server`) — nhưng image cộng đồng thường gói SẴN xl2tpd
#    + chính sách NAT-T cứng, khó cấu hình no-NAT cho P0.8c. Tự dựng để kiểm soát.
#    Lab này dùng strongSwan "legacy" ipsec.conf/starter (charon) — bản 5.9.x của
#    Ubuntu 24.04 vẫn hỗ trợ. (swanctl/vici là hướng mới; nếu gói bỏ starter,
#    chuyển ipsec.conf -> swanctl.conf — xem ghi chú cuối file.)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      strongswan \
      strongswan-pki \
      libcharon-extra-plugins \
      libstrongswan-extra-plugins \
      iproute2 \
      iptables \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY ipsec.conf    /etc/ipsec.conf
COPY ipsec.secrets /etc/ipsec.secrets
COPY strongswan.conf /etc/strongswan.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 600 /etc/ipsec.secrets \
 && chmod +x /usr/local/bin/entrypoint.sh

# IKE 500/udp, NAT-T 4500/udp, ESP proto-50 (không phải cổng — cần host networking)
EXPOSE 500/udp 4500/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ---------------------------------------------------------------------
# Nếu bản strongSwan bỏ 'ipsec'/starter (chỉ còn charon-systemd + swanctl):
#   - đổi ipsec.conf -> /etc/swanctl/conf.d/lab.conf (cú pháp swanctl khác),
#     ipsec.secrets -> swanctl secrets block,
#   - entrypoint chạy: charon &  rồi  swanctl --load-all
# ---------------------------------------------------------------------
