# =====================================================================
# lab/ikev2-ppk — IKEv2 server strongSwan có PPK (RFC 8784) để VALIDATE LIVE
# driver V.1 IKEv2-native + PpkConfiguration của TqkLibrary (Drivers.Ikev2).
#
# KHÁC lab/ikev2-native:
#   - ubuntu:24.04 (strongSwan 5.9.13) — PPK (RFC 8784) chỉ có từ strongSwan
#     5.9.6 trở lên; bản 5.9.5 của 22.04 KHÔNG hỗ trợ PPK.
#   - Cấu hình bằng **swanctl.conf** (vici), KHÔNG dùng ipsec.conf/starter —
#     PPK là tính năng swanctl-only (`ppk_id`/`ppk_required` + secret `ppk`).
#   - Còn lại giữ nguyên: IKEv2 PSK + ESP tunnel + CP virtual IP pool 10.40.0.0/24,
#     khớp đề xuất của IkeClient (aes256-sha256-modp2048 / esp aes256-sha256+gcm16).
#
# An toàn: chạy trên bridge tùy biến (KHÔNG host-net, KHÔNG privileged-host)
# ⇒ strongSwan đụng XFRM chỉ trong netns container, không phá mạng VM.
# =====================================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-swanctl \
        libcharon-extra-plugins \
        libstrongswan-extra-plugins \
        iproute2 \
        iptables \
        tcpdump \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- swanctl config (IKEv2 PSK + PPK + ESP tunnel + CP virtual IP) ---
COPY strongswan.conf /etc/strongswan.conf
COPY swanctl.conf    /etc/swanctl/swanctl.conf
COPY entrypoint.sh   /usr/local/bin/entrypoint.sh

RUN chmod 600 /etc/swanctl/swanctl.conf \
    && chmod +x /usr/local/bin/entrypoint.sh \
    # Gỡ plugin kernel-libipsec: đòi /dev/net/tun (không mount) → charon ABORT khi start.
    # Dùng kernel-netlink (XFRM thật trong netns container) nên KHÔNG cần libipsec.
    && rm -f /usr/lib/ipsec/plugins/libstrongswan-kernel-libipsec.so \
             /etc/strongswan.d/charon/kernel-libipsec.conf

# IKE 500/udp + NAT-T 4500/udp (driver float sang 4500). KHÔNG publish ra ngoài: test nội bộ bridge.
EXPOSE 500/udp 4500/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
