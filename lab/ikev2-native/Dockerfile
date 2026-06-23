# =====================================================================
# lab/ikev2-native — IKEv2-native server bằng strongSwan (IKEv2 PSK +
# ESP TUNNEL mode + Configuration Payload). Validate LIVE driver V.1
# IKEv2-native của TqkLibrary (Drivers.Ikev2) — KHÔNG L2TP, KHÔNG PPP.
#
# Vì sao ubuntu:22.04 (KHÔNG 24.04): giữ strongSwan starter/ipsec.conf
# (legacy) — cùng pattern lab l2tp-nonat đã chứng minh hoạt động trên VM.
#
# KHÁC l2tp-nonat: KHÔNG cài xl2tpd/ppp (client chở gói IP trần trong ESP
# tunnel). Chỉ strongSwan + iptables (MASQUERADE pool virtual-IP).
#
# libcharon-extauth-plugins: chứa plugin eap-mschapv2 (KHÔNG nằm trong
# libcharon-extra-plugins trên Ubuntu 22.04) — cần cho đường IKEv2 EAP-MSCHAPv2
# (conn ikev2-eap, V.1(b)). Thiếu gói này → charon log "loading EAP_MSCHAPV2
# method failed" → EAP/FAIL.
#
# An toàn: chạy trên bridge tùy biến (KHÔNG host-net, KHÔNG privileged-host)
# ⇒ strongSwan đụng XFRM chỉ trong netns container, không phá mạng VM.
# =====================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-starter \
        libcharon-extra-plugins \
        libstrongswan-extra-plugins \
        libcharon-extauth-plugins \
        iproute2 \
        iptables \
        tcpdump \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- strongSwan config (IKEv2 PSK + ESP tunnel + CP virtual IP) ---
COPY ipsec.conf      /etc/ipsec.conf
COPY ipsec.secrets   /etc/ipsec.secrets
COPY strongswan.conf /etc/strongswan.conf
COPY entrypoint.sh   /usr/local/bin/entrypoint.sh

RUN chmod 600 /etc/ipsec.secrets \
    && chmod +x /usr/local/bin/entrypoint.sh \
    # Gỡ plugin kernel-libipsec: nó đòi /dev/net/tun (không mount trong container) → charon
    # ABORT khi khởi động (đã gặp ở lab l2tp-nonat). Ta dùng kernel-netlink (XFRM thật trong
    # netns container) nên KHÔNG cần libipsec.
    && rm -f /usr/lib/ipsec/plugins/libstrongswan-kernel-libipsec.so \
             /etc/strongswan.d/charon/kernel-libipsec.conf

# IKE 500/udp + NAT-T 4500/udp (driver float sang 4500). ESP-in-UDP/4500 nên KHÔNG cần
# proto-50 (khác lab l2tp-nonat no-NAT). KHÔNG publish ra ngoài: test nội bộ bridge.
EXPOSE 500/udp 4500/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
