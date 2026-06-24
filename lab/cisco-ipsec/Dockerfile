# =====================================================================
# lab/cisco-ipsec — Cisco IPsec / EzVPN remote-access server bang strongSwan
# (IKEv1 AGGRESSIVE MODE group PSK + XAUTH + Mode-Config + ESP TUNNEL mode).
# Validate LIVE driver V.12 Cisco IPsec cua TqkLibrary (Drivers.CiscoIpsec) —
# KHONG L2TP, KHONG PPP (client cho goi IP tran trong ESP tunnel).
#
# Vi sao ubuntu:22.04: giu strongSwan starter/ipsec.conf (legacy aggressive=yes)
# — cung pattern lab ikev2-native / l2tp-nonat da chung minh hoat dong tren VM.
#
# KHAC ikev2-native:
#   - keyexchange=ikev1 + aggressive=yes (KHONG ikev2)
#   - rightauth=xauth (XAUTH server tra ipsec.secrets) — client gui user/pass
#   - leftauth=psk (group PSK) — gateway chon PSK theo group name (KEY_ID)
#
# libcharon-extauth-plugins: chua plugin xauth-generic (XAUTH server tra ipsec.secrets,
#   KHONG can RADIUS — mac dinh strongSwan chi co xauth-eap doi RADIUS => auth fail).
# libcharon-extra-plugins: chua attr (in-memory Mode-Config pool tu rightsourceip).
#
# An toan: chay tren bridge tuy bien (KHONG host-net, KHONG privileged-host)
# => strongSwan dung XFRM chi trong netns container, khong pha mang VM.
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

# --- strongSwan config (IKEv1 Aggressive + XAUTH + Mode-Config + ESP tunnel) ---
COPY ipsec.conf      /etc/ipsec.conf
COPY ipsec.secrets   /etc/ipsec.secrets
COPY strongswan.conf /etc/strongswan.conf
COPY entrypoint.sh   /usr/local/bin/entrypoint.sh

RUN chmod 600 /etc/ipsec.secrets \
    && chmod +x /usr/local/bin/entrypoint.sh \
    # Go plugin kernel-libipsec: no doi /dev/net/tun (khong mount trong container) => charon
    # ABORT khi khoi dong. Ta dung kernel-netlink (XFRM that trong netns container).
    && rm -f /usr/lib/ipsec/plugins/libstrongswan-kernel-libipsec.so \
             /etc/strongswan.d/charon/kernel-libipsec.conf

# IKE 500/udp + NAT-T 4500/udp (driver forced NAT-T float sang 4500). ESP-in-UDP/4500
# nen KHONG can proto-50. KHONG publish ra ngoai: test noi bo bridge.
EXPOSE 500/udp 4500/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
