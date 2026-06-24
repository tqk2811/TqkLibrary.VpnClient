#!/bin/sh
# entrypoint lab/cisco-ipsec — chay strongSwan (charon) FOREGROUND.
# Khac l2tp-nonat: KHONG xl2tpd/pppd (client Cisco IPsec cho goi IP tran trong
# ESP tunnel, khong co L2TP/PPP). Chi can charon nhan IKEv1 Aggressive + XAUTH +
# Mode-Config roi cai CHILD_SA tunnel.
set -e

echo "[entrypoint] lab/cisco-ipsec — strongSwan IKEv1 Aggressive + XAUTH + Mode-Config + ESP tunnel"
ipsec --version 2>/dev/null || true

# --- forwarding trong netns container (an toan: chi tac dong netns nay) ---
sysctl -w net.ipv4.ip_forward=1          >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
# Tat rp_filter de ESP tunnel khong bi drop boi reverse-path (live hay vuong).
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

# NAT virtual-IP pool (10.41.0.0/24) ra ngoai de client trong tunnel co the ping
# dich sau gateway (neu can). Cho ping 2-chieu toi chinh gateway thi khong can NAT.
iptables -t nat -A POSTROUTING -s 10.41.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true

# --- start charon FOREGROUND ---
echo "[entrypoint] starting charon (foreground)..."
exec ipsec start --nofork
