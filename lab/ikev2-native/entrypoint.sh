#!/bin/sh
# entrypoint lab/ikev2-native — chạy strongSwan (charon) FOREGROUND.
# Khác l2tp-nonat: KHÔNG xl2tpd/pppd (client IKEv2-native chở gói IP trần trong
# ESP tunnel, không có L2TP/PPP). Chỉ cần charon nhận IKEv2 + cài CHILD_SA tunnel.
set -e

echo "[entrypoint] lab/ikev2-native — strongSwan IKEv2 (PSK + ESP tunnel + CP virtual IP)"
ipsec --version 2>/dev/null || true

# --- forwarding trong netns container (an toàn: chỉ tác động netns này) ---
sysctl -w net.ipv4.ip_forward=1          >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
# Tắt rp_filter để ESP tunnel không bị drop bởi reverse-path (live hay vướng).
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

# NAT virtual-IP pool (10.40.0.0/24) ra ngoài để client trong tunnel có thể ping
# đích sau gateway (nếu cần). Cho ping 2-chiều tới chính gateway thì không cần NAT.
iptables -t nat -A POSTROUTING -s 10.40.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true

# --- start charon FOREGROUND ---
# 'ipsec start --nofork' giữ charon là tiến trình foreground của container (giữ sống + log).
echo "[entrypoint] starting charon (foreground)..."
exec ipsec start --nofork
