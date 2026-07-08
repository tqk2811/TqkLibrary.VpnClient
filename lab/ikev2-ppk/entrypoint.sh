#!/bin/sh
# entrypoint lab/ikev2-ppk — strongSwan (charon) qua **swanctl/vici**, FOREGROUND.
# Khác ikev2-native (starter/ipsec.conf): PPK là tính năng swanctl-only nên phải
# start charon rồi `swanctl --load-all` (nạp connections/secrets/pools từ swanctl.conf).
set -e

echo "[entrypoint] lab/ikev2-ppk — strongSwan IKEv2 PSK + PPK (RFC 8784) via swanctl"
swanctl --version 2>/dev/null || true

# --- forwarding trong netns container (an toàn: chỉ tác động netns này) ---
sysctl -w net.ipv4.ip_forward=1          >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

# NAT virtual-IP pool ra ngoài (client trong tunnel ping/HTTP tới đích sau gateway).
iptables -t nat -A POSTROUTING -s 10.40.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true

# --- start charon (background) + nạp swanctl config + giữ foreground ---
echo "[entrypoint] starting charon..."
/usr/lib/ipsec/charon &
CHARON_PID=$!

# đợi vici socket sẵn sàng
i=0
while [ $i -lt 40 ]; do
    if [ -S /var/run/charon.vici ] || [ -S /run/charon.vici ]; then break; fi
    sleep 0.25; i=$((i+1))
done

echo "[entrypoint] loading swanctl config..."
swanctl --load-all || { echo "[entrypoint] swanctl --load-all FAILED"; }
echo "[entrypoint] connections:"; swanctl --list-conns 2>/dev/null || true

# charon là tiến trình chính của container.
wait $CHARON_PID
