#!/bin/bash
# =====================================================================
# lab/ipencap — peer Linux `ip tunnel` cho V.8 (GRE-47 / IPIP-4 / SIT-41).
# Tạo CẢ 3 tunnel point-to-point trỏ về client (proto khác nhau ⇒ không xung đột),
# gán IP tunnel, dựng dnsmasq trả lời DNS-over-UDP để probe UDP xuyên tunnel.
# Client demo test TỪNG kind một (gre:// | ipip:// | sit://).
# =====================================================================
set -e

PEER_OUTER=172.30.0.2     # IP của peer trên bridge labnet (local cho ip-tunnel)
CLIENT_OUTER=172.30.0.3   # IP của client trên bridge labnet (remote cho ip-tunnel)

echo "[peer] cài iproute2 + dnsmasq + iputils-ping + tcpdump ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq iproute2 dnsmasq iputils-ping tcpdump >/dev/null

echo "[peer] outer: local=$PEER_OUTER remote(client)=$CLIENT_OUTER"

# --- GRE proto-47 (RFC 2784/2890, không key — khớp GreTunnelChannel mặc định) ---
ip link add gre1 type gre local "$PEER_OUTER" remote "$CLIENT_OUTER" ttl 64
ip addr add 10.80.0.1/24 dev gre1
ip link set gre1 up
echo "[peer] gre1 (proto-47) up: 10.80.0.1/24"

# --- IPIP proto-4 (RFC 2003, header-less IPv4-in-IPv4) ---
ip link add ipip1 type ipip local "$PEER_OUTER" remote "$CLIENT_OUTER" ttl 64
ip addr add 10.81.0.1/24 dev ipip1
ip link set ipip1 up
echo "[peer] ipip1 (proto-4) up: 10.81.0.1/24"

# --- SIT proto-41 (RFC 4213, header-less IPv6-in-IPv4) ---
ip link add sit1 type sit local "$PEER_OUTER" remote "$CLIENT_OUTER" ttl 64
ip addr add fd00::1/64 dev sit1
ip link set sit1 up
echo "[peer] sit1 (proto-41) up: fd00::1/64"

echo "[peer] --- địa chỉ tunnel ---"
ip -brief addr show | grep -E 'gre1|ipip1|sit1' || true

# dnsmasq: trả lời MỌI truy vấn DNS (A → 93.184.216.34, AAAA → 2606:2800:220:1:248:1893:25c8:1946)
# trên mọi interface (kể cả các tunnel) ⇒ probe DNS-over-UDP xuyên tunnel nhận phản hồi.
cat >/etc/dnsmasq.d/lab.conf <<'EOF'
bind-dynamic
address=/#/93.184.216.34
address=/#/2606:2800:220:1:248:1893:25c8:1946
EOF
dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf &
echo "[peer] dnsmasq lắng nghe DNS-over-UDP (trả mọi truy vấn)."

echo "[peer] SẴN SÀNG. Tunnel: gre1=10.80.0.1 ipip1=10.81.0.1 sit1=fd00::1 (peer/gateway)."
echo "[peer] Client gán: gre/ipip 10.80.0.2 hoặc 10.81.0.2; sit fd00::2. Test ICMP/UDP tới peer."

# Đứng yên để runbook `docker exec` chạy tcpdump / kiểm tra `ip -s link`.
sleep infinity
