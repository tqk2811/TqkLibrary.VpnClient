#!/bin/sh
# entrypoint lab/wireguard — dựng WireGuard server USERSPACE bằng wireguard-go,
# sinh keypair server+client, viết client.conf (cho demo .NET) ra volume chia sẻ,
# rồi giữ container sống + định kỳ `wg show` để quan sát interop (handshake/transfer).
#
# Server là một peer `wg` chuẩn (initiator = driver .NET của ta). KHÔNG kernel module:
# wireguard-go là TUN userspace, chỉ cần /dev/net/tun + NET_ADMIN (netns container).
set -e

WG_IF=wg0
SERVER_TUN_ADDR=10.50.0.1/24
CLIENT_TUN_ADDR=10.50.0.2/32
WG_PORT=51820
SHARED=/shared            # volume chia sẻ với client container (client.conf để demo đọc)

echo "[entrypoint] lab/wireguard — wireguard-go userspace server"
wireguard-go --version 2>/dev/null || true
wg --version 2>/dev/null || true

# --- forwarding trong netns container (an toàn: chỉ tác động netns này) ---
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# --- sinh keypair server + client (wg genkey | wg pubkey) ---
mkdir -p "$SHARED"
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(printf '%s' "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(printf '%s' "$CLIENT_PRIV" | wg pubkey)
# Tùy chọn preshared-key (Noise_IKpsk2 — bật để validate đường có PSK).
PSK=$(wg genpsk)

echo "[entrypoint] server pubkey = $SERVER_PUB"
echo "[entrypoint] client pubkey = $CLIENT_PUB"

# --- file config server cho `wg setconf` ---
cat > /etc/wg0.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIV
ListenPort = $WG_PORT

[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $PSK
AllowedIPs = $CLIENT_TUN_ADDR
EOF

# --- file client.conf cho demo .NET (đọc qua --vpn <file>.conf) ---
# Endpoint = tên service 'wg-server' trên bridge labnet (client container resolve được).
cat > "$SHARED/client.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.50.0.2/24

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PSK
Endpoint = wg-server:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
EOF
chmod 644 "$SHARED/client.conf"
echo "[entrypoint] wrote $SHARED/client.conf (demo dùng --vpn $SHARED/client.conf)"

# --- dựng interface wireguard-go (userspace TUN) ---
# Chạy FOREGROUND (-f) NỀN (&) + redirect log: nếu để wireguard-go tự daemonize,
# tiến trình cha giữ stdout pipe của entrypoint ⇒ entrypoint block (UAPI cũng treo).
# Foreground-trong-nền tách hẳn ⇒ entrypoint chạy tiếp `wg setconf` ngay.
export WG_PROCESS_FOREGROUND=1
wireguard-go -f "$WG_IF" >/var/log/wireguard-go.log 2>&1 &
WG_GO_PID=$!
echo "[entrypoint] wireguard-go -f $WG_IF (pid $WG_GO_PID), chờ UAPI socket..."
# Đợi UAPI socket sẵn sàng (tối đa ~5s) trước khi setconf.
i=0
while [ ! -S "/var/run/wireguard/$WG_IF.sock" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done

wg setconf "$WG_IF" /etc/wg0.conf
ip address add "$SERVER_TUN_ADDR" dev "$WG_IF"
ip link set "$WG_IF" up
echo "[entrypoint] $WG_IF up — addr $SERVER_TUN_ADDR, listen $WG_PORT"
wg show "$WG_IF"

# --- UDP echo trên 10.50.0.1:7 (cho client test UDP 2 chiều qua tunnel) ---
socat -u UDP4-RECVFROM:7,bind=10.50.0.1,fork SYSTEM:'cat' 2>/dev/null &
socat UDP4-LISTEN:7,bind=10.50.0.1,fork EXEC:'cat' 2>/dev/null &
echo "[entrypoint] UDP echo on 10.50.0.1:7 (socat)"

# --- giám sát: in `wg show` mỗi 10s để thấy handshake + transfer khi client lên ---
echo "[entrypoint] entering monitor loop (wg show mỗi 10s)..."
while true; do
    sleep 10
    echo "----- $(date '+%H:%M:%S') wg show $WG_IF -----"
    wg show "$WG_IF" || true
done
