#!/bin/bash
# entrypoint lab/openvpn — dựng OpenVPN community server tự host, sinh PKI
# (CA + server + client cert/key bằng openssl), build config theo biến môi
# trường, khởi động server, viết file .ovpn INLINE cho demo .NET ra /shared,
# rồi chạy HTTP server nội bộ trên gateway tunnel (test gói lớn) + monitor.
#
# Biến môi trường (đặt ở docker-compose):
#   PROTO   = udp | tcp            (mặc định udp) — proto transport OpenVPN
#   DEV     = tun | tap            (mặc định tun) — L3 routing / L2 bridge
#   CIPHER  = AES-256-GCM | ...    (mặc định AES-256-GCM) — data-ciphers NCP
#   PORT    = 1194                 (mặc định 1194)
#   TUNMTU  = (rỗng)               (nếu đặt -> tun-mtu trên cả server + .ovpn)
set -e

PROTO="${PROTO:-udp}"
DEV="${DEV:-tun}"
CIPHER="${CIPHER:-AES-256-GCM}"
PORT="${PORT:-1194}"
TUNMTU="${TUNMTU:-}"
SHARED=/shared                 # volume chia sẻ với client container (.ovpn để demo đọc)
SERVER_NAME="ovpn-server"      # tên SERVICE trên bridge labnet (client resolve được qua DNS Docker)
NET=10.60.0.0
MASK=255.255.255.0
GW=10.60.0.1                   # gateway tunnel (server) — HTTP test server bind ở đây

echo "[entrypoint] lab/openvpn — PROTO=$PROTO DEV=$DEV CIPHER=$CIPHER PORT=$PORT TUNMTU=${TUNMTU:-default}"
openvpn --version 2>/dev/null | head -1 || true

mkdir -p "$SHARED" /etc/openvpn/pki
cd /etc/openvpn/pki

# ---------------------------------------------------------------------
# Sinh PKI thủ công bằng openssl (nhanh + tất định hơn easy-rsa interactive).
# CA self-signed -> ký server-cert (extendedKeyUsage serverAuth) + client-cert
# (clientAuth). Driver .NET verify server bằng <ca> (chấp nhận-any nếu callback
# null; ở đây demo dùng callback null -> chấp nhận, nhưng vẫn cần CA cho TLS).
# ---------------------------------------------------------------------
echo "[entrypoint] sinh PKI (openssl) ..."

# --- CA ---
openssl genrsa -out ca.key 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/CN=lab-ovpn-ca" -out ca.crt >/dev/null 2>&1

# --- server cert (serverAuth) ---
openssl genrsa -out server.key 2048 >/dev/null 2>&1
openssl req -new -key server.key -subj "/CN=$SERVER_NAME" -out server.csr >/dev/null 2>&1
cat > server.ext <<EOF
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 3650 -sha256 -extfile server.ext -out server.crt >/dev/null 2>&1

# --- client cert (clientAuth) ---
openssl genrsa -out client.key 2048 >/dev/null 2>&1
openssl req -new -key client.key -subj "/CN=lab-ovpn-client" -out client.csr >/dev/null 2>&1
cat > client.ext <<EOF
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 3650 -sha256 -extfile client.ext -out client.crt >/dev/null 2>&1

# --- Diffie-Hellman + tls-auth key ---
openssl dhparam -out dh.pem 2048 >/dev/null 2>&1
openvpn --genkey secret ta.key >/dev/null 2>&1 || openvpn --genkey --secret ta.key >/dev/null 2>&1
echo "[entrypoint] PKI xong (ca/server/client/dh/ta)."

# ---------------------------------------------------------------------
# Build server config theo biến môi trường.
# ---------------------------------------------------------------------
# proto OpenVPN: udp -> 'udp', tcp -> 'tcp-server'
if [ "$PROTO" = "tcp" ]; then SRV_PROTO="tcp-server"; else SRV_PROTO="udp"; fi

MTU_LINE=""
if [ -n "$TUNMTU" ]; then MTU_LINE="tun-mtu $TUNMTU"; fi

# topology subnet cho dev tun (mỗi client 1 IP trong /24, không /30 cũ).
# server-bridge cho dev tap (managed pool: server cấp ifconfig từ pool).
if [ "$DEV" = "tap" ]; then
    MODE_LINE="server-bridge $GW $MASK 10.60.0.50 10.60.0.100"
    TOPOLOGY_LINE=""
else
    MODE_LINE="server $NET $MASK"
    TOPOLOGY_LINE="topology subnet"
fi

cat > /etc/openvpn/server.conf <<EOF
dev $DEV
proto $SRV_PROTO
port $PORT
$MODE_LINE
$TOPOLOGY_LINE
$MTU_LINE

ca   /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/server.crt
key  /etc/openvpn/pki/server.key
dh   /etc/openvpn/pki/dh.pem
tls-auth /etc/openvpn/pki/ta.key 0

# NCP: ép data channel cipher = \$CIPHER (server đẩy qua PUSH_REPLY). data-ciphers
# liệt kê cipher cho phép; phía client offer IV_CIPHERS -> server chốt \$CIPHER.
data-ciphers $CIPHER
data-ciphers-fallback $CIPHER
auth SHA256

# Push route/DNS để client thấy server cấu hình tunnel (PUSH_REPLY).
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $GW"
push "route $GW"

keepalive 10 60
persist-key
persist-tun
client-to-client
duplicate-cn
verb 4
EOF

echo "[entrypoint] ===== server.conf ====="
cat /etc/openvpn/server.conf
echo "[entrypoint] ======================="

# ---------------------------------------------------------------------
# Viết file .ovpn client INLINE cho demo .NET. remote = tên service trên bridge.
# proto client: udp -> 'udp', tcp -> 'tcp-client'. dev/cipher/auth khớp server.
# ---------------------------------------------------------------------
if [ "$PROTO" = "tcp" ]; then CLI_PROTO="tcp-client"; else CLI_PROTO="udp"; fi

CLIENT_MTU_LINE=""
if [ -n "$TUNMTU" ]; then CLIENT_MTU_LINE="tun-mtu $TUNMTU"; fi

{
    echo "client"
    echo "dev $DEV"
    echo "proto $CLI_PROTO"
    echo "remote $SERVER_NAME $PORT"
    echo "$CLIENT_MTU_LINE"
    echo "nobind"
    echo "persist-key"
    echo "persist-tun"
    echo "remote-cert-tls server"
    echo "data-ciphers $CIPHER"
    echo "data-ciphers-fallback $CIPHER"
    echo "cipher $CIPHER"
    echo "auth SHA256"
    echo "key-direction 1"
    echo "verb 3"
    echo "<ca>"
    cat /etc/openvpn/pki/ca.crt
    echo "</ca>"
    echo "<cert>"
    openssl x509 -in /etc/openvpn/pki/client.crt   # PEM cert (bỏ phần text)
    echo "</cert>"
    echo "<key>"
    cat /etc/openvpn/pki/client.key
    echo "</key>"
    echo "<tls-auth>"
    cat /etc/openvpn/pki/ta.key
    echo "</tls-auth>"
} > "$SHARED/client.ovpn"
chmod 644 "$SHARED/client.ovpn"
echo "[entrypoint] wrote $SHARED/client.ovpn (demo dùng --vpn $SHARED/client.ovpn)"

# ---------------------------------------------------------------------
# Khởi động OpenVPN server (background, log ra file). Cần /dev/net/tun.
# ---------------------------------------------------------------------
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then mknod /dev/net/tun c 10 200 2>/dev/null || true; fi

echo "[entrypoint] khởi động openvpn server ..."
openvpn --config /etc/openvpn/server.conf --log /var/log/openvpn-server.log &
OVPN_PID=$!
sleep 3
echo "[entrypoint] ===== openvpn-server.log (đầu) ====="
head -40 /var/log/openvpn-server.log 2>/dev/null || true
echo "[entrypoint] ====================================="

# dev tap + server-bridge: OpenVPN KHÔNG tự cấp IP cho tap0 (nó kỳ vọng tap0 được
# bắc cầu vào br0 thật giữ IP gateway). Lab không có br0 ⇒ tự bring-up tap0 và gán
# GW lên chính tap0 (coi tap0 là "bridge") để HTTP/ICMP nội bộ reachable qua L2.
if [ "$DEV" = "tap" ]; then
    i=0
    while ! ip link show tap0 >/dev/null 2>&1 && [ $i -lt 30 ]; do sleep 0.2; i=$((i+1)); done
    ip link set tap0 up 2>/dev/null || true
    ip addr add "$GW/24" dev tap0 2>/dev/null || true
    echo "[entrypoint] dev tap: tap0 up + addr $GW/24 (server-bridge không tự cấp IP tap0)"
fi

# ---------------------------------------------------------------------
# HTTP test server nội bộ trên gateway tunnel (10.60.0.1:8080) để test GÓI LỚN
# qua tunnel: phục vụ /big = ~64KB payload (phải qua nhiều gói/MTU). Bind GW.
# Chờ interface tun/tap lên (server gán GW) trước khi bind.
# ---------------------------------------------------------------------
i=0
while ! ip addr show 2>/dev/null | grep -q "$GW" && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
echo "[entrypoint] interfaces:"; ip -brief addr 2>/dev/null || ip addr

mkdir -p /var/www
# /big.txt ~ 64KB (test payload lớn qua tunnel: nhiều gói, vượt 1 MTU)
python3 -c "open('/var/www/big.txt','w').write('X'*65536)"
echo "hello-from-ovpn-gateway" > /var/www/index.txt
# HTTP server bind GW:8080 (chỉ trong tunnel). Foreground-in-background.
( cd /var/www && python3 -m http.server 8080 --bind "$GW" ) >/var/log/http.log 2>&1 &
echo "[entrypoint] HTTP test server on $GW:8080 (/index.txt nhỏ, /big.txt ~64KB)"

# UDP echo trên GW:7 (test UDP 2 chiều qua tunnel)
socat -u UDP4-RECVFROM:7,bind=$GW,fork SYSTEM:'cat' 2>/dev/null &
socat UDP4-LISTEN:7,bind=$GW,fork EXEC:'cat' 2>/dev/null &
echo "[entrypoint] UDP echo on $GW:7 (socat)"

# ---------------------------------------------------------------------
# Monitor loop: in trạng thái server + tail log mỗi 10s để thấy client lên
# (Peer Connection Initiated, Data Channel: cipher '...').
# ---------------------------------------------------------------------
echo "[entrypoint] entering monitor loop (tail openvpn log mỗi 10s)..."
while true; do
    sleep 10
    echo "----- $(date '+%H:%M:%S') openvpn-server.log (tail) -----"
    tail -15 /var/log/openvpn-server.log 2>/dev/null || true
done
