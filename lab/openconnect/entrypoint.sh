#!/bin/bash
# entrypoint lab/openconnect — dựng ocserv (OpenConnect server) tự host: sinh
# self-signed server cert (gnutls/openssl), tạo user bằng ocpasswd, build
# ocserv.conf theo biến môi trường, khởi động ocserv, rồi chạy HTTP + UDP-DNS
# test server trên gateway tunnel (10.70.0.1) + monitor loop (tail log + occtl).
#
# Biến môi trường (đặt ở docker-compose):
#   OC_USER   = testuser        (mặc định) — user ocserv (ocpasswd plain)
#   OC_PASS   = testpass        (mặc định) — mật khẩu
#   DTLS      = 1 | 0           (mặc định 1) — bật DTLS data path (udp-port=443)
#   REKEY     = (rỗng)          (nếu đặt số -> rekey-time ngắn để test rekey V5.d)
set -e

OC_USER="${OC_USER:-testuser}"
OC_PASS="${OC_PASS:-testpass}"
DTLS="${DTLS:-1}"
REKEY="${REKEY:-}"
GW=10.70.0.1                   # gateway tunnel (server) — HTTP/UDP test server bind ở đây
NET=10.70.0.0
PREFIX=24

echo "[entrypoint] lab/openconnect — OC_USER=$OC_USER DTLS=$DTLS REKEY=${REKEY:-default}"
ocserv --version 2>/dev/null | head -1 || true

mkdir -p /etc/ocserv /var/log

# ---------------------------------------------------------------------
# Self-signed server cert (gnutls certtool). CN = ocserv-server (tên service
# trên bridge). Driver .NET accept-any (cookie authorize tunnel) nên CN không
# bắt buộc khớp, nhưng vẫn cần cert hợp lệ cho TLS/DTLS bắt tay.
# ---------------------------------------------------------------------
echo "[entrypoint] sinh self-signed server cert ..."
cat > /etc/ocserv/server-cert.tmpl <<EOF
cn = "ocserv-server"
organization = "lab-openconnect"
serial = 001
expiration_days = 3650
signing_key
encryption_key
tls_www_server
EOF

certtool --generate-privkey --outfile /etc/ocserv/server-key.pem >/dev/null 2>&1
certtool --generate-self-signed --load-privkey /etc/ocserv/server-key.pem \
    --template /etc/ocserv/server-cert.tmpl --outfile /etc/ocserv/server-cert.pem >/dev/null 2>&1
echo "[entrypoint] cert xong (CN=ocserv-server)."

# ---------------------------------------------------------------------
# Tạo user bằng ocpasswd (auth plain). Mật khẩu nhập 2 lần qua stdin.
# ---------------------------------------------------------------------
printf '%s\n%s\n' "$OC_PASS" "$OC_PASS" | ocpasswd -c /etc/ocserv/ocpasswd "$OC_USER"
echo "[entrypoint] tạo user '$OC_USER' (ocpasswd plain)."

# ---------------------------------------------------------------------
# Build ocserv.conf theo biến môi trường.
# ---------------------------------------------------------------------
UDP_LINE="udp-port = 443"
# DTLS_LEGACY=false (mặc định) -> ocserv ưu tiên DTLS 1.2 PSK hiện đại (PSK-NEGOTIATE);
# DTLS_LEGACY=true -> bật thêm legacy AnyConnect DTLS resumption (interop cũ).
DTLS_LEGACY_VAL="${DTLS_LEGACY:-false}"
DTLS_LEGACY="dtls-legacy = $DTLS_LEGACY_VAL"
if [ "$DTLS" != "1" ]; then
    # Tắt DTLS: không mở udp-port ⇒ server không quảng bá X-DTLS-* ⇒ client TLS-only.
    UDP_LINE="# udp-port disabled (DTLS off)"
    DTLS_LEGACY="dtls-legacy = false"
fi

REKEY_LINE="rekey-time = 86400"
REKEY_METHOD="rekey-method = ssl"
if [ -n "$REKEY" ]; then
    REKEY_LINE="rekey-time = $REKEY"
    REKEY_METHOD="rekey-method = new-tunnel"
fi

cat > /etc/ocserv/ocserv.conf <<EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = 443
$UDP_LINE
run-as-user = root
run-as-group = root
socket-file = /run/ocserv-socket
use-occtl = true
occtl-socket-file = /run/occtl.socket
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
max-clients = 16
max-same-clients = 4
keepalive = 32
dpd = 20
mobile-dpd = 30
$DTLS_LEGACY
cisco-client-compat = true
log-level = 3
try-mtu-discovery = false
compression = false
auth-timeout = 240
idle-timeout = 1200
$REKEY_LINE
$REKEY_METHOD
device = vpns
predictable-ips = true
ipv4-network = $NET
ipv4-netmask = 255.255.255.0
dns = 1.1.1.1
ping-leases = false
cisco-svc-client-compat = false
EOF

echo "[entrypoint] ===== ocserv.conf ====="
cat /etc/ocserv/ocserv.conf
echo "[entrypoint] ======================="

# ---------------------------------------------------------------------
# Khởi động ocserv (foreground-in-background, log ra file). Cần /dev/net/tun.
# ---------------------------------------------------------------------
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then mknod /dev/net/tun c 10 200 2>/dev/null || true; fi

# NAT để gói tunnel ra ngoài (không bắt buộc cho test nội bộ nhưng vô hại).
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# ocserv log session events qua syslog (không phải stdout) — chạy rsyslog để bắt vào /var/log/syslog.
rsyslogd 2>/dev/null || true
sleep 1
echo "[entrypoint] rsyslog started (ocserv session events -> /var/log/syslog)."

echo "[entrypoint] khởi động ocserv ..."
ocserv --config /etc/ocserv/ocserv.conf --foreground >/var/log/ocserv.log 2>&1 &
OCSERV_PID=$!
sleep 2
echo "[entrypoint] ===== ocserv.log (đầu) ====="
head -30 /var/log/ocserv.log 2>/dev/null || true
echo "[entrypoint] ============================="

# ---------------------------------------------------------------------
# Gán GW lên interface tunnel của server (ocserv tạo 'vpns0' khi client đầu
# tiên lên; trước đó ta thêm 1 dummy để bind HTTP test server tại GW). Thực
# tế ocserv route 10.70.0.0/24 qua device tun của nó; HTTP server bind GW sẽ
# reachable qua tunnel khi client hỏi 10.70.0.1.
# ocserv tự gán GW lên device tun của nó (point-to-point per-client). Để chắc
# có địa chỉ GW reachable, thêm GW lên loopback (server trả lời ICMP/HTTP tại GW).
# ---------------------------------------------------------------------
ip addr add "$GW/32" dev lo 2>/dev/null || true
echo "[entrypoint] GW $GW gán lên lo (HTTP/UDP test server bind tại đây)."

# ---------------------------------------------------------------------
# HTTP test server nội bộ trên gateway tunnel (10.70.0.1:8080) để test gói qua
# tunnel: /index.txt nhỏ + /big.txt ~64KB. UDP echo + DNS giả lập trên GW.
# ---------------------------------------------------------------------
mkdir -p /var/www
python3 -c "open('/var/www/big.txt','w').write('X'*65536)"
echo "hello-from-ocserv-gateway" > /var/www/index.txt
( cd /var/www && python3 -m http.server 8080 --bind "$GW" ) >/var/log/http.log 2>&1 &
echo "[entrypoint] HTTP test server on $GW:8080 (/index.txt nhỏ, /big.txt ~64KB)"

# dnsmasq trên GW:53 (test UDP DNS 2 chiều qua tunnel) — phân giải mọi tên về GW.
dnsmasq --no-daemon --listen-address="$GW" --bind-interfaces \
    --address="/#/$GW" >/var/log/dnsmasq.log 2>&1 &
echo "[entrypoint] dnsmasq DNS on $GW:53 (UDP)"

# UDP echo trên GW:7 (test UDP 2 chiều raw)
socat UDP4-LISTEN:7,bind=$GW,fork EXEC:'cat' 2>/dev/null &
echo "[entrypoint] UDP echo on $GW:7 (socat)"

# ---------------------------------------------------------------------
# Monitor loop: occtl show users + tail log mỗi 10s để thấy client lên
# (user logged in, established, DTLS).
# ---------------------------------------------------------------------
echo "[entrypoint] entering monitor loop (occtl + tail ocserv log mỗi 10s)..."
while true; do
    sleep 10
    echo "----- $(date '+%H:%M:%S') occtl show users -----"
    occtl -s /run/ocserv-socket show users 2>&1 | grep -v "^$" || echo "(occtl: chưa có user / socket chưa sẵn)"
    echo "----- ocserv syslog (tail) -----"
    grep -iE "ocserv|worker" /var/log/syslog 2>/dev/null | tail -12 || tail -12 /var/log/ocserv.log 2>/dev/null || true
done
