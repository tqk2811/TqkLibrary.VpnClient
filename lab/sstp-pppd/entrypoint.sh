#!/bin/sh
# Entrypoint container lab-sstp-pppd: tạo cert self-signed (client repo chấp nhận mọi cert),
# bật IP forwarding, rồi chạy sstp-server (sorz) — nó tự spawn pppd cho mỗi phiên SSTP.
set -e

CERT=/etc/sstp/cert.pem
KEY=/etc/sstp/key.pem
PORT="${SSTP_PORT:-8443}"
LOCAL_IP="${SSTP_LOCAL:-10.30.0.1}"
REMOTE_NET="${SSTP_REMOTE:-10.30.0.0/24}"
LOGLEVEL="${SSTP_LOGLEVEL:-5}"   # 5 = verbose

mkdir -p /etc/sstp /var/log
if [ ! -f "$CERT" ]; then
    echo "[entrypoint] generating self-signed cert..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY" -out "$CERT" -days 3650 \
        -subj "/CN=lab-sstp-pppd" >/dev/null 2>&1
fi

# IP forwarding (để gói client đi ra — dù lab không NAT internet, vẫn cần cho dual-stack).
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

echo "[entrypoint] starting sstpd on :$PORT  local=$LOCAL_IP remote=$REMOTE_NET loglevel=$LOGLEVEL"
# -l 0.0.0.0 BẮT BUỘC: sstpd 0.7.2 mặc định --listen="" → "".split(",")=[""] → getaddrinfo
# fail "Name or service not known". Truyền địa chỉ bind tường minh.
exec /opt/sstp/bin/sstpd \
    -l "${SSTP_LISTEN:-0.0.0.0}" \
    -p "$PORT" \
    -c "$CERT" \
    -k "$KEY" \
    --local "$LOCAL_IP" \
    --remote "$REMOTE_NET" \
    --pppd-config /etc/ppp/options.sstpd \
    -v "$LOGLEVEL"
