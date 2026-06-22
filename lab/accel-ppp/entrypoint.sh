#!/bin/sh
# entrypoint accel-ppp — sinh cert TLS self-signed cho SSTP (nếu chưa có) rồi chạy daemon.
# ⚠️ BẢN NHÁP: tên binary có thể là accel-pppd (apt) hoặc accel-pppd ở /usr/sbin.
set -e

CERT_DIR=/etc/accel-ppp/certs
PEM=$CERT_DIR/sstp.pem
mkdir -p "$CERT_DIR" /var/log/accel-ppp

# ---- Cert SSTP self-signed (RSA 2048, SAN = mọi IP/host của lab) ----
# Client .NET bắt buộc chấp nhận cert bất kỳ vì đây là self-signed (xem README, callback always-true).
if [ ! -f "$PEM" ]; then
    echo "[entrypoint] Sinh cert SSTP self-signed -> $PEM"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/sstp.key" \
        -out    "$CERT_DIR/sstp.crt" \
        -days 3650 \
        -subj "/CN=lab-accel-ppp" \
        -addext "subjectAltName=DNS:lab-accel-ppp,IP:127.0.0.1" 2>/dev/null || \
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/sstp.key" \
        -out    "$CERT_DIR/sstp.crt" \
        -days 3650 \
        -subj "/CN=lab-accel-ppp"   # fallback nếu OpenSSL cũ không hỗ trợ -addext
    # accel-ppp ssl-pemfile mong key+cert trong CÙNG file PEM.
    cat "$CERT_DIR/sstp.key" "$CERT_DIR/sstp.crt" > "$PEM"
    chmod 600 "$PEM" "$CERT_DIR/sstp.key"
fi

# ---- Tìm binary accel-ppp ----
ACCEL_BIN=""
for c in accel-pppd /usr/sbin/accel-pppd accel-ppp /usr/sbin/accel-ppp; do
    if command -v "$c" >/dev/null 2>&1; then ACCEL_BIN="$c"; break; fi
done
if [ -z "$ACCEL_BIN" ]; then
    echo "[entrypoint] !! Không tìm thấy binary accel-pppd. Kiểm tra gói apt hoặc build từ source (xem Dockerfile)." >&2
    exit 1
fi

echo "[entrypoint] Chạy $ACCEL_BIN với /etc/accel-ppp.conf"
# -d = foreground (không daemon hoá) để Docker giữ container + log ra stdout/file.
exec "$ACCEL_BIN" -d -c /etc/accel-ppp.conf
