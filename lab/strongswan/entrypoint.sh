#!/bin/sh
# entrypoint strongSwan — chạy charon foreground qua starter.
# ⚠️ BẢN NHÁP: lệnh khởi động có thể là `ipsec start --nofork`, `charon`, hoặc
#    `/usr/lib/ipsec/starter --nofork`. Thử lần lượt.
set -e

echo "[entrypoint] strongSwan lab Q.1 — version:"
ipsec --version 2>/dev/null || true

# Bật forwarding (sysctl ở compose cũng đặt, lặp lại cho chắc khi privileged).
sysctl -w net.ipv4.ip_forward=1            >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1   >/dev/null 2>&1 || true
# Tắt rp_filter để ESP transport không bị drop bởi reverse-path (live hay vướng).
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

# Foreground: ưu tiên `ipsec start --nofork`; fallback charon trực tiếp.
if ipsec start --nofork 2>/dev/null; then
    :
else
    echo "[entrypoint] 'ipsec start --nofork' không chạy, thử starter trực tiếp..." >&2
    exec /usr/lib/ipsec/starter --daemon charon --nofork
fi
