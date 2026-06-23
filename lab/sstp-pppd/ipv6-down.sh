#!/bin/sh
# pppd ipv6-down hook: dừng radvd khi phiên ppp đóng (tránh radvd trỏ interface đã biến mất).
IFACE="$1"
LOG=/var/log/sstp-ipv6-up.log
PIDFILE=/run/radvd.pid
echo "[$(date)] ipv6-down iface=$IFACE" >> "$LOG"
if [ -f "$PIDFILE" ]; then
    OLDPID=$(cat "$PIDFILE" 2>/dev/null || true)
    [ -n "$OLDPID" ] && kill "$OLDPID" 2>>"$LOG" || true
    rm -f "$PIDFILE"
fi
# Dọn mọi radvd sót (KHÔNG quote $(pidof) — nhiều pid cần word-split thành nhiều arg).
RPIDS=$(pidof radvd 2>/dev/null || true)
[ -n "$RPIDS" ] && kill $RPIDS 2>>"$LOG" || true
exit 0
