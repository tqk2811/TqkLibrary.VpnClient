#!/bin/sh
# pppd ipv6-up hook: chạy khi IPV6CP lên trên 1 interface ppp.
# pppd truyền: $1=interface (ppp0...), $2=tty, $3=speed, $4=local-ll, $5=remote-ll.
# Ta cấu hình radvd để quảng bá prefix global fd00:dead:beef::/64 trên interface này,
# rồi (re)start radvd ⇒ client gửi RS sẽ nhận RA và SLAAC ra địa chỉ global.
set -e
IFACE="$1"
LOG=/var/log/sstp-ipv6-up.log
PIDFILE=/run/radvd.pid
echo "[$(date)] ipv6-up iface=$IFACE local=$4 remote=$5" >> "$LOG"

# Gán 1 địa chỉ global trên ppp server-side để radvd có 'router addr' hợp lệ + route hoạt động.
ip -6 addr add fd00:dead:beef::1/64 dev "$IFACE" 2>>"$LOG" || true

# forwarding cho interface ppp (radvd yêu cầu forwarding bật). net.ipv6.conf.all.forwarding=1
# đã set qua docker-compose sysctls; ghi per-iface có thể fail (/proc/sys ro) nhưng all=1 là đủ.
sysctl -w "net.ipv6.conf.${IFACE}.forwarding=1" >>"$LOG" 2>&1 || true

# Dừng radvd cũ (nếu còn) qua pidfile — tránh leak nhiều instance trỏ interface đã chết.
if [ -f "$PIDFILE" ]; then
    OLDPID=$(cat "$PIDFILE" 2>/dev/null || true)
    [ -n "$OLDPID" ] && kill "$OLDPID" 2>>"$LOG" || true
    rm -f "$PIDFILE"
    sleep 1
fi
# Dọn mọi radvd còn sót (pidof trả nhiều pid → KHÔNG quote, để word-split thành nhiều arg cho kill).
RPIDS=$(pidof radvd 2>/dev/null || true)
[ -n "$RPIDS" ] && kill $RPIDS 2>>"$LOG" || true

# Sinh radvd.conf cho đúng interface và start radvd (1 instance, ghi pidfile).
sed "s/@IFACE@/${IFACE}/g" /etc/radvd.conf.tmpl > /etc/radvd.conf
radvd -C /etc/radvd.conf -m logfile -l "$LOG" -p "$PIDFILE" >>"$LOG" 2>&1 || \
    radvd -C /etc/radvd.conf -p "$PIDFILE" >>"$LOG" 2>&1 || true
echo "[$(date)] radvd started for $IFACE (pid $(cat "$PIDFILE" 2>/dev/null))" >> "$LOG"
exit 0
