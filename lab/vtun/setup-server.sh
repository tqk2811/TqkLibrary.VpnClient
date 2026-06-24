#!/bin/sh
# vtund server entrypoint for the V.11 live lab. Ensures /dev/net/tun exists, enables IP forwarding + relaxed
# reverse-path filtering (so the asymmetric tun reply is not dropped), then runs vtund in the foreground in debug mode.
set -e

echo "[server] vtund version:"
vtund -h 2>&1 | head -1 || true

# Make sure the tun device node is present (the container maps /dev/net/tun, but create it if missing).
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200 || true
  chmod 600 /dev/net/tun || true
fi

# Let the kernel forward and route the tun reply back to the client overlay.
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

echo "[server] starting vtund -s (server) in foreground debug on port 5000 ..."
# -s server mode, -n foreground (no daemonize), -f config, -P port. Debug to stderr.
exec vtund -s -n -f /etc/vtund.conf -P 5000
