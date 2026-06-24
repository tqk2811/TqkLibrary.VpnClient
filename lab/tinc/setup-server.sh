#!/bin/sh
# Runs INSIDE the tinc 1.1 server container. Generates Ed25519 keys for server + client, writes the meta
# config (ExperimentalProtocol = yes → SPTPS), and exports the client private key + server host file to /shared
# so the .NET harness can perform the SPTPS handshake. Then runs tincd in the foreground with debug logging.
set -e

NET=lab
# tinc 1.1pre built from source uses sysconfdir=/usr/local/etc, so the per-net confbase that both
# `tinc -n NET` and `tincd -n NET` default to is /usr/local/etc/tinc/NET. Keep CFG in sync with it.
CFG=/usr/local/etc/tinc/$NET
SHARED=/shared
mkdir -p "$CFG/hosts" "$SHARED"

# --- server (this node) ---
cat > "$CFG/tinc.conf" <<EOF
Name = server
ExperimentalProtocol = yes
Subnet = 10.99.0.0/24
EOF

# Generate the server Ed25519 keypair non-interactively (tinc 1.1: `tinc -n NET generate-ed25519-keys`).
# This writes ed25519_key.priv and appends Ed25519PublicKey to hosts/server.
yes "" | tinc -n "$NET" generate-ed25519-keys 2>/dev/null || tinc -n "$NET" generate-ed25519-keys </dev/null 2>/dev/null || true

# Make sure the server host file has an Address and Subnet for completeness.
cat >> "$CFG/hosts/server" <<EOF
Address = $(hostname -i | awk '{print $1}')
Subnet = 10.99.0.1/32
EOF

# --- client node host entry (server must trust the client's Ed25519 pubkey) ---
# The .NET harness OWNS its own Ed25519 seed (this mirrors how a real tinc node works: each node generates its own
# keypair and registers its public key with its peers). The orchestrator runs `harness gen-key` FIRST, so by the
# time this server container starts, /shared/client.pub already holds the client's Ed25519 public key. We bake it
# into hosts/client *before* tincd starts so the daemon loads the credential at startup — registering it at runtime
# (append after tincd is up) makes tinc 1.1pre18 re-parse and free/replace c->ecdsa on a later code path, leaving
# the SPTPS session pointing at a stale key (observed: receive_sig uses a different public key than the host file).
cat > "$CFG/hosts/client" <<EOF
Subnet = 10.99.0.2/32
EOF
if [ -f "$SHARED/client.pub" ]; then
	echo "Ed25519PublicKey = $(cat "$SHARED/client.pub")" >> "$CFG/hosts/client"
	echo "=== baked client Ed25519PublicKey into hosts/client before tincd start ==="
else
	echo "=== WARNING: /shared/client.pub absent; run 'harness gen-key' before starting the server ==="
fi

# Export to /shared for the harness:
cp "$CFG/hosts/server" "$SHARED/server.host"
echo "server" > "$SHARED/server.name"
cp "$CFG/hosts/client" "$SHARED/client.host.template"

echo "=== server host file ==="
cat "$CFG/hosts/server"
echo "=== client host file seeded (Ed25519PublicKey to be appended by harness registration) ==="
cat "$CFG/hosts/client"
echo "=== exported to /shared ==="
ls -l "$SHARED"
echo "=== confbase ==="; echo "$CFG"

# Run tincd in foreground, no detach, debug level 5 (logs handshake details), no actual tun device needed for
# the handshake test (but tincd may want one; use --no-detach and a dummy device mode).
echo "=== starting tincd (debug 5) ==="
exec tincd -n "$NET" -D -d5 --logfile=/dev/stdout
