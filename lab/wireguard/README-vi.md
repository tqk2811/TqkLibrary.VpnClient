# lab/wireguard — VALIDATE LIVE driver V.3 WireGuard (wireguard-go userspace)

Lab Docker dựng **server WireGuard userspace** bằng [`wireguard-go`](https://git.zx2c4.com/wireguard-go)
(+ `wireguard-tools` cho `wg`/`wg show`) để **validate live** driver
`TqkLibrary.VpnClient.Drivers.WireGuard`
([`WireGuardConnection`](../../src/TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L45)) interop
với một peer `wg` **thật**. Client (initiator) là binary demo `.NET` self-contained chạy trong container
cùng bridge; server là một peer WireGuard chuẩn.

Vì sao **wireguard-go userspace** (KHÔNG kernel module): VM host không có module `wireguard`
(`modprobe` cần sudo password — không passwordless). `wireguard-go` là TUN **userspace**, chỉ cần
`/dev/net/tun` + `NET_ADMIN` trong netns container ⇒ an toàn (không phá mạng VM, không cần kernel
module), đúng pattern lab [`ikev2-native`](../ikev2-native).

> **Bug phát hiện qua lab này (V.3):** seed Noise construction-string. WireGuard thật seed
> `ck0 = BLAKE2s("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")` (cipher **viết tắt** `ChaChaPoly`), nhưng
> code ban đầu dùng tên Noise **đầy đủ** `…ChaCha20Poly1305…` ⇒ transcript-hash lệch ⇒ `wg` từ chối
> initiation (`Received invalid initiation message`). Hằng sai vẫn **tự-interop** (test offline
> self-pair PASS) — chỉ `wg` thật mới lộ. Sửa ở
> [`NoiseSymmetricState.Construction`](../../src/TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs#L23).

---

## 1. Topology (an toàn — như ikev2-native)

2 container trên một Docker bridge tùy biến `labnet`:

| Container | Vai trò |
|---|---|
| `lab-wg-server` | `wireguard-go` userspace, interface `wg0` addr `10.50.0.1/24` listen UDP `51820`, peer = client pubkey allowed-ips `10.50.0.2/32` + PresharedKey. `cap_add: NET_ADMIN` + `devices: /dev/net/tun`. Sinh keypair lúc khởi động + viết `/shared/client.conf` (volume chung) cho demo. UDP echo `10.50.0.1:7` (socat) + giám sát `wg show` mỗi 10s. |
| `lab-wg-client` | `runtime-deps:8.0`, mount `./client-bin` (binary publish) + `/shared` (client.conf), `sleep infinity` — chạy demo bằng `docker exec`. WireGuard chở data trên UDP nên **KHÔNG cần CAP_NET_RAW**. |

An toàn: **KHÔNG** `network_mode: host`, **KHÔNG** privileged-host — `wireguard-go` đụng TUN chỉ trong
netns container. **KHÔNG** publish cổng: test nội bộ bridge.

---

## 2. Config (server sinh runtime → `/shared/client.conf`)

Server entrypoint sinh keypair server+client (`wg genkey`/`wg pubkey`) + PSK (`wg genpsk`) lúc khởi
động, viết file wg-quick cho demo đọc (`--vpn /shared/client.conf`):

```ini
[Interface]
PrivateKey = <client priv>
Address = 10.50.0.2/24

[Peer]
PublicKey = <server pub>
PresharedKey = <psk>
Endpoint = wg-server:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
```

Demo parse file này (parser wg-quick tối giản ở [`VpnTunnel.ParseWireGuardConf`](../../demo/Vpn2ProxyDemo/VpnTunnel.cs))
→ `WireGuardConfig` → `WireGuardConnection`.

---

## 3. Publish client từ Windows host rồi đưa vào VM

```powershell
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained true -o lab/wireguard/client-bin
```

Copy `client-bin` sang VM tại `~/lab/wireguard/client-bin` (compose mount `./client-bin:/opt/client:ro`):

```bash
tar -cf - -C lab/wireguard client-bin | ssh <vm> 'cd ~/lab/wireguard && tar -xf - && chmod +x client-bin/Vpn2ProxyDemo'
```

> `client-bin/` (binary publish ~80MB ELF) **KHÔNG commit** (`.gitignore`) — tạo theo §3 trên từng máy.

---

## 4. Bring-up

```bash
cd ~/lab/wireguard
docker compose up -d --build          # build server image + chạy 2 container nền
docker compose logs wg-server         # thấy server pubkey/client pubkey + 'wg0 up' + monitor loop
docker exec lab-wg-server wg show wg0  # interface + peer (chưa handshake)
```

---

## 5. Chạy client + quan sát THÀNH CÔNG

```bash
docker exec lab-wg-client /opt/client/Vpn2ProxyDemo dns --vpn /shared/client.conf --dns-server 10.50.0.1
#   client: handshake completed; data plane bound → Connected; assigned IP 10.50.0.2
```

**Quan sát phía server (bằng chứng interop):**

```bash
docker exec lab-wg-server wg show wg0
#   THẤY: peer ... latest handshake: N seconds ago
#         transfer: X received, Y sent      <-- CẢ HAI > 0 (giải mã 2 chiều)

docker exec lab-wg-server grep -a -iE "initiation|response" /var/log/wgfix.log
#   THẤY: peer(...) - Received handshake initiation
#         peer(...) - Sending handshake response     <-- KHÔNG còn 'Received invalid initiation message'
```

**Data plane 2 chiều** (TCP round-trip qua tunnel): chạy một responder TCP trên `10.50.0.1:80` ở
server rồi `http-request` qua tunnel — `tcpdump -ni wg0 tcp` thấy SYN `10.50.0.2→10.50.0.1` ↔ SYN/ACK
`10.50.0.1→10.50.0.2` ↔ ACK (3-way handshake hoàn chỉnh qua kênh mã hóa).

---

## 6. Teardown

```bash
cd ~/lab/wireguard && docker compose down -v   # gỡ 2 container + volume wg-shared + network
```

---

## Ghi chú

- Server log dùng `wireguard-go -f wg0` chạy **nền** (`&`) + redirect `/var/log/wireguard-go.log`:
  nếu để `wireguard-go` tự daemonize, tiến trình cha giữ stdout pipe của entrypoint ⇒ entrypoint block
  (UAPI cũng treo). Foreground-trong-nền tách hẳn ⇒ `wg setconf` chạy được ngay.
- Validate single-peer point-to-point full-tunnel (`0.0.0.0/0`) + PresharedKey. Multi-peer /
  multi-endpoint / cookie-dưới-tải / MTU-PMTU với `wg` thật: chưa kiểm live (lab single-peer).
- As-built: [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md) §5 *Drivers.WireGuard* + bảng
  "Khác biệt"; roadmap [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.3; README
  [`WireGuard`](../../src/TqkLibrary.VpnClient.WireGuard/README-vi.md) /
  [`Drivers.WireGuard`](../../src/TqkLibrary.VpnClient.Drivers.WireGuard/README-vi.md).
