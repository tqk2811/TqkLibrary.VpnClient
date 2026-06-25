# Lab Tailscale (V.7.5) — control plane ts2021 vs Headscale + data plane WireGuard (full-tunnel)

Lab kiểm thử **live** driver Tailscale: control plane **ts2021** (Noise IK + đăng nhập Headscale bằng preauth
key + register node + netmap) ghép vào **data plane WireGuard tái dùng nguyên** (V.3) với **responder role** để
**2 node .NET tự bắt tay nhau** (không cần server WireGuard, không cần disco). Control server là **Headscale**
(open-source self-host, image `headscale/headscale`).

## Topology (`docker-compose.yml`, bridge `tsnet` 172.30.0.0/24)

| Container | IP bridge | Vai trò |
|-----------|-----------|---------|
| `ts-headscale` | 172.30.0.2 | Headscale (control server ts2021 + netmap) |
| `ts-client1` | 172.30.0.10 | node .NET 1 — overlay `100.64.0.1`, advertise `172.30.0.10:41641` |
| `ts-client2` | 172.30.0.11 | node .NET 2 — overlay `100.64.0.2`, advertise `172.30.0.11:41641` |

> Mỗi node là **vừa initiator vừa responder**: tie-break theo static pubkey (pubkey lớn hơn initiate, bên kia
> respond) nên đúng 1 node initiate, bên kia trả type-2 → tunnel WireGuard lên không cần server. Node `tailscale`
> THẬT (cần disco/magicsock) là việc tương lai, KHÔNG dùng cho full-tunnel 2-node .NET này.

## Chạy

```bash
# 1. Headscale lên + tạo user + 2 preauth key (1 cho mỗi node)
docker compose up -d
docker exec ts-headscale headscale users create labuser
K1=$(docker exec ts-headscale headscale preauthkeys create --user 1 --reusable --expiration 24h | tail -1)
K2=$(docker exec ts-headscale headscale preauthkeys create --user 1 --reusable --expiration 24h | tail -1)

# 2. publish harness self-contained linux-x64 -> copy publish/ vào /app/publish của cả 2 client
dotnet publish lab/tailscale/harness -c Release -r linux-x64 --self-contained -o publish
#    docker cp publish ts-client1:/app/publish ; docker cp publish ts-client2:/app/publish

# 3. viết /app/c1.tailscale + /app/c2.tailscale (xem dưới) với keys X25519 CỐ ĐỊNH (64-hex) + endpoint advertise
#    rồi PRE-REGISTER mỗi node 1 lần (login + register vào Headscale; lần đầu fail no-peers/timeout là bình thường):
docker exec ts-client1 sh -c 'cd /app/publish && DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 ./harness /app/c1.tailscale "" 3'
docker exec ts-client2 sh -c 'cd /app/publish && DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 ./harness /app/c2.tailscale "" 5'

# 4. chạy CẢ 2 node ĐỒNG THỜI (cùng lệnh, không trễ): node2 hold (trả ICMP tự động), node1 ping node2 overlay.
#    Quan trọng: restart container cho sạch process/socket trước mỗi lần chạy; launch 2 node gần như cùng lúc.
docker restart ts-client1 ts-client2
docker exec -d ts-client2 sh -c 'cd /app/publish && DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 ./harness /app/c2.tailscale "" 90'
docker exec -d ts-client1 sh -c 'cd /app/publish && DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 ./harness /app/c1.tailscale 100.64.0.2 90'
docker exec ts-client1 cat /tmp/... # hoặc bỏ -d để xem trực tiếp: "reply from 100.64.0.2: seq=N rtt=...ms"
```

### File `c1.tailscale` / `c2.tailscale` (ini)

```ini
server=http://172.30.0.2:8080
authkey=<preauth key của node này>
mtu=1280
wgport=41641
endpoint=172.30.0.10:41641     ; (node2 dùng 172.30.0.11:41641)
hostname=netclient1
# Keys X25519 CỐ ĐỊNH (64-hex) — BẮT BUỘC để 2 lần chạy là CÙNG node Headscale (pre-register lần 1 rồi run lần 2);
# nếu để trống, mỗi lần chạy sinh node MỚI → peer kia không có trong netmap.
machinekey=<64 hex>
nodekey=<64 hex>
```

Harness: `./harness <config.tailscale> [pingTargetOverlayIp] [holdSeconds]`. Không có ping target → giữ tunnel sống
+ `TcpIpStack` tự trả ICMP echo (vai trò bên-được-ping). Có ping target → lặp `PingAsync` tới overlay peer.

## Trạng thái validate (2026-06-25)

**FULL-TUNNEL LIVE ICMP 2 CHIỀU — XONG ✓** vs Headscale v0.29.1, giữa 2 node .NET:
- Control ts2021: cả 2 node `GET /key?v=113` → `POST /ts2021` 101 (Noise IK) → `POST /machine/register` 200
  `MachineAuthorized` → `POST /machine/map` netmap (self + peer kia). Headscale log `node connected ... online=true`
  cả 2. Overlay cố định `netclient1=100.64.0.1`, `netclient2=100.64.0.2`.
- Data plane WireGuard **responder role**: tcpdump trên node2 (`eth0` udp/41641):
  - `172.30.0.10.41641 > 172.30.0.11.41641: UDP length 148` = **handshake initiation type-1** (node1 initiate).
  - `172.30.0.11 > 172.30.0.10: UDP length 92` = **handshake response type-2** (node2 RESPOND — responder role).
  - sau đó cặp `length 92` 2 chiều mỗi giây = **type-4 transport data** (ICMP echo request đi + reply về).
- ICMP: node1 ping `100.64.0.2` → **89/89 reply liên tục, RTT 0-8ms** (chỉ timeout khi node2 hold hết hạn). Chiều
  ngược do `TcpIpStack` của node2 tự trả echo reply → **2 chiều qua tunnel WireGuard**.

### Lưu ý vận hành (rút từ live)
- **Pre-register 1 lần mỗi node** (keys cố định) rồi mới chạy live: `LoginAsync` đọc netmap MỘT lần, nên peer kia
  phải đã có trong Headscale (đã register + advertise endpoint) trước khi node này login.
- **Restart container + launch 2 node gần như đồng thời**: process cũ giữ port 41641 (wgport cố định) làm node mới
  không bind được; độ trễ launch lớn khiến node login trước retry (reconnect) chờ peer advertise endpoint.

**Còn lại (future, ngoài phạm vi V.7.5):**
- **disco** (Curve25519-boxed ping/pong, NAT path discovery) để interop data-plane với node `tailscale` THẬT.
- **DERP relay** (WebSocket/HTTPS relay khi không P2P được).
- Netmap **streaming động** (re-poll để học peer mới mà không cần pre-register tĩnh).

## Dọn

```bash
docker compose down -v
```
