# lab/openvpn — VALIDATE LIVE RỘNG driver V.2 OpenVPN (server tự host)

Lab Docker dựng **OpenVPN community server tự host** (OpenVPN 2.6.x) để **validate live rộng** driver
`TqkLibrary.VpnClient.Drivers.OpenVpn`
([`OpenVpnConnection`](../../src/TqkLibrary.VpnClient.Drivers.OpenVpn/OpenVpnConnection.cs#L42)) interop
với một server OpenVPN **thật**, có **kiểm soát** cipher/transport/mode (khác VPN Gate chỉ UDP/AES-128-CBC
NCP-less). Client là binary demo `.NET` self-contained chạy trong container cùng bridge; server sinh
PKI + viết file `.ovpn` inline cho demo đọc qua `--vpn /shared/client.ovpn`.

Vì sao **container** (KHÔNG host-net/privileged-host) — như lab [`ikev2-native`](../ikev2-native) /
[`wireguard`](../wireguard): OpenVPN tạo TUN/TAP **trong netns container** (chỉ cần `/dev/net/tun` +
`NET_ADMIN`), không đụng mạng VM, không cần kernel module riêng. 2 container cùng bridge `labnet` ⇒
client gửi gói OpenVPN (UDP/TCP) tới server qua tên service. KHÔNG publish cổng: test nội bộ bridge.

---

## 1. Topology (an toàn — như ikev2-native/wireguard)

| Container | Vai trò |
|---|---|
| `lab-ovpn-server` | OpenVPN 2.6 community server, `dev tun`/`tap`, `proto udp`/`tcp`, `server 10.60.0.0/24` (tun) hoặc `server-bridge` (tap), `data-ciphers $CIPHER`, push route/DNS, `keepalive 10 60`, `verb 4`. `cap_add: NET_ADMIN` + `devices: /dev/net/tun`. Sinh PKI (openssl) + viết `/shared/client.ovpn` inline lúc khởi động. HTTP test server `10.60.0.1:8080` (`/index.txt` nhỏ + `/big.txt` ~64KB), UDP echo `:7`, dnsmasq `:53` (tùy chọn). Monitor `tail` log mỗi 10s. |
| `lab-ovpn-client` | `runtime-deps:8.0`, mount `./client-bin` (binary publish) + `/shared` (client.ovpn), `sleep infinity` — chạy demo bằng `docker exec`. OpenVPN chở data trên UDP/TCP socket thường ⇒ **KHÔNG cần CAP_NET_RAW**. |

An toàn: **KHÔNG** `network_mode: host`, **KHÔNG** privileged-host. **KHÔNG** publish cổng.

Đổi 3 biến môi trường giữa các lần validate (ở `docker-compose.yml` hoặc inline):

| Biến | Giá trị | Ý nghĩa |
|---|---|---|
| `PROTO` | `udp` \| `tcp` | transport ngoài (UDP datagram / TCP 16-bit length framing) |
| `DEV` | `tun` \| `tap` | L3 routing / L2 Ethernet bridge |
| `CIPHER` | `AES-256-GCM` … | data-ciphers NCP (server chốt → PUSH_REPLY) |

---

## 2. Config (server sinh runtime → `/shared/client.ovpn`)

Entrypoint sinh CA + server-cert (serverAuth) + client-cert (clientAuth) + dh + `ta.key` bằng
`openssl`/`openvpn --genkey`, build `server.conf` theo biến môi trường, rồi viết `.ovpn` **inline**
(`<ca>`/`<cert>`/`<key>`/`<tls-auth>`) cho demo. Driver tự nạp cert/key inline qua
[`OpenVpnConfigParser`](../../src/TqkLibrary.VpnClient.OpenVpn/Config/OpenVpnConfigParser.cs#L13) +
[`OpenVpnClientCertificate.Resolve`](../../src/TqkLibrary.VpnClient.OpenVpn/Helpers).

```ini
client
dev tun
proto udp
remote ovpn-server 1194
remote-cert-tls server
data-ciphers AES-256-GCM
cipher AES-256-GCM
auth SHA256
key-direction 1
<ca>…</ca> <cert>…</cert> <key>…</key> <tls-auth>…</tls-auth>
```

> **dev tap:** OpenVPN `server-bridge` **KHÔNG** tự cấp IP cho `tap0` (kỳ vọng bắc cầu vào `br0` thật).
> Lab không có `br0` ⇒ entrypoint tự `ip link set tap0 up` + gán `10.60.0.1/24` lên chính `tap0` để
> HTTP/ICMP nội bộ reachable qua L2.

---

## 3. Publish client từ Windows host rồi đưa vào VM

```powershell
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained true -o lab/openvpn/client-bin
```

Copy `client-bin` sang VM tại `~/lab/openvpn/client-bin` (compose mount `./client-bin:/opt/client:ro`),
**chmod +x** trên host VM (mount `:ro` không cho chmod trong container):

```bash
scp -r lab/openvpn/client-bin/. <vm>:~/lab/openvpn/client-bin/
ssh <vm> 'chmod +x ~/lab/openvpn/client-bin/Vpn2ProxyDemo'
```

> `client-bin/` (binary publish ELF) **KHÔNG commit** (`.gitignore`) — tạo theo §3 trên từng máy.

---

## 4. Bring-up (đổi PROTO/DEV/CIPHER tùy lần)

```bash
cd ~/lab/openvpn
PROTO=udp DEV=tun CIPHER=AES-256-GCM docker compose up -d --build
docker logs lab-ovpn-server     # thấy server.conf + 'Initialization Sequence Completed' + .ovpn wrote
```

---

## 5. Chạy client + quan sát THÀNH CÔNG

```bash
docker exec lab-ovpn-client /opt/client/Vpn2ProxyDemo http-request \
    --vpn /shared/client.ovpn --url http://10.60.0.1:8080/index.txt
#   client: handshake HARD_RESET→TLS→key-method-2→PUSH_REPLY ifconfig 10.60.0.2 cipher AES-256-GCM
#           tunnel up; => hello-from-ovpn-gateway
```

**Quan sát phía server (bằng chứng interop):**

```bash
docker exec lab-ovpn-server grep -E "Peer Connection Initiated|Data Channel: cipher" /var/log/openvpn-server.log
#   THẤY: [lab-ovpn-client] Peer Connection Initiated with [AF_INET]…
#         Data Channel: cipher 'AES-256-GCM', peer-id: 0     <-- NCP P_DATA_V2 chốt đúng
```

**Kết quả validate (2026-06-24):**

| Mục | Kết quả |
|---|---|
| tun UDP + NCP AES-256-GCM (P_DATA_V2) | ✅ tunnel + HTTP nhỏ + 64KB + UDP DNS + ICMP RTT 1ms; server `Data Channel: cipher 'AES-256-GCM'` |
| tun TCP (16-bit length framing) | ✅ HTTP 4/4 + 64KB 2/2; server `TCPv4_SERVER … bound` |
| gói lớn ~64KB qua tunnel (Q.4) | ✅ cả UDP + TCP carrier (`Received 65536 bytes`) — **Q.4 không tái hiện trên download** |
| tap server-bridge (L2/ARP) | ✅ `tap bridge bound on 10.60.0.50` (OpenVpnTapChannel→ARP→VirtualHost) + ICMP gateway RTT 1ms |

> **Residual (KHÔNG phải OpenVPN — shared IpStack, cross-ref Q.4):** HTTP **upload (request)** đôi khi
> stall: userspace [`TcpIpStack`](../../src/TqkLibrary.VpnClient.IpStack/TcpIpStack.cs) gửi **1 byte/
> segment** rồi rơi vào zero-window persist probe (`_sndWnd` kẹt 0 dù server advertise `win 502 wscale 7`).
> tcpdump tun0 server: handshake `[S]→[S.]→[.]` OK, data + ACK 2 chiều, **mọi checksum correct** ⇒
> tunnel OpenVPN chở MỌI gói TCP đúng (data plane V.2 ĐÚNG). Intermittent theo RTT (TCP-carrier 4/4,
> UDP-carrier ~2/4). Root-cause = send-window update không reopen sau khi peer mở window
> ([`TcpConnection`](../../src/TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs) RFC 5681/7323) — DEFER
> debug IpStack, không sửa mù.

---

## 6. Teardown

```bash
cd ~/lab/openvpn && docker compose down -v   # gỡ 2 container + volume ovpn-shared + network
```

---

## Ghi chú

- PKI sinh bằng `openssl` thủ công (nhanh + tất định hơn easy-rsa interactive); `dhparam 2048` mất
  ~5–15s nên server "Initialization Sequence Completed" sau ~10s.
- `key-direction 1` ở `.ovpn` khớp `tls-auth ta.key 0` ở server (client inverse của server).
- As-built: [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md) §5 *Drivers.OpenVpn* + bảng
  "Khác biệt"; roadmap [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2; README
  [`OpenVpn`](../../src/TqkLibrary.VpnClient.OpenVpn/README-vi.md) /
  [`Drivers.OpenVpn`](../../src/TqkLibrary.VpnClient.Drivers.OpenVpn/README-vi.md).
