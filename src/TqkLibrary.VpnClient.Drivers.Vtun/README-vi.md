# TqkLibrary.VpnClient.Drivers.Vtun

Driver **vtun** (Virtual Tunnel daemon legacy) — ráp các codec thuần ở [`Vtun`](../TqkLibrary.VpnClient.Vtun) thành một tunnel chạy thật sau facade, hỗ trợ cả **L3 (type tun)** lẫn **L2 (type ether/tap)**. vtun chở control + data trên **MỘT kết nối TCP** (`proto tcp`): bắt tay challenge-response (khối ASCII 50-byte, challenge MD5+Blowfish-ECB, server quyết định cờ host) → **tun**: chở **gói IP trần** dạng frame length-prefix; **tap**: chở **frame Ethernet trần** qua [`VtunEthernetChannel`](DataChannel/VtunEthernetChannel.cs) rồi bridge L2↔L3 bằng `ArpResolver`+`VirtualHost` (tái dùng Ethernet fabric) — đều sau [`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs) ổn định, kèm keepalive `VTUN_ECHO`. Config tĩnh [`VtunConfig`](Config/VtunConfig.cs) (host name + password, IP tunnel tĩnh + peer, MTU) → `TunnelConfig` **tĩnh** (vtund không thương lượng địa chỉ in-tunnel — `up`/`down` script đặt tun phía server; **không IPCP/DHCP**). Point-to-point client ↔ 1 vtund host, `compress no`; **data-plane `encrypt`**: hỗ trợ `encrypt no` (cleartext) VÀ `encrypt yes` = Blowfish-128-ECB (cipher mặc định của vtund — cài [`IVtunFrameTransform`](../TqkLibrary.VpnClient.Vtun/Wire/Interfaces/IVtunFrameTransform.cs) vào `VtunControlChannel.DataTransform` theo cipher server chọn).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Ráp codec từ [`Vtun`](../TqkLibrary.VpnClient.Vtun) thành tunnel sống (mirror cấu trúc [`Drivers.Tinc`](../TqkLibrary.VpnClient.Drivers.Tinc), nhưng **1 kết nối TCP** thay vì TCP+UDP):

- **Transport (đơn)**: seam [`IVtunTransportFactory`](Transport/IVtunTransportFactory.cs) trả 1 byte-stream — production [`VtunSocketTransportFactory`](Transport/VtunSocketTransportFactory.cs) (tái dùng [`TcpByteStream`](../TqkLibrary.VpnClient.Transport.Tcp/TcpByteStream.cs) F.1), test inject loopback.
- **Control channel** [`VtunControlChannel`](VtunControlChannel.cs): SỞ HỮU byte-stream + 1 reader buffered dùng chung cho cả 2 pha. `AuthenticateAsync`: greeting → `HOST:` → đọc challenge → gửi response (Blowfish challenge) → parse `OK FLAGS:`/`ERR` (giữ `ServerFlags` + `ServerCipherId`). Sau handshake, `ReadFrameAsync`/`WriteDataFrameAsync`/`WriteControlFrameAsync` chở data-plane (reader tiếp tục liền mạch, không mất byte vắt qua ranh giới handshake→data). Khi `encrypt` bật, `DataTransform` mã hóa payload trước khi frame (write) và giải mã sau khi deframe (read) — chỉ áp cho data frame, control/auth không đụng.
- **Data plane (tun)** [`VtunPacketChannel`](DataChannel/VtunPacketChannel.cs): `IPacketChannel` L3 (bare IP, `MaxHeaderLength`=0). `WriteIpPacketAsync` → frame data; `Deliver` → `InboundIpPacket`.
- **Data plane (tap)** [`VtunEthernetChannel`](DataChannel/VtunEthernetChannel.cs): `IEthernetChannel` L2 (frame Ethernet trần, `MaxHeaderLength`=14). `WriteFrameAsync` → frame data; `Deliver` → `InboundFrame`. Driver dựng `ArpResolver`+`VirtualHost` (Ethernet fabric) bind bridge → stack vẫn thấy IP trần. Inbound route theo mode qua delegate `_deliverData`.
- **Lifecycle** [`VtunConnection`](VtunConnection.cs): receive loop nền (data→channel, ECHO_REQ→reply, CONN_CLOSE/EOF→link-loss) + keepalive timer (gửi ECHO_REQ khi idle, trip khi peer im) + supervisor/auto-reconnect (F.6). Teardown gửi CONN_CLOSE best-effort.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IByteStreamTransport`, exceptions (`VpnAuthenticationException`/`VpnConnectionException`), `IHostResolver`, `Diagnostics` (`VpnLogExtensions`/`VpnDropReason`) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection<TState>`** (base supervisor F.6) + **`VpnReconnectOptions`** (`VtunReconnectOptions` kế thừa) |
| Dùng | [Vtun](../TqkLibrary.VpnClient.Vtun) | `VtunMessageCodec`/`VtunChallengeCodec` (handshake) + `VtunHostFlagsCodec` + `VtunFrameCodec`/`VtunFrameHeader` + `VtunConstants` + enums + **`IVtunFrameTransform`/`VtunFrameTransformFactory`/`VtunCipher`** (data-plane encrypt) |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`MacAddress`/`ArpResolver`/`VirtualHost`** (tap mode — bridge L2↔L3 cho `type ether`) |
| Dùng | [Transport.Tcp](../TqkLibrary.VpnClient.Transport.Tcp) | `TcpByteStream` (control+data TCP/5000, F.1) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseVtun(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Vtun/
├─ VtunDriver.cs               IVpnProtocolDriver: caps (L3Ip/Tcp/Security=None/Auth=PreSharedKey/OutOfBand) + ConnectAsync → VtunConnection
├─ VtunConnection.cs          Điều phối (kế thừa ReconnectingVpnConnection<…> F.6): TCP connect → AuthenticateAsync → kiểm cờ (tun/tcp/compress no) → nếu encrypt: cài DataTransform theo cipher (chỉ BF128ECB) → bind VtunPacketChannel → receive loop + keepalive; supervisor/reconnect ở base
├─ VtunControlChannel.cs      Sở hữu byte-stream: handshake 50-byte block + frame I/O (reader buffered dùng chung 2 pha) + DataTransform (encrypt/decrypt data-frame payload)
├─ VtunVpnConnection.cs       IVpnConnection: 1 session point-to-point; OpenSessionAsync ném NotSupportedException
├─ VtunVpnSession.cs          IVpnSession: PacketChannel ổn định + TunnelConfig tĩnh
├─ VtunReconnectOptions.cs    Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ VtunDriverConstants.cs     DriverName "vtun", DefaultMtu 1450
├─ Config/VtunConfig.cs       host name + password + IP tunnel tĩnh/peer + MAC (tap) + MTU → ToTunnelConfig() (route peer/32, OutOfBand)
├─ Enums/VtunConnectionState.cs  Disconnected/Connecting/Connected/Reconnecting
├─ DataChannel/VtunPacketChannel.cs   IPacketChannel L3 (tun): WriteIpPacketAsync → frame; Deliver → InboundIpPacket (bare IP)
├─ DataChannel/VtunEthernetChannel.cs IEthernetChannel L2 (tap): WriteFrameAsync → frame; Deliver → InboundFrame (Ethernet trần)
└─ Transport/
   ├─ IVtunTransportFactory.cs       Seam dựng 1 byte-stream tới endpoint
   └─ VtunSocketTransportFactory.cs  Production: TcpByteStream (F.1)
```

## Luồng nội bộ (connect)

1. `VtunDriver.ConnectAsync` → `VtunConnection.ConnectAsync` → `EstablishAsync` ([`VtunConnection.cs`](VtunConnection.cs#L103)).
2. `IVtunTransportFactory.ConnectAsync` → TCP byte-stream (`TcpByteStream`); dựng `VtunControlChannel`.
3. `VtunControlChannel.AuthenticateAsync` ([`VtunControlChannel.cs`](VtunControlChannel.cs#L44)): đọc greeting `VTUN…` → gửi `HOST: <name>` → đọc `OK CHAL:` (decode a..p) → gửi `CHAL:` (Blowfish(MD5(pwd)) challenge) → parse `OK FLAGS:` (cờ server) / `ERR` (ném `VpnAuthenticationException`).
4. Kiểm cờ: phải (`type tun` HOẶC `type ether`) + `proto tcp` + KHÔNG zlib/lzo (ném `VpnConnectionException` — chưa hỗ trợ pipe/tty/udp/compress). Nếu `encrypt` bật: resolve cipher từ `ServerCipherId` (`E<n>`) → `VtunFrameTransformFactory.TryCreate` (chỉ BF128ECB; cipher khác ⇒ `VpnConnectionException` nêu rõ tên) → cài `VtunControlChannel.DataTransform`.
5. Bind data plane theo link type: **tun** → `BindTunChannel` (`VtunPacketChannel` L3 thẳng facade); **tap** → `BindTapChannel` (`VtunEthernetChannel` L2 + `ArpResolver` + `VirtualHost` → `Facade.SetInner(virtualHost)`, MTU = link−14). `MarkRunning`; khởi receive loop + keepalive timer.
6. `MarkConnected`. Data: `WriteIpPacketAsync` → frame length-prefix → TCP; inbound frame → `Deliver` (data → `InboundIpPacket`; ECHO_REQ → ECHO_REP; CONN_CLOSE/EOF → link-loss). Keepalive: idle ≥30s → gửi ECHO_REQ; im >30×4s → link-loss → reconnect (F.6).

## Bảng chuẩn / nguồn (clean-room, KHÔNG copy GPL)

| Khía cạnh | Nguồn vtun 3.0.4 | Ghi chú |
|-----------|------------------|---------|
| Handshake client | `auth.c` (`auth_client`) | greeting `VTUN`-prefix → `HOST:` → challenge → response → flags |
| Frame dispatch | `linkfd.c` (`lfd_linker`) | ECHO_REQ → reply ECHO_REP; ECHO_REP ignore; CONN_CLOSE → close; BAD_FRAME → drop |
| Keepalive | `linkfd.c` (`sig_alarm`, `ka_interval`/`ka_maxfail`) | default `30:4` — idle interval gửi ECHO_REQ, maxfail miss → timeout |
| Address out-of-band | `vtund.conf(5)` (`up`/`down` ifconfig) | server tự đặt tun của nó; client IP cấp tĩnh ⇒ `AddressAssignment.OutOfBand` |
| Data-plane encrypt | `lib/lfd_encrypt.c` (`alloc_encrypt`/`encrypt_buf`/`decrypt_buf`) | `encrypt yes` mặc định BF128ECB; mỗi frame `BF-ECB(MD5(pwd), PKCS7-pad-to-8)` (ECB không IV/seq); cipher `E<n>` server gửi |
| Tap (type ether) | `vtund.conf(5)` (`type ether`), `lib/driver/tun_dev.c` | data frame payload = frame Ethernet trần (không header phụ); client bridge L2↔L3 bằng Ethernet fabric (ARP+VirtualHost) |

## Trạng thái & ghi chú

- **OFFLINE**: 8 test [`Drivers.Vtun.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Vtun.Tests) — `VtunConnection` end-to-end vs `SimulatedVtunServer` qua loopback: full handshake + **data-frame round-trip 2 chiều** + **encrypted data-frame round-trip (BF128ECB)** + **tap-mode bridge (type ether → Connected + facade L3 medium)** + reject sai password (`VpnAuthenticationException`) + reject cờ không hỗ trợ (`VpnConnectionException` cho pipe) + **reject cipher không hỗ trợ (AES256OFB)** + capabilities. Build XANH ns2.0 + net8.
- **VALIDATE LIVE ✓ (vtund 3.0.4 thật, lab [`vtun`](../../lab/vtun))**: client .NET → challenge-response MD5+Blowfish (server log `Use SSL-aware challenge/response` + `Session test opened` + tun0 bound) → **4/4 ICMP echo reply 2 chiều** qua tunnel (`10.11.0.2` ↔ `10.11.0.1`, RTT ~0.4ms). Reject path live ✓. **DATA-PLANE ENCRYPT (BF128ECB) ✓ (2026-06-25)**: host `enc` `encrypt blowfish128ecb` → flags Encrypt+Tcp+Tun (E1) → server `Blowfish-128-ECB encryption initialized` → **ICMP 4/4 2 chiều**; tcpdump: data frame 64-byte **ciphertext** (0 plaintext IP). (Ràng buộc env: vtund 3.0.4 trên OpenSSL 3.0 cần legacy provider `OPENSSL_CONF` cho Blowfish.) **TAP MODE (type ether/L2) ✓ (2026-06-25)**: host `tapsrv` → flags Tcp+KeepAlive+Ether → `VtunEthernetChannel`+ArpResolver+VirtualHost → **ICMP 4/4 2 chiều** (`10.13.0.2` ↔ `10.13.0.1`); server `tapsrv ether tap0`; MTU 1436 (1450−14); tcpdump data frame `length 76` (74-byte Ethernet) + 2 ARP frame → bridge L2↔L3 đúng. **0 BUG client** — golden vector OpenSSL khoá offline trước.
- **CHƯA làm (stretch)**: cipher khác **BF128ECB** (Blowfish/AES mode CBC/CFB/OFB + 256-bit — cần `lfd_encrypt` sideband `ivec`/`seq#` framing), **compression** (zlib/lzo — `compress yes`), **UDP transport** (`proto udp`).
