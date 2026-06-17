# TqkLibrary.VpnClient.Drivers.SoftEther

Driver **SoftEther SSL-VPN** (V4.c) — **driver L2 thật đầu tiên**: ráp control handshake ([`SoftEtherHandshake`](../TqkLibrary.VpnClient.SoftEther/SoftEtherHandshake.cs), V4.b) + data plane Ethernet-over-TLS ([`SoftEtherEthernetChannel`](../TqkLibrary.VpnClient.SoftEther/DataChannel/SoftEtherEthernetChannel.cs), V4.c) thành một tunnel sống sau facade, trên **một byte-stream TLS** (SoftEther = "Ethernet over HTTPS"; cùng một stream chạy control rồi data). Sau login (`welcome`), stream chuyển sang **session data**: mỗi block = `uint32(num_frames)` + mỗi frame `uint32(size)·bytes` (raw Ethernet frame hoặc keep-alive). Data channel là **`IEthernetChannel`** cắm vào L2 fabric với **2 chế độ**: (mặc định) bắc-cầu-**1-host** — [`DhcpV4Configurator`](../TqkLibrary.VpnClient.Ethernet/DhcpV4Configurator.cs) (L2.5) lấy IP từ **SecureNAT qua DHCP** → [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) (L2.3) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2.2) xuống `IPacketChannel` ([`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs)); (opt-in `multiHost`) **multi-host broadcast domain** — data channel gắn vào [`EthernetAdapter.ConnectUplink`](../TqkLibrary.VpnClient.Ethernet/EthernetAdapter.cs) như **uplink port** + [`MultiHostSession`](../TqkLibrary.VpnClient.Ethernet/MultiHostSession.cs) (L2.8), mỗi station một MAC/IP DHCP lease riêng do SecureNAT cấp, thêm station qua `OpenSessionAsync` — IP stack chỉ thấy gói IP trần. Auth SHA-0 `secure_password` (V4.b), supervisor/auto-reconnect qua base [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs) dùng chung (F.6 — cùng mẫu OpenConnect/OpenVPN/WireGuard).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp khối protocol thuần từ [`SoftEther`](../TqkLibrary.VpnClient.SoftEther) + L2 fabric từ [`Ethernet`](../TqkLibrary.VpnClient.Ethernet) (mirror [`Drivers.OpenVpn`](../TqkLibrary.VpnClient.Drivers.OpenVpn) tap-mode + [`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard)):

- **Transport**: byte-stream TLS qua seam [`ISoftEtherTransportFactory`](Transport/ISoftEtherTransportFactory.cs) — production [`SoftEtherTlsTransportFactory`](Transport/SoftEtherTlsTransportFactory.cs) (TCP + `SslStream`, cùng shape SSTP `TlsByteStream`, F.1), test inject loopback in-memory.
- **Control plane**: [`SoftEtherHandshake.RunAsync`](../TqkLibrary.VpnClient.SoftEther/SoftEtherHandshake.cs) (watermark POST → hello → login + SHA-0 → welcome) trên cùng stream.
- **Data plane**: [`SoftEtherDataBlockReader`](../TqkLibrary.VpnClient.SoftEther/DataChannel/SoftEtherDataBlockReader.cs) decode block vào → `SoftEtherEthernetChannel.Deliver`; [`SoftEtherEthernetChannel.WriteFrameAsync`](../TqkLibrary.VpnClient.SoftEther/DataChannel/SoftEtherEthernetChannel.cs) encode block ra.
- **L2→L3 bridge**: (1-host) `DhcpV4Configurator` (lease IP) → `ArpResolver` + `VirtualHost` → `IPacketChannel`; (multi-host, opt-in) `EthernetAdapter.ConnectUplink` + `MultiHostSession` → N station, mỗi station DHCP lease riêng.
- **Lifecycle**: keep-alive timer (gửi chuỗi keep-alive cố định) + supervisor/auto-reconnect qua base [`ReconnectingVpnConnection<SoftEtherConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs) (F.6).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`/`IEthernetChannel`, `SwappablePacketChannel`, `IByteStreamTransport`, exceptions, `IHostResolver`, **`Diagnostics`** (`VpnEventIds`/`VpnLogExtensions` — log handshake/DHCP/keepalive, Q.2) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | base `ReconnectingVpnConnection<TState>` (supervisor/reconnect/backoff/jitter/`StateChanged`/teardown) + `VpnReconnectOptions` (F.6) |
| Dùng | [SoftEther](../TqkLibrary.VpnClient.SoftEther) | `SoftEtherHandshake`/`SoftEtherAuth` (control + auth), `SoftEtherEthernetChannel`/`SoftEtherDataBlockReader`/`SoftEtherDataFrameCodec` (data plane), `SoftEtherLoginRequest`/`SoftEtherSessionParams` |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | `DhcpV4Configurator` (L2.5 lease IP), `ArpResolver` (L2.3), `VirtualHost` (L2.2 bridge), `MacAddress` |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | `Sha0` (F.5a) cho `SoftEtherAuth.secure_password` |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseSoftEther(hubName)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.SoftEther/
├─ SoftEtherDriver.cs                 IVpnProtocolDriver: capabilities (L2Ethernet/Tls/UserPassword/Dhcp/L2BroadcastDomain) + ctor multiHost opt-in + ConnectAsync(endpoint+credentials) → SoftEtherConnection
├─ SoftEtherConnection.cs             : ReconnectingVpnConnection<SoftEtherConnectionState> — điều phối: TLS → control handshake → data channel L2 → (1-host) DHCP+ArpResolver+VirtualHost / (multiHost) ConnectUplink+MultiHostSession → facade L3 + keep-alive; supervisor/reconnect ở base (F.6); AddStationAsync thêm station
├─ SoftEtherVpnConnection.cs          IVpnConnection: 1-host ⇒ 1 session + OpenSessionAsync ném NotSupported; multiHost ⇒ primary + OpenSessionAsync thêm station (MAC mới, DHCP lease riêng)
├─ SoftEtherVpnSession.cs             IVpnSession: PacketChannel ổn định + TunnelConfig DHCP-leased
├─ SoftEtherReconnectOptions.cs       : VpnReconnectOptions — named type giữ API public (knob backoff/jitter ở base Drivers.Core, F.6)
├─ Transport/
│  ├─ ISoftEtherTransportFactory.cs   Seam dựng byte-stream TLS tới host:port (production / test loopback)
│  ├─ SoftEtherTlsTransport.cs        IByteStreamTransport thật: TCP + SslStream (cùng shape SSTP TlsByteStream, F.1), cross-TFM
│  └─ SoftEtherTlsTransportFactory.cs Production factory dựng SoftEtherTlsTransport mỗi attempt
├─ Enums/SoftEtherConnectionState.cs  Disconnected/Connecting/Connected/Reconnecting
└─ Models/SoftEtherReconnectInfo.cs   Địa chỉ + cờ AddressChanged sau reconnect (DHCP có thể lease IP khác)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `SoftEtherDriver` | `IVpnProtocolDriver`: capabilities (`L2Ethernet`, **không PPP**, `Tls`, **UserPassword** SHA-0, `Tcp`, `Dhcp`, `L2BroadcastDomain`, **`SupportsMultiHost=true`** L2.8); ctor **`multiHost`** opt-in; `ConnectAsync` dựng `SoftEtherConnection` từ hub (config) + endpoint (host/port) + credentials (user/pass) | [SoftEtherDriver.cs:20](SoftEtherDriver.cs#L20) |
| `SoftEtherConnection` | `: ReconnectingVpnConnection<SoftEtherConnectionState>` (F.6). Bộ điều phối: `EstablishAsync` chạy `ISoftEtherTransportFactory.ConnectAsync` (TLS) → `SoftEtherHandshake.RunAsync` (watermark/hello/login/welcome) → `SoftEtherEthernetChannel` + receive loop decode block → **(1-host)** `EstablishSingleHostAsync` (DHCP lease + `ArpResolver`+`VirtualHost`) / **(multiHost)** `EstablishMultiHostAsync` (`EthernetAdapter.ConnectUplink` + `MultiHostSession`, primary station DHCP) → `Facade.SetInner` → keep-alive timer; `AddStationAsync(mac)` thêm station (DHCP lease riêng); `StopAttemptLoop` dispose keep-alive timer, `CleanupAttemptResourcesAsync` dọn fabric/transport, `OnReconnected` raise `Reconnected`; stream đóng / fault → `OnLinkLost` (base arm supervisor) | [SoftEtherConnection.cs:39](SoftEtherConnection.cs#L39) |
| `SoftEtherVpnConnection` | `IVpnConnection`: 1-host ⇒ 1 session, `OpenSessionAsync` ⇒ `NotSupportedException`; multiHost ⇒ primary + extra sessions, `OpenSessionAsync` gọi `AddStationAsync` (MAC mới locally-administered, DHCP lease riêng) | [SoftEtherVpnConnection.cs:6](SoftEtherVpnConnection.cs#L6) |
| `SoftEtherVpnSession` | `IVpnSession`: `PacketChannel` (facade ổn định) + `Config` (DHCP-leased) | [SoftEtherVpnSession.cs:10](SoftEtherVpnSession.cs#L10) |
| `SoftEtherReconnectOptions` | `: VpnReconnectOptions` (F.6) — named type giữ API public; `Enabled`/`MaxAttempts`/backoff/jitter ở base `Drivers.Core` | [SoftEtherReconnectOptions.cs:11](SoftEtherReconnectOptions.cs#L11) |
| `ISoftEtherTransportFactory` | Seam dựng byte-stream TLS tới host:port (production socket / test loopback) | [Transport/ISoftEtherTransportFactory.cs:13](Transport/ISoftEtherTransportFactory.cs#L13) |
| `SoftEtherTlsTransport` | `IByteStreamTransport` thật: `TcpClient` + `SslStream` (accept-any cert mặc định; cross-TFM net5+ overload ct, ns2.0 cancel-by-dispose) — cùng shape SSTP `TlsByteStream`, **live-only** | [Transport/SoftEtherTlsTransport.cs:18](Transport/SoftEtherTlsTransport.cs#L18) |
| `SoftEtherTlsTransportFactory` | Production factory dựng `SoftEtherTlsTransport` mỗi attempt (cert-callback optional) | [Transport/SoftEtherTlsTransportFactory.cs:13](Transport/SoftEtherTlsTransportFactory.cs#L13) |
| `SoftEtherConnectionState` | `Disconnected`/`Connecting`/`Connected`/`Reconnecting` | [Enums/SoftEtherConnectionState.cs:5](Enums/SoftEtherConnectionState.cs#L5) |
| `SoftEtherReconnectInfo` | Địa chỉ + cờ `AddressChanged` sau reconnect (DHCP có thể lease IP khác) | [Models/SoftEtherReconnectInfo.cs:6](Models/SoftEtherReconnectInfo.cs#L6) |

## Luồng kết nối (as-built)

1. **Transport TLS**: `ISoftEtherTransportFactory.ConnectAsync(host, port, afp, ct)` dựng `IByteStreamTransport` → `transport.ConnectAsync` (TCP + TLS handshake). Resolve host nằm trong transport (`SoftEtherTlsTransport` dùng `IHostResolver`).
2. **Control handshake** ([`SoftEtherHandshake.RunAsync`](../TqkLibrary.VpnClient.SoftEther/SoftEtherHandshake.cs#L143)): watermark POST `/vpnsvc/connect.cgi` → đọc `hello` (random 20B challenge) → POST `login` PACK (`secure_password` SHA-0 + session params) `/vpnsvc/vpn.cgi` → đọc `welcome` (`session_name`) hoặc lỗi (`error`≠0 ⇒ `SoftEtherProtocolException`).
3. **Data channel L2** ([`SoftEtherEthernetChannel`](../TqkLibrary.VpnClient.SoftEther/DataChannel/SoftEtherEthernetChannel.cs)): cùng stream giờ tải Ethernet frame. Bật **receive loop** ([`ReceiveLoopAsync`](SoftEtherConnection.cs#L294)): `SoftEtherDataBlockReader.ReadBlockAsync` decode block vào → mỗi frame `channel.Deliver` (drop keep-alive). EOF/fault ⇒ link lost (`OnLinkLost` ở base).
4. **DHCP lease** ([`DhcpV4Configurator`](../TqkLibrary.VpnClient.Ethernet/DhcpV4Configurator.cs)): gắn `dhcp.HandleInboundFrame` vào `channel.InboundFrame`, chạy `ConfigureAsync` (DISCOVER→OFFER→REQUEST→ACK qua L2 broadcast) → `TunnelConfig` (yiaddr + mask→prefix + router→route + DNS). SecureNAT là DHCP server. Không lease IPv4 ⇒ `VpnConnectionException`.
5. **Bridge L2↔L3**: `ArpResolver(mac, leasedIp, channel)` + `VirtualHost(mac, channel, arp)`; nối `InboundNonIpFrame→arp` (ARP) + `InboundIpPacket→dhcp` (DHCP renewal). `config.Mtu = host.Mtu` (link−14). `Facade.SetInner(virtualHost)` → `MarkConnected()` → state Connected.
6. **Keep-alive**: timer 5s gửi block 1-frame chứa chuỗi `"Internet Connection Keep Alive Packet"` (giữ session mở qua middlebox).

## Vòng đời

- **Gửi data** (`VirtualHost.WriteIpPacketAsync`): đọc dest IP → `ArpResolver.ResolveAsync` (next-hop MAC) → wrap Ethernet frame → `SoftEtherEthernetChannel.WriteFrameAsync` → encode block 1-frame → `transport.WriteAsync`.
- **Nhận data** (receive loop): decode block → `channel.Deliver(frame)` raise `InboundFrame` → `VirtualHost` strip header → `InboundIpPacket` (IP) hoặc `InboundNonIpFrame` (ARP) → `ArpResolver`.
- **Teardown** (`DisconnectAsync` ⇒ base `DisconnectCoreAsync`): hủy reconnect đang chờ, hủy receive loop + keep-alive timer (`StopAttemptLoop`), dispose `VirtualHost`/`ArpResolver`/`DhcpV4Configurator`/transport qua `CleanupAttemptResourcesAsync` (host dispose channel theo).
- **Reconnect** (base supervisor F.6): `EstablishAsync`/`ReconnectLoopAsync` backoff+jitter ở [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs); DHCP lease lại nên `OnReconnected` raise `Reconnected` mang `AddressChanged` thật.
- **Logging/diagnostics (Q.2)**: ctor `SoftEtherConnection`/`SoftEtherDriver` nhận `ILoggerFactory?` (mặc định [`NullLogger`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs) ⇒ no-op, **ADDITIVE không đổi hành vi**). Log qua [`VpnLogExtensions`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs): control handshake + DHCP lease + bridge bind→Handshake; sau khi bind facade→HandshakeCompleted; keep-alive frame→Keepalive; `SetState`→StateChanged; `OnLinkLost`→LinkLost; reconnect attempt/success→ReconnectAttempt/Reconnected.

## Bảng chuẩn / nguồn

| Khối | Chuẩn / nguồn | Ghi chú |
|------|---------------|---------|
| Control handshake | [`.docs/07`](../../.docs/07-softether.md) §Handshake | watermark/hello/login/welcome — re-implement từ behavior, **không copy GPL**; watermark blob placeholder (V4.b) |
| Auth | SHA-0 `secure_password` ([`.docs/07`](../../.docs/07-softether.md) §Auth) | `SoftEtherAuth` (F.5a `Sha0`) — password gốc không qua wire |
| Data frame | [`.docs/07`](../../.docs/07-softether.md) §Multi-host & multi-connection | block length-prefixed `uint32(n)·{uint32(size)·bytes}`; keep-alive chuỗi cố định |
| DHCP lease | RFC 2131 (`DhcpV4Configurator` L2.5) | SecureNAT pool mặc định 192.168.30.x — client = ARP responder + DHCP client trên L2 |
| ARP | RFC 826 (`ArpResolver` L2.3) | resolve next-hop MAC (IPv4-only) |
| Transport | TLS over TCP (HTTPS) | byte-stream `IByteStreamTransport` (F.1); shape giống SSTP `TlsByteStream` |

## Trạng thái & ghi chú

- **Đã có (V4.c)**: end-to-end **offline** — control handshake (watermark/hello/login SHA-0/welcome) → data plane Ethernet-over-TLS → DHCP lease từ SecureNAT giả lập → ARP next-hop → IP round-trip 2 chiều qua bridge L2↔L3; keep-alive; supervisor reconnect; `UseSoftEther(hubName)`. Test offline qua **server SecureNAT giả lập** (control + DHCP server + ARP responder + IP echo) trên byte-pipe in-memory: handshake → lease (OFFER/ACK) → ARP → IP echo → login bị từ chối ⇒ ném (error code) → driver facade → server đóng stream ⇒ Disconnected.
- **Đã có (Q.2)**: luồng `ILoggerFactory?` qua driver/connection → trace control-handshake/DHCP/keepalive/state/link-lost/reconnect (xem Vòng đời). Test offline `SoftEtherLoggingTests.cs`: logger giả lập bắt Handshake (control + DHCP)/HandshakeCompleted/StateChanged khi connect.
- **Đã có (F.6 — migrate supervisor dùng chung)**: `SoftEtherConnection` nay kế thừa [`ReconnectingVpnConnection<SoftEtherConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs) (base gom `Facade`/lifetime CTS/lock/state/`StateChanged`/log/clock + máy link-loss→supervisor→reconnect-loop backoff+jitter); driver chỉ giữ logic protocol (`EstablishAsync`/`CleanupAttemptResourcesAsync`/`StopAttemptLoop` + ánh xạ state + `OnReconnected`). `SoftEtherReconnectOptions : VpnReconnectOptions`. **Không đổi hành vi** — toàn bộ test `SoftEtherConnectionTests`/`SoftEtherLoggingTests` (13) + `Drivers.Core.Tests` (7) vẫn xanh.
- **Đã có (multi-host data-plane, opt-in `multiHost`)**: data channel gắn vào `EthernetAdapter.ConnectUplink` như uplink port + `MultiHostSession` (L2.8) — primary station + `OpenSessionAsync` thêm station, mỗi station một MAC/IP DHCP lease riêng do SecureNAT cấp (server tự trả ARP). Test offline `SoftEtherConnectionTests` (multi-host uplink + OpenSession station + 1-host vẫn ném NotSupported).
- **Chưa**:
  - **multi-connection** (1–32 parallel TCP / 1 session logic, `additional_connect`+`session_key`, `half_connection`) — hiện 1 TCP/1 session.
  - **deflate/RC4 payload** (`use_compress`/`use_encrypt` trên TLS) — hiện payload thô trên TLS (TLS đã mã hóa).
  - **IPv6** trong tunnel (SecureNAT cấp IPv6) — DHCP/ARP hiện IPv4-only (cả 1-host lẫn multi-host); cần wire NDISC L2.4 + SLAAC/DHCPv6 L2.6 lên station.
  - **watermark blob thật** — production cần truyền blob thật qua `SoftEtherWatermark.WithSignature` (placeholder cho test).
  - **validate live** (lab **Q.1** — SoftEther server chính chủ): interop watermark/PACK/SecureNAT thật, multi-connection, IPv6 pool.
- **Tham chiếu**: SoftEther protocol spec/behavior ([`.docs/07`](../../.docs/07-softether.md)) — **chỉ đọc spec/behavior, không copy GPL source** (`Pack.c`/`Watermark.c`/`Protocol.c`/`Connection.c`); roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.4.

> Build xanh cả `netstandard2.0` + `net8.0`. `SoftEtherTlsTransport` theo TFM giống SSTP `TlsByteStream` (net5+ overload ct; ns2.0 cancel-by-dispose). `record`/`init`/`required` qua `TqkLibrary.CompilerServices`.
