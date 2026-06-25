# TqkLibrary.VpnClient.Drivers.N2n

Driver **n2n v3** (ntop; mesh **L2** supernode + edge) — ráp codec thuần ở [`N2n`](../TqkLibrary.VpnClient.N2n) (V.7.4 phase a: REGISTER_SUPER/PACKET codec + transform) + **Ethernet fabric** ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet): ARP/VirtualHost) thành một tunnel **L2 Ethernet** chạy thật sau facade, trên **transport UDP** (n2n chỉ UDP; 1 datagram = 1 message — REGISTER_SUPER/_ACK/PACKET/REGISTER/PEER_INFO, **không framing**). Mở UDP tới supernode, đăng ký edge (**REGISTER_SUPER → REGISTER_SUPER_ACK**, cookie-correlated, lifetime → cadence keepalive), rồi chở **Ethernet frame nguyên gói** dạng **PACKET** (relay qua supernode) sau một [`N2nEthernetChannel`](DataChannel/N2nEthernetChannel.cs) (`IEthernetChannel`); kênh L2 này cắm vào fabric ([`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) static-IP + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs)) bridge xuống facade **L3** ([`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs)) ổn định mà IP stack bind — như SoftEther / OpenVPN-tap, nhưng **IP tĩnh** (n2n `-a`, **không DHCP**). Keepalive timer re-gửi REGISTER_SUPER giữ edge registered. **Driver L2 thứ ba** trong solution.

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp codec phase a + fabric L2 thành 1 tunnel sống (transport seam nhái [`Drivers.Nebula`](../TqkLibrary.VpnClient.Drivers.Nebula); bridge L2↔L3 nhái [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther)):

- **Transport**: UDP qua seam [`IN2nTransportFactory`](Transport/IN2nTransportFactory.cs) — production socket thật [`N2nSocketTransportFactory`](Transport/N2nSocketTransportFactory.cs) (`UdpClient` connected + receive loop), test inject loopback. 1 transport tới supernode; receive loop bơm chung `OnInboundDatagram` demux theo `N2nPacketType`.
- **Control plane**: REGISTER_SUPER → REGISTER_SUPER_ACK ([`N2nPacketCodec`](../TqkLibrary.VpnClient.N2n/N2nPacketCodec.cs)). Auth `simple-id` (token random **1 lần/connection** — supernode pin token, xem "bug live" dưới); `dev_addr` = **static `-a` overlay** (bắt buộc để keepalive là edge known). ACK cung cấp lifetime → cadence keepalive.
- **Data plane (L2)**: [`N2nEthernetChannel`](DataChannel/N2nEthernetChannel.cs) (`IEthernetChannel`): egress đọc dst-MAC từ header Ethernet → đóng frame thành **PACKET** (transform NULL/AES) → gửi UDP; ingress (PACKET đã decode) → `InboundFrame`. Cắm vào [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) (IPv4 static) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2↔L3) → `IPacketChannel`.
- **Timer/lifecycle**: keepalive timer (lifetime/2) re-gửi REGISTER_SUPER + supervisor/auto-reconnect (F.6).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, exceptions, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions` — log handshake/drop, Q.2) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection<TState>`** (base supervisor F.6: facade/lifetime/`OnLinkLost`/`ReconnectLoopAsync`/backoff-jitter/`SetState`/clock/`NextRandomBytes`) + **`VpnReconnectOptions`** (`N2nReconnectOptions` kế thừa) |
| Dùng | [N2n](../TqkLibrary.VpnClient.N2n) | `N2nPacketCodec` (encode/decode REGISTER_SUPER/_ACK/PACKET/…), models `N2nRegisterSuper`/`N2nRegisterSuperAck`/`N2nPacket`/`N2nAuth`/`N2nIpSubnet`, transform `IN2nTransform`/`N2nNullTransform`/`N2nAesTransform` |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`ArpResolver`** (IPv4 next-hop, static IP) + **`VirtualHost`** (bridge L2↔L3) + `MacAddress`/`EthernetFrame` — **KHÔNG viết lại ARP/switch** |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | `AesCbcCipher` qua `N2nAesTransform` (transform AES-CBC) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseN2n(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.N2n/
├─ N2nDriver.cs                     IVpnProtocolDriver: capabilities (L2Ethernet/Udp/None/PreSharedKey/OutOfBand) + ConnectAsync(config+endpoint) → N2nConnection
├─ N2nConnection.cs                 Điều phối (kế thừa ReconnectingVpnConnection<…> F.6): UDP → REGISTER_SUPER/_ACK → bind N2nEthernetChannel vào ArpResolver+VirtualHost → keepalive timer + demux; supervisor/reconnect ở base
├─ N2nVpnConnection.cs              IVpnConnection: 1 session L2 point-to-point; OpenSessionAsync ném NotSupportedException
├─ N2nVpnSession.cs                IVpnSession: PacketChannel ổn định (facade L3 bridge từ L2) + TunnelConfig tĩnh
├─ N2nReconnectOptions.cs          Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ N2nDriverConstants.cs           DriverName "n2n", port 7654, MTU 1290, lifetime mặc định
├─ Config/
│  ├─ N2nConfig.cs                 community + static overlay IP/prefix + edge MAC + transform (NULL/AES + key) + HeaderEncryption (-H) → ToTunnelConfig() (static IP, KHÔNG DHCP)
│  └─ N2nTransformKind.cs          Null / Aes (chọn IN2nTransform)
├─ DataChannel/N2nEthernetChannel.cs IEthernetChannel: WriteFrameAsync đóng Ethernet frame thành PACKET (dst-MAC từ header + transform); Deliver raise InboundFrame
├─ Transport/
│  ├─ IN2nTransportFactory.cs      Seam dựng UDP transport tới supernode (production socket / test loopback)
│  ├─ N2nTransportHandle.cs        IDatagramTransport + SetReceiver + receive-pump trả về từ factory
│  └─ N2nSocketTransportFactory.cs Socket thật: UDP (UdpClient) + receive loop dispatch — live-only, cross-TFM
└─ Enums/N2nConnectionState.cs     Disconnected/Connecting/Connected/Reconnecting
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `N2nDriver` | `IVpnProtocolDriver`: capabilities (**`L2Ethernet`**, **không PPP**, `None` (transform tùy chọn AES, không kind chuẩn), `Udp`, `PreSharedKey` (community), `OutOfBand` (static `-a`)); `ConnectAsync` dựng `N2nConnection` từ `N2nConfig` + endpoint | [N2nDriver.cs:17](N2nDriver.cs#L17) |
| `N2nConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection<N2nConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor F.6): override `EstablishAsync` (resolve supernode → mở UDP qua `IN2nTransportFactory` → **REGISTER_SUPER** (`RegisterSuperAsync`: community + edge MAC + auth `_auth` + `dev_addr`=static overlay) → đợi **REGISTER_SUPER_ACK** (cookie-correlated, lifetime → keepalive) → `N2nEthernetChannel` + `ArpResolver` static-IP + `VirtualHost` → `Facade.SetInner` → `StartKeepAlive` → `MarkConnected`) + `CleanupAttemptResourcesAsync`/`StopAttemptLoop`; keepalive timer re-gửi REGISTER_SUPER; **demux** (`OnInboundDatagram` theo `N2nPacketType`: RegisterSuperAck/Packet/ReRegisterSuper/Register/Nak); fault → `OnLinkLost` của base arm reconnect | [N2nConnection.cs:35](N2nConnection.cs#L35) |
| `N2nConfig` | Config tĩnh: `Community`/`OverlayAddress`+`PrefixLength`/`EdgeMac`(null⇒random)/`Transform`(NULL/AES)+`AesKey`/**`HeaderEncryption`(`-H`)**/`DnsServers`/`Routes`/`Mtu`; `ToTunnelConfig` (static IP + route mặc định = overlay subnet) | [Config/N2nConfig.cs:14](Config/N2nConfig.cs#L14) |
| `N2nEthernetChannel` | `IEthernetChannel` (`Medium=Ethernet`, `MaxHeaderLength=14`, `RequiresLinkAddressResolution=true`): `WriteFrameAsync` đọc dst-MAC từ header → `EncodePacket` (transform) → sink UDP; `Deliver` raise `InboundFrame` | [DataChannel/N2nEthernetChannel.cs:24](DataChannel/N2nEthernetChannel.cs#L24) |
| `N2nVpnConnection` / `N2nVpnSession` | `IVpnConnection` 1 session (point-to-point) + `IVpnSession` (`PacketChannel` facade L3 + `Config` tĩnh) | [N2nVpnConnection.cs:6](N2nVpnConnection.cs#L6) / [N2nVpnSession.cs:12](N2nVpnSession.cs#L12) |
| `IN2nTransportFactory` / `N2nTransportHandle` / `N2nSocketTransportFactory` | Seam dựng UDP transport (1 datagram = 1 message, **không framing**) + socket thật `UdpClient` + receive loop — live-only, cross-TFM (nhái Nebula) | [Transport/IN2nTransportFactory.cs:12](Transport/IN2nTransportFactory.cs#L12) / [N2nTransportHandle.cs:12](Transport/N2nTransportHandle.cs#L12) / [N2nSocketTransportFactory.cs:13](Transport/N2nSocketTransportFactory.cs#L13) |
| `N2nConnectionState` / `N2nReconnectOptions` | `Disconnected/Connecting/Connected/Reconnecting` + kế thừa `VpnReconnectOptions` (F.6) | [Enums/N2nConnectionState.cs:4](Enums/N2nConnectionState.cs#L4) / [N2nReconnectOptions.cs:10](N2nReconnectOptions.cs#L10) |

## Luồng kết nối (as-built)

1. **Resolve supernode endpoint** ([`ResolveSupernodeEndpointAsync`](N2nConnection.cs)): resolve host:port qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs).
2. **Mở transport UDP** qua `IN2nTransportFactory.ConnectAsync(endpoint, ct)` → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)` gắn demux; chạy receive-pump nền (loopback tự pump); `MarkRunning`.
3. **REGISTER_SUPER** ([`RegisterSuperAsync`](N2nConnection.cs)): cookie random + edge MAC + auth `simple-id` (token `_auth` sinh **1 lần/connection**) + **`dev_addr` = static `-a` overlay** ([`BuildDevAddr`](N2nConnection.cs)) → gửi; đợi REGISTER_SUPER_ACK cookie khớp (cap `handshakeTimeout`). Timeout ⇒ `VpnConnectionException`.
4. **REGISTER_SUPER_ACK** ([`ApplyAck`](N2nConnection.cs)): lifetime → `_keepAliveInterval` (lifetime/2); dev_addr supernode gán **chỉ log** (edge dùng static `-a`).
5. **Bind data plane L2**: `N2nEthernetChannel(codec, community, mac, transform, sink)` → `ArpResolver(mac, overlayAddress, channel)` + `VirtualHost(mac, channel, arp)` (ARP qua `InboundNonIpFrame`) → `Facade.SetInner(virtualHost)` → `MarkConnected`.
6. **TunnelConfig**: `N2nConfig.ToTunnelConfig()` (static overlay IP + route + MTU 1290; `VirtualHost.Mtu` = link−14) — tĩnh, không đàm phán.

## Vòng đời

- **Demux** ([`OnInboundDatagram`](N2nConnection.cs)): `RegisterSuperAck` (complete handshake TCS / keepalive-ACK ignore), `Packet` (decode transform → `N2nEthernetChannel.Deliver`), `ReRegisterSuper` (gửi keepalive REGISTER_SUPER ngay), `Register` (edge↔edge → trả REGISTER_ACK), `RegisterSuperNak` (log).
- **Gửi data** (`N2nEthernetChannel.WriteFrameAsync`): dst-MAC từ header → `N2nPacketCodec.EncodePacket` (transform NULL/AES) → sink UDP.
- **Keepalive timer** (lifetime/2): re-gửi REGISTER_SUPER (token `_auth` + `dev_addr` static **giữ nguyên** → supernode coi là cùng edge → ACK, không NAK).
- **Teardown** (`DisconnectAsync`/`DisposeAsync`): hủy reconnect đang chờ, hủy receive loop + timer, dispose VirtualHost/ArpResolver/channel/transport.
- **Reconnect** (supervisor): ở base [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6) — `OnLinkLost` arm `ReconnectLoopAsync` (backoff+jitter) gọi `EstablishAsync` sau `SwappablePacketChannel` ổn định.
- **Logging (Q.2)**: ctor nhận `ILoggerFactory?` (mặc định no-op). Log state/REGISTER_SUPER/REGISTER_SUPER_ACK/HandshakeCompleted/HandshakeFailed/PacketDropped (`VpnDropReason`)/LinkLost.

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Wire | n2n v3 (`n2n_typedefs.h`/`wire.c`) | common header 24B cleartext, big-endian (xem [N2n README](../TqkLibrary.VpnClient.N2n/README-vi.md)) |
| Đăng ký | REGISTER_SUPER / REGISTER_SUPER_ACK | cookie-correlated, auth `simple-id` (token cố định/connection), `dev_addr` = static `-a` |
| Data plane | PACKET (Ethernet frame) + transform NULL/AES-CBC | dst-MAC từ header Ethernet; AES-CBC null-IV + 16B preamble |
| L2 fabric | ARP (RFC 826) + VirtualHost | tái dùng `Ethernet` — KHÔNG viết lại; IP **tĩnh** (`-a`), không DHCP |
| Transport | UDP (n2n không TCP) | 1 datagram = 1 message, không framing; supernode-relay (P2P hole-punching = future) |
| Address | out-of-band (static `-a`) | không DHCP — `N2nConfig` → `TunnelConfig` |

## Trạng thái & ghi chú

- **Đã có (V.7.4 phase b)**: end-to-end **offline** — REGISTER_SUPER → ACK → data plane L2 PACKET 2 chiều qua ARP + VirtualHost (NULL/AES transform), keepalive, supervisor reconnect; config tĩnh point-to-point; `UseN2n(config)` + demo scheme `.n2n`. Test offline qua **supernode giả lập** (`SimulatedN2nSupernode`: REGISTER_SUPER → ACK; PACKET → ARP reply gateway + IP echo) trên loopback UDP: register + Connected + IP round-trip 2 chiều NULL/AES + register-timeout + channel/config (9 test).
- **VALIDATE LIVE L2 FULL-TUNNEL ✓ (lab [`n2n`](../../lab/n2n) [docker-compose.live.yml](../../lab/n2n/docker-compose.live.yml) — n2n v3.1.1 THẬT: supernode + edge gateway tun `10.7.0.1/24` + client .NET `10.7.0.2/24`, community `labnet`, transform NULL, demo `--vpn /lab/client.n2n`)**: supernode `Rx REGISTER_SUPER` → `created edge` → `Tx REGISTER_SUPER_ACK` (+ **keepalive ACK, 0 NAK** sau fix); demo `Gateway nội bộ 10.7.0.1 (ICMP reachable, RTT ~7ms)`; **tcpdump edge0** (tun edge thật): `10.7.0.2 > 10.7.0.1 ICMP echo request` + `10.7.0.1 > 10.7.0.2 ICMP echo reply` — ARP resolve gateway qua fabric + ICMP 2 chiều qua L2 overlay (supernode relay).
- **HEADER ENCRYPTION (`-H`) ✓ + VALIDATE LIVE** (2026-06-25, lab [docker-compose.he.yml](../../lab/n2n/docker-compose.he.yml) — supernode `-c community.list` + edge gateway `-H` + client `headerencryption=true`): `N2nConfig.HeaderEncryption` bật [`N2nHeaderEncryption`](../TqkLibrary.VpnClient.N2n/N2nHeaderEncryption.cs) (SPECK + Pearson key từ community). Connection giải mã header mọi datagram vào trước peek + mã hóa control message toàn bộ (header_len = length); [`N2nEthernetChannel`](DataChannel/N2nEthernetChannel.cs#L24) mã hóa **chỉ header PACKET** (header_len loại payload, payload vẫn dưới transform) — đúng `edge_utils.c`. Supernode `Rx REGISTER_SUPER` + `Tx REGISTER_SUPER_ACK` (KHÔNG "time stamp error"/"header decrypt fail") + ICMP 2 chiều RTT 6ms + tcpdump header ciphertext on-wire (community "labnet" KHÔNG cleartext).
- **3 bug interop sửa qua live** (self-pair offline KHÔNG bắt — đối chiếu `sn_utils.c`/`n2n.c`, **KHÔNG copy GPL**):
  1. **keepalive auth token-reuse**: `auth_edge` so sánh **toàn struct `n2n_auth_t` bằng memcmp**; supernode pin token từ register đầu → keepalive phải dùng **cùng token** → sinh random mỗi keepalive ⇒ `authentication failed`→REGISTER_SUPER_NAK. Fix = `_auth` sinh **1 lần/connection**.
  2. **dev_addr static bắt buộc**: advertise `dev_addr = 0.0.0.0/0` (Unset) ⇒ supernode gán địa chỉ động + coi keepalive là registration mới (mismatch). Fix = advertise **static `-a` overlay** (`BuildDevAddr`, như edge n2n với `-a`) ⇒ ACK giữ dev_addr, keepalive là edge known.
  3. **timestamp left-bound (`-H`)**: n2n `time_stamp()` = `(seconds<<32)|(µs<<12)` (KHÔNG plain µs); plain-µs lệch khung anti-replay (`TIME_STAMP_FRAME`=16<<32) ⇒ supernode drop "time stamp error". Fix = `NextStamp()` emit left-bound.
- **Chưa**:
  - **transform key-derivation** (Pearson của password cho AES/ChaCha20) — hiện `N2nAesTransform` nhận key sẵn; transform ChaCha20/Speck chưa làm.
  - **P2P edge↔edge UDP hole-punching** (QUERY_PEER/PEER_INFO/REGISTER trực tiếp) — hiện supernode-relay (đủ point-to-point).
- **Tham chiếu**: n2n github.com/ntop/n2n — **chỉ đọc spec wire/behavior, không copy GPL/source**; taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.7.4 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`NebulaSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.Nebula/Transport/NebulaSocketTransportFactory.cs) (net5+ overload ct; ns2.0 cancel-by-dispose). Bridge L2↔L3 (ARP + VirtualHost static-IP) nhái [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) nhưng **không DHCP**.
