# TqkLibrary.VpnClient.Drivers.L2tpv3Eth

Driver **L2TPv3 Ethernet-pseudowire (RFC 3931 + RFC 4719)** — **L2-over-UDP**, chế độ **static/unmanaged** — chở **Ethernet frame nguyên gói** sau một **header data L2TPv3** (Session ID 32-bit + Cookie 0/4/8 byte + Default L2-Specific Sublayer 4 byte tùy chọn cho sequencing) trên **UDP** (port mặc định **1701**), cắm vào **Ethernet fabric** ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet): ARP/VirtualHost) thành một tunnel **L2 Ethernet** chạy thật sau facade. **Sibling của driver [`vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan) / [`geneve`](../TqkLibrary.VpnClient.Drivers.Geneve)** (header L2TPv3 thay VXLAN/Geneve header) và cũng **BỎ hết control plane**: KHÔNG L2TP control channel, KHÔNG registration/handshake, KHÔNG transform/mã hóa, KHÔNG keepalive. Session ID + Cookie **cấu hình tĩnh 2 đầu** (giống `ip l2tp add session ... pwtype ethernet`). Remote là **unicast tĩnh** (host từ `VpnEndpoint`, port từ config = 1701). Egress: prepend header L2TPv3 (Session ID **remote** 32-bit BE + Cookie + tùy chọn Default L2-Specific Sublayer với sequence 24-bit) → gửi UDP; ingress: kiểm Session ID = **local** khớp + Cookie khớp → bóc payload = Ethernet frame → fabric; **drop** nếu control message (T-bit) / Session ID 0 (control channel) / Session ID sai / Cookie sai / header cụt. IP tĩnh (overlay address, **không DHCP**), no-elevation.

> **No-admin variant của L2TPv3**: driver chạy header data L2TPv3-over-IP **thẳng trong UDP payload** (biến thể no-admin của V.8c L2TPv3 proto-115, không cần raw socket / elevation). **KHÁC** Linux `ip l2tp ... encap udp` — Linux thêm prefix 4 byte (Ver/flags 16-bit + reserved 16-bit) TRƯỚC Session ID; driver này KHÔNG có prefix đó (xem [Bảng chuẩn / RFC](#bảng-chuẩn--rfc) + [Trạng thái](#trạng-thái--ghi-chú)).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp codec L2TPv3 (tự chứa, [`L2tpv3DataHeader`](L2tpv3DataHeader.cs)) + fabric L2 ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet)) thành 1 tunnel sống; bridge L2↔L3 + supervisor/reconnect nhái [`Drivers.Geneve`](../TqkLibrary.VpnClient.Drivers.Geneve) — **không có bước register/handshake/keepalive/transform**:

- **Transport**: UDP qua seam [`IL2tpv3EthTransportFactory`](Transport/IL2tpv3EthTransportFactory.cs) — production socket thật [`L2tpv3EthUdpTransportFactory`](Transport/L2tpv3EthUdpTransportFactory.cs) (`Socket` UDP: bind ephemeral + connect remote, IPv4/IPv6 + receive loop), test inject loopback. 1 transport tới remote; receive loop bơm `OnInboundDatagram`.
- **Không control plane**: L2TPv3 static không có control channel, không handshake — `EstablishAsync` chỉ mở transport rồi bind data plane. State `Connecting` là transient.
- **Data plane (L2)**: [`L2tpv3EthEthernetChannel`](DataChannel/L2tpv3EthEthernetChannel.cs) (`IEthernetChannel`): egress prepend header L2TPv3 (`L2tpv3DataHeader.EncodeData(remoteSessionId, cookie, sequencing, seq, frame)`) → gửi UDP; ingress (frame đã bóc header) → `InboundFrame`. Cắm vào [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) (IPv4 static) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2↔L3) → `IPacketChannel`.
- **Lifecycle**: supervisor/auto-reconnect (F.6) ở base — không timer keepalive.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions`) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection`** (base supervisor F.6: facade/lifetime/`OnLinkLost`/`ReconnectLoopAsync`/backoff-jitter/`SetState`/clock/`NextRandomBytes`) + **`VpnReconnectOptions`** (`L2tpv3EthReconnectOptions` kế thừa) + **`VpnConnectionState`** (enum state dùng chung) |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`ArpResolver`** (IPv4 next-hop, static IP) + **`VirtualHost`** (bridge L2↔L3) + `MacAddress`/`EthernetFrame` — **KHÔNG viết lại ARP/switch** |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseL2tpv3Ethernet(config)` đăng ký driver |

Không dùng `Vxlan`/`Geneve`/`L2tpIpsec`/`Crypto` (L2TPv3 có wire codec riêng — header data L2TPv3, không mã hóa; L2TPv2 driver [`L2tpIpsec`](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) là giao thức KHÁC hẳn).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.L2tpv3Eth/
├─ L2tpv3EthDriver.cs                    IVpnProtocolDriver: capabilities (L2Ethernet/Udp/None/None-auth/OutOfBand, no-elevation) + ConnectAsync(config+endpoint) → L2tpv3EthConnection
├─ L2tpv3EthConnection.cs                Điều phối (kế thừa ReconnectingVpnConnection F.6): UDP → bind L2tpv3EthEthernetChannel vào ArpResolver+VirtualHost → demux; KHÔNG register/keepalive/transform; supervisor/reconnect ở base
├─ L2tpv3EthVpnConnection.cs             IVpnConnection: 1 session L2 point-to-point; OpenSessionAsync ném NotSupportedException
├─ L2tpv3EthVpnSession.cs                IVpnSession: PacketChannel ổn định (facade L3 bridge từ L2) + TunnelConfig tĩnh
├─ L2tpv3DataHeader.cs                   Static/stateless: EncodeData(sessionId, cookie, sequencing, seq, frame) (Session ID 32-bit BE + cookie 0/4/8 + tùy chọn Default L2-Specific Sublayer + frame); TryDecodeData (reject runt/control-T-bit/zero-SID/SID-mismatch/cookie-mismatch/truncated, bóc seq + frame) → L2tpv3DecodeError; const DefaultPort=1701/SessionIdLength=4/ControlMessageBit=0x80/MaxSessionId=0x7FFFFFFF/L2SpecificSublayerLength=4/SublayerSequenceBit=0x40/MaxSequenceNumber
├─ L2tpv3EthReconnectOptions.cs          Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ L2tpv3EthDriverConstants.cs           DriverName "l2tpv3-eth", DefaultPort 1701, DefaultMtu 1400
├─ Config/L2tpv3EthConfig.cs             LocalSessionId + RemoteSessionId + Cookie (0/4/8, shared) + EnableSequencing + Port(1701) + static overlay IP/prefix + LocalMac (null⇒random LAA) + DnsServers/Routes + Mtu → ToTunnelConfig() (static IP, KHÔNG DHCP); ResolveLocalMac + validate Session ID (non-zero, top bit clear) + cookie length
├─ DataChannel/L2tpv3EthEthernetChannel.cs IEthernetChannel: WriteFrameAsync prepend header L2TPv3 (remote Session ID + cookie + tùy chọn sublayer với sequence counter) → sink UDP; Deliver raise InboundFrame
├─ Enums/L2tpv3DecodeError.cs            Kết quả decode: None/Runt/ControlMessage/ZeroSessionId/SessionIdMismatch/CookieMismatch/Truncated
├─ Properties/AssemblyInfo.cs           InternalsVisibleTo test assembly (channel là internal)
└─ Transport/
   ├─ IL2tpv3EthTransportFactory.cs      Seam dựng UDP transport tới remote (production socket / test loopback)
   ├─ L2tpv3EthTransportHandle.cs        IDatagramTransport + SetReceiver + receive-pump trả về từ factory
   └─ L2tpv3EthUdpTransportFactory.cs    Socket thật: UDP bind ephemeral + connect remote (IPv4/IPv6) + receive loop — live-only, cross-TFM
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `L2tpv3EthDriver` | `IVpnProtocolDriver`: capabilities (**`L2Ethernet`**, không PPP, `None` security, `Udp`, **`None` auth** (không control plane), `OutOfBand` static, **no-elevation/no-raw**); `ConnectAsync` dựng `L2tpv3EthConnection` từ `L2tpv3EthConfig` + endpoint (host từ endpoint, port từ config) | [L2tpv3EthDriver.cs:22](L2tpv3EthDriver.cs#L22) |
| `L2tpv3EthConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor F.6): override `EstablishAsync` (resolve remote → mở UDP qua `IL2tpv3EthTransportFactory` → `L2tpv3EthEthernetChannel(remoteSid, cookie, seq, mac, sink)` + `ArpResolver` static-IP + `VirtualHost` → `Facade.SetInner` → `MarkConnected`) + `CleanupAttemptResourcesAsync`; **demux** (`OnInboundDatagram`: `L2tpv3DataHeader.TryDecodeData` khớp local Session ID + Cookie → `Deliver`, map `L2tpv3DecodeError`→`VpnDropReason`); **KHÔNG** register/keepalive/transform; fault → `OnLinkLost` của base arm reconnect | [L2tpv3EthConnection.cs:32](L2tpv3EthConnection.cs#L32) |
| `L2tpv3EthConfig` | Config tĩnh: `LocalSessionId`/`RemoteSessionId` (validate non-zero + top bit clear)/`Cookie`(0/4/8, shared)/`EnableSequencing`/`Port`(1701)/`OverlayAddress`+`PrefixLength`/`LocalMac`(null⇒random LAA)/`DnsServers`/`Routes`/`Mtu`(1400); `ToTunnelConfig` (static IP + route mặc định = overlay subnet); `ResolveLocalMac` | [Config/L2tpv3EthConfig.cs:18](Config/L2tpv3EthConfig.cs#L18) |
| `L2tpv3DataHeader` | Static/stateless codec (RFC 3931 §4.1 + RFC 4719): `EncodeData(sessionId, cookie, sequencing, seq, frame)` (Session ID 32-bit BE + cookie 0/4/8 + tùy chọn Default L2-Specific Sublayer 4B với S-bit + seq 24-bit + frame); `TryDecodeData` (reject runt / control-T-bit / zero-SID / SID-mismatch / cookie-mismatch / truncated, bóc seq + frame) trả về `L2tpv3DecodeError`; const `DefaultPort`/`SessionIdLength`/`ControlMessageBit`/`MaxSessionId`/`L2SpecificSublayerLength`/`SublayerSequenceBit`/`MaxSequenceNumber` | [L2tpv3DataHeader.cs:24](L2tpv3DataHeader.cs#L24) |
| `L2tpv3EthEthernetChannel` | `IEthernetChannel` (`Medium=Ethernet`, `MaxHeaderLength=14`, `RequiresLinkAddressResolution=true`): `WriteFrameAsync` prepend header L2TPv3 (remote Session ID + cookie + tùy chọn sublayer với sequence counter tăng dần 24-bit) → sink UDP; `Deliver` raise `InboundFrame` | [DataChannel/L2tpv3EthEthernetChannel.cs:27](DataChannel/L2tpv3EthEthernetChannel.cs#L27) |
| `L2tpv3DecodeError` | Enum kết quả decode: `None` (thành công) / `Runt` / `ControlMessage` (T-bit) / `ZeroSessionId` / `SessionIdMismatch` / `CookieMismatch` / `Truncated` — 1 lý do drop rõ ràng cho log + test | [Enums/L2tpv3DecodeError.cs:8](Enums/L2tpv3DecodeError.cs#L8) |
| `L2tpv3EthVpnConnection` / `L2tpv3EthVpnSession` | `IVpnConnection` 1 session (point-to-point) + `IVpnSession` (`PacketChannel` facade L3 + `Config` tĩnh) | [L2tpv3EthVpnConnection.cs:9](L2tpv3EthVpnConnection.cs#L9) / [L2tpv3EthVpnSession.cs:13](L2tpv3EthVpnSession.cs#L13) |
| `IL2tpv3EthTransportFactory` / `L2tpv3EthTransportHandle` / `L2tpv3EthUdpTransportFactory` | Seam dựng UDP transport (1 datagram = 1 message, **không framing**) + socket thật `Socket` UDP (bind ephemeral + connect, IPv4/IPv6) + receive loop — live-only, cross-TFM (nhái Geneve) | [Transport/IL2tpv3EthTransportFactory.cs:14](Transport/IL2tpv3EthTransportFactory.cs#L14) / [L2tpv3EthTransportHandle.cs:15](Transport/L2tpv3EthTransportHandle.cs#L15) / [L2tpv3EthUdpTransportFactory.cs:18](Transport/L2tpv3EthUdpTransportFactory.cs#L18) |
| `VpnConnectionState` / `L2tpv3EthReconnectOptions` | `Disconnected/Connecting/Connected/Reconnecting` (dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) — state kế thừa từ base) + kế thừa `VpnReconnectOptions` (F.6) | [../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) / [L2tpv3EthReconnectOptions.cs:10](L2tpv3EthReconnectOptions.cs#L10) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Data message | **RFC 3931** (L2TPv3) §4.1 | header data: Session ID 32-bit BE (KHÁC 0 — 0 dành control channel; **bit cao = T/control flag** ⇒ data Session ID là 1..0x7FFFFFFF) + Cookie 0/4/8 byte + tùy chọn Default L2-Specific Sublayer |
| L2-Specific Sublayer | RFC 3931 §4.6 | Default sublayer 4 byte: byte0 bit1 = **S** (Sequence present) → `0x40`, bit 8-31 = Sequence Number 24-bit BE; chỉ có khi bật sequencing |
| Ethernet pseudowire | **RFC 4719** | payload sau header = **Ethernet frame nguyên gói** → L2 fabric (`pwtype ethernet`) |
| Encap | UDP/**1701** (dùng chung L2TPv2) | phân biệt data vs control bằng Session ID / T-bit; 1 datagram = 1 message, không framing; remote unicast tĩnh. **KHÁC Linux `encap udp`**: Linux thêm prefix 4B (Ver/flags 16-bit + reserved 16-bit) trước Session ID — driver này chạy header L2TPv3-over-IP thẳng trong UDP (không prefix), biến thể no-admin |
| L2 fabric | ARP (RFC 826) + VirtualHost | tái dùng `Ethernet` — KHÔNG viết lại; IP **tĩnh**, không DHCP |
| Address | out-of-band (static) | không DHCP — `L2tpv3EthConfig` → `TunnelConfig` |
| Security | none | L2TPv3 data không mã hóa (RFC 3931 không định nghĩa crypto; muốn mã hóa gắn IPsec ESP bên ngoài) |

## Luồng nội bộ (UDP ↔ fabric, as-built)

1. **Resolve remote** ([`ResolveRemoteEndpointAsync`](L2tpv3EthConnection.cs)): resolve host (từ `VpnEndpoint.Host`) qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) → `IPEndPoint(ip, config.Port)`.
2. **Mở transport UDP** qua `IL2tpv3EthTransportFactory.ConnectAsync(endpoint, ct)` → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)`; chạy receive-pump nền (loopback tự pump); `MarkRunning`.
3. **Bind data plane L2**: `L2tpv3EthEthernetChannel(remoteSid, cookie, sequencing, mac, sink)` → `ArpResolver(mac, overlayAddress, channel)` + `VirtualHost(mac, channel, arp)` (ARP qua `InboundNonIpFrame`) → `Facade.SetInner(virtualHost)` → `MarkConnected`. **Không** có handshake/register.
4. **Egress** (`L2tpv3EthEthernetChannel.WriteFrameAsync`): `L2tpv3DataHeader.EncodeData(remoteSid, cookie, sequencing, seq++, frame)` (Session ID **remote** BE + cookie + tùy chọn sublayer + frame) → sink UDP.
5. **Ingress** (`OnInboundDatagram`): `L2tpv3DataHeader.TryDecodeData` (kiểm runt → control-T-bit → Session ID = **local** khớp → Cookie khớp → header đủ dài, bóc seq + payload); nếu `L2tpv3DecodeError.None` → `L2tpv3EthEthernetChannel.Deliver(frame)` → fabric → IP stack; ngược lại log drop (map error→`VpnDropReason`).
6. **TunnelConfig**: `L2tpv3EthConfig.ToTunnelConfig()` (static overlay IP + route + MTU 1400; `VirtualHost.Mtu` = link−14) — tĩnh, không đàm phán.
7. **Teardown/Reconnect**: hủy receive loop + dispose VirtualHost/ArpResolver/channel/transport; reconnect ở base (`OnLinkLost` → `ReconnectLoopAsync` backoff+jitter → `EstablishAsync`).

## Trạng thái & ghi chú

- **Đã có (V.23)**: end-to-end **offline code + test XONG** — `EstablishAsync` mở UDP → data plane L2 L2TPv3 2 chiều qua ARP + VirtualHost; config tĩnh point-to-point; `UseL2tpv3Ethernet(config)`. Test offline qua **peer giả lập** (L2TPv3 echo) trên loopback UDP: codec round-trip (Session ID 32-bit big-endian, cookie 0/4/8, sublayer on/off + sequence 24-bit, reject runt/control-T-bit/zero-SID/SID-mismatch/cookie-mismatch/truncated + throw khi Session ID 0/top-bit/cookie-length/seq>24-bit), channel egress/deliver + sequence tăng dần, config projection + validate, connection IP round-trip 2 chiều qua fabric (có + không cookie/sequencing), driver capabilities. **38 test offline** (chạy qua `dotnet exec`, xUnit v3, 38/38 pass).
- **Còn lại (residual live-validate)**: chờ **peer Linux** `ip l2tp add tunnel ... encap udp` + `ip l2tp add session ... pwtype ethernet` để round-trip ICMP thật qua L2 pseudowire. ⚠️ **Lưu ý interop**: Linux `encap udp` thêm **prefix 4 byte** (Ver 16-bit + reserved 16-bit) TRƯỚC Session ID; driver này chạy header L2TPv3-over-IP **thẳng trong UDP** (không prefix) — cần thêm tùy chọn prefix hoặc peer L2TPv3-over-IP (proto-115) để byte-match với kernel Linux `encap udp`.
- **Tham chiếu**: RFC 3931 §4.1/§4.6, RFC 4719; taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.23 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`Drivers.Geneve`](../TqkLibrary.VpnClient.Drivers.Geneve/Transport/GeneveUdpTransportFactory.cs) (net5+ overload ct; ns2.0 `ArraySegment` fallback). Bridge L2↔L3 (ARP + VirtualHost static-IP) + codec self-contained nhái [`Drivers.Geneve`](../TqkLibrary.VpnClient.Drivers.Geneve) nhưng wire codec là **header data L2TPv3** (Session ID + Cookie + Default L2-Specific Sublayer) thay base header Geneve.
