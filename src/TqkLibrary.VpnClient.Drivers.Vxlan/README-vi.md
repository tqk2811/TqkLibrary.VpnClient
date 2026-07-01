# TqkLibrary.VpnClient.Drivers.Vxlan

Driver **VXLAN (RFC 7348)** — **L2-over-UDP** — chở **Ethernet frame nguyên gói** sau một **VXLAN header 8 byte** trên **UDP/4789**, cắm vào **Ethernet fabric** ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet): ARP/VirtualHost) thành một tunnel **L2 Ethernet** chạy thật sau facade. **Mirror driver [`n2n`](../TqkLibrary.VpnClient.Drivers.N2n) nhưng BỎ hết control plane**: KHÔNG registration, KHÔNG transform/mã hóa, KHÔNG keepalive, KHÔNG header-encryption. VXLAN chỉ là header — không signalling. Remote VTEP là **unicast tĩnh** (host từ `VpnEndpoint`, port từ config = 4789). Egress: prepend 8B header (flags `0x08` + VNI 24-bit) → gửi UDP; ingress: decode header → bóc Ethernet frame = `datagram[8..]` → fabric. IP tĩnh (overlay address, **không DHCP**), no-elevation.

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp codec VXLAN (tự chứa, [`VxlanCodec`](VxlanCodec.cs)) + fabric L2 ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet)) thành 1 tunnel sống; bridge L2↔L3 + supervisor/reconnect nhái [`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n) nhưng **không có bước register/keepalive/transform**:

- **Transport**: UDP qua seam [`IVxlanTransportFactory`](Transport/IVxlanTransportFactory.cs) — production socket thật [`VxlanUdpTransportFactory`](Transport/VxlanUdpTransportFactory.cs) (`Socket` UDP: bind ephemeral + connect remote VTEP, IPv4/IPv6 + receive loop), test inject loopback. 1 transport tới remote VTEP; receive loop bơm `OnInboundDatagram`.
- **Không control plane**: VXLAN không đăng ký, không handshake — `EstablishAsync` chỉ mở transport rồi bind data plane. State `Connecting` là transient.
- **Data plane (L2)**: [`VxlanEthernetChannel`](DataChannel/VxlanEthernetChannel.cs) (`IEthernetChannel`): egress prepend VXLAN header (`VxlanCodec.EncodeVxlan(vni, frame)`) → gửi UDP; ingress (frame đã bóc header) → `InboundFrame`. Cắm vào [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) (IPv4 static) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2↔L3) → `IPacketChannel`.
- **Lifecycle**: supervisor/auto-reconnect (F.6) ở base — không timer keepalive.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions`) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection<TState>`** (base supervisor F.6: facade/lifetime/`OnLinkLost`/`ReconnectLoopAsync`/backoff-jitter/`SetState`/clock/`NextRandomBytes`) + **`VpnReconnectOptions`** (`VxlanReconnectOptions` kế thừa) |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`ArpResolver`** (IPv4 next-hop, static IP) + **`VirtualHost`** (bridge L2↔L3) + `MacAddress`/`EthernetFrame` — **KHÔNG viết lại ARP/switch** |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseVxlan(config)` đăng ký driver |

Không dùng `N2n`/`Crypto` (VXLAN không có wire codec riêng ngoài header 8B, không mã hóa).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Vxlan/
├─ VxlanDriver.cs                     IVpnProtocolDriver: capabilities (L2Ethernet/Udp/None/None-auth/OutOfBand, no-elevation) + ConnectAsync(config+endpoint) → VxlanConnection
├─ VxlanConnection.cs                 Điều phối (kế thừa ReconnectingVpnConnection<…> F.6): UDP → bind VxlanEthernetChannel vào ArpResolver+VirtualHost → demux; KHÔNG register/keepalive/transform; supervisor/reconnect ở base
├─ VxlanVpnConnection.cs              IVpnConnection: 1 session L2 point-to-point; OpenSessionAsync ném NotSupportedException
├─ VxlanVpnSession.cs                IVpnSession: PacketChannel ổn định (facade L3 bridge từ L2) + TunnelConfig tĩnh
├─ VxlanCodec.cs                     Static/stateless: EncodeVxlan(vni, frame) (8B header + frame); TryDecodeVxlan (len≥8 + bit 0x08, bóc VNI + frame); const DefaultPort=4789/HeaderLength=8/FlagVniPresent=0x08/MaxVni
├─ VxlanReconnectOptions.cs          Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ VxlanDriverConstants.cs           DriverName "vxlan", DefaultPort 4789, DefaultMtu 1400 (VXLAN +50B overhead)
├─ Config/VxlanConfig.cs             VNI (24-bit) + Port(4789) + static overlay IP/prefix + LocalMac (null⇒random LAA) + DnsServers/Routes + Mtu → ToTunnelConfig() (static IP, KHÔNG DHCP); ResolveLocalMac + validate VNI≤0xFFFFFF
├─ DataChannel/VxlanEthernetChannel.cs IEthernetChannel: WriteFrameAsync prepend VXLAN header (VNI) → sink UDP; Deliver raise InboundFrame
├─ Enums/VxlanConnectionState.cs     Disconnected/Connecting/Connected/Reconnecting
└─ Transport/
   ├─ IVxlanTransportFactory.cs      Seam dựng UDP transport tới remote VTEP (production socket / test loopback)
   ├─ VxlanTransportHandle.cs        IDatagramTransport + SetReceiver + receive-pump trả về từ factory
   └─ VxlanUdpTransportFactory.cs    Socket thật: UDP bind ephemeral + connect remote (IPv4/IPv6) + receive loop — live-only, cross-TFM
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `VxlanDriver` | `IVpnProtocolDriver`: capabilities (**`L2Ethernet`**, không PPP, `None` security, `Udp`, **`None` auth** (không control plane), `OutOfBand` static, **no-elevation/no-raw**); `ConnectAsync` dựng `VxlanConnection` từ `VxlanConfig` + endpoint (host từ endpoint, port từ config) | [VxlanDriver.cs:20](VxlanDriver.cs#L20) |
| `VxlanConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection<VxlanConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor F.6): override `EstablishAsync` (resolve VTEP → mở UDP qua `IVxlanTransportFactory` → `VxlanEthernetChannel(vni, mac, sink)` + `ArpResolver` static-IP + `VirtualHost` → `Facade.SetInner` → `MarkConnected`) + `CleanupAttemptResourcesAsync`; **demux** (`OnInboundDatagram`: `VxlanCodec.TryDecodeVxlan` → tùy chọn kiểm VNI → `Deliver`); **KHÔNG** register/keepalive/transform; fault → `OnLinkLost` của base arm reconnect | [VxlanConnection.cs:29](VxlanConnection.cs#L29) |
| `VxlanConfig` | Config tĩnh: `Vni`(24-bit, validate ≤0xFFFFFF)/`Port`(4789)/`OverlayAddress`+`PrefixLength`/`LocalMac`(null⇒random LAA)/`DnsServers`/`Routes`/`Mtu`(1400); `ToTunnelConfig` (static IP + route mặc định = overlay subnet); `ResolveLocalMac` | [Config/VxlanConfig.cs:17](Config/VxlanConfig.cs#L17) |
| `VxlanCodec` | Static/stateless codec (RFC 7348 §5): `EncodeVxlan(vni, frame)` (8B header + frame); `TryDecodeVxlan` (len≥8 + bit `0x08`, bóc VNI big-endian + frame); const `DefaultPort`/`HeaderLength`/`FlagVniPresent`/`MaxVni` | [VxlanCodec.cs:19](VxlanCodec.cs#L19) |
| `VxlanEthernetChannel` | `IEthernetChannel` (`Medium=Ethernet`, `MaxHeaderLength=14`, `RequiresLinkAddressResolution=true`): `WriteFrameAsync` prepend VXLAN header → sink UDP; `Deliver` raise `InboundFrame` | [DataChannel/VxlanEthernetChannel.cs:26](DataChannel/VxlanEthernetChannel.cs#L26) |
| `VxlanVpnConnection` / `VxlanVpnSession` | `IVpnConnection` 1 session (point-to-point) + `IVpnSession` (`PacketChannel` facade L3 + `Config` tĩnh) | [VxlanVpnConnection.cs:9](VxlanVpnConnection.cs#L9) / [VxlanVpnSession.cs:14](VxlanVpnSession.cs#L14) |
| `IVxlanTransportFactory` / `VxlanTransportHandle` / `VxlanUdpTransportFactory` | Seam dựng UDP transport (1 datagram = 1 message, **không framing**) + socket thật `Socket` UDP (bind ephemeral + connect, IPv4/IPv6) + receive loop — live-only, cross-TFM (nhái N2n) | [Transport/IVxlanTransportFactory.cs:12](Transport/IVxlanTransportFactory.cs#L12) / [VxlanTransportHandle.cs:14](Transport/VxlanTransportHandle.cs#L14) / [VxlanUdpTransportFactory.cs:19](Transport/VxlanUdpTransportFactory.cs#L19) |
| `VxlanConnectionState` / `VxlanReconnectOptions` | `Disconnected/Connecting/Connected/Reconnecting` + kế thừa `VpnReconnectOptions` (F.6) | [Enums/VxlanConnectionState.cs:4](Enums/VxlanConnectionState.cs#L4) / [VxlanReconnectOptions.cs:9](VxlanReconnectOptions.cs#L9) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Encapsulation | **RFC 7348** (VXLAN) §5 | header 8B: byte0 flags `0x08` (I-bit VNI valid), byte1-3 reserved 0, byte4-6 VNI 24-bit big-endian, byte7 reserved 0; sau header là Ethernet frame nguyên gói |
| Transport | UDP/**4789** (IANA) | 1 datagram = 1 message, không framing; remote VTEP unicast tĩnh |
| L2 fabric | ARP (RFC 826) + VirtualHost | tái dùng `Ethernet` — KHÔNG viết lại; IP **tĩnh**, không DHCP |
| Address | out-of-band (static) | không DHCP — `VxlanConfig` → `TunnelConfig` |
| Security | none | VXLAN không mã hóa (RFC 7348 không định nghĩa crypto) |

## Luồng nội bộ (UDP ↔ fabric, as-built)

1. **Resolve remote VTEP** ([`ResolveRemoteEndpointAsync`](VxlanConnection.cs)): resolve host (từ `VpnEndpoint.Host`) qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) → `IPEndPoint(ip, config.Port)`.
2. **Mở transport UDP** qua `IVxlanTransportFactory.ConnectAsync(endpoint, ct)` → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)`; chạy receive-pump nền (loopback tự pump); `MarkRunning`.
3. **Bind data plane L2**: `VxlanEthernetChannel(vni, mac, sink)` → `ArpResolver(mac, overlayAddress, channel)` + `VirtualHost(mac, channel, arp)` (ARP qua `InboundNonIpFrame`) → `Facade.SetInner(virtualHost)` → `MarkConnected`. **Không** có handshake/register.
4. **Egress** (`VxlanEthernetChannel.WriteFrameAsync`): `VxlanCodec.EncodeVxlan(vni, frame)` (8B header + frame) → sink UDP.
5. **Ingress** (`OnInboundDatagram`): `VxlanCodec.TryDecodeVxlan` (kiểm len≥8 + bit `0x08`, bóc VNI + frame); tùy chọn `strictVni` kiểm VNI khớp config → `VxlanEthernetChannel.Deliver(frame)` → fabric → IP stack.
6. **TunnelConfig**: `VxlanConfig.ToTunnelConfig()` (static overlay IP + route + MTU 1400; `VirtualHost.Mtu` = link−14) — tĩnh, không đàm phán.
7. **Teardown/Reconnect**: hủy receive loop + dispose VirtualHost/ArpResolver/channel/transport; reconnect ở base (`OnLinkLost` → `ReconnectLoopAsync` backoff+jitter → `EstablishAsync`).

## Trạng thái & ghi chú

- **Đã có (V.14)**: end-to-end **offline code + test XONG** — `EstablishAsync` mở UDP → data plane L2 VXLAN 2 chiều qua ARP + VirtualHost; config tĩnh point-to-point; `UseVxlan(config)`. Test offline qua **peer giả lập** (VXLAN echo) trên loopback UDP: codec round-trip (VNI big-endian, bit `0x08`, reject runt/no-I-bit), channel egress/deliver, config projection + VNI validate, connection IP round-trip 2 chiều qua fabric, driver capabilities.
- **Còn lại (residual live-validate)**: chờ **peer Linux** `ip link add type vxlan id <VNI> remote <ip> dstport 4789` + `ip addr add <overlay>` để round-trip ICMP thật qua L2 overlay (validate on-wire header + fabric ARP).
- **Tham chiếu**: RFC 7348; taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.14 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`Drivers.GreInUdp`](../TqkLibrary.VpnClient.Drivers.GreInUdp/UdpDatagramTransport.cs) (net5+ overload ct; ns2.0 `ArraySegment` fallback). Bridge L2↔L3 (ARP + VirtualHost static-IP) nhái [`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n) nhưng **bỏ registration/keepalive/transform**.
