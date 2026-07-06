# TqkLibrary.VpnClient.Drivers.Geneve

Driver **Geneve (RFC 8926)** — **L2-over-UDP** — chở **Ethernet frame nguyên gói** sau một **Geneve base header 8 byte** (+ khối **options TLV biến thiên** tùy chọn) trên **UDP/6081**, cắm vào **Ethernet fabric** ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet): ARP/VirtualHost) thành một tunnel **L2 Ethernet** chạy thật sau facade. **Sibling trực tiếp của driver [`vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan)** (UDP/6081 thay 4789, base header + VNI + **options TLV** + **protocol-type tường minh** thay header cố định) và cũng **BỎ hết control plane**: KHÔNG registration, KHÔNG transform/mã hóa, KHÔNG keepalive, KHÔNG header-encryption. Geneve chỉ là header — không signalling. Remote là **unicast tĩnh** (host từ `VpnEndpoint`, port từ config = 6081). Egress: prepend base header 8B (Ver/OptLen=0 + proto-type `0x6558` + VNI 24-bit, không options) → gửi UDP; ingress: parse base header, **skip options theo OptLen×4**, bóc payload = phần sau options → fabric; **drop nếu có critical-option lạ** (RFC 8926 §3.5) hoặc version lạ / options cụt / proto-type ≠ 0x6558. IP tĩnh (overlay address, **không DHCP**), no-elevation.

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp codec Geneve (tự chứa, [`GeneveCodec`](GeneveCodec.cs)) + fabric L2 ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet)) thành 1 tunnel sống; bridge L2↔L3 + supervisor/reconnect nhái [`Drivers.Vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan) — **không có bước register/keepalive/transform**:

- **Transport**: UDP qua seam [`IGeneveTransportFactory`](Transport/IGeneveTransportFactory.cs) — production socket thật [`GeneveUdpTransportFactory`](Transport/GeneveUdpTransportFactory.cs) (`Socket` UDP: bind ephemeral + connect remote, IPv4/IPv6 + receive loop), test inject loopback. 1 transport tới remote; receive loop bơm `OnInboundDatagram`.
- **Không control plane**: Geneve không đăng ký, không handshake — `EstablishAsync` chỉ mở transport rồi bind data plane. State `Connecting` là transient.
- **Data plane (L2)**: [`GeneveEthernetChannel`](DataChannel/GeneveEthernetChannel.cs) (`IEthernetChannel`): egress prepend Geneve base header (`GeneveCodec.EncodeGeneve(vni, 0x6558, frame)`, OptLen=0) → gửi UDP; ingress (frame đã bóc header+options) → `InboundFrame`. Cắm vào [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) (IPv4 static) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2↔L3) → `IPacketChannel`.
- **Lifecycle**: supervisor/auto-reconnect (F.6) ở base — không timer keepalive.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions`) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection`** (base supervisor F.6: facade/lifetime/`OnLinkLost`/`ReconnectLoopAsync`/backoff-jitter/`SetState`/clock/`NextRandomBytes`) + **`VpnReconnectOptions`** (`GeneveReconnectOptions` kế thừa) + **`VpnConnectionState`** (enum state dùng chung) |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`ArpResolver`** (IPv4 next-hop, static IP) + **`VirtualHost`** (bridge L2↔L3) + `MacAddress`/`EthernetFrame` — **KHÔNG viết lại ARP/switch** |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseGeneve(config)` đăng ký driver |

Không dùng `Vxlan`/`N2n`/`Crypto` (Geneve có wire codec riêng — base header 8B + options TLV, không mã hóa).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Geneve/
├─ GeneveDriver.cs                     IVpnProtocolDriver: capabilities (L2Ethernet/Udp/None/None-auth/OutOfBand, no-elevation) + ConnectAsync(config+endpoint) → GeneveConnection
├─ GeneveConnection.cs                 Điều phối (kế thừa ReconnectingVpnConnection F.6): UDP → bind GeneveEthernetChannel vào ArpResolver+VirtualHost → demux; KHÔNG register/keepalive/transform; supervisor/reconnect ở base
├─ GeneveVpnConnection.cs              IVpnConnection: 1 session L2 point-to-point; OpenSessionAsync ném NotSupportedException
├─ GeneveVpnSession.cs                IVpnSession: PacketChannel ổn định (facade L3 bridge từ L2) + TunnelConfig tĩnh
├─ GeneveCodec.cs                     Static/stateless: EncodeGeneve(vni, protoType, payload) (8B base header + payload, OptLen=0); TryDecodeGeneve (len≥8 + Ver=0, skip options OptLen×4, drop critical-option lạ §3.5, bóc VNI/proto-type/payload); const DefaultPort=6081/BaseHeaderLength=8/ProtocolTypeTransparentEthernet=0x6558/CriticalOptionTypeBit=0x80/MaxVni
├─ GeneveReconnectOptions.cs          Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ GeneveDriverConstants.cs           DriverName "geneve", DefaultPort 6081, DefaultMtu 1400 (Geneve ≥50B overhead)
├─ Config/GeneveConfig.cs             VNI (24-bit) + Port(6081) + static overlay IP/prefix + LocalMac (null⇒random LAA) + DnsServers/Routes + Mtu → ToTunnelConfig() (static IP, KHÔNG DHCP); ResolveLocalMac + validate VNI≤0xFFFFFF
├─ DataChannel/GeneveEthernetChannel.cs IEthernetChannel: WriteFrameAsync prepend Geneve base header (VNI, proto 0x6558) → sink UDP; Deliver raise InboundFrame
├─ Properties/AssemblyInfo.cs         InternalsVisibleTo test assembly (channel là internal)
└─ Transport/
   ├─ IGeneveTransportFactory.cs      Seam dựng UDP transport tới remote (production socket / test loopback)
   ├─ GeneveTransportHandle.cs        IDatagramTransport + SetReceiver + receive-pump trả về từ factory
   └─ GeneveUdpTransportFactory.cs    Socket thật: UDP bind ephemeral + connect remote (IPv4/IPv6) + receive loop — live-only, cross-TFM
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `GeneveDriver` | `IVpnProtocolDriver`: capabilities (**`L2Ethernet`**, không PPP, `None` security, `Udp`, **`None` auth** (không control plane), `OutOfBand` static, **no-elevation/no-raw**); `ConnectAsync` dựng `GeneveConnection` từ `GeneveConfig` + endpoint (host từ endpoint, port từ config) | [GeneveDriver.cs:21](GeneveDriver.cs#L21) |
| `GeneveConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor F.6): override `EstablishAsync` (resolve remote → mở UDP qua `IGeneveTransportFactory` → `GeneveEthernetChannel(vni, mac, sink)` + `ArpResolver` static-IP + `VirtualHost` → `Facade.SetInner` → `MarkConnected`) + `CleanupAttemptResourcesAsync`; **demux** (`OnInboundDatagram`: `GeneveCodec.TryDecodeGeneve` → kiểm proto-type 0x6558 → tùy chọn kiểm VNI → `Deliver`); **KHÔNG** register/keepalive/transform; fault → `OnLinkLost` của base arm reconnect | [GeneveConnection.cs:30](GeneveConnection.cs#L30) |
| `GeneveConfig` | Config tĩnh: `Vni`(24-bit, validate ≤0xFFFFFF)/`Port`(6081)/`OverlayAddress`+`PrefixLength`/`LocalMac`(null⇒random LAA)/`DnsServers`/`Routes`/`Mtu`(1400); `ToTunnelConfig` (static IP + route mặc định = overlay subnet); `ResolveLocalMac` | [Config/GeneveConfig.cs:17](Config/GeneveConfig.cs#L17) |
| `GeneveCodec` | Static/stateless codec (RFC 8926 §3): `EncodeGeneve(vni, protoType, payload)` (8B base header + payload, OptLen=0); `TryDecodeGeneve` (len≥8 + Ver=0, **skip options** OptLen×4, **drop critical-option** §3.5 / version lạ / options cụt, bóc VNI big-endian + proto-type + payload); const `DefaultPort`/`BaseHeaderLength`/`OptionLengthUnit`/`ProtocolTypeTransparentEthernet`/`CriticalOptionTypeBit`/`MaxVni` | [GeneveCodec.cs:22](GeneveCodec.cs#L22) |
| `GeneveEthernetChannel` | `IEthernetChannel` (`Medium=Ethernet`, `MaxHeaderLength=14`, `RequiresLinkAddressResolution=true`): `WriteFrameAsync` prepend Geneve base header (proto 0x6558, OptLen=0) → sink UDP; `Deliver` raise `InboundFrame` | [DataChannel/GeneveEthernetChannel.cs:27](DataChannel/GeneveEthernetChannel.cs#L27) |
| `GeneveVpnConnection` / `GeneveVpnSession` | `IVpnConnection` 1 session (point-to-point) + `IVpnSession` (`PacketChannel` facade L3 + `Config` tĩnh) | [GeneveVpnConnection.cs:9](GeneveVpnConnection.cs#L9) / [GeneveVpnSession.cs:13](GeneveVpnSession.cs#L13) |
| `IGeneveTransportFactory` / `GeneveTransportHandle` / `GeneveUdpTransportFactory` | Seam dựng UDP transport (1 datagram = 1 message, **không framing**) + socket thật `Socket` UDP (bind ephemeral + connect, IPv4/IPv6) + receive loop — live-only, cross-TFM (nhái Vxlan) | [Transport/IGeneveTransportFactory.cs:13](Transport/IGeneveTransportFactory.cs#L13) / [GeneveTransportHandle.cs:15](Transport/GeneveTransportHandle.cs#L15) / [GeneveUdpTransportFactory.cs:18](Transport/GeneveUdpTransportFactory.cs#L18) |
| `VpnConnectionState` / `GeneveReconnectOptions` | `Disconnected/Connecting/Connected/Reconnecting` (dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) — state kế thừa từ base) + kế thừa `VpnReconnectOptions` (F.6) | [../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) / [GeneveReconnectOptions.cs:10](GeneveReconnectOptions.cs#L10) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Encapsulation | **RFC 8926** (Geneve) §3 | base header 8B: byte0 Ver(2b)+OptLen(6b, đơn vị 4B), byte1 O(1b OAM)+C(1b critical)+Rsvd(6b), byte2-3 Protocol Type 16b BE (`0x6558` TEB), byte4-6 VNI 24-bit BE, byte7 reserved; sau base header là options `OptLen×4` byte (TLV: OptionClass 16b ‖ Type 8b (bit cao=Critical) ‖ Rsvd 3b+Length 5b (đơn vị 4B) ‖ data), rồi payload (Ethernet frame khi proto=0x6558) |
| Options handling | RFC 8926 §3.5 | receiver **skip toàn bộ options theo OptLen** (không hiểu option nào); **drop** nếu gặp option Critical (bit cao Type) — không xử lý được critical ⇒ phải drop |
| Transport | UDP/**6081** (IANA) | 1 datagram = 1 message, không framing; remote unicast tĩnh |
| L2 fabric | ARP (RFC 826) + VirtualHost | tái dùng `Ethernet` — KHÔNG viết lại; IP **tĩnh**, không DHCP |
| Address | out-of-band (static) | không DHCP — `GeneveConfig` → `TunnelConfig` |
| Security | none | Geneve không mã hóa (RFC 8926 không định nghĩa crypto) |

## Luồng nội bộ (UDP ↔ fabric, as-built)

1. **Resolve remote** ([`ResolveRemoteEndpointAsync`](GeneveConnection.cs)): resolve host (từ `VpnEndpoint.Host`) qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) → `IPEndPoint(ip, config.Port)`.
2. **Mở transport UDP** qua `IGeneveTransportFactory.ConnectAsync(endpoint, ct)` → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)`; chạy receive-pump nền (loopback tự pump); `MarkRunning`.
3. **Bind data plane L2**: `GeneveEthernetChannel(vni, mac, sink)` → `ArpResolver(mac, overlayAddress, channel)` + `VirtualHost(mac, channel, arp)` (ARP qua `InboundNonIpFrame`) → `Facade.SetInner(virtualHost)` → `MarkConnected`. **Không** có handshake/register.
4. **Egress** (`GeneveEthernetChannel.WriteFrameAsync`): `GeneveCodec.EncodeGeneve(vni, 0x6558, frame)` (8B base header, OptLen=0 + frame) → sink UDP.
5. **Ingress** (`OnInboundDatagram`): `GeneveCodec.TryDecodeGeneve` (kiểm len≥8 + Ver=0, **skip options** OptLen×4, **drop critical-option** §3.5 / options cụt, bóc VNI + proto-type + payload); kiểm proto-type = 0x6558; tùy chọn `strictVni` kiểm VNI khớp config → `GeneveEthernetChannel.Deliver(frame)` → fabric → IP stack.
6. **TunnelConfig**: `GeneveConfig.ToTunnelConfig()` (static overlay IP + route + MTU 1400; `VirtualHost.Mtu` = link−14) — tĩnh, không đàm phán.
7. **Teardown/Reconnect**: hủy receive loop + dispose VirtualHost/ArpResolver/channel/transport; reconnect ở base (`OnLinkLost` → `ReconnectLoopAsync` backoff+jitter → `EstablishAsync`).

## Trạng thái & ghi chú

- **Đã có (V.22)**: end-to-end **offline code + test XONG** — `EstablishAsync` mở UDP → data plane L2 Geneve 2 chiều qua ARP + VirtualHost; config tĩnh point-to-point; `UseGeneve(config)`. Test offline qua **peer giả lập** (Geneve echo) trên loopback UDP: codec round-trip (VNI big-endian, Ver/OptLen, proto-type 0x6558/0x0800/0x86DD, **skip non-critical option theo OptLen**, **drop critical option §3.5**, reject runt/unknown-version/options-cụt), channel egress/deliver, config projection + VNI validate, connection IP round-trip 2 chiều qua fabric, driver capabilities.
- **Còn lại (residual live-validate)**: chờ **peer Linux** `ip link add type geneve id <VNI> remote <ip> dstport 6081` + `ip addr add <overlay>` để round-trip ICMP thật qua L2 overlay (validate on-wire base header + fabric ARP), và interop có options TLV thật.
- **Tham chiếu**: RFC 8926; taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.22 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`Drivers.Vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan/Transport/VxlanUdpTransportFactory.cs) (net5+ overload ct; ns2.0 `ArraySegment` fallback). Bridge L2↔L3 (ARP + VirtualHost static-IP) + codec self-contained nhái [`Drivers.Vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan) nhưng **thêm options TLV + protocol-type + critical-bit drop**.
