# TqkLibrary.VpnClient.Drivers.VxlanGpe

Driver **VXLAN-GPE (Generic Protocol Extension, `draft-ietf-nvo3-vxlan-gpe`)** — **L2-over-UDP** — chở **Ethernet frame nguyên gói** sau một **VXLAN-GPE header 8 byte** trên **UDP/4790**, cắm vào **Ethernet fabric** ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet): ARP/VirtualHost) thành một tunnel **L2 Ethernet** chạy thật sau facade. **SUPERSET của driver [`vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan)**: cùng header 8 byte + VNI 24-bit, nhưng **flags byte set thêm bit P** (Next-Protocol present ⇒ `byte0 = I|P = 0x0C`) và **byte3 = Next Protocol** (0x01 IPv4/0x02 IPv6/**0x03 Ethernet**/0x04 NSH) để 1 UDP port multiplex nhiều inner-proto. Cùng **BỎ hết control plane** như VXLAN: KHÔNG registration, KHÔNG transform/mã hóa, KHÔNG keepalive, KHÔNG header-encryption — chỉ là header, không signalling. Remote là **unicast tĩnh** (host từ `VpnEndpoint`, port từ config = 4790). Egress: prepend 8B header (flags `0x0C` + Next-Protocol + VNI 24-bit) → gửi UDP; ingress: validate Ver=0/I/P/O + đọc Next-Protocol → nếu Ethernet bóc frame = `datagram[8..]` → fabric (Next-Protocol khác/OAM → drop). IP tĩnh (overlay address, **không DHCP**), no-elevation.

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp codec VXLAN-GPE (tự chứa, [`VxlanGpeHeader`](VxlanGpeHeader.cs)) + fabric L2 ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet)) thành 1 tunnel sống; bridge L2↔L3 + supervisor/reconnect nhái [`Drivers.Vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan) nhưng **thêm bit P + Next-Protocol** và **không có bước register/keepalive/transform**:

- **Transport**: UDP qua seam [`IVxlanGpeTransportFactory`](Transport/IVxlanGpeTransportFactory.cs) — production socket thật [`VxlanGpeUdpTransportFactory`](Transport/VxlanGpeUdpTransportFactory.cs) (`Socket` UDP: bind ephemeral + connect remote, IPv4/IPv6 + receive loop), test inject loopback. 1 transport tới remote; receive loop bơm `OnInboundDatagram`.
- **Không control plane**: VXLAN-GPE không đăng ký, không handshake — `EstablishAsync` chỉ mở transport rồi bind data plane. State `Connecting` là transient.
- **Data plane (L2)**: [`VxlanGpeEthernetChannel`](DataChannel/VxlanGpeEthernetChannel.cs) (`IEthernetChannel`): egress prepend VXLAN-GPE header (`VxlanGpeHeader.EncodeVxlanGpe(vni, nextProto, frame)`) → gửi UDP; ingress (frame đã bóc header) → `InboundFrame`. Cắm vào [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) (IPv4 static) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2↔L3) → `IPacketChannel`.
- **Lifecycle**: supervisor/auto-reconnect (F.6) ở base — không timer keepalive.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions`) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection`** (base supervisor F.6: facade/lifetime/`OnLinkLost`/`ReconnectLoopAsync`/backoff-jitter/`SetState`/clock/`NextRandomBytes`) + **`VpnReconnectOptions`** (`VxlanGpeReconnectOptions` kế thừa) + **`VpnConnectionState`** (enum state dùng chung) |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`ArpResolver`** (IPv4 next-hop, static IP) + **`VirtualHost`** (bridge L2↔L3) + `MacAddress`/`EthernetFrame` — **KHÔNG viết lại ARP/switch** |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseVxlanGpe(config)` đăng ký driver |

Không dùng `Vxlan`/`N2n`/`Crypto` (VXLAN-GPE không có wire codec riêng ngoài header 8B, không mã hóa — codec tự chứa, KHÔNG ref project Vxlan).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.VxlanGpe/
├─ VxlanGpeDriver.cs                     IVpnProtocolDriver: capabilities (L2Ethernet/Udp/None/None-auth/OutOfBand, no-elevation) + ConnectAsync(config+endpoint) → VxlanGpeConnection
├─ VxlanGpeConnection.cs                 Điều phối (kế thừa ReconnectingVpnConnection F.6): UDP → bind VxlanGpeEthernetChannel vào ArpResolver+VirtualHost → demux; drop Next-Protocol≠Ethernet/OAM; KHÔNG register/keepalive/transform; supervisor/reconnect ở base
├─ VxlanGpeVpnConnection.cs              IVpnConnection: 1 session L2 point-to-point; OpenSessionAsync ném NotSupportedException
├─ VxlanGpeVpnSession.cs                IVpnSession: PacketChannel ổn định (facade L3 bridge từ L2) + TunnelConfig tĩnh
├─ VxlanGpeHeader.cs                    Static/stateless codec: EncodeVxlanGpe(vni, nextProto, frame) (8B header + frame); TryDecodeVxlanGpe (len≥8 + Ver=0 + I + P + O=0, bóc Next-Protocol + VNI + frame); const DefaultPort=4790/HeaderLength=8/FlagVniPresent=0x08/FlagNextProtocolPresent=0x04/FlagOam=0x01/NextProtocol*=0x01..0x04/MaxVni
├─ VxlanGpeReconnectOptions.cs          Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ VxlanGpeDriverConstants.cs           DriverName "vxlan-gpe", DefaultPort 4790, DefaultMtu 1400 (VXLAN-GPE +50B overhead)
├─ Config/VxlanGpeConfig.cs             VNI (24-bit) + Port(4790) + NextProtocol(mặc định Ethernet) + static overlay IP/prefix + LocalMac (null⇒random LAA) + DnsServers/Routes + Mtu → ToTunnelConfig() (static IP, KHÔNG DHCP); ResolveLocalMac + validate VNI≤0xFFFFFF
├─ Enums/VxlanGpeNextProtocol.cs        enum byte: Ipv4=0x01/Ipv6=0x02/Ethernet=0x03/Nsh=0x04 (chỉ Ethernet đã wire data plane)
├─ DataChannel/VxlanGpeEthernetChannel.cs IEthernetChannel: WriteFrameAsync prepend VXLAN-GPE header (VNI + Next-Protocol) → sink UDP; Deliver raise InboundFrame
└─ Transport/
   ├─ IVxlanGpeTransportFactory.cs      Seam dựng UDP transport tới remote (production socket / test loopback)
   ├─ VxlanGpeTransportHandle.cs        IDatagramTransport + SetReceiver + receive-pump trả về từ factory
   └─ VxlanGpeUdpTransportFactory.cs    Socket thật: UDP bind ephemeral + connect remote (IPv4/IPv6) + receive loop — live-only, cross-TFM
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `VxlanGpeDriver` | `IVpnProtocolDriver`: capabilities (**`L2Ethernet`**, không PPP, `None` security, `Udp`, **`None` auth** (không control plane), `OutOfBand` static, **no-elevation/no-raw**); `ConnectAsync` dựng `VxlanGpeConnection` từ `VxlanGpeConfig` + endpoint (host từ endpoint, port từ config) | [VxlanGpeDriver.cs:21](VxlanGpeDriver.cs#L21) |
| `VxlanGpeConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor F.6): override `EstablishAsync` (resolve → mở UDP qua `IVxlanGpeTransportFactory` → `VxlanGpeEthernetChannel(vni, nextProto, mac, sink)` + `ArpResolver` static-IP + `VirtualHost` → `Facade.SetInner` → `MarkConnected`) + `CleanupAttemptResourcesAsync`; **demux** (`OnInboundDatagram`: `VxlanGpeHeader.TryDecodeVxlanGpe` → **drop nếu Next-Protocol≠Ethernet** hoặc OAM/Ver≠0/thiếu I\|P → tùy chọn kiểm VNI → `Deliver`); **KHÔNG** register/keepalive/transform; fault → `OnLinkLost` của base arm reconnect | [VxlanGpeConnection.cs:30](VxlanGpeConnection.cs#L30) |
| `VxlanGpeConfig` | Config tĩnh: `Vni`(24-bit, validate ≤0xFFFFFF)/`Port`(4790)/`NextProtocol`(mặc định Ethernet)/`OverlayAddress`+`PrefixLength`/`LocalMac`(null⇒random LAA)/`DnsServers`/`Routes`/`Mtu`(1400); `ToTunnelConfig` (static IP + route mặc định = overlay subnet); `ResolveLocalMac`; `NextProtocolByte` | [Config/VxlanGpeConfig.cs:18](Config/VxlanGpeConfig.cs#L18) |
| `VxlanGpeHeader` | Static/stateless codec (`draft-ietf-nvo3-vxlan-gpe`): `EncodeVxlanGpe(vni, nextProto, frame)` (8B header flags `0x0C` + Next-Protocol + VNI BE + frame); `TryDecodeVxlanGpe` (len≥8 + Ver=0 + bit I + bit P + O=0, bóc Next-Protocol big-endian VNI + frame); const `DefaultPort`/`HeaderLength`/`FlagVniPresent`/`FlagNextProtocolPresent`/`FlagOam`/`NextProtocol*`/`MaxVni` | [VxlanGpeHeader.cs:23](VxlanGpeHeader.cs#L23) |
| `VxlanGpeNextProtocol` | enum `byte`: `Ipv4=0x01`/`Ipv6=0x02`/`Ethernet=0x03`/`Nsh=0x04` — **chỉ Ethernet đã wire data plane** | [Enums/VxlanGpeNextProtocol.cs](Enums/VxlanGpeNextProtocol.cs) |
| `VxlanGpeEthernetChannel` | `IEthernetChannel` (`Medium=Ethernet`, `MaxHeaderLength=14`, `RequiresLinkAddressResolution=true`): `WriteFrameAsync` prepend VXLAN-GPE header (VNI + Next-Protocol) → sink UDP; `Deliver` raise `InboundFrame` | [DataChannel/VxlanGpeEthernetChannel.cs:27](DataChannel/VxlanGpeEthernetChannel.cs#L27) |
| `VxlanGpeVpnConnection` / `VxlanGpeVpnSession` | `IVpnConnection` 1 session (point-to-point) + `IVpnSession` (`PacketChannel` facade L3 + `Config` tĩnh) | [VxlanGpeVpnConnection.cs:9](VxlanGpeVpnConnection.cs#L9) / [VxlanGpeVpnSession.cs:13](VxlanGpeVpnSession.cs#L13) |
| `IVxlanGpeTransportFactory` / `VxlanGpeTransportHandle` / `VxlanGpeUdpTransportFactory` | Seam dựng UDP transport (1 datagram = 1 message, **không framing**) + socket thật `Socket` UDP (bind ephemeral + connect, IPv4/IPv6) + receive loop — live-only, cross-TFM (nhái Vxlan) | [Transport/IVxlanGpeTransportFactory.cs:13](Transport/IVxlanGpeTransportFactory.cs#L13) / [VxlanGpeTransportHandle.cs:15](Transport/VxlanGpeTransportHandle.cs#L15) / [VxlanGpeUdpTransportFactory.cs:18](Transport/VxlanGpeUdpTransportFactory.cs#L18) |
| `VpnConnectionState` / `VxlanGpeReconnectOptions` | `Disconnected/Connecting/Connected/Reconnecting` (dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) — state kế thừa từ base) + kế thừa `VpnReconnectOptions` (F.6) | [../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) / [VxlanGpeReconnectOptions.cs:10](VxlanGpeReconnectOptions.cs#L10) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Encapsulation | **`draft-ietf-nvo3-vxlan-gpe`** (VXLAN-GPE) | header 8B: byte0 flags `R R Ver(2) I P B O` — I=0x08 (VNI valid), P=0x04 (Next-Protocol present), Ver=(byte0>>4)&0x03, O=0x01 (OAM); byte1-2 reserved 0; byte3 Next Protocol (0x01 IPv4/0x02 IPv6/0x03 Ethernet/0x04 NSH); byte4-6 VNI 24-bit big-endian; byte7 reserved 0. Client phát `byte0 = I|P = 0x0C`, Ver 0. Sau header là payload theo Next Protocol (Ethernet frame nguyên gói khi Next-Protocol=Ethernet) |
| Transport | UDP/**4790** (IANA) | 1 datagram = 1 message, không framing; remote unicast tĩnh |
| L2 fabric | ARP (RFC 826) + VirtualHost | tái dùng `Ethernet` — KHÔNG viết lại; IP **tĩnh**, không DHCP |
| Address | out-of-band (static) | không DHCP — `VxlanGpeConfig` → `TunnelConfig` |
| Security | none | VXLAN-GPE không mã hóa (draft không định nghĩa crypto) |

## Luồng nội bộ (UDP ↔ fabric, as-built)

1. **Resolve remote** ([`ResolveRemoteEndpointAsync`](VxlanGpeConnection.cs)): resolve host (từ `VpnEndpoint.Host`) qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) → `IPEndPoint(ip, config.Port)`.
2. **Mở transport UDP** qua `IVxlanGpeTransportFactory.ConnectAsync(endpoint, ct)` → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)`; chạy receive-pump nền (loopback tự pump); `MarkRunning`.
3. **Bind data plane L2**: `VxlanGpeEthernetChannel(vni, nextProto, mac, sink)` → `ArpResolver(mac, overlayAddress, channel)` + `VirtualHost(mac, channel, arp)` (ARP qua `InboundNonIpFrame`) → `Facade.SetInner(virtualHost)` → `MarkConnected`. **Không** có handshake/register.
4. **Egress** (`VxlanGpeEthernetChannel.WriteFrameAsync`): `VxlanGpeHeader.EncodeVxlanGpe(vni, nextProto, frame)` (8B header + frame) → sink UDP.
5. **Ingress** (`OnInboundDatagram`): `VxlanGpeHeader.TryDecodeVxlanGpe` (kiểm len≥8 + Ver=0 + bit I + bit P + O=0 drop OAM, bóc Next-Protocol + VNI + frame); **drop nếu Next-Protocol ≠ Ethernet 0x03** (log); tùy chọn `strictVni` kiểm VNI khớp config → `VxlanGpeEthernetChannel.Deliver(frame)` → fabric → IP stack.
6. **TunnelConfig**: `VxlanGpeConfig.ToTunnelConfig()` (static overlay IP + route + MTU 1400; `VirtualHost.Mtu` = link−14) — tĩnh, không đàm phán.
7. **Teardown/Reconnect**: hủy receive loop + dispose VirtualHost/ArpResolver/channel/transport; reconnect ở base (`OnLinkLost` → `ReconnectLoopAsync` backoff+jitter → `EstablishAsync`).

## Trạng thái & ghi chú

- **Đã có (V.22)**: end-to-end **offline code + test XONG** — `EstablishAsync` mở UDP → data plane L2 VXLAN-GPE 2 chiều qua ARP + VirtualHost; config tĩnh point-to-point; `UseVxlanGpe(config)`. Test offline qua **peer giả lập** (VXLAN-GPE echo, Next-Protocol Ethernet) trên loopback UDP: codec round-trip (flags byte `0x0C`, Ver, I/P bits, **Next-Protocol 4 giá trị 0x01–0x04**, VNI 24-bit BE, reject Ver≠0/I=0/P=0/OAM=1/runt), channel egress/deliver, config projection + VNI validate, connection IP round-trip 2 chiều qua fabric, **drop non-Ethernet Next-Protocol**, driver capabilities. **25 case** (chạy `dotnet exec` xUnit v3, 25/25 pass).
- **Đã wire trên wire**: **CHỈ Next-Protocol Ethernet (0x03)** cho data plane L2. Next-Protocol IPv4/IPv6/NSH được **parse + validate** trên wire (codec đọc đúng byte3) nhưng **chưa có data plane L3/NSH** — ingress drop nếu Next-Protocol ≠ Ethernet. Mode L3 IP là mở rộng tương lai (sẽ cần passthrough channel IP thay `IEthernetChannel`).
- **Còn lại (residual live-validate)**: chờ **peer Linux/OVS** `ip link add type vxlan id <VNI> remote <ip> dstport 4790 gpe` (hoặc Open vSwitch bridge với `exts gpe`) + `ip addr add <overlay>` để round-trip ICMP thật qua L2 overlay (validate on-wire header 8B I|P + Next-Protocol + fabric ARP).
- **Tham chiếu**: `draft-ietf-nvo3-vxlan-gpe`; taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.22 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`Drivers.Vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan/Transport/VxlanUdpTransportFactory.cs) (net5+ overload ct; ns2.0 `ArraySegment` fallback). Codec + bridge L2↔L3 (ARP + VirtualHost static-IP) nhái [`Drivers.Vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan) nhưng **thêm bit P + Next-Protocol** (superset), vẫn **bỏ registration/keepalive/transform**.
