# TqkLibrary.VpnClient.Abstractions

> VPN platform abstractions: link channels, byte/datagram transport contracts, driver plugin interface.

## Mục đích

`TqkLibrary.VpnClient.Abstractions` là tầng **CORE** của thư viện — tập hợp **hợp đồng (interface) + model + enum** mà mọi tầng khác phụ thuộc vào. Project này **không hiện thực protocol/RFC nào**, chỉ định nghĩa khung kiểu để:

- **Đảo ngược phụ thuộc (Dependency Inversion):** các driver protocol (L2TP/IPsec, SSTP...), tầng transport và userspace IP stack đều lập trình theo các interface ở đây, không lệ thuộc trực tiếp lẫn nhau. Façade (`TqkLibrary.VpnClient`) khám phá driver qua [`IVpnProtocolDriver`](Drivers/Interfaces/IVpnProtocolDriver.cs#L9) mà không cần biết hiện thực cụ thể.
- **Tách data plane khỏi control plane:** stack TCP/IP userspace chỉ bind vào [`IPacketChannel`](Channels/Interfaces/IPacketChannel.cs#L6) (L3, IP thuần), không bao giờ thấy Ethernet hay chi tiết tunnel.
- **Mô tả năng lực driver:** [`VpnDriverCapabilities`](Drivers/Models/VpnDriverCapabilities.cs#L9) cho phép façade thương lượng (transport/security/auth/elevation) trước khi kết nối, và từ chối nhẹ nhàng khi không đủ quyền.

Một số enum/flag là **khung mở rộng** định nghĩa sẵn để driver mới chỉ cần khai báo năng lực mà không phải đổi CORE. Phần lớn nay đã được wire (WireGuard/Noise, OpenVPN/OpenConnect, DTLS, RawIp/native-ESP); còn lại thuần khung tương lai là L2/Ethernet driver production, MPPE, DHCP, SAML/OTP.

## Vị trí trong kiến trúc

- **Tầng:** CORE (đáy đồ thị phụ thuộc).
- **Target frameworks:** `netstandard2.0` ; `net8.0`.
- **Phụ thuộc (ProjectReference):** **không có** — đây là project đáy, không tham chiếu project nào trong solution.
- **PackageReference:** `Microsoft.Extensions.Logging.Abstractions` 8.0.2 (`ILogger`/`ILoggerFactory`/`NullLogger` cho seam `Diagnostics` — lib `netstandard2.0` nên cả 2 TFM dùng được). Ngoài ra trên `netstandard2.0` kế thừa polyfill chung từ [Directory.Build.props](../Directory.Build.props#L16-L25): `System.Memory`, `System.Threading.Channels`, `System.IO.Pipelines`, `Microsoft.Bcl.AsyncInterfaces` (cung cấp `Span/Memory`, `IAsyncDisposable`, `ValueTask`) và `TqkLibrary.CompilerServices` (source-only: `IsExternalInit` + attribute `required` → cho phép `init`/`record`/`required`). Trên `net8.0` các kiểu BCL này có sẵn.
- **Được dùng bởi (ProjectReference trực tiếp — 37 project):** mọi driver `Drivers.*` (`Core`, `L2tpIpsec`, `Ikev2`, `Sstp`, `SoftEther`, `OpenVpn`, `OpenConnect`, `WireGuard`, `Pptp`, `IpEncap`, `Nebula`, `Tinc`, `N2n`, `CiscoIpsec`, `ZeroTier`, `Tailscale`, `Ssh`, `Vtun`) + các project lõi protocol/transport (`Ipsec`, `L2tp`, `Ppp`, `Pptp`, `IpStack`, `Sockets`, `Ethernet`, `IpEncap`, `OpenConnect`, `OpenVpn`, `SoftEther`, `WireGuard`, `Tailscale`, `Ssh`, `Vtun`, `Transport.Tcp`, `Transport.Tls`, `Transport.Dtls`, `Transport.RawIp`). Façade `Vpn` dùng gián tiếp qua các tầng đó (**không** ref trực tiếp). **Không** tham chiếu Abstractions: `Crypto`, và các core protocol thuần codec `Nebula`/`Tinc`/`N2n`/`ZeroTier` (driver tương ứng mới là consumer).

Xem thêm tài liệu as-built: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Abstractions/
├── Channels/                 # Lớp "link" mà userspace stack chạy bên trên (L2/L3)
│   ├── Enums/                #   LinkMedium (Ip vs Ethernet)
│   ├── Interfaces/           #   ILinkChannel + IPacketChannel (L3) + IEthernetChannel (L2) + slot INeighborResolver/IAddressConfigurator
│   └── SwappablePacketChannel.cs  # facade IPacketChannel hot-swap được (reconnect không rebind stack)
├── Transport/Interfaces/     # Ống truyền bên dưới: byte (TCP/TLS) + datagram (UDP) + TLS-aware + raw-IP
│   #   IByteStreamTransport, IDatagramTransport, ITlsByteStream (lộ cert), ITlsKeyingMaterialExporter (RFC 5705), IRawIpTransportFactory (raw socket, cần elevation)
├── Net/                      # Resolve outer host → IPAddress theo họ IP (AddressFamilyPreference, IHostResolver, DnsHostResolver)
├── Diagnostics/              # Seam log/diagnostics dùng chung (Q.2): VpnEventIds + Enums/VpnDropReason + Extensions/VpnLogExtensions
└── Drivers/                  # Hợp đồng plugin driver + model cấu hình + enum năng lực
    ├── Enums/                #   VpnLinkLayer/Transport/Security/Auth + Address/MultiHost
    ├── Models/               #   VpnEndpoint, VpnCredentials, TunnelConfig, VpnDriverCapabilities
    ├── Interfaces/           #   IVpnProtocolDriver → IVpnConnection → IVpnSession
    ├── VpnElevationRequiredException.cs        # cần quyền admin/root (kế thừa Exception)
    ├── VpnConnectionException.cs               # base lỗi kết nối (không sealed)
    ├── VpnAuthenticationException.cs           # con: sai credential
    ├── VpnServerRejectedException.cs           # con: server từ chối ở mức giao thức
    └── VpnNetworkTimeoutException.cs           # con: handshake no-response trong timeout
```

## Thành phần chính

### Channels — lớp link cho data plane

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `LinkMedium` | Enum: link mang IP thuần (L3) hay Ethernet frame (L2) | [LinkMedium.cs:5](Channels/Enums/LinkMedium.cs#L5) |
| `ILinkChannel` | Base duplex link: `Medium`, `Mtu`, `MaxHeaderLength`, có cần resolve link-address (ARP/NDISC) | [ILinkChannel.cs:9](Channels/Interfaces/ILinkChannel.cs#L9) |
| `IPacketChannel` | L3 channel: `WriteIpPacketAsync` + event `InboundIpPacket`; **stack TCP/IP chỉ bind vào đây** | [IPacketChannel.cs:6](Channels/Interfaces/IPacketChannel.cs#L6) |
| `IEthernetChannel` | L2 channel: `LinkAddress` (MAC), `WriteFrameAsync` + event `InboundFrame` | [IEthernetChannel.cs:7](Channels/Interfaces/IEthernetChannel.cs#L7) |
| `INeighborResolver` | **Slot L2** (design 00 §5): resolve next-hop IP → MAC (raw 6 byte); ARP (L2.3, IPv4) đã có impl — NDISC (L2.4, IPv6) chưa | [INeighborResolver.cs:11](Channels/Interfaces/INeighborResolver.cs#L11) |
| `IAddressConfigurator` | **Slot L2** (design 00 §5): cấp IP/DNS/route (trả `TunnelConfig`); chưa hiện thực — DHCPv4 (L2.5) / SLAAC+DHCPv6 (L2.6) | [IAddressConfigurator.cs:11](Channels/Interfaces/IAddressConfigurator.cs#L11) |
| `SwappablePacketChannel` | Facade `IPacketChannel` cho phép **hot-swap** inner channel qua reconnect mà stack không rebind; metadata pin từ inner đầu tiên | [SwappablePacketChannel.cs:14](Channels/SwappablePacketChannel.cs#L14) |

### Transport — ống truyền bên dưới

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `IByteStreamTransport` | Ống byte tin cậy, có thứ tự (TCP/TLS/SSH); nền cho PPP-over-stream và SSL-VPN. **Đã có hiện thực dùng chung** ở [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) (F.1 xong): `TlsByteStream` (BCL `SslStream`) + `BouncyCastleTlsByteStream`, phục vụ SSTP/SoftEther/OpenConnect | [IByteStreamTransport.cs:4](Transport/Interfaces/IByteStreamTransport.cs#L4) |
| `IDatagramTransport` | Ống datagram (UDP), giữ biên gói; comment trỏ IKE/ESP demux trên UDP/4500 (RFC 3948) về [`Ipsec/Nat`](../TqkLibrary.VpnClient.Ipsec/Nat) (`NatTraversal`/`NatTraversalChannel`); impl: `DtlsDatagramTransport` ([`Transport.Dtls`](../TqkLibrary.VpnClient.Transport.Dtls) — DTLS 1.2 client qua BouncyCastle, F.3 xong) + UDP socket trong driver OpenVPN/WireGuard | [IDatagramTransport.cs:10](Transport/Interfaces/IDatagramTransport.cs#L10) |
| `ITlsByteStream` | `IByteStreamTransport` + lộ `RemoteCertificate` (server cert bắt lúc handshake); SSTP crypto-binding ([MS-SSTP] §3.2.4) hash cert này. Tách khỏi `IByteStreamTransport` để byte-pipe vẫn Connect/Read/Write thuần; impl chung ở [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) (SSTP/SoftEther/OpenConnect) + fake stub cert cho test offline | [ITlsByteStream.cs:13](Transport/Interfaces/ITlsByteStream.cs#L13) |
| `ITlsKeyingMaterialExporter` | Export keying material từ phiên TLS finished theo **RFC 5705** (`ExportKeyingMaterial(label, context, length)`); `SslStream` của BCL không có API này nên chỉ TLS stream nền BouncyCastle (`Transport.Tls.BouncyCastleTlsByteStream`) hiện thực. Consumer đầu: OpenConnect (V.5) DTLS 1.2 PSK (`"EXPORTER-openconnect-psk"`); cũng hợp OpenVPN `tls-ekm` | [ITlsKeyingMaterialExporter.cs:16](Transport/Interfaces/ITlsKeyingMaterialExporter.cs#L16) |
| `IRawIpTransportFactory` | Tạo `IDatagramTransport` raw-IP mang IP-proto tuỳ ý (ESP-50, GRE-47…) trực tiếp trên IP, không bọc UDP/TCP; **cần elevation** (Windows Admin / Linux root·CAP_NET_RAW). Seam opt-in: driver phụ thuộc interface, mặc định no-admin; factory cụ thể ở [`Transport.RawIp`](../TqkLibrary.VpnClient.Transport.RawIp). `IsAvailable` = probe quyền thật; `Create(remote, ipProtocol, localBind?)` | [IRawIpTransportFactory.cs:12](Transport/Interfaces/IRawIpTransportFactory.cs#L12) |

### Net — resolve outer host (P1.2)

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `AddressFamilyPreference` | Enum chọn họ IP cho outer transport: `Auto`(=IPv4-first, giữ hành vi cũ) / `IPv4` / `IPv6` — luôn fallback họ còn lại | [AddressFamilyPreference.cs:8](Net/AddressFamilyPreference.cs#L8) |
| `IHostResolver` | Seam resolve host (name/literal) → 1 `IPAddress` theo preference; instance để test với fake không cần DNS | [IHostResolver.cs:10](Net/IHostResolver.cs#L10) |
| `DnsHostResolver` | Impl mặc định: literal-passthrough + `Dns.GetHostAddresses` + `Select` (pure static — ưu tiên 1 họ, fallback họ kia; testable không DNS). Consumer thật: `Transport.Tls.TlsByteStream`, L2TP `L2tpIpsecConnection` | [DnsHostResolver.cs:12](Net/DnsHostResolver.cs#L12) |

### Diagnostics — seam log/diagnostics dùng chung (Q.2)

Cross-cutting trace cho driver/protocol qua `Microsoft.Extensions.Logging`. Driver luồn `ILoggerFactory?` (mặc định `NullLogger` ⇒ no-op, **ADDITIVE không đổi hành vi**). Consumer hiện tại: 3 driver mới nhất WireGuard / OpenConnect / SoftEther.

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `VpnEventIds` | Tập `EventId` ổn định gắn lên mỗi log entry: 1xx handshake (`StateChanged`/`Handshake`/`HandshakeCompleted`/`HandshakeFailed`), 2xx steady (`Rekey`/`Keepalive`), 3xx reconnect (`LinkLost`/`ReconnectAttempt`/`Reconnected`), 4xx drop (`PacketDropped`) — id là contract, chỉ thêm không đánh số lại | [VpnEventIds.cs:11](Diagnostics/VpnEventIds.cs#L11) |
| `VpnDropReason` | Enum lý do drop gói vào (`Unspecified`/`DecryptFailed`/`AuthFailed`/`Replay`/`Malformed`/`Unexpected`/`NoRoute`) — field structured trên entry `PacketDropped` | [VpnDropReason.cs:8](Diagnostics/Enums/VpnDropReason.cs#L8) |
| `VpnLogExtensions` | Extension `ILogger` strongly-typed (`LogStateChanged`/`LogHandshake`/`LogHandshakeCompleted`/`LogHandshakeFailed`/`LogRekey`/`LogKeepalive`/`LogLinkLost`/`LogReconnectAttempt`/`LogReconnected`/`LogPacketDropped`) — wrapper `LoggerMessage.Define` allocation-free, no-op khi level tắt | [VpnLogExtensions.cs:15](Diagnostics/Extensions/VpnLogExtensions.cs#L15) |

### Drivers — hợp đồng plugin + model

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `IVpnProtocolDriver` | **Điểm vào plugin**: `Name`, `Capabilities`, `ConnectAsync` | [IVpnProtocolDriver.cs:9](Drivers/Interfaces/IVpnProtocolDriver.cs#L9) |
| `IVpnConnection` | Một kết nối live (1 transport / 1 IKE-SA / 1 TLS); chứa nhiều `IVpnSession`, `OpenSessionAsync` | [IVpnConnection.cs:7](Drivers/Interfaces/IVpnConnection.cs#L7) |
| `IVpnSession` | Một IP endpoint logic: `Config` + `PacketChannel` (1 IP / 1 stack) | [IVpnSession.cs:10](Drivers/Interfaces/IVpnSession.cs#L10) |
| `VpnDriverCapabilities` | Bảng năng lực driver: link layer, multi-host, PPP, transport/security/auth, address assignment, raw-IP/elevation | [VpnDriverCapabilities.cs:9](Drivers/Models/VpnDriverCapabilities.cs#L9) |
| `VpnEndpoint` | Host + port của server + `AddressFamilyPreference` (chọn họ IP outer transport, P1.2) | [VpnEndpoint.cs:6](Drivers/Models/VpnEndpoint.cs#L6) |
| `VpnCredentials` | `Username` / `Password` / `PreSharedKey` | [VpnCredentials.cs:4](Drivers/Models/VpnCredentials.cs#L4) |
| `TunnelConfig` | Kết quả mạng của session: địa chỉ IPv4 + prefix, **địa chỉ IPv6 + prefix (`AssignedAddressV6`/`PrefixLengthV6`, P1.1 — null nếu không bật IPv6)**, DNS, routes, MTU (chỉ dùng nội bộ, không ghi routing table OS) | [TunnelConfig.cs:9](Drivers/Models/TunnelConfig.cs#L9) |
| `VpnElevationRequiredException` | Ném khi driver cần quyền admin/root/CAP_NET_RAW nhưng tiến trình không có (kế thừa `Exception`, **không** thuộc cây `VpnConnectionException`) | [VpnElevationRequiredException.cs:7](Drivers/VpnElevationRequiredException.cs#L7) |
| `VpnConnectionException` | **Base** (không sealed) cho mọi lỗi khi thiết lập/duy trì kết nối; catch để xử lý chung, catch lớp con để phản ứng theo nguyên nhân | [VpnConnectionException.cs:8](Drivers/VpnConnectionException.cs#L8) |
| `VpnAuthenticationException` | (sealed, con của `VpnConnectionException`) server từ chối credential: PPP MS-CHAPv2 fail / IKE PSK·HASH_R mismatch — retry cùng credential vô ích | [VpnAuthenticationException.cs:7](Drivers/VpnAuthenticationException.cs#L7) |
| `VpnServerRejectedException` | (sealed, con của `VpnConnectionException`) server từ chối session ở mức giao thức: SSTP Call-Connect-Nak/Call-Abort, non-200 handshake, IKE Quick Mode không có SA | [VpnServerRejectedException.cs:8](Drivers/VpnServerRejectedException.cs#L8) |
| `VpnNetworkTimeoutException` | (sealed, con của `VpnConnectionException`) handshake không có hồi đáp trong timeout (IKE gateway im, TLS không xong) — vấn đề transport/reachability; caller `OperationCanceledException` **không** bị tái phân loại | [VpnNetworkTimeoutException.cs:8](Drivers/VpnNetworkTimeoutException.cs#L8) |
| `VpnLinkLayer` | Enum: L3Ip / L2Ethernet / Both | [VpnLinkLayer.cs:4](Drivers/Enums/VpnLinkLayer.cs#L4) |
| `MultiHostModel` | Enum: None / RoutedPrefixes / L2BroadcastDomain | [MultiHostModel.cs:4](Drivers/Enums/MultiHostModel.cs#L4) |
| `AddressAssignment` | Enum: Ipcp / ConfigPush / OutOfBand / Dhcp | [AddressAssignment.cs:4](Drivers/Enums/AddressAssignment.cs#L4) |
| `VpnTransportKind` | `[Flags]`: Tcp/Udp/Tls/Dtls/RawIp | [VpnTransportKind.cs:5](Drivers/Enums/VpnTransportKind.cs#L5) |
| `VpnSecurityKind` | `[Flags]`: Tls/Dtls/Esp/Noise/Mppe | [VpnSecurityKind.cs:5](Drivers/Enums/VpnSecurityKind.cs#L5) |
| `VpnAuthMethod` | `[Flags]`: PreSharedKey/Certificate/UserPassword/Eap/Saml/Otp | [VpnAuthMethod.cs:5](Drivers/Enums/VpnAuthMethod.cs#L5) |

## Chuẩn / RFC tuân thủ

Project này là **CORE thuần hợp đồng — không hiện thực RFC nào**. Bảng dưới ánh xạ các chuẩn được **tham chiếu (referenced) trong comment** để mô tả ngữ cảnh của hợp đồng (việc hiện thực thực tế nằm ở các project khác), cộng vài chuẩn suy luận từ tên thành viên enum.

| Chuẩn (RFC/FIPS/NIST/MS-*) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| RFC 3948 (UDP encapsulation of ESP, demux IKE/ESP trên UDP/4500) | `IDatagramTransport` | [IDatagramTransport.cs:5](Transport/Interfaces/IDatagramTransport.cs#L5) | RFC 3948 **được trích trong comment** làm ngữ cảnh; IKE/ESP demux thật ở [`Ipsec/Nat`](../TqkLibrary.VpnClient.Ipsec/Nat) (`NatTraversal`/`NatTraversalChannel`), không phải transport decorator |
| MS-CHAPv2 (RFC 2759) | `VpnCredentials.Username` / `.Password` | [VpnCredentials.cs:7](Drivers/Models/VpnCredentials.cs#L7), [VpnCredentials.cs:10](Drivers/Models/VpnCredentials.cs#L10) | Comment nêu MS-CHAPv2/PAP/EAP; hiện thực ở `Ppp` |
| smoltcp `Medium` / gVisor `ARPHardwareType` (tham chiếu thiết kế, không phải RFC) | `LinkMedium` | [LinkMedium.cs:4](Channels/Enums/LinkMedium.cs#L4) | Soi chiếu nguồn cảm hứng cho phân biệt L2/L3 |
| RFC 826 / RFC 4861 (ARP / IPv6 NDISC) | `ILinkChannel.RequiresLinkAddressResolution`, `IEthernetChannel` | [ILinkChannel.cs:20](Channels/Interfaces/ILinkChannel.cs#L20), [IEthernetChannel.cs:7](Channels/Interfaces/IEthernetChannel.cs#L7) | (suy luận) — comment chỉ ghi "ARP/NDISC", không nêu số RFC |
| IEEE 802.3 (Ethernet frame, header 14 byte) | `IEthernetChannel`, `ILinkChannel.MaxHeaderLength` | [IEthernetChannel.cs:7](Channels/Interfaces/IEthernetChannel.cs#L7), [ILinkChannel.cs:18](Channels/Interfaces/ILinkChannel.cs#L18) | (suy luận) — comment ghi "14 for Ethernet" |
| RFC 1661 / RFC 1332 (PPP / IPCP) | `AddressAssignment.Ipcp` | [AddressAssignment.cs:7](Drivers/Enums/AddressAssignment.cs#L7) | (suy luận) — comment ghi "PPP IPCP negotiation" |
| RFC 7296 (IKEv2 CFG payload) — cấp địa chỉ in-band | `AddressAssignment.ConfigPush` | [AddressAssignment.cs:9](Drivers/Enums/AddressAssignment.cs#L9) | (suy luận) — comment nêu "IKEv2 CFG payload" cùng OpenVPN/CSTP |
| RFC 2131 (DHCP) | `AddressAssignment.Dhcp` | [AddressAssignment.cs:15](Drivers/Enums/AddressAssignment.cs#L15) | (suy luận) — comment ghi "DHCP over an L2 segment" |
| RFC 4303 (IPsec ESP) | `VpnSecurityKind.Esp`, `VpnTransportKind` ngữ cảnh ESP | [VpnSecurityKind.cs:10](Drivers/Enums/VpnSecurityKind.cs#L10) | (suy luận) — chỉ là tên flag năng lực |
| RFC 5246 / RFC 8446 (TLS), RFC 6347 / RFC 9147 (DTLS) | `VpnSecurityKind.Tls` / `.Dtls`, `VpnTransportKind.Tls` / `.Dtls` | [VpnSecurityKind.cs:8](Drivers/Enums/VpnSecurityKind.cs#L8), [VpnTransportKind.cs:11](Drivers/Enums/VpnTransportKind.cs#L11) | (suy luận) — tên flag năng lực, khung mở rộng |
| Noise Protocol (WireGuard), MPPE (RFC 3078) | `VpnSecurityKind.Noise` / `.Mppe` | [VpnSecurityKind.cs:11](Drivers/Enums/VpnSecurityKind.cs#L11), [VpnSecurityKind.cs:12](Drivers/Enums/VpnSecurityKind.cs#L12) | (suy luận) — khung mở rộng tương lai, chưa wire |
| EAP (RFC 3748) | `VpnAuthMethod.Eap` | [VpnAuthMethod.cs:11](Drivers/Enums/VpnAuthMethod.cs#L11) | (suy luận) — tên flag auth |

## API / cách dùng

Điểm vào của một driver luôn là [`IVpnProtocolDriver`](Drivers/Interfaces/IVpnProtocolDriver.cs#L9). Façade đọc `Capabilities` rồi gọi `ConnectAsync`; kết quả cho ra cây `IVpnConnection → IVpnSession → IPacketChannel` để userspace stack bind vào.

```csharp
// Phía consumer (façade) chỉ làm việc với hợp đồng — không lệ thuộc hiện thực cụ thể.
IVpnProtocolDriver driver = /* ví dụ: L2tpIpsecDriver từ TqkLibrary.VpnClient.Drivers.L2tpIpsec */;

VpnDriverCapabilities caps = driver.Capabilities;
// (Có thể kiểm tra caps.RequiresElevation / caps.AuthMethods... trước khi kết nối.)

IVpnConnection connection = await driver.ConnectAsync(
    new VpnEndpoint("vpn.example.com", 500),
    new VpnCredentials { Username = "user", Password = "pass", PreSharedKey = pskBytes },
    cancellationToken);

IVpnSession session = connection.Sessions[0];     // hoặc await connection.OpenSessionAsync()
TunnelConfig cfg = session.Config;                // AssignedAddress / DnsServers / Routes / Mtu
IPacketChannel link = session.PacketChannel;      // userspace TCP/IP stack bind vào đây
```

Một số mảnh hợp đồng đáng chú ý:

- `IByteStreamTransport`: `ConnectAsync` + `ReadAsync`/`WriteAsync` thuần (Memory). Hiện thực dùng chung `Transport.Tls.TlsByteStream` bọc `TcpClient`+`SslStream`, honor `CancellationToken` cả 2 TFM (biến thể `BouncyCastleTlsByteStream` còn hiện thực `ITlsByteStream`+`ITlsKeyingMaterialExporter`).
- `IPacketChannel.InboundIpPacket`: buffer **chỉ hợp lệ trong handler**, phải copy nếu cần dùng lâu hơn — [IPacketChannel.cs:11-15](Channels/Interfaces/IPacketChannel.cs#L11-L15).

## Luồng nội bộ

Phần lớn project là hợp đồng không có logic; lớp có logic duy nhất là `SwappablePacketChannel` — facade giữ kết nối ổn định cho stack qua reconnect:

1. **Khởi tạo rỗng:** constructor cache một delegate `_forward` duy nhất để `-=` trong `SetInner`/`DisposeAsync` thực sự detach đúng instance — [SwappablePacketChannel.cs:22-26](Channels/SwappablePacketChannel.cs#L22-L26).
2. **Attach/hot-swap inner:** `SetInner` lock, detach inner cũ, **pin metadata** (`Medium/Mtu/MaxHeaderLength/RequiresLinkAddressResolution`) từ inner **đầu tiên** rồi gắn handler vào inner mới — [SwappablePacketChannel.cs:44-63](Channels/SwappablePacketChannel.cs#L44-L63).
3. **Ghi ra:** `WriteIpPacketAsync` forward tới inner hiện tại; khi chưa có inner (trước connect đầu hoặc giữa reconnect) **drop im lặng**, không throw — [SwappablePacketChannel.cs:66-70](Channels/SwappablePacketChannel.cs#L66-L70).
4. **Nhận vào:** delegate `_forward` re-raise `InboundIpPacket` **đồng bộ**, giữ đúng hợp đồng buffer-lifetime của `IPacketChannel` — [SwappablePacketChannel.cs:25](Channels/SwappablePacketChannel.cs#L25).
5. **Dispose:** detach handler, null inner, dispose inner hiện tại — [SwappablePacketChannel.cs:73-83](Channels/SwappablePacketChannel.cs#L73-L83).

## Trạng thái & ghi chú

- **Đã hiện thực (có code chạy):** `SwappablePacketChannel` là lớp duy nhất có logic; phần còn lại là interface/model/enum thuần hợp đồng.
- **Khung mở rộng tương lai (chưa wire bởi driver nào):** vài thành viên enum năng lực mới chỉ là khung cho protocol chưa hiện thực — `LinkMedium.Ethernet`, `VpnSecurityKind.Mppe`, `MultiHostModel.L2BroadcastDomain`, `AddressAssignment.Dhcp`, `VpnAuthMethod.Saml`/`.Otp`. Riêng `IEthernetChannel` (L2) **đã có impl** [`EthernetSwitch.Port`](../TqkLibrary.VpnClient.Ethernet/EthernetSwitch.Port.cs#L13) trên nền L2.0–L2.3 (switch học MAC + `VirtualHost` bridge L2↔L3 + ARP IPv4) — chỉ **chưa có driver L2 production** ráp end-to-end (cần NDISC/DHCP/`EthernetAdapter`).
- **Đã được wire (không còn chỉ là khung):** `VpnTransportKind.Dtls`/`VpnSecurityKind.Dtls` đã có impl `DtlsDatagramTransport` ([`Transport.Dtls`](../TqkLibrary.VpnClient.Transport.Dtls), F.3) + consumer OpenConnect/WireGuard; `VpnTransportKind.RawIp` đã có seam [`IRawIpTransportFactory`](Transport/Interfaces/IRawIpTransportFactory.cs#L12) + factory thật ở [`Transport.RawIp`](../TqkLibrary.VpnClient.Transport.RawIp) (native-ESP, cần elevation); `VpnSecurityKind.Noise` đã được driver WireGuard dùng. Các driver lõi đầu (L2TP/IPsec đang chạy, SSTP) chỉ dùng tập con (L3/IP, ESP/TLS, IPCP, PSK/UserPassword).
- **Slot L2 (khai báo phase L2.0):** `INeighborResolver` (ARP/NDISC) + `IAddressConfigurator` (DHCP/SLAAC) là 2 slot của `EthernetAdapter` tương lai (design 00 §5). Dùng raw bytes/`IPAddress` (không ref `MacAddress` của project `TqkLibrary.VpnClient.Ethernet`) để giữ CORE không phụ thuộc codec L2. `INeighborResolver` **đã có impl IPv4** ([`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs#L26), ARP/L2.3); còn NDISC IPv4 (L2.4) + `IAddressConfigurator` (DHCP/SLAAC, L2.5→L2.6) chưa.
- **Không hiện thực RFC trực tiếp:** mọi RFC/chuẩn trong bảng trên chỉ là *ngữ cảnh hợp đồng*; hiện thực thật nằm ở `Ipsec` (gồm NAT-T `Nat/`), `L2tp`, `Ppp`, `IpStack`, `Crypto`.
- **netstandard2.0 vs net8.0:** API giống hệt nhau; khác biệt duy nhất là trên `netstandard2.0` cần polyfill (`System.Memory`, `Microsoft.Bcl.AsyncInterfaces`...) cho `Span/Memory`, `ValueTask`, `IAsyncDisposable` — kế thừa từ [Directory.Build.props](../Directory.Build.props#L16-L25). `record`/`init` đã khả dụng cả 2 TFM nhờ `TqkLibrary.CompilerServices` (`IsExternalInit`), nhưng các model hiện tại ở đây vẫn là `class` với property `get; set;` (as-built).
- **Không phụ thuộc project nào** → an toàn để mọi tầng khác tham chiếu mà không tạo vòng phụ thuộc.
