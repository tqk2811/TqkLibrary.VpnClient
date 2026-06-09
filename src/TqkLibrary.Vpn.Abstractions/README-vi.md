# TqkLibrary.Vpn.Abstractions

> VPN platform abstractions: link channels, transport/security/encapsulation contracts, driver plugin interface.

## Mục đích

`TqkLibrary.Vpn.Abstractions` là tầng **CORE** của thư viện — tập hợp **hợp đồng (interface) + model + enum** mà mọi tầng khác phụ thuộc vào. Project này **không hiện thực protocol/RFC nào**, chỉ định nghĩa khung kiểu để:

- **Đảo ngược phụ thuộc (Dependency Inversion):** các driver protocol (L2TP/IPsec, SSTP...), tầng transport, tầng crypto-session và userspace IP stack đều lập trình theo các interface ở đây, không lệ thuộc trực tiếp lẫn nhau. Façade (`TqkLibrary.Vpn`) khám phá driver qua [`IVpnProtocolDriver`](Drivers/Interfaces/IVpnProtocolDriver.cs#L9) mà không cần biết hiện thực cụ thể.
- **Tách data plane khỏi control plane:** stack TCP/IP userspace chỉ bind vào [`IPacketChannel`](Channels/Interfaces/IPacketChannel.cs#L6) (L3, IP thuần), không bao giờ thấy Ethernet hay chi tiết tunnel.
- **Mô tả năng lực driver:** [`VpnDriverCapabilities`](Drivers/Models/VpnDriverCapabilities.cs#L9) cho phép façade thương lượng (transport/security/auth/elevation) trước khi kết nối, và từ chối nhẹ nhàng khi không đủ quyền.

Nhiều enum/flag trong project là **khung mở rộng tương lai** (WireGuard, OpenVPN, DTLS, L2/Ethernet, Noise, MPPE...) — định nghĩa sẵn để các driver mới chỉ cần khai báo năng lực mà không phải đổi CORE.

## Vị trí trong kiến trúc

- **Tầng:** CORE (đáy đồ thị phụ thuộc).
- **Target frameworks:** `netstandard2.0` ; `net8.0`.
- **Phụ thuộc (ProjectReference):** **không có** — đây là project đáy, không tham chiếu project nào trong solution.
- **PackageReference:** không có package đặc thù riêng. Trên `netstandard2.0` kế thừa polyfill chung từ [Directory.Build.props](../Directory.Build.props#L16-L21): `System.Memory`, `System.Threading.Channels`, `System.IO.Pipelines`, `Microsoft.Bcl.AsyncInterfaces` (cung cấp `Span/Memory`, `IAsyncDisposable`, `ValueTask`). Trên `net8.0` các kiểu này có sẵn trong BCL.
- **Được dùng bởi:** `Drivers.L2tpIpsec`, `Drivers.Sstp`, `IpStack`, `Ipsec`, `Transport.Udp`, `L2tp`, `Sockets`, `Ppp` (gián tiếp qua các tầng đó là `Vpn`).

Xem thêm tài liệu as-built: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Abstractions/
├── Channels/                 # Lớp "link" mà userspace stack chạy bên trên (L2/L3)
│   ├── Enums/                #   LinkMedium (Ip vs Ethernet)
│   ├── Interfaces/           #   ILinkChannel + IPacketChannel (L3) + IEthernetChannel (L2)
│   └── SwappablePacketChannel.cs  # facade IPacketChannel hot-swap được (reconnect không rebind stack)
├── Transport/Interfaces/     # Ống truyền byte/datagram bên dưới (TCP/TLS vs UDP)
├── Security/Interfaces/      # Lớp crypto-session: handshake + protect/unprotect
├── Encapsulation/Interfaces/ # Đóng khung payload lên transport (length-prefix/HDLC/datagram/TLV)
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
| `SwappablePacketChannel` | Facade `IPacketChannel` cho phép **hot-swap** inner channel qua reconnect mà stack không rebind; metadata pin từ inner đầu tiên | [SwappablePacketChannel.cs:14](Channels/SwappablePacketChannel.cs#L14) |

### Transport — ống truyền bên dưới

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `IByteStreamTransport` | Ống byte tin cậy, có thứ tự (TCP/TLS/SSH); nền cho PPP-over-stream và SSL-VPN | [IByteStreamTransport.cs:4](Transport/Interfaces/IByteStreamTransport.cs#L4) |
| `IDatagramTransport` | Ống datagram (UDP), giữ biên gói; comment nêu decorator `EspIkeDemuxTransport` tách IKE/ESP trên UDP/4500 (tên design-intent — hiện thực thật ở `Transport.Udp` là `NatTraversal`/`NatTraversalChannel`) | [IDatagramTransport.cs:7](Transport/Interfaces/IDatagramTransport.cs#L7) |

### Security & Encapsulation

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `ISecuritySession` | Lớp crypto của driver: `PerformHandshakeAsync` + `Protect`/`Unprotect`; tự quản keying & rekey | [ISecuritySession.cs:7](Security/Interfaces/ISecuritySession.cs#L7) |
| `IPacketEncapsulator` | Đóng khung payload: `Encode` (IBufferWriter) + `TryDecode` incremental (ReadOnlySequence) | [IPacketEncapsulator.cs:9](Encapsulation/Interfaces/IPacketEncapsulator.cs#L9) |

### Drivers — hợp đồng plugin + model

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `IVpnProtocolDriver` | **Điểm vào plugin**: `Name`, `Capabilities`, `ConnectAsync` | [IVpnProtocolDriver.cs:9](Drivers/Interfaces/IVpnProtocolDriver.cs#L9) |
| `IVpnConnection` | Một kết nối live (1 transport / 1 IKE-SA / 1 TLS); chứa nhiều `IVpnSession`, `OpenSessionAsync` | [IVpnConnection.cs:7](Drivers/Interfaces/IVpnConnection.cs#L7) |
| `IVpnSession` | Một IP endpoint logic: `Config` + `PacketChannel` (1 IP / 1 stack) | [IVpnSession.cs:10](Drivers/Interfaces/IVpnSession.cs#L10) |
| `VpnDriverCapabilities` | Bảng năng lực driver: link layer, multi-host, PPP, transport/security/auth, address assignment, raw-IP/elevation | [VpnDriverCapabilities.cs:9](Drivers/Models/VpnDriverCapabilities.cs#L9) |
| `VpnEndpoint` | Host + port của server | [VpnEndpoint.cs:4](Drivers/Models/VpnEndpoint.cs#L4) |
| `VpnCredentials` | `Username` / `Password` / `PreSharedKey` | [VpnCredentials.cs:4](Drivers/Models/VpnCredentials.cs#L4) |
| `TunnelConfig` | Kết quả mạng của session: địa chỉ, prefix, DNS, routes, MTU (chỉ dùng nội bộ, không ghi routing table OS) | [TunnelConfig.cs:9](Drivers/Models/TunnelConfig.cs#L9) |
| `VpnElevationRequiredException` | Ném khi driver cần quyền admin/root/CAP_NET_RAW nhưng tiến trình không có (kế thừa `Exception`, **không** thuộc cây `VpnConnectionException`) | [VpnElevationRequiredException.cs:7](Drivers/VpnElevationRequiredException.cs#L7) |
| `VpnConnectionException` | **Base** (không sealed) cho mọi lỗi khi thiết lập/duy trì kết nối; catch để xử lý chung, catch lớp con để phản ứng theo nguyên nhân | [VpnConnectionException.cs:8](Drivers/VpnConnectionException.cs#L8) |
| `VpnAuthenticationException` | (sealed, con của `VpnConnectionException`) server từ chối credential: PPP MS-CHAPv2 fail / IKE PSK·HASH_R mismatch — retry cùng credential vô ích | [VpnAuthenticationException.cs:7](Drivers/VpnAuthenticationException.cs#L7) |
| `VpnServerRejectedException` | (sealed, con của `VpnConnectionException`) server từ chối session ở mức giao thức: SSTP Call-Connect-Nak/Call-Abort, non-200 handshake, IKE Quick Mode không có SA | [VpnServerRejectedException.cs:8](Drivers/VpnServerRejectedException.cs#L8) |
| `VpnNetworkTimeoutException` | (sealed, con của `VpnConnectionException`) handshake không có hồi đáp trong timeout (IKE gateway im, TLS không xong) — vấn đề transport/reachability; caller `OperationCanceledException` **không** bị tái phân loại | [VpnNetworkTimeoutException.cs:8](Drivers/VpnNetworkTimeoutException.cs#L8) |
| `VpnLinkLayer` | Enum: L3Ip / L2Ethernet / Both | [VpnLinkLayer.cs:4](Drivers/Enums/VpnLinkLayer.cs#L4) |
| `MultiHostModel` | Enum: None / RoutedPrefixes / L2BroadcastDomain | [MultiHostModel.cs:5](Drivers/Enums/MultiHostModel.cs#L5) |
| `AddressAssignment` | Enum: Ipcp / ConfigPush / OutOfBand / Dhcp | [AddressAssignment.cs:5](Drivers/Enums/AddressAssignment.cs#L5) |
| `VpnTransportKind` | `[Flags]`: Tcp/Udp/Tls/Dtls/RawIp | [VpnTransportKind.cs:5](Drivers/Enums/VpnTransportKind.cs#L5) |
| `VpnSecurityKind` | `[Flags]`: Tls/Dtls/Esp/Noise/Mppe | [VpnSecurityKind.cs:5](Drivers/Enums/VpnSecurityKind.cs#L5) |
| `VpnAuthMethod` | `[Flags]`: PreSharedKey/Certificate/UserPassword/Eap/Saml/Otp | [VpnAuthMethod.cs:5](Drivers/Enums/VpnAuthMethod.cs#L5) |

## Chuẩn / RFC tuân thủ

Project này là **CORE thuần hợp đồng — không hiện thực RFC nào**. Bảng dưới ánh xạ các chuẩn được **tham chiếu (referenced) trong comment** để mô tả ngữ cảnh của hợp đồng (việc hiện thực thực tế nằm ở các project khác), cộng vài chuẩn suy luận từ tên thành viên enum.

| Chuẩn (RFC/FIPS/NIST/MS-*) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| RFC 3948 (UDP encapsulation of ESP, demux IKE/ESP trên UDP/4500) | `IDatagramTransport` (comment nêu decorator `EspIkeDemuxTransport`) | [IDatagramTransport.cs:5](Transport/Interfaces/IDatagramTransport.cs#L5) | RFC 3948 **được trích trong comment** làm ngữ cảnh. Tên `EspIkeDemuxTransport` chỉ là design-intent — không có type đó; hiện thực thật ở `Transport.Udp` là `NatTraversal`/`NatTraversalChannel` |
| MS-CHAPv2 (RFC 2759) | `VpnCredentials.Username` / `.Password` | [VpnCredentials.cs:6](Drivers/Models/VpnCredentials.cs#L6), [VpnCredentials.cs:9](Drivers/Models/VpnCredentials.cs#L9) | Comment nêu MS-CHAPv2/PAP/EAP; hiện thực ở `Ppp` |
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
IVpnProtocolDriver driver = /* ví dụ: L2tpIpsecDriver từ TqkLibrary.Vpn.Drivers.L2tpIpsec */;

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

- `ISecuritySession.Protect/Unprotect` trả `int` byte ghi ra; `Unprotect` trả `-1` khi auth fail — xem [ISecuritySession.cs:15-16](Security/Interfaces/ISecuritySession.cs#L15-L16).
- `IPacketEncapsulator.TryDecode` decode **incremental** trên `ReadOnlySequence<byte>`, tự advance buffer khi thành công — [IPacketEncapsulator.cs:18](Encapsulation/Interfaces/IPacketEncapsulator.cs#L18).
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
- **Khung mở rộng tương lai (chưa wire bởi driver nào):** nhiều thành viên enum năng lực mới chỉ là khung cho protocol chưa hiện thực — `LinkMedium.Ethernet` & `IEthernetChannel` (L2/SoftEther/tap), `VpnSecurityKind.Noise`/`.Mppe`, `VpnTransportKind.Dtls`/`.RawIp`, `MultiHostModel.L2BroadcastDomain`, `AddressAssignment.Dhcp`, `VpnAuthMethod.Saml`/`.Otp`. Các driver hiện có (L2TP/IPsec đang chạy, SSTP) chỉ dùng tập con (L3/IP, ESP/TLS, IPCP, PSK/UserPassword).
- **Không hiện thực RFC trực tiếp:** mọi RFC/chuẩn trong bảng trên chỉ là *ngữ cảnh hợp đồng*; hiện thực thật nằm ở `Ipsec`, `L2tp`, `Ppp`, `Transport.Udp`, `IpStack`, `Crypto`.
- **netstandard2.0 vs net8.0:** API giống hệt nhau; khác biệt duy nhất là trên `netstandard2.0` cần polyfill (`System.Memory`, `Microsoft.Bcl.AsyncInterfaces`...) cho `Span/Memory`, `ValueTask`, `IAsyncDisposable` — kế thừa từ [Directory.Build.props](../Directory.Build.props#L16-L21). Vì vậy tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`), các model ở đây đều là `class` với property `get; set;`.
- **Không phụ thuộc project nào** → an toàn để mọi tầng khác tham chiếu mà không tạo vòng phụ thuộc.
