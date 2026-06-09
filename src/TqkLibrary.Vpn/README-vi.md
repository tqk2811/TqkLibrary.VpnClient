# TqkLibrary.Vpn

> Façade của thư viện: `VpnClient` / `VpnClientBuilder`, đăng ký driver, lắp ráp DI. Đây là tầng cao nhất mà ứng dụng gọi vào.

## Mục đích

Project này là **điểm vào (entry point)** duy nhất của toàn bộ thư viện TqkLibrary.Vpn — một VPN client thuần userspace, plugin theo driver.

- Cho ứng dụng một API gọn để **đăng ký các protocol driver** (SSTP, L2TP/IPsec...) theo kiểu fluent rồi **mở kết nối theo tên giao thức**.
- Giấu toàn bộ độ phức tạp của stack bên dưới (IKE/ESP/L2TP/PPP/IP stack): app chỉ thấy `VpnClient.ConnectAsync(...)` trả về một `IVpnConnection`.
- Là nơi **đảo ngược phụ thuộc** hội tụ: façade biết về các driver cụ thể (`SstpDriver`, `L2tpIpsecDriver`), còn mọi tầng dưới chỉ phụ thuộc vào abstractions.

Vì sao tồn tại: tách "ai dùng giao thức nào" (ứng dụng) khỏi "giao thức được lắp ráp ra sao" (driver + protocol + crypto). App chỉ cần `TqkLibrary.Vpn`, không phải tham chiếu trực tiếp tới Ipsec/L2tp/Ppp...

## Vị trí trong kiến trúc

- **Tầng:** APP / Façade — đỉnh của đồ thị phụ thuộc, được ứng dụng tiêu thụ tham chiếu.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [Directory.Build.props](../Directory.Build.props)). Tránh `record`/`init` vì netstandard2.0 thiếu `IsExternalInit`.
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.Vpn.Sockets](../TqkLibrary.Vpn.Sockets) — API socket chạy trong tunnel (re-export cho app).
  - [TqkLibrary.Vpn.Crypto](../TqkLibrary.Vpn.Crypto) — primitive mã hóa.
  - [TqkLibrary.Vpn.Drivers.L2tpIpsec](../TqkLibrary.Vpn.Drivers.L2tpIpsec) — nơi `L2tpIpsecDriver` được khai báo.
  - [TqkLibrary.Vpn.Drivers.Sstp](../TqkLibrary.Vpn.Drivers.Sstp) — nơi `SstpDriver` được khai báo.
  - Không có `PackageReference` đặc thù.
- **Được dùng bởi:** ứng dụng tiêu thụ (không project nào khác trong solution ref tới project này).

## Cấu trúc thư mục

```
TqkLibrary.Vpn/
├── VpnClientBuilder.cs   # Builder fluent: AddDriver / UseSstp / UseL2tpIpsec → Build()
└── VpnClient.cs          # Client đã build: giữ map driver theo tên, ConnectAsync / Protocols / GetCapabilities
```

Project chỉ gồm 2 type — toàn bộ "logic" thực sự nằm ở các project driver/protocol bên dưới.

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `VpnClientBuilder` | Builder fluent: đăng ký driver theo `Name`, có shortcut `UseSstp()`/`UseL2tpIpsec()`, kết thúc bằng `Build()` | [VpnClientBuilder.cs:8](VpnClientBuilder.cs#L8) |
| `VpnClientBuilder.AddDriver` | Đăng ký một `IVpnProtocolDriver` bất kỳ (keyed theo `driver.Name`) | [VpnClientBuilder.cs:13](VpnClientBuilder.cs#L13) |
| `VpnClientBuilder.UseSstp` | Đăng ký `SstpDriver` (key `"sstp"`), auto-reconnect bật mặc định; overload nhận `SstpReconnectOptions` | [VpnClientBuilder.cs:20-23](VpnClientBuilder.cs#L20-L23) |
| `VpnClientBuilder.UseL2tpIpsec` | Đăng ký `L2tpIpsecDriver` (key `"l2tp-ipsec"`), auto-reconnect bật mặc định; overload nhận `L2tpIpsecReconnectOptions` và `(reconnect, L2tpIpsecTimeoutOptions)` | [VpnClientBuilder.cs:26-33](VpnClientBuilder.cs#L26-L33) |
| `VpnClient` | Client đã build: giữ `IReadOnlyDictionary<string, IVpnProtocolDriver>` các driver | [VpnClient.cs:8](VpnClient.cs#L8) |
| `VpnClient.ConnectAsync` | Tra driver theo tên giao thức rồi ủy thác `driver.ConnectAsync(endpoint, credentials, ct)`; ném `NotSupportedException` nếu chưa đăng ký | [VpnClient.cs:18](VpnClient.cs#L18) |
| `VpnClient.Protocols` | Liệt kê tên các giao thức đã đăng ký | [VpnClient.cs:15](VpnClient.cs#L15) |
| `VpnClient.GetCapabilities` | Trả `VpnDriverCapabilities` của một driver đã đăng ký | [VpnClient.cs:27](VpnClient.cs#L27) |

Các hợp đồng/model mà façade thao tác (định nghĩa ở Abstractions):

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `IVpnProtocolDriver` | Điểm vào plugin của 1 giao thức: `Name`, `Capabilities`, `ConnectAsync` | [IVpnProtocolDriver.cs:9](../TqkLibrary.Vpn.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs#L9) |
| `IVpnConnection` | Kết nối sống (1 IKE-SA / 1 TLS), sở hữu nhiều `IVpnSession`; `IAsyncDisposable` | [IVpnConnection.cs:7](../TqkLibrary.Vpn.Abstractions/Drivers/Interfaces/IVpnConnection.cs#L7) |
| `IVpnSession` | Một endpoint IP logic: `Config` + `PacketChannel` | [IVpnSession.cs:10](../TqkLibrary.Vpn.Abstractions/Drivers/Interfaces/IVpnSession.cs#L10) |
| `VpnEndpoint` | Địa chỉ server (host + port) | [VpnEndpoint.cs:4](../TqkLibrary.Vpn.Abstractions/Drivers/Models/VpnEndpoint.cs#L4) |
| `VpnCredentials` | `Username` / `Password` (MS-CHAPv2) + `PreSharedKey` (IKE PSK) | [VpnCredentials.cs:4](../TqkLibrary.Vpn.Abstractions/Drivers/Models/VpnCredentials.cs#L4) |
| `VpnDriverCapabilities` | Khả năng driver (link layer, transport, security, auth, elevation...) | [VpnDriverCapabilities.cs:9](../TqkLibrary.Vpn.Abstractions/Drivers/Models/VpnDriverCapabilities.cs#L9) |
| `TunnelConfig` | IP/DNS/route/MTU một session nhận được | [TunnelConfig.cs:9](../TqkLibrary.Vpn.Abstractions/Drivers/Models/TunnelConfig.cs#L9) |

## Chuẩn / RFC tuân thủ

Bản thân project façade **không hiện thực chuẩn mạng nào** — nó chỉ điều phối driver. Các chuẩn dưới đây được **truy cập gián tiếp** qua hai shortcut `UseSstp()` / `UseL2tpIpsec()`; cột "Vị trí" link tới nơi façade kích hoạt driver tương ứng, và (nếu có) tới comment ở driver. Project này không có comment `RFC` nào (chỉ một chú thích `MS-SSTP`), nên gần như toàn bộ là **(suy luận)** — chi tiết ánh xạ chuẩn → code nằm ở README của các project Drivers/Ipsec/L2tp/Ppp.

| Chuẩn (RFC/FIPS/NIST/MS-*) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| [MS-SSTP] (Secure Socket Tunneling Protocol) | `SstpDriver` qua `UseSstp()` | [VpnClientBuilder.cs:20-23](VpnClientBuilder.cs#L20-L23), [SstpDriver.cs:7-8](../TqkLibrary.Vpn.Drivers.Sstp/SstpDriver.cs#L7-L8) | Comment "MS-SSTP driver" ở façade; driver mô tả "TLS over 443, PPP, MS-CHAPv2" |
| RFC 2759 (MS-CHAPv2) | `SstpDriver` + `L2tpIpsecDriver` (PPP auth) | [VpnClientBuilder.cs:20](VpnClientBuilder.cs#L20), [VpnClientBuilder.cs:26](VpnClientBuilder.cs#L26) | (suy luận) — hiện thực thực tế ở Ppp/`MsChapV2` |
| RFC 2409 (IKEv1 / ISAKMP) | `L2tpIpsecDriver` qua `UseL2tpIpsec()` | [VpnClientBuilder.cs:26-29](VpnClientBuilder.cs#L26-L29), [L2tpIpsecDriver.cs:8](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L8) | (suy luận) — comment driver "IKEv1 PSK over NAT-T"; logic ở Ipsec `Ike/V1` |
| RFC 4303 (ESP) | `L2tpIpsecDriver` (data plane) | [L2tpIpsecDriver.cs:8](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L8), [L2tpIpsecDriver.cs:37](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L37) | (suy luận) — `SecurityKinds = Esp`; hiện thực ở Ipsec `Esp` |
| RFC 3948 (UDP encapsulation / NAT-T) | `L2tpIpsecDriver` (transport UDP) | [L2tpIpsecDriver.cs:8](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L8), [L2tpIpsecDriver.cs:36](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L36) | (suy luận) — "NAT-T"; hiện thực ở Transport.Udp |
| RFC 2661 (L2TPv2) | `L2tpIpsecDriver` | [L2tpIpsecDriver.cs:8](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L8) | (suy luận) — comment driver "L2TP"; hiện thực ở L2tp |
| RFC 1661/1332 (PPP/IPCP) | cả 2 driver (`UsesPpp`, `AddressAssignment.Ipcp`) | [SstpDriver.cs:22-31](../TqkLibrary.Vpn.Drivers.Sstp/SstpDriver.cs#L22-L31), [L2tpIpsecDriver.cs:31-40](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L31-L40) | (suy luận) — IP cấp qua IPCP; hiện thực ở Ppp |
| FIPS-197 (AES), NIST SP 800-38D (AES-GCM) | dùng gián tiếp khi mã hóa ESP/TLS | — | (suy luận) — primitive ở Crypto; façade không chạm trực tiếp |

> Tóm lại: dùng bảng này như **bản đồ "shortcut façade → chuẩn"**. Để xem ánh xạ chuẩn → file:line chính xác (có comment RFC trong code), đọc README các project: Drivers, Ipsec, L2tp, Ppp, Transport.Udp, Crypto.

## API / cách dùng

Điểm vào public:

- `VpnClientBuilder` → `UseSstp()`, `UseSstp(SstpReconnectOptions)`, `UseL2tpIpsec()`, `UseL2tpIpsec(L2tpIpsecReconnectOptions)`, `UseL2tpIpsec(L2tpIpsecReconnectOptions, L2tpIpsecTimeoutOptions)`, `AddDriver(IVpnProtocolDriver)`, `Build()`.
- `VpnClient` → `ConnectAsync(protocol, endpoint, credentials, ct)`, `Protocols`, `GetCapabilities(protocol)`.

Ví dụ tối thiểu:

```csharp
using TqkLibrary.Vpn;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

// 1) Đăng ký driver rồi build client
var vpn = new VpnClientBuilder()
    .UseSstp()
    .UseL2tpIpsec()       // auto-reconnect bật mặc định
    .Build();

// 2) Mở kết nối theo tên giao thức
var endpoint = new VpnEndpoint("vpn.example.com", 443);
var creds = new VpnCredentials { Username = "user", Password = "pass" };

await using IVpnConnection conn = await vpn.ConnectAsync("sstp", endpoint, creds);

// 3) Mỗi session là một endpoint IP có PacketChannel để cắm IP stack / socket
IVpnSession session = conn.Sessions[0];
var ip = session.Config.AssignedAddress;
```

Tùy biến auto-reconnect cho L2TP/IPsec:

```csharp
var vpn = new VpnClientBuilder()
    .UseL2tpIpsec(new L2tpIpsecReconnectOptions { Enabled = false }) // single-shot
    .Build();
```

## Luồng nội bộ

Façade rất mỏng, gồm hai bước:

1. **Đăng ký (build-time).** `UseSstp()`/`UseL2tpIpsec()` tạo driver cụ thể và gọi `AddDriver` để nạp vào `Dictionary<string, IVpnProtocolDriver>` keyed theo `driver.Name` (`"sstp"`, `"l2tp-ipsec"`) — [VpnClientBuilder.cs:13-33](VpnClientBuilder.cs#L13-L33). `Build()` đóng gói dictionary đó vào `VpnClient` — [VpnClientBuilder.cs:36](VpnClientBuilder.cs#L36).
2. **Kết nối (run-time).** `ConnectAsync` tra driver theo `protocol`: nếu không có → `NotSupportedException` kèm danh sách giao thức đã đăng ký; nếu có → ủy thác thẳng `driver.ConnectAsync(endpoint, credentials, ct)` và trả `IVpnConnection` — [VpnClient.cs:18-24](VpnClient.cs#L18-L24).

Toàn bộ việc lắp ráp stack (IKE → ESP → L2TP → PPP → IP) diễn ra **bên trong driver**, không nằm ở project này. Hai driver nằm ở hai project anh em: [TqkLibrary.Vpn.Drivers.L2tpIpsec](../TqkLibrary.Vpn.Drivers.L2tpIpsec) và [TqkLibrary.Vpn.Drivers.Sstp](../TqkLibrary.Vpn.Drivers.Sstp). Ví dụ điều phối L2TP/IPsec: `L2tpIpsecDriver.ConnectAsync` dựng `L2tpIpsecConnection` rồi gọi `ConnectAsync` của nó — [L2tpIpsecDriver.cs:43-57](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L43-L57). Chi tiết luồng handshake xem [.docs/10 §6](../../.docs/10-codebase-architecture-and-flow.md).

## Trạng thái & ghi chú

- **Driver đã wire:** `sstp` và `l2tp-ipsec` (qua `UseSstp()`/`UseL2tpIpsec()`). Driver tùy ý khác có thể nạp qua `AddDriver(IVpnProtocolDriver)`.
- **L2TP/IPsec chạy trên IKEv1** (đã kiểm chứng live trên VPN Gate). IKEv2 trong project Ipsec đã đủ và có test nhưng **chưa driver nào dùng** — façade hiện không có `UseIkeV2()`.
- **PSK mặc định:** nếu `VpnCredentials.PreSharedKey` null, `L2tpIpsecDriver` dùng `DefaultPreSharedKey = "vpn"` (group PSK của VPN Gate) — [L2tpIpsecDriver.cs:11-12](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L11-L12), [L2tpIpsecDriver.cs:45](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L45).
- **Multi-host:** `OpenSessionAsync` được khai báo ở `IVpnConnection` nhưng cả SSTP lẫn L2TP đều đặt `MultiHostModel.None` → chỉ một session/kết nối.
- **netstandard2.0 vs net8.0:** không khác biệt API ở tầng façade; khác biệt chỉ phát sinh tận tầng Crypto (BouncyCastle cho AES-GCM trên netstandard2.0). Tránh `record`/`init` để build xanh cả hai TFM.
- **Không ghi vào OS:** façade/driver **không chạm bảng route hệ điều hành**; tất cả là userspace — app tự lái lưu lượng qua `PacketChannel`/sockets trong tunnel.
