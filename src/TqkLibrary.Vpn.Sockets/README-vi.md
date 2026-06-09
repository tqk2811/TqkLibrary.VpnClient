# TqkLibrary.Vpn.Sockets

> Public socket-like API: VpnTcpClient, VpnUdpClient, VpnStream over the userspace IP stack.

API socket-like (`VpnTcpClient` / `VpnUdpClient` / `VpnNetworkStream`) chạy **bên trong** tunnel VPN: mọi byte đi qua userspace TCP/IP stack ([`TqkLibrary.Vpn.IpStack`](../TqkLibrary.Vpn.IpStack)) rồi xuống `IPacketChannel` của session, không đụng tới socket OS.

---

## Mục đích

Project này là **tầng tiêu thụ** của VPN client: sau khi một `IVpnSession` được thiết lập (đã có IP gán + `IPacketChannel`), ứng dụng cần gửi/nhận dữ liệu **qua tunnel** thay vì qua card mạng vật lý. Vì TqkLibrary.Vpn là VPN client **thuần userspace** (không tạo TUN/TAP, không đụng routing table của OS), socket `System.Net.Sockets` của hệ điều hành sẽ đi thẳng ra Internet chứ không vào tunnel. Sockets giải quyết vấn đề đó bằng cách cung cấp:

- `VpnTcpClient` — mở kết nối TCP qua tunnel và trả về một `Stream` chuẩn (`VpnNetworkStream`) để **cắm thẳng vào `HttpClient`** hoặc bất kỳ code nào nhận `Stream`.
- `VpnUdpClient` — UDP client kết nối tới một remote endpoint cố định (ví dụ gửi truy vấn DNS tới `<dns-server>:53` qua tunnel).
- `VpnNetworkStream` — adapter `Stream` duplex trên một `TcpConnection` userspace.
- `VpnSessionSocketsExtensions.CreateTcpStack` — helper lắp `TcpIpStack` từ `IVpnSession` (lấy `PacketChannel` + `AssignedAddress`).

Toàn bộ là lớp mỏng (thin wrapper) đặt API quen thuộc lên trên `TqkLibrary.Vpn.IpStack`; logic IP/TCP/UDP thực sự nằm ở IpStack.

---

## Vị trí trong kiến trúc

Tầng **Sockets** (ngay dưới entry point `TqkLibrary.Vpn`, trên `IpStack`):

```
APP        TqkLibrary.Vpn            VpnClient / VpnClientBuilder (entry point)
        => TqkLibrary.Vpn.Sockets   VpnTcpClient / VpnUdpClient / VpnNetworkStream  (project này)
PROTOCOL   TqkLibrary.Vpn.IpStack   IPv4 / TCP / UDP userspace
CORE       TqkLibrary.Vpn.Abstractions   interface + model + enum
```

- **Target frameworks:** `netstandard2.0` ; `net8.0` (xem [Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [`TqkLibrary.Vpn.Abstractions`](../TqkLibrary.Vpn.Abstractions) — cho `IVpnSession` / `IPacketChannel` (dùng trong extension).
  - [`TqkLibrary.Vpn.IpStack`](../TqkLibrary.Vpn.IpStack) — cho `TcpIpStack` / `TcpConnection` / `UdpConnection`.
  - Không có `PackageReference` đặc thù.
- **Được dùng bởi:** [`TqkLibrary.Vpn`](../TqkLibrary.Vpn) (entry point) — re-export cho ứng dụng tiêu thụ.

---

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Sockets/
├── VpnTcpClient.cs        TCP client qua tunnel; ConnectAsync -> GetStream() trả Stream
├── VpnUdpClient.cs        UDP client kết nối tới một remote endpoint cố định (Send / ReceiveAsync)
├── VpnNetworkStream.cs    adapter Stream duplex trên TcpConnection (dùng cho HttpClient)
└── Extensions/
    └── VpnSessionSocketsExtensions.cs   IVpnSession.CreateTcpStack() -> TcpIpStack
```

---

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `VpnTcpClient` | Mở TCP qua tunnel (`ConnectAsync`), trả `Stream` qua `GetStream()`; bọc một `TcpConnection`. | [VpnTcpClient.cs:8](VpnTcpClient.cs#L8) |
| `VpnTcpClient.ConnectAsync` | Gọi `stack.ConnectAsync(...)` để hoàn tất 3-way handshake rồi trả client. | [VpnTcpClient.cs:15](VpnTcpClient.cs#L15) |
| `VpnNetworkStream` | `Stream` duplex trên `TcpConnection`: `ReadAsync` -> `TcpConnection.ReadAsync`, `Write` -> `TcpConnection.Send`, `Dispose` -> `CloseSend` (gửi FIN). Non-seekable. | [VpnNetworkStream.cs:7](VpnNetworkStream.cs#L7) |
| `VpnUdpClient` | UDP client "connected" (remote endpoint cố định): `Send` / `ReceiveAsync`; bọc một `UdpConnection`. | [VpnUdpClient.cs:10](VpnUdpClient.cs#L10) |
| `VpnUdpClient.ReceiveAsync` | Lọc datagram: chỉ trả về gói từ đúng `remoteAddress`:`remotePort`, bỏ qua nguồn khác. | [VpnUdpClient.cs:34](VpnUdpClient.cs#L34) |
| `VpnSessionSocketsExtensions.CreateTcpStack` | Extension trên `IVpnSession`: dựng `TcpIpStack` từ `PacketChannel` + `Config.AssignedAddress` (ném `InvalidOperationException` nếu chưa có IP). | [VpnSessionSocketsExtensions.cs:10](Extensions/VpnSessionSocketsExtensions.cs#L10) |

Các kiểu nền (ở project IpStack, không thuộc Sockets) mà API trên dựa vào:

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `TcpIpStack` | Bind `IPacketChannel` + local IP, demux gói inbound theo local port, mở kết nối TCP/UDP. | [TcpIpStack.cs:11](../TqkLibrary.Vpn.IpStack/Tcp/TcpIpStack.cs#L11) |
| `TcpConnection` | TCP active-open tối giản trên byte stream tin cậy (handshake, in-order data, ACK, FIN). | [TcpConnection.cs:13](../TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs#L13) |
| `UdpConnection` | UDP socket userspace bound một local port; `SendTo` / `ReceiveAsync` + `UdpReceiveResult`. | [UdpConnection.cs:10](../TqkLibrary.Vpn.IpStack/Tcp/UdpConnection.cs#L10) |
| `IVpnSession` | Một IP endpoint logic: `Config` (IP gán) + `PacketChannel`. | [IVpnSession.cs:10](../TqkLibrary.Vpn.Abstractions/Drivers/Interfaces/IVpnSession.cs#L10) |
| `IPacketChannel` | Kênh L3 mang gói IPv4/IPv6 trần; stack bind vào đây. | [IPacketChannel.cs:6](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) |

---

## Chuẩn / RFC tuân thủ

Project Sockets **không hiện thực trực tiếp** chuẩn mạng nào — nó chỉ đặt API socket-like lên trên userspace stack. Các chuẩn dưới đây được **tuân thủ gián tiếp** thông qua `TqkLibrary.Vpn.IpStack` mà các kiểu ở đây dựa vào; cột "Vị trí" trỏ tới nơi hành vi tương ứng được dùng/hiện thực. Trong số đó, **RFC 768 và RFC 1071 được trích dẫn trực tiếp (cited-in-code)** trong comment của IpStack; RFC 793 và RFC 791 là **(suy luận)** (không có chuỗi "RFC" trong code, chỉ khớp hành vi).

| Chuẩn (RFC/FIPS/NIST/MS-*) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| RFC 793 — TCP (handshake, ACK, FIN, sequence number) | `TcpConnection` (qua `VpnTcpClient` / `VpnNetworkStream`) | [TcpConnection.cs:13](../TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs#L13) | (suy luận) không có comment "RFC" trong code; bỏ qua retransmission/SACK vì tunnel bên dưới đã tin cậy/in-order — xem chú thích [TcpConnection.cs:8-12](../TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs#L8-L12) |
| RFC 768 — UDP (datagram không trạng thái) | `UdpConnection` / `VpnUdpClient` (build ở `UdpDatagram`) | [UdpConnection.cs:10](../TqkLibrary.Vpn.IpStack/Tcp/UdpConnection.cs#L10) | **cited-in-code** tại [UdpDatagram.cs:5](../TqkLibrary.Vpn.IpStack/UdpDatagram.cs#L5) (`... (RFC 768)`); `VpnUdpClient` thêm lọc theo remote endpoint cố định |
| RFC 791 — IPv4 (header 20 byte, không option, set DF) | `Ipv4.Build` | [Ipv4.cs:18](../TqkLibrary.Vpn.IpStack/Ipv4.cs#L18) | (suy luận) header tối giản, không cite RFC trong code; mọi gói TCP/UDP của Sockets đi qua đây |
| RFC 1071 — Internet checksum (1's-complement) | `InternetChecksum` (qua `Ipv4.Build` / `TcpSegment.Build` / `UdpDatagram.Build`) | [InternetChecksum.cs:3](../TqkLibrary.Vpn.IpStack/InternetChecksum.cs#L3) | **cited-in-code** (`... Internet checksum (RFC 1071) ...`); hàm `Compute` ở [InternetChecksum.cs:7](../TqkLibrary.Vpn.IpStack/InternetChecksum.cs#L7), được `Ipv4.Build` gọi tại [Ipv4.cs:36](../TqkLibrary.Vpn.IpStack/Ipv4.cs#L36) |

> Lưu ý: bản thân thư mục `TqkLibrary.Vpn.Sockets` không chứa từ khóa `RFC`/`FIPS`/`NIST`/`MS-` nào (đã grep). Bảng trên là ánh xạ tới project phụ thuộc IpStack để tiện tra cứu.

---

## API / cách dùng

Điểm vào chính (tất cả đều `public`):

- `IVpnSession.CreateTcpStack()` → `TcpIpStack` — bước đầu tiên, dựng stack từ session.
- `VpnTcpClient.ConnectAsync(stack, remoteAddress, remotePort, ct)` → `Task<VpnTcpClient>`; rồi `client.GetStream()` → `Stream`.
- `VpnUdpClient.Connect(stack, remoteAddress, remotePort)` → `VpnUdpClient`; rồi `Send(...)` / `await ReceiveAsync(ct)`.

### Ví dụ — HttpClient qua tunnel

```csharp
using TqkLibrary.Vpn.Sockets;
using TqkLibrary.Vpn.Sockets.Extensions;

// session: IVpnSession đã kết nối (từ TqkLibrary.Vpn)
TcpIpStack stack = session.CreateTcpStack();

var handler = new SocketsHttpHandler
{
    ConnectCallback = async (ctx, ct) =>
    {
        IPAddress ip = IPAddress.Parse("93.184.216.34"); // đã resolve sẵn
        VpnTcpClient tcp = await VpnTcpClient.ConnectAsync(stack, ip, (ushort)ctx.DnsEndPoint.Port, ct);
        return tcp.GetStream();
    }
};
using var http = new HttpClient(handler);
string html = await http.GetStringAsync("http://example.com/");
```

### Ví dụ — DNS qua tunnel (UDP tới port 53)

```csharp
TcpIpStack stack = session.CreateTcpStack();
VpnUdpClient dns = VpnUdpClient.Connect(stack, IPAddress.Parse("8.8.8.8"), 53);
dns.Send(dnsQueryBytes);                 // gói DNS đã tự build
byte[] reply = await dns.ReceiveAsync();  // chỉ nhận từ 8.8.8.8:53
```

---

## Luồng nội bộ

### TCP — từ `ConnectAsync` tới `Stream`

1. `VpnTcpClient.ConnectAsync` gọi `stack.ConnectAsync(remoteAddress, remotePort, ct)` — [VpnTcpClient.cs:15-19](VpnTcpClient.cs#L15-L19).
2. `TcpIpStack.ConnectAsync` cấp local port ephemeral, tạo `TcpConnection`, `StartConnect()` (gửi SYN) rồi chờ `connection.Connected` (handshake xong) — [TcpIpStack.cs:28-40](../TqkLibrary.Vpn.IpStack/Tcp/TcpIpStack.cs#L28-L40).
3. `GetStream()` bọc `TcpConnection` thành `VpnNetworkStream` — [VpnTcpClient.cs:22](VpnTcpClient.cs#L22).
4. Đọc/ghi qua stream: `WriteAsync`/`Write` → `TcpConnection.Send` (chia theo MSS, gửi PSH|ACK); `ReadAsync` → `TcpConnection.ReadAsync` — [VpnNetworkStream.cs:29-45](VpnNetworkStream.cs#L29-L45).
5. `Dispose` gọi `_connection.CloseSend()` → gửi FIN, đóng nửa gửi — [VpnNetworkStream.cs:60-64](VpnNetworkStream.cs#L60-L64).

Gói inbound đi ngược lại: `IPacketChannel.InboundIpPacket` → `TcpIpStack.OnInbound` demux theo destination port → `TcpConnection.OnSegment` — [TcpIpStack.cs:55-77](../TqkLibrary.Vpn.IpStack/Tcp/TcpIpStack.cs#L55-L77).

### UDP — connected client

1. `VpnUdpClient.Connect` gọi `stack.BindUdp()` (ephemeral port) và nhớ remote endpoint — [VpnUdpClient.cs:27-28](VpnUdpClient.cs#L27-L28).
2. `Send` → `UdpConnection.SendTo(_remoteAddress, _remotePort, data)` — [VpnUdpClient.cs:31](VpnUdpClient.cs#L31).
3. `ReceiveAsync` vòng lặp `UdpConnection.ReceiveAsync` và chỉ trả về gói khớp `(_remoteAddress, _remotePort)`, bỏ qua nguồn khác — [VpnUdpClient.cs:34-42](VpnUdpClient.cs#L34-L42).

---

## Trạng thái & ghi chú

- **Đã hiện thực:** `VpnTcpClient` + `VpnNetworkStream` (đủ để cắm `HttpClient`), `VpnUdpClient` (connected UDP, phù hợp DNS), `CreateTcpStack`. Tất cả là wrapper mỏng; mọi logic giao thức nằm ở `TqkLibrary.Vpn.IpStack`.
- **`VpnUdpClient` không có gì đặc thù DNS** — nó là UDP client kết nối thông thường; "DNS-over-tunnel" chỉ là use-case (gửi gói DNS đã build sẵn tới `<server>:53`). Việc encode/decode bản tin DNS nằm ngoài project này.
- **Tên trong `<Description>` của .csproj ghi "VpnStream"** nhưng class thực tế là `VpnNetworkStream` ([VpnNetworkStream.cs:7](VpnNetworkStream.cs#L7)) — chỉ là khác biệt mô tả, không phải kiểu khác.
- **Giới hạn (kế thừa từ IpStack):** `TcpConnection` là active-open tối giản, **không** retransmission/SACK/congestion-control vì giả định tunnel bên dưới (SSTP/L2TP) đã reliable + in-order ([TcpConnection.cs:8-12](../TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs#L8-L12)); MSS cố định 1360, không có listen/accept (chỉ client).
- **`netstandard2.0` vs `net8.0`:** không có code rẽ nhánh theo TFM trong project này; tránh `record`/`init` theo quy ước repo (netstandard2.0 thiếu `IsExternalInit`).
- **DNS resolution:** Sockets nhận `IPAddress` đã resolve sẵn; không tự phân giải tên miền — tầng gọi (entry point/ứng dụng) chịu trách nhiệm resolve (có thể tự dùng `VpnUdpClient` tới DNS server qua tunnel).

---

Tài liệu kiến trúc as-built tổng thể: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
