# TqkLibrary.VpnClient.Sockets

> Public socket-like API: VpnTcpClient, VpnUdpClient, VpnStream over the userspace IP stack.

API socket-like (`VpnTcpClient` / `VpnUdpClient` / `VpnNetworkStream`) chạy **bên trong** tunnel VPN: mọi byte đi qua userspace TCP/IP stack ([`TqkLibrary.VpnClient.IpStack`](../TqkLibrary.VpnClient.IpStack)) rồi xuống `IPacketChannel` của session, không đụng tới socket OS.

---

## Mục đích

Project này là **tầng tiêu thụ** của VPN client: sau khi một `IVpnSession` được thiết lập (đã có IP gán + `IPacketChannel`), ứng dụng cần gửi/nhận dữ liệu **qua tunnel** thay vì qua card mạng vật lý. Vì TqkLibrary.VpnClient là VPN client **thuần userspace** (không tạo TUN/TAP, không đụng routing table của OS), socket `System.Net.Sockets` của hệ điều hành sẽ đi thẳng ra Internet chứ không vào tunnel. Sockets giải quyết vấn đề đó bằng cách cung cấp:

- `VpnTcpClient` — mở kết nối TCP qua tunnel và trả về một `Stream` chuẩn (`VpnNetworkStream`) để **cắm thẳng vào `HttpClient`** hoặc bất kỳ code nào nhận `Stream`.
- `VpnUdpClient` — UDP client kết nối tới một remote endpoint cố định (ví dụ gửi truy vấn DNS tới `<dns-server>:53` qua tunnel).
- `VpnNetworkStream` — adapter `Stream` duplex trên một `TcpConnection` userspace.
- `VpnSessionSocketsExtensions.CreateTcpStack` — helper lắp `TcpIpStack` từ `IVpnSession` (lấy `PacketChannel` + `AssignedAddress`, và `AssignedAddressV6` nếu session bật IPv6 → stack **dual-stack**).

Toàn bộ là lớp mỏng (thin wrapper) đặt API quen thuộc lên trên `TqkLibrary.VpnClient.IpStack`; logic IP/TCP/UDP thực sự nằm ở IpStack.

---

## Vị trí trong kiến trúc

Tầng **Sockets** (ngay dưới entry point `TqkLibrary.VpnClient`, trên `IpStack`):

```
APP        TqkLibrary.VpnClient            VpnClient / VpnClientBuilder (entry point)
        => TqkLibrary.VpnClient.Sockets   VpnTcpClient / VpnUdpClient / VpnNetworkStream  (project này)
PROTOCOL   TqkLibrary.VpnClient.IpStack   IPv4 / TCP / UDP userspace
CORE       TqkLibrary.VpnClient.Abstractions   interface + model + enum
```

- **Target frameworks:** `netstandard2.0` ; `net8.0` (xem [Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [`TqkLibrary.VpnClient.Abstractions`](../TqkLibrary.VpnClient.Abstractions) — cho `IVpnSession` / `IPacketChannel` (dùng trong extension).
  - [`TqkLibrary.VpnClient.IpStack`](../TqkLibrary.VpnClient.IpStack) — cho `TcpIpStack` / `TcpConnection` / `UdpConnection`.
  - Không có `PackageReference` đặc thù.
- **Được dùng bởi:** [`TqkLibrary.VpnClient`](../TqkLibrary.VpnClient) (entry point) — re-export cho ứng dụng tiêu thụ.

---

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Sockets/
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
| `VpnTcpClient` | Mở TCP qua tunnel (`ConnectAsync`), trả `Stream` qua `GetStream()`; bọc một `TcpConnection`. | [VpnTcpClient.cs:9](VpnTcpClient.cs#L9) |
| `VpnTcpClient.ConnectAsync` | Gọi `stack.ConnectAsync(...)` để hoàn tất 3-way handshake rồi trả client. | [VpnTcpClient.cs:16](VpnTcpClient.cs#L16) |
| `VpnNetworkStream` | `Stream` duplex trên `TcpConnection`: `ReadAsync` -> `TcpConnection.ReadAsync`, `Write`/`WriteAsync` -> `TcpConnection.SendAsync` (**backpressure** theo cửa sổ peer + ném `IOException` khi connection fault — P0.3), `FlushAsync` surfaces fault, `Dispose` -> `CloseSend` (gửi FIN). Non-seekable. | [VpnNetworkStream.cs:7](VpnNetworkStream.cs#L7) |
| `VpnUdpClient` | UDP client "connected" (remote endpoint cố định): `Send` / `ReceiveAsync`; bọc một `UdpConnection`. | [VpnUdpClient.cs:11](VpnUdpClient.cs#L11) |
| `VpnUdpClient.ReceiveAsync` | Lọc datagram: chỉ trả về gói từ đúng `remoteAddress`:`remotePort`, bỏ qua nguồn khác. | [VpnUdpClient.cs:35](VpnUdpClient.cs#L35) |
| `VpnSessionSocketsExtensions.CreateTcpStack` | Extension trên `IVpnSession`: dựng `TcpIpStack` từ `PacketChannel` + `Config.AssignedAddress` (+ `Config.AssignedAddressV6` khi bật IPv6 → overload dual-stack); ném `InvalidOperationException` nếu **cả hai** địa chỉ đều null. | [VpnSessionSocketsExtensions.cs:14](Extensions/VpnSessionSocketsExtensions.cs#L14) |

Các kiểu nền (ở project IpStack, không thuộc Sockets) mà API trên dựa vào:

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `TcpIpStack` | Bind `IPacketChannel` + local IP, demux gói inbound theo local port, mở kết nối TCP/UDP. | [TcpIpStack.cs:19](../TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L19) |
| `TcpConnection` | TCP active-open **đầy đủ độ tin cậy**: handshake, retransmit/RTO (RFC 6298), flow-control + zero-window persist, NewReno congestion-control (RFC 5681/6582) + window scaling (RFC 7323), SACK (RFC 2018/6675), PMTUD (RFC 1191/8201), ráp out-of-order, half-close FSM (FIN/TIME-WAIT). | [TcpConnection.cs:13](../TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs#L13) |
| `UdpConnection` | UDP socket userspace bound một local port; `SendTo` / `ReceiveAsync` + `UdpReceiveResult`. | [UdpConnection.cs:12](../TqkLibrary.VpnClient.IpStack/Udp/UdpConnection.cs#L12) |
| `IVpnSession` | Một IP endpoint logic: `Config` (IP gán) + `PacketChannel`. | [IVpnSession.cs:10](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnSession.cs#L10) |
| `IPacketChannel` | Kênh L3 mang gói IPv4/IPv6 trần; stack bind vào đây. | [IPacketChannel.cs:6](../TqkLibrary.VpnClient.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) |

---

## Chuẩn / RFC tuân thủ

Project Sockets **không hiện thực trực tiếp** chuẩn mạng nào — nó chỉ đặt API socket-like lên trên userspace stack. Các chuẩn dưới đây được **tuân thủ gián tiếp** thông qua `TqkLibrary.VpnClient.IpStack` mà các kiểu ở đây dựa vào; cột "Vị trí" trỏ tới nơi hành vi tương ứng được dùng/hiện thực. Trong số đó, **RFC 768 / 1071 / 793 được trích dẫn trực tiếp (cited-in-code)** trong comment của IpStack (UDP, Internet checksum, và TCP — `RST (RFC 793)` + pseudo-header); **RFC 791** được cite ở đường phân mảnh/ráp (`Ipv4.Fragment` §2.3 / `Ipv4Reassembler` §3.2) còn hàm `Ipv4.Build` tối giản thì chỉ khớp hành vi. Ngoài ra `TcpConnection` còn dẫn nguồn **RFC 6298 / 5681 / 6582 / 7323 / 2018 / 6675 / 1191 / 8201** cho retransmit/RTO, NewReno, window-scaling, SACK và PMTUD.

| Chuẩn (RFC/FIPS/NIST/MS-*) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| RFC 793 — TCP (handshake, ACK, FIN, sequence number) + reliability đầy đủ | `TcpConnection` (qua `VpnTcpClient` / `VpnNetworkStream`) | [TcpConnection.cs:13](../TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs#L13) | **cited-in-code** (`... → RST (RFC 793)` tại [TcpIpStack.cs:197](../TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L197), pseudo-header checksum tại [InternetChecksum.cs:9](../TqkLibrary.VpnClient.IpStack/InternetChecksum.cs#L9)); **không** bỏ qua reliability — retransmit/RTO, flow-control + zero-window persist, NewReno, SACK, window-scaling, PMTUD, ráp out-of-order, half-close FSM đều có — xem tóm tắt [TcpConnection.cs:13-27](../TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs#L13-L27) |
| RFC 768 — UDP (datagram không trạng thái) | `UdpConnection` / `VpnUdpClient` (build ở `UdpDatagram`) | [UdpConnection.cs:12](../TqkLibrary.VpnClient.IpStack/Udp/UdpConnection.cs#L12) | **cited-in-code** tại [UdpDatagram.cs:5](../TqkLibrary.VpnClient.IpStack/UdpDatagram.cs#L5) (`... (RFC 768)`); `VpnUdpClient` thêm lọc theo remote endpoint cố định |
| RFC 791 — IPv4 (header 20 byte, không option, set DF) | `Ipv4.Build` | [Ipv4.cs:18](../TqkLibrary.VpnClient.IpStack/Ipv4.cs#L18) | header build tối giản tại `Ipv4.Build` (không cite RFC ngay đây — khớp hành vi); RFC 791 **cited-in-code** ở đường phân mảnh/ráp ([Ipv4.cs:80](../TqkLibrary.VpnClient.IpStack/Ipv4.cs#L80) §2.3 / [Ipv4Reassembler.cs:6](../TqkLibrary.VpnClient.IpStack/Ipv4Reassembler.cs#L6) §3.2); mọi gói TCP/UDP của Sockets đi qua `Ipv4.Build` |
| RFC 1071 — Internet checksum (1's-complement) | `InternetChecksum` (qua `Ipv4.Build` / `TcpSegment.Build` / `UdpDatagram.Build`) | [InternetChecksum.cs:5](../TqkLibrary.VpnClient.IpStack/InternetChecksum.cs#L5) | **cited-in-code** (`... Internet checksum (RFC 1071) ...`); hàm `Compute` ở [InternetChecksum.cs:29](../TqkLibrary.VpnClient.IpStack/InternetChecksum.cs#L29), được `Ipv4.Build` gọi tại [Ipv4.cs:36](../TqkLibrary.VpnClient.IpStack/Ipv4.cs#L36) |

> Lưu ý: bản thân thư mục `TqkLibrary.VpnClient.Sockets` không chứa từ khóa `RFC`/`FIPS`/`NIST`/`MS-` nào (đã grep). Bảng trên là ánh xạ tới project phụ thuộc IpStack để tiện tra cứu.

---

## API / cách dùng

Điểm vào chính (tất cả đều `public`):

- `IVpnSession.CreateTcpStack()` → `TcpIpStack` — bước đầu tiên, dựng stack từ session.
- `VpnTcpClient.ConnectAsync(stack, remoteAddress, remotePort, ct)` → `Task<VpnTcpClient>`; rồi `client.GetStream()` → `Stream`.
- `VpnUdpClient.Connect(stack, remoteAddress, remotePort)` → `VpnUdpClient`; rồi `Send(...)` / `await ReceiveAsync(ct)`.

### Ví dụ — HttpClient qua tunnel

```csharp
using TqkLibrary.VpnClient.Sockets;
using TqkLibrary.VpnClient.Sockets.Extensions;

// session: IVpnSession đã kết nối (từ TqkLibrary.VpnClient)
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

1. `VpnTcpClient.ConnectAsync` gọi `stack.ConnectAsync(remoteAddress, remotePort, ct)` — [VpnTcpClient.cs:16-20](VpnTcpClient.cs#L16-L20).
2. `TcpIpStack.ConnectAsync` cấp local port ephemeral, tạo `TcpConnection` (chọn source theo address-family remote), `StartConnect()` (gửi SYN) rồi chờ `connection.Connected` (handshake xong) — [TcpIpStack.cs:67-81](../TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L67-L81).
3. `GetStream()` bọc `TcpConnection` thành `VpnNetworkStream` — [VpnTcpClient.cs:23](VpnTcpClient.cs#L23).
4. Đọc/ghi qua stream: `WriteAsync`/`Write` → `TcpConnection.SendAsync` (**backpressure**: chờ cửa sổ peer khi buffer chưa-gửi đầy `SendBufferHighWaterMark`, ném `IOException` khi RST/give-up; chia theo MSS, gửi PSH|ACK), `FlushAsync` → `SendAsync(empty)` surfaces fault; `ReadAsync` → `TcpConnection.ReadAsync` — [VpnNetworkStream.cs:29-52](VpnNetworkStream.cs#L29-L52).
5. `Dispose` gọi `_connection.CloseSend()` → gửi FIN, đóng nửa gửi — [VpnNetworkStream.cs:61-65](VpnNetworkStream.cs#L61-L65).

Gói inbound đi ngược lại: `IPacketChannel.InboundIpPacket` → `TcpIpStack.OnInbound` ([:170](../TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L170)) chọn theo version nibble rồi `OnInboundV4`/`OnInboundV6` demux theo destination port → `TcpConnection.OnSegment` (không socket khớp → RST, RFC 793) — [TcpIpStack.cs:178-198](../TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L178-L198).

### UDP — connected client

1. `VpnUdpClient.Connect` gọi `stack.BindUdp()` (ephemeral port) và nhớ remote endpoint — [VpnUdpClient.cs:28-29](VpnUdpClient.cs#L28-L29).
2. `Send` → `UdpConnection.SendTo(_remoteAddress, _remotePort, data)` — [VpnUdpClient.cs:32](VpnUdpClient.cs#L32).
3. `ReceiveAsync` vòng lặp `UdpConnection.ReceiveAsync` và chỉ trả về gói khớp `(_remoteAddress, _remotePort)`, bỏ qua nguồn khác — [VpnUdpClient.cs:35-43](VpnUdpClient.cs#L35-L43).

---

## Trạng thái & ghi chú

- **Đã hiện thực:** `VpnTcpClient` + `VpnNetworkStream` (đủ để cắm `HttpClient`), `VpnUdpClient` (connected UDP, phù hợp DNS), `CreateTcpStack`. Tất cả là wrapper mỏng; mọi logic giao thức nằm ở `TqkLibrary.VpnClient.IpStack`.
- **`VpnUdpClient` không có gì đặc thù DNS** — nó là UDP client kết nối thông thường; "DNS-over-tunnel" chỉ là use-case (gửi gói DNS đã build sẵn tới `<server>:53`). Việc encode/decode bản tin DNS nằm ngoài project này.
- **Tên trong `<Description>` của .csproj ghi "VpnStream"** nhưng class thực tế là `VpnNetworkStream` ([VpnNetworkStream.cs:7](VpnNetworkStream.cs#L7)) — chỉ là khác biệt mô tả, không phải kiểu khác.
- **Giới hạn (kế thừa từ IpStack):** `TcpConnection` là active-open (chỉ client, **không** listen/accept). Stack **tin cậy đầy đủ** — retransmit/RTO (RFC 6298) + flow control + zero-window persist + out-of-order reassembly + NewReno congestion-control (RFC 5681/6582) + window scaling (RFC 7323) + SACK (RFC 2018/6675) + PMTUD (RFC 1191/8201) + half-close FSM (FINWAIT/CLOSING/TIMEWAIT/CLOSEWAIT/LASTACK) (vì peer là host thật trên internet, đoạn gateway↔host mất gói/đảo thứ tự thật) ([TcpConnection.cs:13-27](../TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs#L13-L27)); MSS suy từ link MTU (`Mtu`−40, mặc định 1360, clamp theo MSS peer + PMTUD hạ thêm khi ICMP "fragmentation needed").
- **`netstandard2.0` vs `net8.0`:** không có code rẽ nhánh theo TFM trong project này; `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`).
- **DNS resolution:** Sockets nhận `IPAddress` đã resolve sẵn; không tự phân giải tên miền — tầng gọi (entry point/ứng dụng) chịu trách nhiệm resolve (có thể tự dùng `VpnUdpClient` tới DNS server qua tunnel).

---

Tài liệu kiến trúc as-built tổng thể: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
