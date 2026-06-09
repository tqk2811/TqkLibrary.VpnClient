# TqkLibrary.Vpn.IpStack

> Userspace IPv4 layer (parse/checksum/demux) + TCP + UDP chạy hoàn toàn trong tunnel, trên một `IPacketChannel`.

## Mục đích

Project này hiện thực một **TCP/IP stack thuần userspace** — không đụng tới socket của hệ điều hành, không cần TUN/TAP, không cần quyền admin. Sau khi một driver VPN (L2TP/IPsec hoặc SSTP) đã dựng xong đường hầm và lộ ra một kênh L3 (`IPacketChannel`) chở các gói IPv4 trần, stack này:

- **Đóng gói** dữ liệu ứng dụng thành segment TCP / datagram UDP rồi bọc trong gói IPv4 (kèm checksum) để bơm vào tunnel.
- **Phân giải (demux)** các gói IPv4 đi vào từ tunnel theo **local port** về đúng connection/socket userspace.
- **Chạy state machine TCP** của một client active-open: bắt tay 3 bước SYN-SENT → ESTABLISHED, truyền dữ liệu in-order với cumulative ACK, đóng kết nối bằng FIN.

Lý do tồn tại: VPN client của thư viện là **thuần userspace** — toàn bộ ngăn xếp giao thức (IKE/ESP, L2TP, PPP, và cả TCP/IP) đều được tự hiện thực trong tiến trình, nên một socket TCP/UDP "ảo" chạy bên trong tunnel cũng phải tự viết. IpStack chính là tầng đó. Các kiểu public ở đây ([TcpConnection.cs](Tcp/TcpConnection.cs#L13), [UdpConnection.cs](Tcp/UdpConnection.cs#L10)) là nền cho `VpnTcpClient` / `VpnUdpClient` ở project `TqkLibrary.Vpn.Sockets`.

Vì lớp dưới (tunnel L2TP/SSTP + IPsec) đã là một **byte stream tin cậy, đúng thứ tự**, nên TCP ở đây cố tình **lược bỏ retransmission / SACK / cửa sổ trượt động** — xem ghi chú ở [TcpConnection.cs:8-12](Tcp/TcpConnection.cs#L8-L12).

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (`TqkLibrary.Vpn.IpStack` — IPv4 / TCP / UDP userspace).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ `src/Directory.Build.props`).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.Vpn.Abstractions.csproj](../TqkLibrary.Vpn.Abstractions/TqkLibrary.Vpn.Abstractions.csproj) — chỉ dùng [IPacketChannel.cs:6](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) làm kênh L3 vào/ra.
  - Không có PackageReference đặc thù.
- **Được dùng bởi:** `TqkLibrary.Vpn.Sockets` (lắp `VpnTcpClient` / `VpnUdpClient` / `VpnNetworkStream` trên các kiểu của project này).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.IpStack/
├── InternetChecksum.cs      # Internet checksum one's-complement (RFC 1071), dùng chung IPv4/TCP/UDP/ICMP
├── Ipv4.cs                  # Build/parse header IPv4 tối thiểu (20 byte, không option), hằng số protocol
├── UdpDatagram.cs           # Build/parse datagram UDP + checksum theo pseudo-header IPv4 (RFC 768)
└── Tcp/
    ├── TcpSegment.cs        # Build/parse segment TCP + checksum pseudo-header, option MSS cho SYN
    ├── TcpConnection.cs     # State machine TCP active-open (handshake/data/ACK/FIN) + buffer nhận
    ├── UdpConnection.cs     # "Socket" UDP userspace bound theo local port + UdpReceiveResult
    ├── TcpIpStack.cs        # Demux gói IPv4 đi vào theo local port; mở TCP / bind UDP
    └── Enums/
        ├── TcpFlags.cs      # Cờ điều khiển TCP (FIN/SYN/RST/PSH/ACK)
        └── TcpState.cs      # Tập con trạng thái TCP cho client (RFC 793)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `TcpIpStack` | Bind `IPacketChannel` + địa chỉ tunnel; demux gói IPv4 inbound theo local port; mở TCP / bind UDP | [TcpIpStack.cs:11](Tcp/TcpIpStack.cs#L11) |
| `TcpConnection` | State machine TCP active-open: handshake, data in-order, cumulative ACK, FIN; đọc qua `ReadAsync` | [TcpConnection.cs:13](Tcp/TcpConnection.cs#L13) |
| `UdpConnection` | "Socket" UDP userspace bound 1 local port; `SendTo` / `ReceiveAsync`, không có connection state | [UdpConnection.cs:10](Tcp/UdpConnection.cs#L10) |
| `UdpReceiveResult` | Struct kết quả nhận UDP (data + địa chỉ/port nguồn) | [UdpConnection.cs:84](Tcp/UdpConnection.cs#L84) |
| `Ipv4` | Build/parse header IPv4 tối thiểu (20 byte, DF set); hằng số protocol TCP=6/UDP=17/ICMP=1 | [Ipv4.cs:6](Ipv4.cs#L6) |
| `TcpSegment` | Build/parse segment TCP, checksum pseudo-header, option MSS | [TcpSegment.cs:7](Tcp/TcpSegment.cs#L7) |
| `UdpDatagram` | Build/parse datagram UDP, checksum pseudo-header IPv4 | [UdpDatagram.cs:6](UdpDatagram.cs#L6) |
| `InternetChecksum` | Internet checksum one's-complement: `Compute` + `Finish` (gập tổng 32-bit) | [InternetChecksum.cs:4](InternetChecksum.cs#L4) |
| `TcpFlags` | Enum `[Flags]` cờ điều khiển TCP | [TcpFlags.cs:5](Tcp/Enums/TcpFlags.cs#L5) |
| `TcpState` | Enum trạng thái TCP (tập con cho client active-open) | [TcpState.cs:4](Tcp/Enums/TcpState.cs#L4) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class / Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| RFC 1071 — Computing the Internet Checksum | `InternetChecksum` | [InternetChecksum.cs:3](InternetChecksum.cs#L3) | Ghi rõ trong comment; one's-complement, gập carry; dùng chung cho IPv4/TCP/UDP. |
| RFC 768 — User Datagram Protocol | `UdpDatagram` | [UdpDatagram.cs:5](UdpDatagram.cs#L5) | Ghi rõ trong comment; checksum tính trên **pseudo-header IPv4** [UdpDatagram.cs:41-56](UdpDatagram.cs#L41-L56); checksum = 0 truyền dưới dạng `0xFFFF` [UdpDatagram.cs:21](UdpDatagram.cs#L21). |
| RFC 793 — Transmission Control Protocol | `TcpState`, `TcpConnection`, `TcpSegment` | [TcpState.cs:3](Tcp/Enums/TcpState.cs#L3) | Comment ghi "RFC 793, subset"; chỉ hiện thực tập con state cho client active-open; handshake/ACK/FIN ở [TcpConnection.cs:144](Tcp/TcpConnection.cs#L144). |
| RFC 791 — Internet Protocol (IPv4) | `Ipv4` | [Ipv4.cs:6](Ipv4.cs#L6) | (suy luận) Không ghi RFC trong comment; header 20 byte, version 4/IHL 5, DF set, TTL 64 [Ipv4.cs:18-42](Ipv4.cs#L18-L42). |
| RFC 9293 — TCP (gộp/cập nhật RFC 793) | `TcpConnection` | [TcpConnection.cs:13](Tcp/TcpConnection.cs#L13) | (suy luận) Code dẫn nguồn theo RFC 793; RFC 9293 chỉ là bản hợp nhất hiện hành của cùng giao thức. |

Lưu ý: project **không** dùng FIPS/NIST/MS-* (đó là phạm vi của các tầng CRYPTO/Ipsec/Ppp). Toàn bộ checksum ở đây là số học one's-complement thuần, không phải hàm băm mật mã.

## API / cách dùng

Điểm vào là `TcpIpStack` — bọc một `IPacketChannel` (do driver VPN cung cấp) và địa chỉ IP cấp cho client trong tunnel:

```csharp
// channel: IPacketChannel từ driver (L2TP/IPsec hoặc SSTP); localAddress: IP được cấp trong tunnel
var stack = new TcpIpStack(channel, localAddress);

// Mở 1 TCP connection (chờ xong handshake 3 bước)
TcpConnection tcp = await stack.ConnectAsync(IPAddress.Parse("1.1.1.1"), 80, ct);
tcp.Send(requestBytes);
int n = await tcp.ReadAsync(buffer, 0, buffer.Length, ct); // 0 = end of stream
tcp.CloseSend(); // gửi FIN

// UDP: bind 1 local port ephemeral rồi gửi/nhận datagram
UdpConnection udp = stack.BindUdp();
udp.SendTo(IPAddress.Parse("8.8.8.8"), 53, dnsQuery);
UdpReceiveResult res = await udp.ReceiveAsync(ct);
```

Các điểm vào public chính:

- `TcpIpStack.ConnectAsync(IPAddress, ushort, CancellationToken)` → [TcpIpStack.cs:28](Tcp/TcpIpStack.cs#L28): cấp local port ephemeral (bắt đầu 49152), tạo `TcpConnection`, gửi SYN và chờ `Connected`.
- `TcpIpStack.BindUdp()` / `BindUdp(ushort)` → [TcpIpStack.cs:43](Tcp/TcpIpStack.cs#L43): bind socket UDP userspace.
- `TcpConnection.Send` / `ReadAsync` / `CloseSend` → [TcpConnection.cs:80](Tcp/TcpConnection.cs#L80), [TcpConnection.cs:96](Tcp/TcpConnection.cs#L96), [TcpConnection.cs:125](Tcp/TcpConnection.cs#L125).
- `UdpConnection.SendTo` / `ReceiveAsync` → [UdpConnection.cs:30](Tcp/UdpConnection.cs#L30), [UdpConnection.cs:38](Tcp/UdpConnection.cs#L38).

## Luồng nội bộ

### Đường gói đi vào (demux)

1. `TcpIpStack` đăng ký handler `InboundIpPacket` của `IPacketChannel` ngay trong constructor — [TcpIpStack.cs:24](Tcp/TcpIpStack.cs#L24).
2. Mỗi gói IPv4 inbound vào `OnInbound` — [TcpIpStack.cs:55](Tcp/TcpIpStack.cs#L55): đọc protocol [Ipv4.cs:48](Ipv4.cs#L48); nếu TCP (6) lấy **destination port = local port của ta** [TcpIpStack.cs:65](Tcp/TcpIpStack.cs#L65) rồi tra `TcpConnection`; nếu UDP (17) tra `UdpConnection` theo local port [TcpIpStack.cs:73](Tcp/TcpIpStack.cs#L73).
3. Segment được đẩy vào state machine qua `TcpConnection.OnSegment` — [TcpConnection.cs:74](Tcp/TcpConnection.cs#L74); datagram UDP qua `UdpConnection.OnDatagram` — [UdpConnection.cs:59](Tcp/UdpConnection.cs#L59).

### TCP state machine (active-open)

- **Khởi tạo handshake:** `StartConnect` sinh ISS ngẫu nhiên (`RandomNumberGenerator`), gửi SYN kèm option MSS=1360, chuyển sang `SynSent` — [TcpConnection.cs:58](Tcp/TcpConnection.cs#L58).
- **SYN-SENT → ESTABLISHED:** nhận SYN+ACK ⇒ đặt `_rcvNxt = seq+1`, gửi ACK, complete `Connected` — [TcpConnection.cs:161-169](Tcp/TcpConnection.cs#L161-L169).
- **Truyền dữ liệu:** payload đúng `_rcvNxt` được đẩy vào hàng đợi nhận và phát cumulative ACK — [TcpConnection.cs:177-185](Tcp/TcpConnection.cs#L177-L185); chiều gửi cắt theo MSS, mỗi chunk 1 segment PSH|ACK — [TcpConnection.cs:80-93](Tcp/TcpConnection.cs#L80-L93).
- **Đóng kết nối:** nhận FIN ⇒ +1 `_rcvNxt`, ACK, kết thúc luồng đọc (`ReadAsync` trả 0), chuyển `CloseWait`/`LastAck` — [TcpConnection.cs:187-193](Tcp/TcpConnection.cs#L187-L193); chủ động gửi FIN qua `CloseSend` (`Established → FinWait1`, `CloseWait → LastAck`) — [TcpConnection.cs:125-142](Tcp/TcpConnection.cs#L125-L142).
- **RST:** bất kỳ lúc nào nhận RST ⇒ `Fail`, fault `Connected` + kết thúc đọc với lỗi — [TcpConnection.cs:153-157](Tcp/TcpConnection.cs#L153-L157), [TcpConnection.cs:232](Tcp/TcpConnection.cs#L232).
- So sánh số thứ tự dùng số học modulo (`SeqGreater`) để an toàn với wrap-around — [TcpConnection.cs:238](Tcp/TcpConnection.cs#L238).

### Đóng gói đi ra

`SendSegment` → build TCP segment [TcpSegment.cs:10](Tcp/TcpSegment.cs#L10) → bọc IPv4 [Ipv4.cs:18](Ipv4.cs#L18) → đẩy qua `IPacketChannel.WriteIpPacketAsync` (`SendIp`) — [TcpConnection.cs:225-230](Tcp/TcpConnection.cs#L225-L230), [TcpIpStack.cs:53](Tcp/TcpIpStack.cs#L53). Checksum TCP/UDP tính trên pseudo-header IPv4 (src/dst/protocol/length) — [TcpSegment.cs:39-55](Tcp/TcpSegment.cs#L39-L55), [UdpDatagram.cs:41-56](UdpDatagram.cs#L41-L56).

## Trạng thái & ghi chú

- **Đã hiện thực:** IPv4 build/parse (không option, DF set); TCP client active-open đầy đủ handshake/data/ACK/FIN/RST; UDP send/receive theo local port; checksum IPv4/TCP/UDP (pseudo-header). Demux inbound theo destination port.
- **Cố tình lược bỏ:** retransmission, SACK, cửa sổ trượt động, slow-start/congestion control, Nagle, ráp lại phân mảnh IP. Hợp lệ vì tunnel bên dưới đã tin cậy & đúng thứ tự — xem [TcpConnection.cs:8-12](Tcp/TcpConnection.cs#L8-L12). Dữ liệu TCP đến **không đúng** `_rcvNxt` (out-of-order) bị **bỏ qua** (không buffer reorder) — [TcpConnection.cs:179](Tcp/TcpConnection.cs#L179).
- **Phạm vi giao thức:** chỉ **IPv4** (dù `IPacketChannel` mô tả là IPv4/IPv6); ICMP được nhắc trong `Ipv4.ProtocolIcmp`/comment `InternetChecksum` nhưng **chưa có handler** trong `OnInbound`.
- **TCP chỉ active-open (client):** không có trạng thái `Listen`/passive-open; enum `TcpState` cố ý chỉ gồm tập con cho client — [TcpState.cs:4-12](Tcp/Enums/TcpState.cs#L4-L12). Cũng không có `TIME-WAIT`/`CLOSING` đầy đủ.
- **MSS cố định 1360, receive window cố định 65535** — [TcpConnection.cs:15-16](Tcp/TcpConnection.cs#L15-L16); window quảng bá tĩnh, không phản ánh buffer thực.
- **netstandard2.0 vs net8.0:** không khác biệt API/hành vi đáng kể trong project này; tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`) theo quy ước chung của solution. `UdpReceiveResult`/`Datagram` dùng `readonly struct` thay vì record.

Tham chiếu chéo tài liệu as-built toàn cục: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
