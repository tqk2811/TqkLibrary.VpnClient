# TqkLibrary.Vpn.IpStack

> Userspace IPv4 layer (parse/checksum/demux) + TCP + UDP chạy hoàn toàn trong tunnel, trên một `IPacketChannel`.

## Mục đích

Project này hiện thực một **TCP/IP stack thuần userspace** — không đụng tới socket của hệ điều hành, không cần TUN/TAP, không cần quyền admin. Sau khi một driver VPN (L2TP/IPsec hoặc SSTP) đã dựng xong đường hầm và lộ ra một kênh L3 (`IPacketChannel`) chở các gói IPv4 trần, stack này:

- **Đóng gói** dữ liệu ứng dụng thành segment TCP / datagram UDP rồi bọc trong gói IPv4 (kèm checksum) để bơm vào tunnel.
- **Phân giải (demux)** các gói IPv4 đi vào từ tunnel theo **local port** về đúng connection/socket userspace.
- **Chạy state machine TCP** của một client active-open: bắt tay 3 bước SYN-SENT → ESTABLISHED, truyền dữ liệu tin cậy (retransmit/RTO + flow control), ráp lại segment đến lệch thứ tự, và đóng kết nối qua half-close FSM đầy đủ.

Lý do tồn tại: VPN client của thư viện là **thuần userspace** — toàn bộ ngăn xếp giao thức (IKE/ESP, L2TP, PPP, và cả TCP/IP) đều được tự hiện thực trong tiến trình, nên một socket TCP/UDP "ảo" chạy bên trong tunnel cũng phải tự viết. IpStack chính là tầng đó. Các kiểu public ở đây ([TcpConnection.cs](Tcp/TcpConnection.cs#L25), [UdpConnection.cs](Tcp/UdpConnection.cs#L10)) là nền cho `VpnTcpClient` / `VpnUdpClient` ở project `TqkLibrary.Vpn.Sockets`.

Peer của TCP ở đây là **host thật trên internet** (định tuyến qua gateway VPN), nên đoạn gateway↔host đi internet công cộng — **mất gói / đảo thứ tự là thật**. Vì vậy đây là một stack **tin cậy**: **phía gửi** giữ retx queue + **RTO RFC 6298** (RTT SRTT/RTTVAR + ×2 backoff + give-up cap) + **sliding-window flow control** (tôn trọng cửa sổ peer) + **zero-window persist**; **phía nhận** **ráp lại out-of-order** trước khi giao in-order; **đóng kết nối** chạy **half-close FSM đầy đủ** (FinWait1/2, Closing, TimeWait, CloseWait, LastAck) + TIME-WAIT linger — xem ghi chú ở [TcpConnection.cs:12-24](Tcp/TcpConnection.cs#L12-L24), tunable qua [TcpRetransmitOptions](Tcp/TcpRetransmitOptions.cs#L14). **Không** congestion control (chỉ flow control); **gói IPv4 phân mảnh inbound được ráp lại** trước khi demux (RFC 791 §3.2) qua [Ipv4Reassembler](Ipv4Reassembler.cs#L16), và đối xứng **chiều gửi tự phân mảnh** datagram vượt MTU của link (RFC 791 §2.3) qua [Ipv4.Fragment](Ipv4.cs#L85) tại chokepoint `SendIp`. Gói inbound tới **local port không có socket** không còn drop im lặng: UDP nhận **ICMP port unreachable** (RFC 792 / RFC 1122 §3.2.2.1), TCP nhận **RST** (RFC 793).

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
├── InternetChecksum.cs          # Internet checksum one's-complement (RFC 1071), dùng chung IPv4/TCP/UDP/ICMP
├── Ipv4.cs                      # Build/parse header IPv4 tối thiểu (20 byte, không option) + accessor field phân mảnh + BuildFragment + Fragment (cắt datagram > MTU), hằng số protocol
├── Ipv4Reassembler.cs           # Ráp lại gói IPv4 phân mảnh inbound theo (src,dst,proto,id) (RFC 791 §3.2) + timeout + bound chống DoS
├── Ipv4ReassemblyOptions.cs     # Tunable cho Ipv4Reassembler (Timeout/MaxConcurrent/MaxDatagramSize); Default = mặc định RFC
├── UdpDatagram.cs               # Build/parse datagram UDP + checksum theo pseudo-header IPv4 (RFC 768)
├── Icmpv4.cs                    # Build/parse ICMP Echo Request/Reply + Destination Unreachable (RFC 792), checksum toàn message
├── PingReply.cs                 # Struct kết quả PingAsync (RTT + data + địa chỉ responder)
├── IcmpUnreachableException.cs  # Ngoại lệ PingAsync khi nhận Destination Unreachable (kèm code)
└── Tcp/
    ├── TcpSegment.cs            # Build/parse segment TCP + checksum pseudo-header, option MSS cho SYN
    ├── TcpConnection.cs         # State machine TCP active-open: handshake + send tin cậy (retx/RTO/sliding-window/persist) + out-of-order reassembly + half-close FSM
    ├── TcpRetransmitOptions.cs  # Tunable timer (RTO RFC 6298 + zero-window persist + TIME-WAIT); Default = mặc định RFC
    ├── UdpConnection.cs         # "Socket" UDP userspace bound theo local port + UdpReceiveResult
    ├── TcpIpStack.cs            # Demux gói IPv4 đi vào theo protocol→port; mở TCP / bind UDP / PingAsync + auto Echo Reply; port đóng → RST (TCP) / ICMP port-unreachable (UDP)
    └── Enums/
        ├── TcpFlags.cs          # Cờ điều khiển TCP (FIN/SYN/RST/PSH/ACK)
        └── TcpState.cs          # Trạng thái TCP cho client active-open + half-close FSM (RFC 793)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `TcpIpStack` | Bind `IPacketChannel` + địa chỉ tunnel; demux gói IPv4 inbound theo protocol→port; mở TCP / bind UDP / `PingAsync` + tự trả lời Echo Request; port không có socket → RST (TCP, RFC 793) / ICMP port-unreachable (UDP, RFC 792) | [TcpIpStack.cs:14](Tcp/TcpIpStack.cs#L14) ([SendTcpReset:193](Tcp/TcpIpStack.cs#L193), [SendPortUnreachable:229](Tcp/TcpIpStack.cs#L229)) |
| `TcpConnection` | State machine TCP active-open: handshake, cumulative ACK, đọc qua `ReadAsync`. **Tin cậy**: phía gửi retx queue + RTO (RFC 6298) + sliding-window flow control + zero-window persist; phía nhận **reassembly out-of-order**; **half-close FSM đầy đủ** (FinWait2/Closing/TimeWait) + TIME-WAIT linger; `State` public; terminal → event `Closed`; `IDisposable` (dọn timer) | [TcpConnection.cs:25](Tcp/TcpConnection.cs#L25) |
| `TcpRetransmitOptions` | Tunable timer: `InitialRto`/`MinRto`/`MaxRto`/`MaxRetransmits` (RTO RFC 6298) + `PersistMin`/`PersistMax` (zero-window) + `TimeWait`. `Default` = mặc định RFC; test dùng timer ngắn | [TcpRetransmitOptions.cs:14](Tcp/TcpRetransmitOptions.cs#L14) |
| `UdpConnection` | "Socket" UDP userspace bound 1 local port; `SendTo` / `ReceiveAsync`, không có connection state | [UdpConnection.cs:10](Tcp/UdpConnection.cs#L10) |
| `UdpReceiveResult` | Struct kết quả nhận UDP (data + địa chỉ/port nguồn) | [UdpConnection.cs:84](Tcp/UdpConnection.cs#L84) |
| `Ipv4` | Build/parse header IPv4 tối thiểu (20 byte, DF set); accessor field phân mảnh (`MoreFragments`/`FragmentOffset`/`Identification`/`TotalLength`) + `BuildFragment` (build 1 fragment) + `Fragment` (cắt 1 datagram > MTU thành nhiều fragment, RFC 791 §2.3); hằng số protocol TCP=6/UDP=17/ICMP=1 | [Ipv4.cs:6](Ipv4.cs#L6) ([BuildFragment:50](Ipv4.cs#L50), [Fragment:85](Ipv4.cs#L85)) |
| `Ipv4Reassembler` | Ráp lại gói IPv4 phân mảnh inbound theo key (src,dst,proto,id); `Offer` → gói nguyên / `null` (còn chờ) / gói đã ráp; coalesce interval, hoàn tất khi phủ kín `[0,TotalLength)`; lazy-expire quá hạn + evict oldest khi quá cap; `PendingCount` để quan sát; thread-safe | [Ipv4Reassembler.cs:16](Ipv4Reassembler.cs#L16) |
| `Ipv4ReassemblyOptions` | Tunable: `Timeout` (mặc định 15s, RFC 791 §3.2) + `MaxConcurrent` (64) + `MaxDatagramSize` (65535). `Default` = mặc định | [Ipv4ReassemblyOptions.cs:8](Ipv4ReassemblyOptions.cs#L8) |
| `Icmpv4` | Build/parse ICMP Echo Request/Reply + Destination Unreachable; checksum one's-complement trên **toàn message** (không pseudo-header) | [Icmpv4.cs:7](Icmpv4.cs#L7) |
| `PingReply` | Struct kết quả `PingAsync` (data echo + RTT + địa chỉ responder) | [PingReply.cs:6](PingReply.cs#L6) |
| `IcmpUnreachableException` | Ngoại lệ `PingAsync` khi target trả Destination Unreachable (kèm `Code`) | [IcmpUnreachableException.cs:4](IcmpUnreachableException.cs#L4) |
| `TcpSegment` | Build/parse segment TCP, checksum pseudo-header, build + đọc option MSS (`MaxSegmentSize`) và Window Scale (`WindowScale`, RFC 7323) | [TcpSegment.cs:7](Tcp/TcpSegment.cs#L7) ([MaxSegmentSize:97](Tcp/TcpSegment.cs#L97), [WindowScale:104](Tcp/TcpSegment.cs#L104)) |
| `UdpDatagram` | Build/parse datagram UDP, checksum pseudo-header IPv4 | [UdpDatagram.cs:6](UdpDatagram.cs#L6) |
| `InternetChecksum` | Internet checksum one's-complement: `Compute` + `Finish` (gập tổng 32-bit) | [InternetChecksum.cs:4](InternetChecksum.cs#L4) |
| `TcpFlags` | Enum `[Flags]` cờ điều khiển TCP | [TcpFlags.cs:5](Tcp/Enums/TcpFlags.cs#L5) |
| `TcpState` | Enum trạng thái TCP cho client active-open + half-close FSM đầy đủ (9 state) | [TcpState.cs:4](Tcp/Enums/TcpState.cs#L4) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class / Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| RFC 1071 — Computing the Internet Checksum | `InternetChecksum` | [InternetChecksum.cs:3](InternetChecksum.cs#L3) | Ghi rõ trong comment; one's-complement, gập carry; dùng chung cho IPv4/TCP/UDP. |
| RFC 768 — User Datagram Protocol | `UdpDatagram` | [UdpDatagram.cs:5](UdpDatagram.cs#L5) | Ghi rõ trong comment; checksum tính trên **pseudo-header IPv4** [UdpDatagram.cs:41-56](UdpDatagram.cs#L41-L56); checksum = 0 truyền dưới dạng `0xFFFF` [UdpDatagram.cs:21](UdpDatagram.cs#L21). |
| RFC 793 — Transmission Control Protocol | `TcpState`, `TcpConnection`, `TcpSegment`, `TcpIpStack` | [TcpState.cs:3](Tcp/Enums/TcpState.cs#L3) | Comment ghi "RFC 793, subset incl. half-close FSM"; handshake/data/FIN ở [TcpConnection.cs:233](Tcp/TcpConnection.cs#L233); window-update WL1/WL2 ở [TcpConnection.cs:447-453](Tcp/TcpConnection.cs#L447-L453); half-close FSM (FinWait1→FinWait2/Closing/TimeWait, CloseWait→LastAck) ở [AdvanceClose:359](Tcp/TcpConnection.cs#L359). **MSS option (kind 2)**: quảng bá MSS = link MTU−40 trong SYN, parse + clamp theo MSS peer ([TcpSegment.MaxSegmentSize](Tcp/TcpSegment.cs#L97); peer thiếu option → giả định 536, RFC 1122 §4.2.2.6). **Reset generation (p.36)**: segment tới local port không có connection → RST (mượn seq từ ACK, hoặc seq 0 + ACK span đã tiêu; không RST đáp RST) ở [SendTcpReset:193](Tcp/TcpIpStack.cs#L193). |
| RFC 6298 — Computing TCP's Retransmission Timer | `TcpConnection`, `TcpRetransmitOptions` | [TcpConnection.cs:426](Tcp/TcpConnection.cs#L426) | Ghi rõ trong comment; RTT estimator SRTT/RTTVAR (α=1/8, β=1/4, K=4) [UpdateRto:458](Tcp/TcpConnection.cs#L458), RTO ×2 backoff + give-up cap [OnRtoTimer:520](Tcp/TcpConnection.cs#L520). Sai khác cố ý: cho phép `MinRto` < 1s (RFC khuyến nghị 1s) để test chạy nhanh — mặc định stack vẫn 1s. |
| RFC 792 — Internet Control Message Protocol | `Icmpv4`, `TcpIpStack` | [Icmpv4.cs:3](Icmpv4.cs#L3) | Ghi rõ trong comment; Echo Request/Reply + Destination Unreachable; checksum tính trên **toàn ICMP message** (không pseudo-header) [Icmpv4.cs](Icmpv4.cs); error message quote "IP header + 8 byte payload" [Icmpv4.cs](Icmpv4.cs). **Tự sinh Destination Unreachable / Port Unreachable** (code 3) cho datagram UDP tới local port không có socket (RFC 1122 §3.2.2.1) ở [SendPortUnreachable:229](Tcp/TcpIpStack.cs#L229). |
| RFC 791 — Internet Protocol (IPv4) | `Ipv4`, `Ipv4Reassembler` | [Ipv4.cs:6](Ipv4.cs#L6) | (suy luận) Header 20 byte, version 4/IHL 5, DF set, TTL 64 [Ipv4.cs:18-42](Ipv4.cs#L18-L42); **§3.2 reassembly** gói phân mảnh inbound ở [Ipv4Reassembler.cs:16](Ipv4Reassembler.cs#L16) (comment ghi RFC; timeout 15s + bound chống DoS); **§2.3 fragmentation** chiều gửi ở [Ipv4.Fragment:85](Ipv4.cs#L85) (cắt trên ranh 8 byte, xóa DF/đặt MF), `BuildFragment` build 1 fragment ở [Ipv4.cs:50](Ipv4.cs#L50). |
| RFC 7323 — TCP Extensions for High Performance | `TcpConnection`, `TcpSegment` | [TcpSegment.cs:104](Tcp/TcpSegment.cs#L104) | **Window Scale option (kind 3)**: quảng bá shift `RcvWScale=2` trong SYN ([StartConnect:155](Tcp/TcpConnection.cs#L155)); nếu peer cũng gửi WS option (SYN-ACK), áp shift của peer vào cửa sổ peer → send window vượt 64 KB ([ProcessAck:426](Tcp/TcpConnection.cs#L426)) và mở rộng cửa sổ nhận hiệu lực (≈256 KB) cho bound OOO ([RcvWindowEffective:290](Tcp/TcpConnection.cs#L290)). **Chưa** dùng Timestamps/PAWS. |
| RFC 9293 — TCP (gộp/cập nhật RFC 793) | `TcpConnection` | [TcpConnection.cs:25](Tcp/TcpConnection.cs#L25) | (suy luận) Code dẫn nguồn theo RFC 793/6298; RFC 9293 là bản hợp nhất hiện hành (gồm zero-window persist §3.8.6.1). |

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

// ICMP: ping một host trong tunnel (đo RTT). Host được cấp IP trong tunnel cũng tự trả lời ping của người khác.
PingReply pong = await stack.PingAsync(IPAddress.Parse("10.0.0.2"), cancellationToken: ct);
Console.WriteLine($"RTT = {pong.RoundTripTime.TotalMilliseconds} ms");
```

Các điểm vào public chính:

- `TcpIpStack.ConnectAsync(IPAddress, ushort, CancellationToken)` → [TcpIpStack.cs:41](Tcp/TcpIpStack.cs#L41): cấp local port ephemeral (bắt đầu 49152), tạo `TcpConnection`, gửi SYN và chờ `Connected`.
- `TcpIpStack.BindUdp()` / `BindUdp(ushort)` → [TcpIpStack.cs:57](Tcp/TcpIpStack.cs#L57): bind socket UDP userspace.
- `TcpIpStack.PingAsync(IPAddress, ReadOnlyMemory<byte>, CancellationToken)` → [TcpIpStack.cs:72](Tcp/TcpIpStack.cs#L72): cấp sequence, gửi ICMP Echo Request, chờ Echo Reply khớp identifier/sequence → `PingReply` (RTT); nhận Destination Unreachable ⇒ ném `IcmpUnreachableException`.
- `TcpConnection.Send` / `ReadAsync` / `CloseSend` → [TcpConnection.cs:179](Tcp/TcpConnection.cs#L179), [TcpConnection.cs:194](Tcp/TcpConnection.cs#L194), [TcpConnection.cs:223](Tcp/TcpConnection.cs#L223). `Send` đệm dữ liệu rồi flush trong cửa sổ peer; `CloseSend` hoãn FIN tới khi đệm gửi cạn. `State` ([TcpConnection.cs:149](Tcp/TcpConnection.cs#L149)) phơi trạng thái FSM hiện tại để quan sát; `Closed` (event) báo connection đã terminal.
- `UdpConnection.SendTo` / `ReceiveAsync` → [UdpConnection.cs:30](Tcp/UdpConnection.cs#L30), [UdpConnection.cs:38](Tcp/UdpConnection.cs#L38).

## Luồng nội bộ

### Đường gói đi vào (demux)

1. `TcpIpStack` đăng ký handler `InboundIpPacket` của `IPacketChannel` ngay trong constructor — [TcpIpStack.cs:37](Tcp/TcpIpStack.cs#L37).
2. Mỗi gói IPv4 inbound vào `OnInbound` — [TcpIpStack.cs:112](Tcp/TcpIpStack.cs#L112): **trước tiên đưa qua `Ipv4Reassembler.Offer`** [TcpIpStack.cs:117](Tcp/TcpIpStack.cs#L117) — gói nguyên đi thẳng, fragment được buffer (return `null` ⇒ bỏ qua tới khi ráp xong); sau đó đọc protocol [Ipv4.cs:128](Ipv4.cs#L128); nếu TCP (6) lấy **destination port = local port của ta** [TcpIpStack.cs:127](Tcp/TcpIpStack.cs#L127) rồi tra `TcpConnection`; nếu UDP (17) tra `UdpConnection` theo local port [TcpIpStack.cs:137](Tcp/TcpIpStack.cs#L137); nếu ICMP (1) vào `OnIcmp` [TcpIpStack.cs:147](Tcp/TcpIpStack.cs#L147).
3. Segment được đẩy vào state machine qua `TcpConnection.OnSegment` — [TcpConnection.cs:173](Tcp/TcpConnection.cs#L173); datagram UDP qua `UdpConnection.OnDatagram` — [UdpConnection.cs:59](Tcp/UdpConnection.cs#L59).
4. **Local port không có socket** (sau lookup hụt): segment TCP → `SendTcpReset` phát **RST** về peer (RFC 793 p.36) — [TcpIpStack.cs:131](Tcp/TcpIpStack.cs#L131)/[SendTcpReset:193](Tcp/TcpIpStack.cs#L193); datagram UDP → `SendPortUnreachable` phát **ICMP Destination Unreachable / Port Unreachable** trích gói gốc (RFC 792 / RFC 1122 §3.2.2.1) — [TcpIpStack.cs:141](Tcp/TcpIpStack.cs#L141)/[SendPortUnreachable:229](Tcp/TcpIpStack.cs#L229). Cả hai chui qua `SendIp` nên cũng được phân mảnh nếu cần.

### IPv4 reassembly (RFC 791 §3.2)

`Ipv4Reassembler.Offer` — [Ipv4Reassembler.cs:38](Ipv4Reassembler.cs#L38) xử lý gói inbound **trước** demux:

- **Gói nguyên** (More-Fragments=0 và offset=0) → trả về nguyên vẹn, không đụng buffer.
- **Fragment** → buffer theo key `(src,dst,protocol,identification)`; mỗi fragment ghi payload vào staging buffer tại đúng offset rồi **coalesce** khoảng `[start,end)` đã nhận. Hoàn tất khi đã thấy fragment cuối (MF=0, biết `TotalLength`) **và** các khoảng phủ kín `[0,TotalLength)` → build lại gói nguyên qua [Ipv4.Build](Ipv4.cs#L18) (xóa cờ phân mảnh) trả về cho demux. Đến/đảo thứ tự, trùng lặp, chồng lấp đều xử lý đúng — [Partial.Add/Coalesce](Ipv4Reassembler.cs#L16).
- **Chống cạn bộ nhớ (DoS):** datagram dở quá `Timeout` (mặc định 15s) bị **lazy-expire** ở đầu mỗi `Offer`; vượt `MaxConcurrent` (mặc định 64) → **evict cái cũ nhất**; fragment khiến tổng vượt `MaxDatagramSize` (65535) bị drop. `PendingCount` phơi số datagram đang dở để quan sát/test.

### ICMP (RFC 792)

`OnIcmp` — [TcpIpStack.cs:151](Tcp/TcpIpStack.cs#L151) phân loại theo type:

- **Echo Request (8) → tự trả lời:** build Echo Reply echo lại payload + identifier/sequence rồi gửi về source — [TcpIpStack.cs:156-162](Tcp/TcpIpStack.cs#L156-L162). Host được cấp IP trong tunnel vì thế đáp ping của bên khác.
- **Echo Reply (0) → khớp ping đang chờ:** chỉ nhận nếu `identifier == _pingIdentifier` (per-stack, random), tra `_pings` theo sequence rồi complete `PingReply` — [TcpIpStack.cs:164-169](Tcp/TcpIpStack.cs#L164-L169).
- **Destination Unreachable (3) → fail ping:** trích datagram bị quote (IP header + 8 byte = Echo Request đã gửi), đọc identifier/sequence để định danh ping rồi ném `IcmpUnreachableException(code)` — [TcpIpStack.cs:171-184](Tcp/TcpIpStack.cs#L171-L184).
- **`PingAsync`** — [TcpIpStack.cs:72](Tcp/TcpIpStack.cs#L72): cấp sequence bằng vòng `Interlocked` + `TryAdd` (sequence còn ping pending bị bỏ qua thay vì ghi đè waiter — an toàn khi đếm wrap qua 65536), build Echo Request + đo `Stopwatch`, gửi rồi `await` (hủy qua `CancellationToken`); `finally` gỡ entry khỏi `_pings`.
- **Tự sinh Port Unreachable (chiều ngược):** datagram UDP inbound tới local port không có socket được `SendPortUnreachable` đáp lại bằng Destination Unreachable / Port Unreachable (code 3) trích gói gốc — [SendPortUnreachable:229](Tcp/TcpIpStack.cs#L229).

### TCP state machine (active-open)

- **Khởi tạo handshake:** `StartConnect` sinh ISS ngẫu nhiên (`RandomNumberGenerator`), gửi SYN kèm option **MSS suy từ link MTU** (`IPacketChannel.Mtu`−40, mặc định 1360) **+ Window Scale** (shift `RcvWScale=2`, RFC 7323), đưa SYN vào retx queue rồi chuyển `SynSent` — [TcpConnection.cs:155](Tcp/TcpConnection.cs#L155).
- **SYN-SENT → ESTABLISHED:** nhận SYN+ACK ⇒ `_rcvNxt = seq+1`, **clamp MSS gửi = min(MSS ta, MSS peer quảng bá)** (peer không gửi option → giả định 536, RFC 1122), `ProcessAck` (gỡ SYN khỏi retx, lấy mẫu RTT, **seed cửa sổ gửi** `_sndWnd` — **chưa scale** vì cửa sổ SYN-ACK không scale), nếu peer cũng gửi **Window Scale** option thì bật scaling (`_sndWScale`/`_rcvScaleActive`) cho các segment sau, gửi ACK, complete `Connected` rồi flush dữ liệu đã đệm — [TcpConnection.cs:252-269](Tcp/TcpConnection.cs#L252-L269).
- **Nhận dữ liệu (reassembly):** `ReceiveData` giao ngay nếu `seq == _rcvNxt`, ngược lại **buffer out-of-order** (trong cửa sổ, dedupe) và `DrainOoo` ráp lại khi lấp đầy khoảng trống (drop wholly-old); luôn phát cumulative/dup ACK — [ReceiveData:293](Tcp/TcpConnection.cs#L293)/[DrainOoo:314](Tcp/TcpConnection.cs#L314).
- **Gửi dữ liệu (tin cậy):** `Send` đệm bytes; `TrySendData` chỉ phát trong cửa sổ khả dụng `_sndUna+_sndWnd−_sndNxt`, cắt theo MSS, mỗi chunk PSH|ACK đưa vào retx queue — [TcpConnection.cs:402](Tcp/TcpConnection.cs#L402). `ProcessAck` đẩy `_sndUna`, gỡ unit đã ACK, cập nhật RTT (Karn: bỏ mẫu của segment đã retransmit) + cửa sổ (WL1/WL2) — [TcpConnection.cs:426](Tcp/TcpConnection.cs#L426).
- **Retransmit/RTO (RFC 6298):** unit cũ nhất chưa ACK quá hạn `_rtoMs` ⇒ phát lại + ×2 backoff; quá `MaxRetransmits` ⇒ `Fail` — [TcpConnection.cs:520](Tcp/TcpConnection.cs#L520). RTO suy từ SRTT/RTTVAR — [UpdateRto:458](Tcp/TcpConnection.cs#L458).
- **Zero-window persist:** cửa sổ peer = 0 mà còn dữ liệu ⇒ persist timer dò **1 byte** (chỉ khi không có gì in-flight; RTO lo retransmit byte dò) tới khi cửa sổ mở lại — [TcpConnection.cs:574](Tcp/TcpConnection.cs#L574).
- **Half-close FSM:** peer FIN được ghi nhận rồi **chỉ tiêu thụ khi `_rcvNxt` chạm tới** (sau reassembly) ⇒ `ReadAsync` trả 0 — [NoteFin:339](Tcp/TcpConnection.cs#L339)/[TryConsumePeerFin:347](Tcp/TcpConnection.cs#L347). `AdvanceClose` lái trạng thái: FinWait1→**FinWait2** (FIN ta được ACK) / **Closing** (đóng đồng thời) / **TimeWait** (FIN+ACK 1 segment); FinWait2·Closing→TimeWait; CloseWait→LastAck; LastAck→CLOSED — [AdvanceClose:359](Tcp/TcpConnection.cs#L359). Chủ động đóng qua `CloseSend` (Established→FinWait1, CloseWait→LastAck), **FIN hoãn** tới khi đệm gửi cạn — [CloseSend:223](Tcp/TcpConnection.cs#L223).
- **TIME-WAIT linger:** vào TimeWait arm `_closeTimer` (mặc định 2s, tunable); retransmitted FIN của peer được re-ACK + reset linger; hết linger → CLOSED — [EnterTimeWait:383](Tcp/TcpConnection.cs#L383)/[OnCloseTimer:391](Tcp/TcpConnection.cs#L391).
- **Terminal:** graceful CLOSED, RST, hoặc hết retry đều qua **một đường** `Terminate`: dừng mọi timer, fault `Connected` (nếu lỗi) + kết thúc đọc, raise event `Closed` (stack gỡ + dispose) — [RST:246](Tcp/TcpConnection.cs#L246), [Terminate:627](Tcp/TcpConnection.cs#L627). `Dispose` gọi trực tiếp khi kết nối còn sống cũng **abort an toàn**: pending `ReadAsync` nhận end-of-stream, pending connect fault `ObjectDisposedException`, rồi mới nhả timer — [Dispose:648](Tcp/TcpConnection.cs#L648).
- So sánh số thứ tự dùng số học modulo (`SeqGreater`/`SeqGeq`) để an toàn với wrap-around — [TcpConnection.cs:660](Tcp/TcpConnection.cs#L660).

### Đóng gói đi ra

`EmitSegment(seq, flags, payload)` → build TCP segment tại seq cho trước [TcpSegment.cs:10](Tcp/TcpSegment.cs#L10) → bọc IPv4 [Ipv4.cs:18](Ipv4.cs#L18) → đẩy qua `IPacketChannel.WriteIpPacketAsync` (`SendIp`) — [TcpConnection.cs:493](Tcp/TcpConnection.cs#L493), [TcpIpStack.cs:98](Tcp/TcpIpStack.cs#L98). Data/SYN/FIN còn được đưa vào retx queue (`EnqueueRetx`) để retransmit theo seq đã lưu. Checksum TCP/UDP tính trên pseudo-header IPv4 (src/dst/protocol/length) — [TcpSegment.cs:39-55](Tcp/TcpSegment.cs#L39-L55), [UdpDatagram.cs:41-56](UdpDatagram.cs#L41-L56). ICMP build qua [Icmpv4.cs:7](Icmpv4.cs#L7) (checksum trên toàn message, không pseudo-header) rồi cũng bọc IPv4 + `SendIp`.

`SendIp` — [TcpIpStack.cs:98](Tcp/TcpIpStack.cs#L98) là **chokepoint egress duy nhất**: gói ≤ `IPacketChannel.Mtu` đi thẳng; gói lớn hơn (datagram UDP/ICMP to) được **phân mảnh** qua [Ipv4.Fragment](Ipv4.cs#L85) thành nhiều fragment ≤ MTU (RFC 791 §2.3) thay vì gửi nguyên với DF rồi bị drop. Segment TCP luôn ≤ MSS (= link MTU − 40, mặc định 1360) nên không bao giờ chạm đường này — đối xứng với việc ráp lại fragment **inbound** ở `OnInbound`. RST (port TCP đóng) và ICMP port-unreachable (port UDP đóng) cũng phát qua đây.

## Trạng thái & ghi chú

- **Đã hiện thực:** IPv4 build/parse (không option, DF set) + **ráp lại gói IPv4 phân mảnh inbound** (RFC 791 §3.2, [Ipv4Reassembler](Ipv4Reassembler.cs#L16)) + **phân mảnh chiều gửi** datagram > MTU (RFC 791 §2.3, [Ipv4.Fragment](Ipv4.cs#L85) tại chokepoint `SendIp`); TCP client active-open **tin cậy đầy đủ** — handshake/RST + **đàm phán MSS** (suy từ link MTU, clamp theo MSS peer quảng bá) + **window scaling (RFC 7323)** (SYN mang WS option; khi peer cũng gửi → send window vượt 64 KB + cửa sổ nhận hiệu lực ≈256 KB); **phía gửi** retx queue + RTO (RFC 6298, RTT SRTT/RTTVAR + ×2 backoff + give-up cap) + sliding-window flow control (tôn trọng cửa sổ peer, WL1/WL2) + zero-window persist; **phía nhận** out-of-order reassembly; **half-close FSM đầy đủ** (FinWait1/2, Closing, TimeWait, CloseWait, LastAck) + TIME-WAIT linger; terminal → event `Closed`; UDP send/receive theo local port; **ICMP echo/ping (`PingAsync` + tự trả lời Echo Request) + Destination Unreachable (RFC 792)**; **tự sinh phản hồi cho port đóng** — RST cho TCP (RFC 793) + ICMP port-unreachable cho UDP (RFC 1122 §3.2.2.1) tới local port không có socket; checksum IPv4/TCP/UDP (pseudo-header) + ICMP (toàn message). Demux inbound theo protocol→destination port (sau reassembly).
- **Cố tình lược bỏ:** **không** SACK, **không** congestion control (cwnd/slow-start/fast-retransmit — chỉ flow control + window scaling), không Nagle, không Timestamps/PAWS. **Phân mảnh chiều gửi đã có** ([Ipv4.Fragment](Ipv4.cs#L85), cắt theo `IPacketChannel.Mtu`) + **MSS TCP nay suy từ link MTU** (`Mtu`−40) và **clamp theo MSS peer** quảng bá, **nhưng chưa Path-MTU-Discovery** — MTU lấy thẳng từ link, chưa dò DF/ICMP fragmentation-needed để hạ path-MTU dưới link (và chưa re-segment retx queue đang in-flight). Lưu ý phân biệt 2 loại reassembly: **gói IPv4 phân mảnh** ([Ipv4Reassembler](Ipv4Reassembler.cs#L16)) vs **segment TCP out-of-order** ([TcpConnection.DrainOoo](Tcp/TcpConnection.cs#L314)). Stack tin cậy chỉ cần vì peer là host thật trên internet — xem [TcpConnection.cs:12-24](Tcp/TcpConnection.cs#L12-L24).
- **Phạm vi giao thức:** chỉ **IPv4/ICMPv4** (dù `IPacketChannel` mô tả là IPv4/IPv6); chưa có IPv6/ICMPv6. ICMP nay **đã có handler** trong `OnInbound`/`OnIcmp` (echo + destination-unreachable). Gói tới **local port không có socket** nay **tự sinh phản hồi**: TCP → RST (RFC 793 p.36, [SendTcpReset:193](Tcp/TcpIpStack.cs#L193)), UDP → ICMP port-unreachable (RFC 1122 §3.2.2.1, [SendPortUnreachable:229](Tcp/TcpIpStack.cs#L229)); không còn drop im lặng. Lưu ý: TCP dùng **RST** (chuẩn host theo RFC 1122 §4.2.3.x) chứ không phải ICMP port-unreachable.
- **TCP chỉ active-open (client):** không có trạng thái `Listen`/passive-open; enum `TcpState` gồm đủ FSM cho client + half-close — [TcpState.cs:4-13](Tcp/Enums/TcpState.cs#L4-L13). Half-close đầy đủ: `FINWAIT2`/`CLOSING`/`TIME-WAIT` đã có (xem [AdvanceClose:359](Tcp/TcpConnection.cs#L359)).
- **MSS suy từ link MTU (`Mtu`−40, mặc định 1360, clamp theo MSS peer); receive window field 65535, scale ×4 khi WS negotiated (hiệu lực ≈256 KB)** — [TcpConnection.cs:27-31](Tcp/TcpConnection.cs#L27-L31); window **ta quảng bá** tĩnh (không phản ánh buffer thực, nhưng buffer reassembly bị chặn ≤ cửa sổ nhận hiệu lực), còn **cửa sổ peer** được tôn trọng (và scale theo WS của peer) ở chiều gửi. Thời gian RTO/persist/TIME-WAIT tunable qua [TcpRetransmitOptions](Tcp/TcpRetransmitOptions.cs#L14).
- **netstandard2.0 vs net8.0:** không khác biệt API/hành vi đáng kể trong project này; tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`) theo quy ước chung của solution. `UdpReceiveResult`/`Datagram` dùng `readonly struct` thay vì record.

Tham chiếu chéo tài liệu as-built toàn cục: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
