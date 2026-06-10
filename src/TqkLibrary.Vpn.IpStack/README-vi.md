# TqkLibrary.Vpn.IpStack

> Userspace IPv4 layer (parse/checksum/demux) + TCP + UDP chạy hoàn toàn trong tunnel, trên một `IPacketChannel`.

## Mục đích

Project này hiện thực một **TCP/IP stack thuần userspace** — không đụng tới socket của hệ điều hành, không cần TUN/TAP, không cần quyền admin. Sau khi một driver VPN (L2TP/IPsec hoặc SSTP) đã dựng xong đường hầm và lộ ra một kênh L3 (`IPacketChannel`) chở các gói IPv4 trần, stack này:

- **Đóng gói** dữ liệu ứng dụng thành segment TCP / datagram UDP rồi bọc trong gói IPv4 (kèm checksum) để bơm vào tunnel.
- **Phân giải (demux)** các gói IPv4 đi vào từ tunnel theo **local port** về đúng connection/socket userspace.
- **Chạy state machine TCP** của một client active-open: bắt tay 3 bước SYN-SENT → ESTABLISHED, truyền dữ liệu tin cậy (retransmit/RTO + flow control), ráp lại segment đến lệch thứ tự, và đóng kết nối qua half-close FSM đầy đủ.

Lý do tồn tại: VPN client của thư viện là **thuần userspace** — toàn bộ ngăn xếp giao thức (IKE/ESP, L2TP, PPP, và cả TCP/IP) đều được tự hiện thực trong tiến trình, nên một socket TCP/UDP "ảo" chạy bên trong tunnel cũng phải tự viết. IpStack chính là tầng đó. Các kiểu public ở đây ([TcpConnection.cs](Tcp/TcpConnection.cs#L25), [UdpConnection.cs](Tcp/UdpConnection.cs#L10)) là nền cho `VpnTcpClient` / `VpnUdpClient` ở project `TqkLibrary.Vpn.Sockets`.

Peer của TCP ở đây là **host thật trên internet** (định tuyến qua gateway VPN), nên đoạn gateway↔host đi internet công cộng — **mất gói / đảo thứ tự là thật**. Vì vậy đây là một stack **tin cậy**: **phía gửi** giữ retx queue + **RTO RFC 6298** (RTT SRTT/RTTVAR + ×2 backoff + give-up cap) + **sliding-window flow control** (tôn trọng cửa sổ peer) + **zero-window persist**; **phía nhận** **ráp lại out-of-order** trước khi giao in-order; **đóng kết nối** chạy **half-close FSM đầy đủ** (FinWait1/2, Closing, TimeWait, CloseWait, LastAck) + TIME-WAIT linger — xem ghi chú ở [TcpConnection.cs:12-24](Tcp/TcpConnection.cs#L12-L24), tunable qua [TcpRetransmitOptions](Tcp/TcpRetransmitOptions.cs#L14). **Không** congestion control (chỉ flow control); IP fragment coi như đã được tầng IP ráp sẵn.

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
├── Ipv4.cs                      # Build/parse header IPv4 tối thiểu (20 byte, không option), hằng số protocol
├── UdpDatagram.cs               # Build/parse datagram UDP + checksum theo pseudo-header IPv4 (RFC 768)
├── Icmpv4.cs                    # Build/parse ICMP Echo Request/Reply + Destination Unreachable (RFC 792), checksum toàn message
├── PingReply.cs                 # Struct kết quả PingAsync (RTT + data + địa chỉ responder)
├── IcmpUnreachableException.cs  # Ngoại lệ PingAsync khi nhận Destination Unreachable (kèm code)
└── Tcp/
    ├── TcpSegment.cs            # Build/parse segment TCP + checksum pseudo-header, option MSS cho SYN
    ├── TcpConnection.cs         # State machine TCP active-open: handshake + send tin cậy (retx/RTO/sliding-window/persist) + out-of-order reassembly + half-close FSM
    ├── TcpRetransmitOptions.cs  # Tunable timer (RTO RFC 6298 + zero-window persist + TIME-WAIT); Default = mặc định RFC
    ├── UdpConnection.cs         # "Socket" UDP userspace bound theo local port + UdpReceiveResult
    ├── TcpIpStack.cs            # Demux gói IPv4 đi vào theo protocol→port; mở TCP / bind UDP / PingAsync + auto Echo Reply
    └── Enums/
        ├── TcpFlags.cs          # Cờ điều khiển TCP (FIN/SYN/RST/PSH/ACK)
        └── TcpState.cs          # Trạng thái TCP cho client active-open + half-close FSM (RFC 793)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `TcpIpStack` | Bind `IPacketChannel` + địa chỉ tunnel; demux gói IPv4 inbound theo protocol→port; mở TCP / bind UDP / `PingAsync` + tự trả lời Echo Request | [TcpIpStack.cs:13](Tcp/TcpIpStack.cs#L13) |
| `TcpConnection` | State machine TCP active-open: handshake, cumulative ACK, đọc qua `ReadAsync`. **Tin cậy**: phía gửi retx queue + RTO (RFC 6298) + sliding-window flow control + zero-window persist; phía nhận **reassembly out-of-order**; **half-close FSM đầy đủ** (FinWait2/Closing/TimeWait) + TIME-WAIT linger; `State` public; terminal → event `Closed`; `IDisposable` (dọn timer) | [TcpConnection.cs:25](Tcp/TcpConnection.cs#L25) |
| `TcpRetransmitOptions` | Tunable timer: `InitialRto`/`MinRto`/`MaxRto`/`MaxRetransmits` (RTO RFC 6298) + `PersistMin`/`PersistMax` (zero-window) + `TimeWait`. `Default` = mặc định RFC; test dùng timer ngắn | [TcpRetransmitOptions.cs:14](Tcp/TcpRetransmitOptions.cs#L14) |
| `UdpConnection` | "Socket" UDP userspace bound 1 local port; `SendTo` / `ReceiveAsync`, không có connection state | [UdpConnection.cs:10](Tcp/UdpConnection.cs#L10) |
| `UdpReceiveResult` | Struct kết quả nhận UDP (data + địa chỉ/port nguồn) | [UdpConnection.cs:84](Tcp/UdpConnection.cs#L84) |
| `Ipv4` | Build/parse header IPv4 tối thiểu (20 byte, DF set); hằng số protocol TCP=6/UDP=17/ICMP=1 | [Ipv4.cs:6](Ipv4.cs#L6) |
| `Icmpv4` | Build/parse ICMP Echo Request/Reply + Destination Unreachable; checksum one's-complement trên **toàn message** (không pseudo-header) | [Icmpv4.cs:7](Icmpv4.cs#L7) |
| `PingReply` | Struct kết quả `PingAsync` (data echo + RTT + địa chỉ responder) | [PingReply.cs:6](PingReply.cs#L6) |
| `IcmpUnreachableException` | Ngoại lệ `PingAsync` khi target trả Destination Unreachable (kèm `Code`) | [IcmpUnreachableException.cs:4](IcmpUnreachableException.cs#L4) |
| `TcpSegment` | Build/parse segment TCP, checksum pseudo-header, option MSS | [TcpSegment.cs:7](Tcp/TcpSegment.cs#L7) |
| `UdpDatagram` | Build/parse datagram UDP, checksum pseudo-header IPv4 | [UdpDatagram.cs:6](UdpDatagram.cs#L6) |
| `InternetChecksum` | Internet checksum one's-complement: `Compute` + `Finish` (gập tổng 32-bit) | [InternetChecksum.cs:4](InternetChecksum.cs#L4) |
| `TcpFlags` | Enum `[Flags]` cờ điều khiển TCP | [TcpFlags.cs:5](Tcp/Enums/TcpFlags.cs#L5) |
| `TcpState` | Enum trạng thái TCP cho client active-open + half-close FSM đầy đủ (9 state) | [TcpState.cs:4](Tcp/Enums/TcpState.cs#L4) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class / Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| RFC 1071 — Computing the Internet Checksum | `InternetChecksum` | [InternetChecksum.cs:3](InternetChecksum.cs#L3) | Ghi rõ trong comment; one's-complement, gập carry; dùng chung cho IPv4/TCP/UDP. |
| RFC 768 — User Datagram Protocol | `UdpDatagram` | [UdpDatagram.cs:5](UdpDatagram.cs#L5) | Ghi rõ trong comment; checksum tính trên **pseudo-header IPv4** [UdpDatagram.cs:41-56](UdpDatagram.cs#L41-L56); checksum = 0 truyền dưới dạng `0xFFFF` [UdpDatagram.cs:21](UdpDatagram.cs#L21). |
| RFC 793 — Transmission Control Protocol | `TcpState`, `TcpConnection`, `TcpSegment` | [TcpState.cs:3](Tcp/Enums/TcpState.cs#L3) | Comment ghi "RFC 793, subset incl. half-close FSM"; handshake/data/FIN ở [TcpConnection.cs:213](Tcp/TcpConnection.cs#L213); window-update WL1/WL2 ở [TcpConnection.cs:413-419](Tcp/TcpConnection.cs#L413-L419); half-close FSM (FinWait1→FinWait2/Closing/TimeWait, CloseWait→LastAck) ở [AdvanceClose:325](Tcp/TcpConnection.cs#L325). |
| RFC 6298 — Computing TCP's Retransmission Timer | `TcpConnection`, `TcpRetransmitOptions` | [TcpConnection.cs:392](Tcp/TcpConnection.cs#L392) | Ghi rõ trong comment; RTT estimator SRTT/RTTVAR (α=1/8, β=1/4, K=4) [UpdateRto:424](Tcp/TcpConnection.cs#L424), RTO ×2 backoff + give-up cap [OnRtoTimer:486](Tcp/TcpConnection.cs#L486). Sai khác cố ý: cho phép `MinRto` < 1s (RFC khuyến nghị 1s) để test chạy nhanh — mặc định stack vẫn 1s. |
| RFC 792 — Internet Control Message Protocol | `Icmpv4`, `TcpIpStack` | [Icmpv4.cs:3](Icmpv4.cs#L3) | Ghi rõ trong comment; Echo Request/Reply + Destination Unreachable; checksum tính trên **toàn ICMP message** (không pseudo-header) [Icmpv4.cs](Icmpv4.cs); error message quote "IP header + 8 byte payload" [Icmpv4.cs](Icmpv4.cs). |
| RFC 791 — Internet Protocol (IPv4) | `Ipv4` | [Ipv4.cs:6](Ipv4.cs#L6) | (suy luận) Không ghi RFC trong comment; header 20 byte, version 4/IHL 5, DF set, TTL 64 [Ipv4.cs:18-42](Ipv4.cs#L18-L42). |
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

- `TcpIpStack.ConnectAsync(IPAddress, ushort, CancellationToken)` → [TcpIpStack.cs:39](Tcp/TcpIpStack.cs#L39): cấp local port ephemeral (bắt đầu 49152), tạo `TcpConnection`, gửi SYN và chờ `Connected`.
- `TcpIpStack.BindUdp()` / `BindUdp(ushort)` → [TcpIpStack.cs:54](Tcp/TcpIpStack.cs#L54): bind socket UDP userspace.
- `TcpIpStack.PingAsync(IPAddress, ReadOnlyMemory<byte>, CancellationToken)` → [TcpIpStack.cs:69](Tcp/TcpIpStack.cs#L69): cấp sequence, gửi ICMP Echo Request, chờ Echo Reply khớp identifier/sequence → `PingReply` (RTT); nhận Destination Unreachable ⇒ ném `IcmpUnreachableException`.
- `TcpConnection.Send` / `ReadAsync` / `CloseSend` → [TcpConnection.cs:159](Tcp/TcpConnection.cs#L159), [TcpConnection.cs:174](Tcp/TcpConnection.cs#L174), [TcpConnection.cs:203](Tcp/TcpConnection.cs#L203). `Send` đệm dữ liệu rồi flush trong cửa sổ peer; `CloseSend` hoãn FIN tới khi đệm gửi cạn. `State` ([TcpConnection.cs:129](Tcp/TcpConnection.cs#L129)) phơi trạng thái FSM hiện tại để quan sát; `Closed` (event) báo connection đã terminal.
- `UdpConnection.SendTo` / `ReceiveAsync` → [UdpConnection.cs:30](Tcp/UdpConnection.cs#L30), [UdpConnection.cs:38](Tcp/UdpConnection.cs#L38).

## Luồng nội bộ

### Đường gói đi vào (demux)

1. `TcpIpStack` đăng ký handler `InboundIpPacket` của `IPacketChannel` ngay trong constructor — [TcpIpStack.cs:35](Tcp/TcpIpStack.cs#L35).
2. Mỗi gói IPv4 inbound vào `OnInbound` — [TcpIpStack.cs:96](Tcp/TcpIpStack.cs#L96): đọc protocol [Ipv4.cs:48](Ipv4.cs#L48); nếu TCP (6) lấy **destination port = local port của ta** [TcpIpStack.cs:106](Tcp/TcpIpStack.cs#L106) rồi tra `TcpConnection`; nếu UDP (17) tra `UdpConnection` theo local port [TcpIpStack.cs:114](Tcp/TcpIpStack.cs#L114); nếu ICMP (1) vào `OnIcmp` [TcpIpStack.cs:118](Tcp/TcpIpStack.cs#L118).
3. Segment được đẩy vào state machine qua `TcpConnection.OnSegment` — [TcpConnection.cs:153](Tcp/TcpConnection.cs#L153); datagram UDP qua `UdpConnection.OnDatagram` — [UdpConnection.cs:59](Tcp/UdpConnection.cs#L59).

### ICMP (RFC 792)

`OnIcmp` — [TcpIpStack.cs:126](Tcp/TcpIpStack.cs#L126) phân loại theo type:

- **Echo Request (8) → tự trả lời:** build Echo Reply echo lại payload + identifier/sequence rồi gửi về source — [TcpIpStack.cs:131-137](Tcp/TcpIpStack.cs#L131-L137). Host được cấp IP trong tunnel vì thế đáp ping của bên khác.
- **Echo Reply (0) → khớp ping đang chờ:** chỉ nhận nếu `identifier == _pingIdentifier` (per-stack, random), tra `_pings` theo sequence rồi complete `PingReply` — [TcpIpStack.cs:139-144](Tcp/TcpIpStack.cs#L139-L144).
- **Destination Unreachable (3) → fail ping:** trích datagram bị quote (IP header + 8 byte = Echo Request đã gửi), đọc identifier/sequence để định danh ping rồi ném `IcmpUnreachableException(code)` — [TcpIpStack.cs:146-158](Tcp/TcpIpStack.cs#L146-L158).
- **`PingAsync`** — [TcpIpStack.cs:69](Tcp/TcpIpStack.cs#L69): cấp sequence (`Interlocked`), đăng ký `TaskCompletionSource` vào `_pings`, build Echo Request + đo `Stopwatch`, gửi rồi `await` (hủy qua `CancellationToken`); `finally` gỡ entry khỏi `_pings`.

### TCP state machine (active-open)

- **Khởi tạo handshake:** `StartConnect` sinh ISS ngẫu nhiên (`RandomNumberGenerator`), gửi SYN kèm option MSS=1360, đưa SYN vào retx queue rồi chuyển `SynSent` — [TcpConnection.cs:135](Tcp/TcpConnection.cs#L135).
- **SYN-SENT → ESTABLISHED:** nhận SYN+ACK ⇒ `_rcvNxt = seq+1`, `ProcessAck` (gỡ SYN khỏi retx, lấy mẫu RTT, **seed cửa sổ gửi** `_sndWnd`), gửi ACK, complete `Connected` rồi flush dữ liệu đã đệm — [TcpConnection.cs:230-242](Tcp/TcpConnection.cs#L230-L242).
- **Nhận dữ liệu (reassembly):** `ReceiveData` giao ngay nếu `seq == _rcvNxt`, ngược lại **buffer out-of-order** (trong cửa sổ, dedupe) và `DrainOoo` ráp lại khi lấp đầy khoảng trống (drop wholly-old); luôn phát cumulative/dup ACK — [ReceiveData:259](Tcp/TcpConnection.cs#L259)/[DrainOoo:280](Tcp/TcpConnection.cs#L280).
- **Gửi dữ liệu (tin cậy):** `Send` đệm bytes; `TrySendData` chỉ phát trong cửa sổ khả dụng `_sndUna+_sndWnd−_sndNxt`, cắt theo MSS, mỗi chunk PSH|ACK đưa vào retx queue — [TcpConnection.cs:368](Tcp/TcpConnection.cs#L368). `ProcessAck` đẩy `_sndUna`, gỡ unit đã ACK, cập nhật RTT (Karn: bỏ mẫu của segment đã retransmit) + cửa sổ (WL1/WL2) — [TcpConnection.cs:392](Tcp/TcpConnection.cs#L392).
- **Retransmit/RTO (RFC 6298):** unit cũ nhất chưa ACK quá hạn `_rtoMs` ⇒ phát lại + ×2 backoff; quá `MaxRetransmits` ⇒ `Fail` — [TcpConnection.cs:486](Tcp/TcpConnection.cs#L486). RTO suy từ SRTT/RTTVAR — [UpdateRto:424](Tcp/TcpConnection.cs#L424).
- **Zero-window persist:** cửa sổ peer = 0 mà còn dữ liệu ⇒ persist timer dò **1 byte** (chỉ khi không có gì in-flight; RTO lo retransmit byte dò) tới khi cửa sổ mở lại — [TcpConnection.cs:539](Tcp/TcpConnection.cs#L539).
- **Half-close FSM:** peer FIN được ghi nhận rồi **chỉ tiêu thụ khi `_rcvNxt` chạm tới** (sau reassembly) ⇒ `ReadAsync` trả 0 — [NoteFin:305](Tcp/TcpConnection.cs#L305)/[TryConsumePeerFin:313](Tcp/TcpConnection.cs#L313). `AdvanceClose` lái trạng thái: FinWait1→**FinWait2** (FIN ta được ACK) / **Closing** (đóng đồng thời) / **TimeWait** (FIN+ACK 1 segment); FinWait2·Closing→TimeWait; CloseWait→LastAck; LastAck→CLOSED — [AdvanceClose:325](Tcp/TcpConnection.cs#L325). Chủ động đóng qua `CloseSend` (Established→FinWait1, CloseWait→LastAck), **FIN hoãn** tới khi đệm gửi cạn — [CloseSend:203](Tcp/TcpConnection.cs#L203).
- **TIME-WAIT linger:** vào TimeWait arm `_closeTimer` (mặc định 2s, tunable); retransmitted FIN của peer được re-ACK + reset linger; hết linger → CLOSED — [EnterTimeWait:349](Tcp/TcpConnection.cs#L349)/[OnCloseTimer:357](Tcp/TcpConnection.cs#L357).
- **Terminal:** graceful CLOSED, RST, hoặc hết retry đều qua **một đường** `Terminate`: dừng mọi timer, fault `Connected` (nếu lỗi) + kết thúc đọc, raise event `Closed` (stack gỡ + dispose) — [RST:224](Tcp/TcpConnection.cs#L224), [Terminate:592](Tcp/TcpConnection.cs#L592).
- So sánh số thứ tự dùng số học modulo (`SeqGreater`/`SeqGeq`) để an toàn với wrap-around — [TcpConnection.cs:617](Tcp/TcpConnection.cs#L617).

### Đóng gói đi ra

`EmitSegment(seq, flags, payload)` → build TCP segment tại seq cho trước [TcpSegment.cs:10](Tcp/TcpSegment.cs#L10) → bọc IPv4 [Ipv4.cs:18](Ipv4.cs#L18) → đẩy qua `IPacketChannel.WriteIpPacketAsync` (`SendIp`) — [TcpConnection.cs:459](Tcp/TcpConnection.cs#L459), [TcpIpStack.cs:94](Tcp/TcpIpStack.cs#L94). Data/SYN/FIN còn được đưa vào retx queue (`EnqueueRetx`) để retransmit theo seq đã lưu. Checksum TCP/UDP tính trên pseudo-header IPv4 (src/dst/protocol/length) — [TcpSegment.cs:39-55](Tcp/TcpSegment.cs#L39-L55), [UdpDatagram.cs:41-56](UdpDatagram.cs#L41-L56). ICMP build qua [Icmpv4.cs:7](Icmpv4.cs#L7) (checksum trên toàn message, không pseudo-header) rồi cũng bọc IPv4 + `SendIp`.

## Trạng thái & ghi chú

- **Đã hiện thực:** IPv4 build/parse (không option, DF set); TCP client active-open **tin cậy đầy đủ** — handshake/RST; **phía gửi** retx queue + RTO (RFC 6298, RTT SRTT/RTTVAR + ×2 backoff + give-up cap) + sliding-window flow control (tôn trọng cửa sổ peer, WL1/WL2) + zero-window persist; **phía nhận** out-of-order reassembly; **half-close FSM đầy đủ** (FinWait1/2, Closing, TimeWait, CloseWait, LastAck) + TIME-WAIT linger; terminal → event `Closed`; UDP send/receive theo local port; **ICMP echo/ping (`PingAsync` + tự trả lời Echo Request) + Destination Unreachable (RFC 792)**; checksum IPv4/TCP/UDP (pseudo-header) + ICMP (toàn message). Demux inbound theo protocol→destination port.
- **Cố tình lược bỏ:** **không** SACK, **không** congestion control (cwnd/slow-start/fast-retransmit — chỉ flow control), không Nagle, không ráp lại phân mảnh **IP** (giả định tầng IP đã ráp; reassembly ở đây là cho **segment TCP** out-of-order). Stack tin cậy chỉ cần vì peer là host thật trên internet — xem [TcpConnection.cs:12-24](Tcp/TcpConnection.cs#L12-L24).
- **Phạm vi giao thức:** chỉ **IPv4/ICMPv4** (dù `IPacketChannel` mô tả là IPv4/IPv6); chưa có IPv6/ICMPv6. ICMP nay **đã có handler** trong `OnInbound`/`OnIcmp` (echo + destination-unreachable); **chưa** tự sinh ICMP port-unreachable cho gói TCP/UDP tới port không có socket (vẫn drop im lặng — tránh đổi hành vi data plane đang chạy live).
- **TCP chỉ active-open (client):** không có trạng thái `Listen`/passive-open; enum `TcpState` gồm đủ FSM cho client + half-close — [TcpState.cs:4-13](Tcp/Enums/TcpState.cs#L4-L13). Half-close đầy đủ: `FINWAIT2`/`CLOSING`/`TIME-WAIT` đã có (xem [AdvanceClose:325](Tcp/TcpConnection.cs#L325)).
- **MSS cố định 1360, receive window cố định 65535** — [TcpConnection.cs:27-28](Tcp/TcpConnection.cs#L27-L28); window **ta quảng bá** tĩnh (không phản ánh buffer thực, nhưng buffer reassembly bị chặn ≤ receive window), còn **cửa sổ peer** được tôn trọng ở chiều gửi. Thời gian RTO/persist/TIME-WAIT tunable qua [TcpRetransmitOptions](Tcp/TcpRetransmitOptions.cs#L14).
- **netstandard2.0 vs net8.0:** không khác biệt API/hành vi đáng kể trong project này; tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`) theo quy ước chung của solution. `UdpReceiveResult`/`Datagram` dùng `readonly struct` thay vì record.

Tham chiếu chéo tài liệu as-built toàn cục: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
