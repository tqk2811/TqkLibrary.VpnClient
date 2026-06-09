# TqkLibrary.Vpn.L2tp

> L2TPv2 control (SCCRQ/SCCRP/SCCCN, ICRQ/ICRP/ICCN) + data channel carrying PPP.

## Mục đích

Project hiện thực **L2TPv2 (RFC 2661)** ở phía **LAC** (L2TP Access Concentrator — bên khởi tạo): dựng một tunnel và một session bên trong nó, rồi vận chuyển các **PPP frame** qua data message của L2TP.

Trong stack VPN userspace của thư viện, L2TP là tầng nằm **giữa**:
- Phía dưới: data plane IPsec/ESP (UDP/1701 đã được ESP bảo vệ) hoặc một transport in-process cho test.
- Phía trên: tầng PPP (LCP/IPCP/MS-CHAPv2). PPP frame đi vào/ra qua sự kiện [`DataReceived`](L2tpClient.cs#L45) và method [`SendDataAsync`](L2tpClient.cs#L61).

Project giải quyết các bài toán cốt lõi của L2TP:
- **Bắt tay tunnel** (3-way: SCCRQ → SCCRP → SCCCN) và **bắt tay session** (ICRQ → ICRP → ICCN).
- **Kênh điều khiển tin cậy** trên nền UDP không tin cậy: số thứ tự Ns/Nr, ack tích lũy, ZLB ack, và retransmit.
- **HELLO keepalive**, **CDN/StopCCN teardown**.
- **Mã hóa/giải mã** header L2TP + AVP, và đóng/mở gói PPP frame trong data message.

Lưu ý: đây là **L2TP thuần** — bản thân nó không làm IPsec/ESP. Việc bảo vệ UDP/1701 bằng ESP do driver L2TP/IPsec ở tầng DRIVER đảm nhiệm thông qua `IL2tpTransport`.

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (giao thức tunnel L2TPv2 control + data).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ `src/Directory.Build.props`).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.Vpn.Abstractions](../TqkLibrary.Vpn.Abstractions) — xem [TqkLibrary.Vpn.L2tp.csproj:8](TqkLibrary.Vpn.L2tp.csproj#L8). Không có PackageReference đặc thù.
- **Được dùng bởi:**
  - [TqkLibrary.Vpn.Drivers](../TqkLibrary.Vpn.Drivers) — driver `L2tpIpsec/` lắp `L2tpClient` lên trên transport ESP-over-UDP (`IpsecL2tpTransport`) và phơi PPP frame ra qua channel (`L2tpPppFrameChannel`).

> Ghi chú: dù phụ thuộc `Abstractions`, các kiểu trong project hiện chỉ dùng kiểu .NET cơ bản (`Task`, `Action<>`, `ReadOnlyMemory<byte>`) cho ranh giới `IL2tpTransport`; không trực tiếp tham chiếu interface VPN nào của `Abstractions` trong các file `.cs` hiện tại.

## Cấu trúc thư mục

```
TqkLibrary.Vpn.L2tp/
├── L2tpClient.cs            # Client LAC: dựng tunnel + session, vào/ra PPP frame (điểm vào chính)
├── L2tpControlChannel.cs    # Kênh điều khiển tin cậy: Ns/Nr, ack tích lũy, ZLB, retransmit
├── L2tpCodec.cs             # Encode/decode header L2TP (control & data) + danh sách AVP
├── IL2tpTransport.cs        # Ranh giới transport: gửi/nhận một L2TP datagram (UDP/1701 payload)
├── Enums/
│   ├── L2tpMessageType.cs   # Các loại control message (SCCRQ/SCCRP/.../CDN/StopCCN/HELLO...)
│   └── L2tpAvpType.cs       # Các loại AVP attribute (HostName, AssignedTunnelId, ResultCode...)
└── Models/
    ├── L2tpAvp.cs           # Một AVP: cờ M|H, length 10-bit, VendorId, Type, value + helper UInt16/UInt32/Text
    └── L2tpControlMessage.cs# Một control message: tunnel/session id, Ns/Nr, MessageType, danh sách AVP
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `L2tpClient` | Client LAC: `ConnectAsync` dựng tunnel+session, `SendDataAsync`/`DataReceived` cho PPP, HELLO + CDN/StopCCN teardown. Điểm vào chính. | [L2tpClient.cs:12](L2tpClient.cs#L12) |
| `L2tpControlChannel` | Kênh điều khiển tin cậy: gán Ns/Nr, ack tích lũy, ZLB ack, retransmit qua `Timer`, giao message in-order qua `ControlReceived`. | [L2tpControlChannel.cs:10](L2tpControlChannel.cs#L10) |
| `L2tpCodec` | Static codec: `EncodeControl`/`DecodeControl`, `EncodeData`/`TryDecodeData`, `IsControl`. | [L2tpCodec.cs:11](L2tpCodec.cs#L11) |
| `IL2tpTransport` | Ranh giới transport (`SendAsync` + `DatagramReceived`); driver hiện thực qua ESP-over-UDP, test dùng cặp in-process. | [IL2tpTransport.cs:7](IL2tpTransport.cs#L7) |
| `L2tpAvp` | Model AVP + factory `Create`/`UInt16`/`UInt32`/`Text` và `AsUInt16`/`AsUInt32`; `Write`/`Parse` nội bộ. | [L2tpAvp.cs:10](Models/L2tpAvp.cs#L10) |
| `L2tpControlMessage` | Model control message + builder `Create`/`With`/`Ack`/`Find`; cờ `IsZeroLengthBody` cho ZLB. | [L2tpControlMessage.cs:9](Models/L2tpControlMessage.cs#L9) |
| `L2tpMessageType` | Enum loại control message. | [L2tpMessageType.cs:4](Enums/L2tpMessageType.cs#L4) |
| `L2tpAvpType` | Enum loại AVP attribute. | [L2tpAvpType.cs:4](Enums/L2tpAvpType.cs#L4) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|-------------------------|--------------------|---------|
| RFC 2661 §3.1 (định dạng L2TPv2 header — control/data, cờ T/L/S/O, Ver=2) | `L2tpCodec` | [L2tpCodec.cs:7](L2tpCodec.cs#L7) | Control: header đầy đủ T=L=S=1; Data: header tối thiểu T=0 |
| RFC 2661 §4.1 (định dạng AVP — cờ M|H, length 10-bit, VendorId, Type, value) | `L2tpAvp` (Models) | [L2tpAvp.cs:7](Models/L2tpAvp.cs#L7) | Chỉ sinh AVP IETF (vendor 0), non-hidden; AVP hidden parse được nhưng không giải mã |
| RFC 2661 §4.4 (bảng control message type) | `L2tpMessageType` (Enums) | [L2tpMessageType.cs:3](Enums/L2tpMessageType.cs#L3) | SCCRQ/SCCRP/SCCCN/StopCCN/HELLO/ICRQ/ICRP/ICCN/CDN/SetLinkInfo |
| RFC 2661 §4.4 (bảng AVP attribute type) | `L2tpAvpType` (Enums) | [L2tpAvpType.cs:3](Enums/L2tpAvpType.cs#L3) | Tập AVP mà client này dùng |
| RFC 2661 §5.8 (kênh điều khiển tin cậy — Ns/Nr, ack tích lũy, ZLB, retransmit) | `L2tpControlChannel` | [L2tpControlChannel.cs:6](L2tpControlChannel.cs#L6) | Ack tích lũy: một Nr nhận được xóa mọi message đã queue dưới nó |
| RFC 2661 §5.5 (HELLO keepalive) | `L2tpClient.SendHelloAsync` | [L2tpClient.cs:64](L2tpClient.cs#L64) | HELLO gửi tin cậy trên control channel |
| RFC 2661 §5.6 (Call-Disconnect-Notify teardown session) | `L2tpClient.SendCallDisconnectAsync` | [L2tpClient.cs:68](L2tpClient.cs#L68) | `resultCode` 3 = administrative |
| RFC 2661 (Stop-Control-Connection-Notification teardown tunnel) | `L2tpClient.SendStopControlConnectionAsync` | [L2tpClient.cs:78](L2tpClient.cs#L78) | `resultCode` 1 = general request to clear (suy luận §5.x — không chú thích số mục trong comment) |
| RFC 2661 §1.x (L2TP chạy trên UDP/1701 — mỗi message là một datagram) | `IL2tpTransport` | [IL2tpTransport.cs:3](IL2tpTransport.cs#L3) | UDP/1701 payload; driver bọc trong ESP (suy luận — comment nói "UDP/1701" nhưng không ghi số mục RFC) |

## API / cách dùng

Các kiểu/điểm vào public chính:

- `L2tpClient(IL2tpTransport transport, string hostName = "anonymous", TimeSpan? retransmitInterval = null)` — [L2tpClient.cs:21](L2tpClient.cs#L21)
- `Task ConnectAsync(CancellationToken)` — dựng tunnel rồi session, hoàn tất khi session up — [L2tpClient.cs:51](L2tpClient.cs#L51)
- `Task SendDataAsync(ReadOnlyMemory<byte> pppFrame)` — gửi PPP frame trong data message — [L2tpClient.cs:61](L2tpClient.cs#L61)
- `event Action<ReadOnlyMemory<byte>> DataReceived` — nhận PPP frame của session — [L2tpClient.cs:45](L2tpClient.cs#L45)
- `event Action<string> Disconnected` — server tear down (StopCCN/CDN) sau khi đã established — [L2tpClient.cs:48](L2tpClient.cs#L48)
- `Task SendHelloAsync()` / `Task SendCallDisconnectAsync(...)` / `Task SendStopControlConnectionAsync(...)` — keepalive & teardown — [L2tpClient.cs:65](L2tpClient.cs#L65)
- `LocalTunnelId` / `LocalSessionId` / `PeerTunnelId` / `PeerSessionId` — id hai phía — [L2tpClient.cs:33-42](L2tpClient.cs#L33-L42)

Ví dụ ngắn (transport do tầng driver cung cấp):

```csharp
// transport: IL2tpTransport (vd ESP-over-UDP từ driver L2tpIpsec, hoặc cặp in-process trong test)
using var l2tp = new L2tpClient(transport, hostName: "anonymous");

l2tp.DataReceived += pppFrame => { /* đẩy frame lên tầng PPP (LCP/IPCP/MS-CHAPv2) */ };
l2tp.Disconnected += reason => { /* server StopCCN/CDN -> dọn dẹp */ };

await l2tp.ConnectAsync(cancellationToken); // SCCRQ->SCCRP->SCCCN, rồi ICRQ->ICRP->ICCN

await l2tp.SendDataAsync(pppFrameFromPppLayer);     // gửi PPP ra
await l2tp.SendHelloAsync();                          // keepalive định kỳ

await l2tp.SendCallDisconnectAsync();                // teardown session (CDN)
await l2tp.SendStopControlConnectionAsync();         // teardown tunnel (StopCCN)
```

## Luồng nội bộ

### 1. Bắt tay tunnel + session (`ConnectAsync`)

[`ConnectAsync`](L2tpClient.cs#L51) chạy tuần tự hai pha, mỗi pha chờ một `TaskCompletionSource`:

1. **Tunnel:** gửi **SCCRQ** ([`SendSccrqAsync`](L2tpClient.cs#L83)) với các AVP ProtocolVersion/Framing/Bearer/HostName/AssignedTunnelId/ReceiveWindowSize → chờ [`_tunnelUp`](L2tpClient.cs#L17).
2. Khi nhận **SCCRP** trong [`OnControl`](L2tpClient.cs#L120): lấy `AssignedTunnelId` của server làm `PeerTunnelId`, gán cho control channel, gửi **SCCCN** ([`SendScccnAsync`](L2tpClient.cs#L96)), rồi `_tunnelUp.TrySetResult(true)`.
3. **Session:** gửi **ICRQ** ([`SendIcrqAsync`](L2tpClient.cs#L99)) với AssignedSessionId/CallSerialNumber → chờ [`_sessionUp`](L2tpClient.cs#L18).
4. Khi nhận **ICRP** ([`OnControl`](L2tpClient.cs#L131)): lấy `AssignedSessionId` của server làm `PeerSessionId`, gửi **ICCN** ([`SendIccnAsync`](L2tpClient.cs#L107)), rồi `_sessionUp.TrySetResult(true)`. Session đã established.

Nếu server gửi **StopCCN/CDN**: [`OnControl`](L2tpClient.cs#L138-L146) gọi [`Fail`](L2tpClient.cs#L163) (đẩy exception vào hai TCS) và raise `Disconnected`.

### 2. Kênh điều khiển tin cậy (`L2tpControlChannel`)

- **Gửi:** [`SendAsync`](L2tpControlChannel.cs#L36) gán `Ns = _ns`, `Nr = _nr`, encode, đưa vào hàng `_unacked`, tăng `_ns`, rồi truyền.
- **Nhận:** [`OnDatagram`](L2tpControlChannel.cs#L52):
  - **Ack tích lũy** — xóa mọi message trong `_unacked` có `Ns < message.Nr` ([dòng 61-62](L2tpControlChannel.cs#L61-L62)).
  - **ZLB** (`IsZeroLengthBody`) — chỉ là ack, return ngay ([dòng 64-65](L2tpControlChannel.cs#L64-L65)).
  - **In-order** (`Ns == _nr`) — tăng `_nr`, đánh dấu deliver; sau đó raise `ControlReceived` và gửi standalone ZLB ack ([dòng 67-83](L2tpControlChannel.cs#L67-L83)).
  - **Trùng** (`Ns < _nr`) — peer retransmit vì lỡ ack của ta → re-ack ([dòng 72-76](L2tpControlChannel.cs#L72-L76)).
- **Retransmit:** [`Timer`](L2tpControlChannel.cs#L26) định kỳ gọi [`Retransmit`](L2tpControlChannel.cs#L98) gửi lại message đầu hàng `_unacked` (mặc định 1s).
- So sánh seq wrap-around 16-bit: [`SeqLess`](L2tpControlChannel.cs#L108).

### 3. Encode/decode header (`L2tpCodec`)

- **Control:** [`EncodeControl`](L2tpCodec.cs#L23) ghi header 12 byte (cờ T=L=S=1, Ver=2, Length, TunnelId, SessionId, Ns, Nr) + AVP Message Type + các AVP; [`DecodeControl`](L2tpCodec.cs#L48) parse header theo cờ rồi duyệt AVP (AVP đầu là Message Type).
- **Data:** [`EncodeData`](L2tpCodec.cs#L98) bọc PPP frame trong header tối thiểu 6 byte (T=0); [`TryDecodeData`](L2tpCodec.cs#L110) tách PPP frame ra theo cờ L/S/O.
- **Định tuyến datagram:** [`OnDatagram`](L2tpClient.cs#L150) gọi [`IsControl`](L2tpCodec.cs#L20) — control đưa vào control channel, data giải mã và (nếu `sessionId == LocalSessionId`) raise `DataReceived`.

### 4. AVP (`L2tpAvp`)

[`Write`](Models/L2tpAvp.cs#L49) đóng gói cờ M|H + length 10-bit + VendorId + Type + Value; [`Parse`](Models/L2tpAvp.cs#L64) làm ngược lại. Helper [`UInt16`/`UInt32`/`Text`](Models/L2tpAvp.cs#L32-L41) tạo value big-endian/ASCII.

## Trạng thái & ghi chú

- **Đã hiện thực (as-built):** vai trò **LAC/initiator** với một tunnel + một session; bắt tay đầy đủ SCCRQ/SCCRP/SCCCN + ICRQ/ICRP/ICCN; control channel tin cậy (Ns/Nr, ack tích lũy, ZLB, retransmit); HELLO keepalive; teardown CDN + StopCCN; data plane mang PPP frame. Xem chi tiết as-built tại [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
- **Hạn chế đã biết / khung mở rộng:**
  - Chỉ hỗ trợ **một** session trên một tunnel (chỉ so khớp `LocalSessionId` ở [L2tpClient.cs:156-157](L2tpClient.cs#L156-L157)).
  - **AVP Hidden** parse được nhưng **không giải mã** ([L2tpAvp.cs:8](Models/L2tpAvp.cs#L8), [L2tpAvp.cs:16](Models/L2tpAvp.cs#L16)).
  - **Tunnel CHAP** (Challenge/ChallengeResponse) có trong enum [`L2tpAvpType`](Enums/L2tpAvpType.cs#L36-L40) nhưng client chưa dùng để xác thực tunnel.
  - **SetLinkInfo** có trong enum nhưng `OnControl` chưa xử lý loại message này.
  - Retransmit gửi lại **message đầu hàng** mỗi tick, không có giới hạn số lần thử (no max-retry/abort) ở [`Retransmit`](L2tpControlChannel.cs#L98).
  - Cửa sổ truyền/nhận hiệu dụng là **1** (gửi message tiếp theo không chặn theo `ReceiveWindowSize` đã quảng cáo).
  - Là vai trò **LAC**; không hiện thực vai trò **LNS/server**.
- **Khác biệt netstandard2.0 vs net8.0:** không có khác biệt hành vi trong project này; tránh `record`/`init` theo quy ước thư viện (netstandard2.0 thiếu `IsExternalInit`).
- **Bảo mật transport:** L2TP ở đây **không tự mã hóa**; tính bí mật/toàn vẹn do ESP/IPsec ở tầng DRIVER cung cấp qua `IL2tpTransport`.
