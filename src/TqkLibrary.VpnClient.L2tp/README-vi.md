# TqkLibrary.VpnClient.L2tp

> L2TPv2 control (SCCRQ/SCCRP/SCCCN, ICRQ/ICRP/ICCN) + data channel carrying PPP.

## Mục đích

Project hiện thực **L2TPv2 (RFC 2661)** ở phía **LAC** (L2TP Access Concentrator — bên khởi tạo): dựng một tunnel và **một hoặc nhiều** session bên trong nó, rồi vận chuyển các **PPP frame** qua data message của L2TP.

Trong stack VPN userspace của thư viện, L2TP là tầng nằm **giữa**:
- Phía dưới: data plane IPsec/ESP (UDP/1701 đã được ESP bảo vệ) hoặc một transport in-process cho test.
- Phía trên: tầng PPP (LCP/IPCP/MS-CHAPv2). Mỗi session có một luồng PPP riêng: frame đi vào/ra qua sự kiện [`L2tpSession.DataReceived`](L2tpSession.cs#L29) và method [`L2tpSession.SendDataAsync`](L2tpSession.cs#L35) (session chính cũng phơi qua [`L2tpClient.DataReceived`](L2tpClient.cs#L56)/[`SendDataAsync`](L2tpClient.cs#L115)).

Project giải quyết các bài toán cốt lõi của L2TP:
- **Bắt tay tunnel** (3-way: SCCRQ → SCCRP → SCCCN) và **bắt tay session** (ICRQ → ICRP → ICCN), nhiều session trên cùng một tunnel.
- **Kênh điều khiển tin cậy** trên nền UDP không tin cậy: số thứ tự Ns/Nr, ack tích lũy, ZLB ack, và retransmit.
- **HELLO keepalive**, **CDN/StopCCN teardown**.
- **Mã hóa/giải mã** header L2TP + AVP, và đóng/mở gói PPP frame trong data message.

Lưu ý: đây là **L2TP thuần** — bản thân nó không làm IPsec/ESP. Việc bảo vệ UDP/1701 bằng ESP do driver L2TP/IPsec ở tầng DRIVER đảm nhiệm thông qua `IL2tpTransport`.

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (giao thức tunnel L2TPv2 control + data).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ `src/Directory.Build.props`).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — xem [TqkLibrary.VpnClient.L2tp.csproj:8](TqkLibrary.VpnClient.L2tp.csproj#L8). Không có PackageReference đặc thù.
- **Được dùng bởi:**
  - [TqkLibrary.VpnClient.Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) — driver L2TP/IPsec lắp `L2tpClient` lên trên transport ESP-over-UDP (`IpsecL2tpTransport`) và phơi PPP frame của từng `L2tpSession` ra qua channel (`L2tpPppFrameChannel`).

> Ghi chú: dù phụ thuộc `Abstractions`, các kiểu trong project hiện chỉ dùng kiểu .NET cơ bản (`Task`, `Action<>`, `ReadOnlyMemory<byte>`) cho ranh giới `IL2tpTransport`; không trực tiếp tham chiếu interface VPN nào của `Abstractions` trong các file `.cs` hiện tại.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.L2tp/
├── L2tpClient.cs            # Client LAC: dựng tunnel + N session, demux data theo session (điểm vào chính)
├── L2tpSession.cs           # Một call/session trong tunnel: session id riêng, DataReceived/SendDataAsync/CDN của nó
├── L2tpControlChannel.cs    # Kênh điều khiển tin cậy: Ns/Nr, ack tích lũy, ZLB, retransmit one-shot backoff (có cap → event Failed)
├── L2tpRetransmitOptions.cs # Chính sách retransmit control channel: interval + exponential backoff (multiplier/cap/jitter) + cap số lần
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
| `L2tpClient` | Client LAC: `ConnectAsync` dựng tunnel + session chính (`PrimarySession`), `OpenSessionAsync` mở session phụ trên cùng tunnel, demux data inbound theo session id, HELLO + StopCCN teardown tunnel. Điểm vào chính. | [L2tpClient.cs:13](L2tpClient.cs#L13) |
| `L2tpSession` | Một call/session trong tunnel: `LocalSessionId`/`PeerSessionId` riêng, `DataReceived`/`SendDataAsync` luồng PPP của nó, `SendCallDisconnectAsync` (CDN session). | [L2tpSession.cs:9](L2tpSession.cs#L9) |
| `L2tpControlChannel` | Kênh điều khiển tin cậy: gán Ns/Nr, ack tích lũy, ZLB ack, retransmit qua `Timer` one-shot tự-reschedule với exponential backoff+jitter (cap `MaxRetransmits` → raise `Failed` khi peer im lặng), giao message in-order qua `ControlReceived`. | [L2tpControlChannel.cs:12](L2tpControlChannel.cs#L12) |
| `L2tpRetransmitOptions` | Chính sách retransmit control channel: `Interval`/`MaxRetransmits`/`BackoffMultiplier`/`MaxInterval`/`JitterFraction` + `IntervalFor(resends)`. Mặc định `BackoffMultiplier=1.0` ⇒ giữ nguyên hành vi interval cố định cũ. | [L2tpRetransmitOptions.cs:10](L2tpRetransmitOptions.cs#L10) |
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
| RFC 2661 §5.5 (HELLO keepalive) | `L2tpClient.SendHelloAsync` | [L2tpClient.cs:122](L2tpClient.cs#L122) | HELLO gửi tin cậy trên control channel |
| RFC 2661 §5.6 (Call-Disconnect-Notify teardown session) | `L2tpSession.SendCallDisconnectAsync` | [L2tpSession.cs:38](L2tpSession.cs#L38) | CDN địa chỉ theo session id; `L2tpClient.SendCallDisconnectAsync` ([L2tpClient.cs:126](L2tpClient.cs#L126)) gửi cho session chính; `resultCode` 3 = administrative |
| RFC 2661 §3.3 (multi-session: ICRQ/ICRP/ICCN nhiều call trên một tunnel) | `L2tpClient.OpenSessionAsync` | [L2tpClient.cs:80](L2tpClient.cs#L80) | Tương quan ICRP/CDN theo session id ở header (fallback session đang mở khi peer trả 0) |
| RFC 2661 (Stop-Control-Connection-Notification teardown tunnel) | `L2tpClient.SendStopControlConnectionAsync` | [L2tpClient.cs:142](L2tpClient.cs#L142) | `resultCode` 1 = general request to clear (suy luận §5.x — không chú thích số mục trong comment) |
| RFC 2661 §1.x (L2TP chạy trên UDP/1701 — mỗi message là một datagram) | `IL2tpTransport` | [IL2tpTransport.cs:3](IL2tpTransport.cs#L3) | UDP/1701 payload; driver bọc trong ESP (suy luận — comment nói "UDP/1701" nhưng không ghi số mục RFC) |

## API / cách dùng

Các kiểu/điểm vào public chính:

- `L2tpClient(IL2tpTransport transport, string hostName = "anonymous", L2tpRetransmitOptions? retransmitOptions = null)` — `retransmitOptions` chỉnh interval + exponential backoff (multiplier/cap/jitter) + cap số lần (`MaxRetransmits` > 0 ⇒ link chết sau N lần retransmit không ack; null = mặc định 1s, không backoff, vô hạn) — [L2tpClient.cs:29](L2tpClient.cs#L29)
- `Task ConnectAsync(CancellationToken)` — dựng tunnel rồi session chính, hoàn tất khi session up — [L2tpClient.cs:62](L2tpClient.cs#L62)
- `Task<L2tpSession> OpenSessionAsync(CancellationToken)` — mở session phụ trên cùng tunnel (ICRQ/ICRP/ICCN); ném nếu server từ chối bằng CDN hoặc timeout — [L2tpClient.cs:80](L2tpClient.cs#L80)
- `L2tpSession PrimarySession` — session đầu tiên do `ConnectAsync` dựng — [L2tpClient.cs:47](L2tpClient.cs#L47)
- `Task L2tpSession.SendDataAsync(ReadOnlyMemory<byte> pppFrame)` + `event Action<...> L2tpSession.DataReceived` — gửi/nhận PPP frame của session đó (session chính cũng phơi qua `L2tpClient.SendDataAsync`/`DataReceived`) — [L2tpSession.cs:35](L2tpSession.cs#L35), [L2tpSession.cs:29](L2tpSession.cs#L29)
- `event Action<string> L2tpClient.Disconnected` — tunnel down (StopCCN/control-fail) **hoặc** session chính bị CDN; mỗi session phụ có `L2tpSession.Disconnected` riêng — [L2tpClient.cs:59](L2tpClient.cs#L59)
- `Task SendHelloAsync()` / `Task SendStopControlConnectionAsync(...)` — keepalive & teardown tunnel — [L2tpClient.cs:122](L2tpClient.cs#L122)
- `LocalTunnelId` / `PeerTunnelId` (tunnel) + `LocalSessionId`/`PeerSessionId` (session chính) — id hai phía — [L2tpClient.cs:41-53](L2tpClient.cs#L41-L53)

Ví dụ ngắn (transport do tầng driver cung cấp):

```csharp
// transport: IL2tpTransport (vd ESP-over-UDP từ driver L2tpIpsec, hoặc cặp in-process trong test)
using var l2tp = new L2tpClient(transport, hostName: "anonymous");

l2tp.DataReceived += pppFrame => { /* đẩy frame lên tầng PPP (LCP/IPCP/MS-CHAPv2) */ };
l2tp.Disconnected += reason => { /* server StopCCN/CDN -> dọn dẹp */ };

await l2tp.ConnectAsync(cancellationToken); // SCCRQ->SCCRP->SCCCN, rồi ICRQ->ICRP->ICCN (session chính)

await l2tp.SendDataAsync(pppFrameFromPppLayer);     // gửi PPP ra (session chính)
await l2tp.SendHelloAsync();                          // keepalive định kỳ

// (tùy chọn) mở session phụ trên cùng tunnel — best-effort, đa số server từ chối bằng CDN
L2tpSession extra = await l2tp.OpenSessionAsync(cancellationToken);
extra.DataReceived += f => { /* luồng PPP thứ hai */ };
await extra.SendDataAsync(otherPppFrame);

await l2tp.SendCallDisconnectAsync();                // teardown session chính (CDN)
await l2tp.SendStopControlConnectionAsync();         // teardown tunnel (StopCCN)
```

## Luồng nội bộ

### 1. Bắt tay tunnel + session (`ConnectAsync`)

[`ConnectAsync`](L2tpClient.cs#L62) chạy tuần tự: dựng tunnel rồi gọi `OpenSessionInternalAsync` cho session chính:

1. **Tunnel:** gửi **SCCRQ** ([`SendSccrqAsync`](L2tpClient.cs#L147)) với các AVP ProtocolVersion/Framing/Bearer/HostName/VendorName/AssignedTunnelId/ReceiveWindowSize → chờ [`_tunnelUp`](L2tpClient.cs#L18).
2. Khi nhận **SCCRP** trong [`OnControl`](L2tpClient.cs#L180): lấy `AssignedTunnelId` của server làm `PeerTunnelId`, gán cho control channel, gửi **SCCCN** ([`SendScccnAsync`](L2tpClient.cs#L160)), rồi `_tunnelUp.TrySetResult(true)`.
3. **Session:** mỗi session sinh `LocalSessionId` riêng ([`NewSessionId`](L2tpClient.cs#L306), đảm bảo khác mọi session đang mở), đăng ký vào `_sessions` + `_pendingSession`, gửi **ICRQ** ([`SendIcrqAsync`](L2tpClient.cs#L163)) với AssignedSessionId/CallSerialNumber → chờ TCS [`L2tpSession.Up`](L2tpSession.cs#L14).
4. Khi nhận **ICRP** ([`OnControl`](L2tpClient.cs#L195)): tương quan về session đang mở theo session id ở header (fallback `_pendingSession` khi peer trả 0), lấy `AssignedSessionId` của server làm `PeerSessionId`, gửi **ICCN** ([`SendIccnAsync`](L2tpClient.cs#L171)), rồi hoàn tất `Up`. Session đã established.

**Session phụ:** [`OpenSessionAsync`](L2tpClient.cs#L80) lặp lại bước 3-4 trên cùng tunnel (mở tuần tự từng cái). Server từ chối bằng **CDN** ([`OnCallDisconnect`](L2tpClient.cs#L220)) → đẩy exception vào `Up` của session đang mở (OpenSessionAsync ném). **StopCCN/control-fail** → [`FailTunnel`](L2tpClient.cs#L242): đẩy exception vào `_tunnelUp` + `Up` của mọi session đang mở, raise `Disconnected` (mỗi session established nhận `Disconnected` riêng; session chính chuyển tiếp ra `L2tpClient.Disconnected`).

### 2. Kênh điều khiển tin cậy (`L2tpControlChannel`)

- **Gửi:** [`SendAsync`](L2tpControlChannel.cs#L52) gán `Ns = _ns`, `Nr = _nr`, encode, đưa vào hàng `_unacked`, tăng `_ns`, rồi truyền.
- **Nhận:** [`OnDatagram`](L2tpControlChannel.cs#L68):
  - **Ack tích lũy** — xóa mọi message trong `_unacked` có `Ns < message.Nr` ([dòng 77-78](L2tpControlChannel.cs#L77-L78)).
  - **ZLB** (`IsZeroLengthBody`) — chỉ là ack, return ngay ([dòng 80-81](L2tpControlChannel.cs#L80-L81)).
  - **In-order** (`Ns == _nr`) — tăng `_nr`, đánh dấu deliver; sau đó raise `ControlReceived` và gửi standalone ZLB ack ([dòng 83-99](L2tpControlChannel.cs#L83-L99)).
  - **Trùng** (`Ns < _nr`) — peer retransmit vì lỡ ack của ta → re-ack ([dòng 88-92](L2tpControlChannel.cs#L88-L92)).
- **Retransmit:** [`Timer`](L2tpControlChannel.cs#L38) **one-shot tự-reschedule** gọi [`Retransmit`](L2tpControlChannel.cs#L114) gửi lại message đầu hàng `_unacked`; mỗi lần resend, khoảng chờ kế **nhân đôi có jitter** ([`IntervalFor`](L2tpRetransmitOptions.cs#L32) — `Interval × multiplier^resends`, mặc định 1s tới cap 8s; tick rỗng poll lại ở base interval). Mỗi message giữ bộ đếm `Attempts`; khi vượt `MaxRetransmits` (nếu > 0) → dừng timer + raise [`Failed`](L2tpControlChannel.cs#L49) (peer im lặng), `L2tpClient` chuyển thành `Disconnected`.
- So sánh seq wrap-around 16-bit: [`SeqLess`](L2tpControlChannel.cs#L165).

### 3. Encode/decode header (`L2tpCodec`)

- **Control:** [`EncodeControl`](L2tpCodec.cs#L23) ghi header 12 byte (cờ T=L=S=1, Ver=2, Length, TunnelId, SessionId, Ns, Nr) + AVP Message Type + các AVP; [`DecodeControl`](L2tpCodec.cs#L48) parse header theo cờ rồi duyệt AVP (AVP đầu là Message Type).
- **Data:** [`EncodeData`](L2tpCodec.cs#L98) bọc PPP frame trong header tối thiểu 6 byte (T=0); [`TryDecodeData`](L2tpCodec.cs#L110) tách PPP frame ra theo cờ L/S/O.
- **Định tuyến datagram:** [`OnDatagram`](L2tpClient.cs#L262) gọi [`IsControl`](L2tpCodec.cs#L20) — control đưa vào control channel, data giải mã rồi **demux theo `sessionId`**: tra `_sessions` và raise `DataReceived` đúng `L2tpSession` (gói cho session không tồn tại bị bỏ).

### 4. AVP (`L2tpAvp`)

[`Write`](Models/L2tpAvp.cs#L49) đóng gói cờ M|H + length 10-bit + VendorId + Type + Value; [`Parse`](Models/L2tpAvp.cs#L64) làm ngược lại. Helper [`UInt16`/`UInt32`/`Text`](Models/L2tpAvp.cs#L32-L41) tạo value big-endian/ASCII.

## Trạng thái & ghi chú

- **Đã hiện thực (as-built):** vai trò **LAC/initiator** với một tunnel + **một hoặc nhiều** session; bắt tay đầy đủ SCCRQ/SCCRP/SCCCN + ICRQ/ICRP/ICCN; control channel tin cậy (Ns/Nr, ack tích lũy, ZLB, retransmit); HELLO keepalive; teardown CDN (theo session) + StopCCN (tunnel); data plane mang PPP frame **demux theo session id**. Xem chi tiết as-built tại [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
- **Hạn chế đã biết / khung mở rộng:**
  - **Multi-session là best-effort:** đa số server remote-access chỉ cho **một** session và từ chối ICRQ thứ hai bằng CDN ([`OnCallDisconnect`](L2tpClient.cs#L220)). Session phụ mở tuần tự (một `_pendingSession` tại một thời điểm); driver L2TP/IPsec **không** tái lập session phụ khi auto-reconnect (chỉ dựng lại session chính).
  - **AVP Hidden** parse được nhưng **không giải mã** ([L2tpAvp.cs:8](Models/L2tpAvp.cs#L8), [L2tpAvp.cs:16](Models/L2tpAvp.cs#L16)).
  - **Tunnel CHAP** (Challenge/ChallengeResponse) có trong enum [`L2tpAvpType`](Enums/L2tpAvpType.cs#L37-L40) nhưng client chưa dùng để xác thực tunnel.
  - **SetLinkInfo** có trong enum nhưng `OnControl` chưa xử lý loại message này.
  - Retransmit gửi lại **message đầu hàng** với **exponential backoff + jitter** (khoảng chờ ×`BackoffMultiplier` mỗi resend tới `MaxInterval`, [`IntervalFor`](L2tpRetransmitOptions.cs#L32)); có **cap số lần thử** tùy chọn (`MaxRetransmits`, mặc định 0 = vô hạn) ở [`Retransmit`](L2tpControlChannel.cs#L114) — vượt cap raise `Failed`. Driver L2TP/IPsec đặt cap 8 + backoff 1s ×2 tới cap 8s qua `L2tpIpsecTimeoutOptions`.
  - Cửa sổ truyền/nhận hiệu dụng là **1** (gửi message tiếp theo không chặn theo `ReceiveWindowSize` đã quảng cáo).
  - Là vai trò **LAC**; không hiện thực vai trò **LNS/server**.
- **Khác biệt netstandard2.0 vs net8.0:** không có khác biệt hành vi trong project này; `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`).
- **Bảo mật transport:** L2TP ở đây **không tự mã hóa**; tính bí mật/toàn vẹn do ESP/IPsec ở tầng DRIVER cung cấp qua `IL2tpTransport`.
