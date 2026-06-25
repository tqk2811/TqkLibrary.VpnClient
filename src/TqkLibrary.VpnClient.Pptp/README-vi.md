# TqkLibrary.VpnClient.Pptp

Thư viện **protocol PPTP** (Point-to-Point Tunneling Protocol, RFC 2637; server opensource **poptop**/**accel-ppp**) thuần .NET cho driver **V.6**. Project protocol-level: codec control-connection TCP/1723, state machine control, và **CCP negotiator** ghép option **MPPE** (RFC 3078/3079, đã có ở [Crypto](../TqkLibrary.VpnClient.Crypto)) vào tầng [PPP](../TqkLibrary.VpnClient.Ppp) sẵn có.

> **Trạng thái:** **V6.a + V6.b (data plane) — phần OFFLINE xong** (code + test offline). Đã có: (1) **codec control TCP/1723** — `PptpControlCodec` encode/decode đúng wire RFC 2637 cho mọi control message (SCCRQ/SCCRP, OCRQ/OCRP, Echo-Request/Reply, Set-Link-Info, Call-Clear-Request, Call-Disconnect-Notify, Stop-Control-Connection-Request/Reply) + reassembler streaming qua mọi ranh đọc TCP; (2) **state machine control** — `PptpControlConnection` chạy luồng client (PNS): SCCRQ→SCCRP → OCRQ→OCRP → Echo keep-alive → Call-Clear/Stop, trên một [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs); (3) **CCP/MPPE negotiator** — `CcpNegotiator` (kế thừa [`PppNegotiator`](../TqkLibrary.VpnClient.Ppp/PppNegotiator.cs#L23) dùng chung) thương lượng option MPPE đơn (RFC 2118/3078), `MppeConfigOption` codec 4-byte supported-bits, `MppeSessionFactory` dựng cặp [`MppeSession`](../TqkLibrary.VpnClient.Crypto/Mppe/MppeSession.cs#L16) từ MS-CHAPv2 + kết quả CCP; (4) **GRE + MPPE data plane** — `PptpGreCodec`/`PptpGrePacket` (Enhanced GRE RFC 2637 §4.1), `PptpGreChannel` (`IPppFrameChannel` trên [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs) proto-47 — seq/ack §4.4, receive-loop), `MppePppFrameChannel` (decorator chạy CCP nội bộ + mã hóa MPPE giữa `PppEngine` ↔ GRE).
>
> **NGOÀI project này (driver runtime, cần F.9 raw-IP, elevate):** project Pptp là protocol-only — `PptpGreChannel` cần một `IDatagramTransport` proto-47 thật (raw socket IP, **đường duy nhất** userspace gửi/nhận proto-47). **F.9 [`Transport.RawIp`](../TqkLibrary.VpnClient.Transport.RawIp) đã có** và driver runtime đã ráp ở project riêng [`Drivers.Pptp`](../TqkLibrary.VpnClient.Drivers.Pptp) (supervisor/reconnect). Trong project này codec + channel + decorator được test **offline** toàn bộ.
>
> **VALIDATE LIVE (2026-06-24, lab [`pptp`](../../lab/pptp/README-vi.md) — accel-ppp PPTP Docker, no-NAT bridge):** client **ĐÚNG tới tầng MPPE, khớp byte-for-byte với reference `pptp`+`pppd`** — control/GRE-47/LCP/MS-CHAPv2/CCP-MPPE OK, **MPPE encrypt byte-perfect** (gói mã hóa đầu giải mã ra IPCP hợp lệ bằng reference Python, khớp thuật toán kernel `ppp_mppe.c`). **2 bug protocol-này sửa qua live:** (1) **GRE double-FF03** (`PptpGreChannel`, idempotent prepend — xem §GRE data plane); (2) **IPCP-trước-CCP** — `MppePppFrameChannel.CcpOpened` nay được `PptpConnection` dùng để hoãn network layer (gói IPCP đầu mã hóa). Bug thứ 3 (**MPPE stateless first-packet rekey**) ở [`Crypto/Mppe/MppeSession`](../TqkLibrary.VpnClient.Crypto/Mppe/MppeSession.cs#L100). **IPCP blocked SERVER-SIDE** (accel-ppp không mở IPCP, reference `pppd` fail y hệt) ⇒ chờ server PPTP khác để chốt full ICMP — chi tiết [lab/pptp](../../lab/pptp/README-vi.md).
>
> **CẢNH BÁO BẢO MẬT:** MS-CHAPv2 + MPPE/RC4 **đã bị phá** (MS-CHAPv2 brute-force DES, MPPE không toàn vẹn) — chỉ dùng để **tương thích** server PPTP cũ, **không** dùng cho dữ liệu nhạy cảm.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [OpenConnect](../TqkLibrary.VpnClient.OpenConnect)/[WireGuard](../TqkLibrary.VpnClient.WireGuard)/[SoftEther](../TqkLibrary.VpnClient.SoftEther)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)): khối giao thức thuần, I/O đi qua seam [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) (TCP/1723 thật do driver cấp). PPTP **tái dùng nguyên PPP** (LCP/MS-CHAPv2/IPCP của [`PppEngine`](../TqkLibrary.VpnClient.Ppp/PppEngine.cs#L17)) chạy **trên kênh GRE** (data plane V.6 sau, cần F.9); CCP chỉ thêm một negotiator MPPE.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) (control TCP/1723), [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs) (GRE proto-47), `ILogger` (transitive `Microsoft.Extensions.Logging.Abstractions`) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | MPPE F.5b: [`MsChapV2`](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs) (`DeriveMppe*StartKey`), [`MppeSession`](../TqkLibrary.VpnClient.Crypto/Mppe/MppeSession.cs#L16), [`MppeKeyStrength`](../TqkLibrary.VpnClient.Crypto/Mppe/Enums/MppeKeyStrength.cs) |
| Dùng | [Ppp](../TqkLibrary.VpnClient.Ppp) | [`PppNegotiator`](../TqkLibrary.VpnClient.Ppp/PppNegotiator.cs#L23) (CCP kế thừa), [`PppControlCodec`](../TqkLibrary.VpnClient.Ppp/PppControlCodec.cs#L9)/[`PppOption`](../TqkLibrary.VpnClient.Ppp/Models/PppOption.cs#L4), [`IPppFrameChannel`](../TqkLibrary.VpnClient.Ppp/Interfaces/IPppFrameChannel.cs) (GRE + MPPE decorator hiện thực), `PppProtocol.Ccp`/`Compressed`/`Lcp`/`Ip` |
| Được dùng bởi | [Drivers.Pptp](../TqkLibrary.VpnClient.Drivers.Pptp) (driver runtime V.6: control TCP/1723 + GRE proto-47 data plane qua raw-IP F.9) |

> `System.Buffers.Binary.BinaryPrimitives` (big-endian codec) + `System.Threading.Channels` (test) có cả 2 TFM.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Pptp/
├─ PptpControlCodec.cs           Codec wire RFC 2637 (encode/decode mọi control message) + reassembler streaming
├─ PptpControlConnection.cs      State machine control (PNS/client) trên IByteStreamTransport
├─ Enums/
│  ├─ PptpMessageType.cs         PPTP Message Type (Control=1/Management=2)
│  ├─ PptpControlMessageType.cs  Control Message Type (SCCRQ=1 ... Set-Link-Info=15)
│  ├─ PptpResultCode.cs          General Result Code (Successful=1, NotAuthorized=4...)
│  ├─ PptpFramingCapability.cs   Bitmask Framing Capabilities (Async/Sync)
│  ├─ PptpBearerCapability.cs    Bitmask Bearer Capabilities (Analog/Digital)
│  ├─ PptpControlState.cs        Trạng thái rút gọn state machine (Idle→...→CallEstablished→Closed)
│  ├─ CcpOptionType.cs           Loại option CCP (MPPE/MPPC = 18)
│  └─ MppeSupportedBits.cs       Field 32-bit supported-bits MPPE (40/56/128-bit + Stateless + MPPC)
├─ Interfaces/
│  └─ IPptpControlMessage.cs     Hợp đồng một control message (tự biết ControlMessageType)
├─ Models/
│  ├─ PptpControlHeader.cs       Header chung 8-byte + magic cookie 0x1A2B3C4D
│  ├─ StartControlConnectionRequest.cs / StartControlConnectionReply.cs   SCCRQ/SCCRP (§2.1/§2.2)
│  ├─ OutgoingCallRequest.cs / OutgoingCallReply.cs                       OCRQ/OCRP (§2.7/§2.8)
│  ├─ EchoRequest.cs / EchoReply.cs                                       Echo (§2.5/§2.6)
│  ├─ SetLinkInfo.cs                                                      Set-Link-Info (§2.15)
│  ├─ CallClearRequest.cs / CallDisconnectNotify.cs                       Call-Clear/CDN (§2.12/§2.13)
│  └─ StopControlConnectionRequest.cs / StopControlConnectionReply.cs     Stop-CC (§2.3/§2.4)
├─ Ccp/
│  ├─ MppeConfigOption.cs        Codec option MPPE (4-byte supported-bits ↔ MppeKeyStrength + stateless)
│  ├─ CcpNegotiator.cs           Negotiator CCP (kế thừa PppNegotiator): offer/ack/Nak/reject option MPPE
│  ├─ MppeSessionFactory.cs      Dựng cặp MppeSession (send/receive) từ MS-CHAPv2 + kết quả CCP
│  └─ MppePppFrameChannel.cs     Decorator IPppFrameChannel: chạy CCP nội bộ + mã hóa/giải mã MPPE (PppEngine ↔ GRE)
└─ Gre/
   ├─ PptpGrePacket.cs           Model một gói Enhanced GRE (CallId/Seq/Ack/Payload)
   ├─ PptpGreCodec.cs            Codec static Encode/TryDecode Enhanced GRE (RFC 2637 §4.1)
   └─ PptpGreChannel.cs          Kênh data plane IPppFrameChannel trên IDatagramTransport proto-47 (seq/ack §4.4)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `PptpControlCodec` | static `Encode(message)`/`Decode(packet)` cho mọi control message; instance `Append(chunk)`+`TryReadMessage(out)` ráp gói qua mọi ranh đọc TCP; reject magic cookie sai / length mismatch | [PptpControlCodec.cs:22](PptpControlCodec.cs#L22) |
| `PptpControlConnection` | state machine PNS/client: `EstablishControlConnectionAsync` (SCCRQ→SCCRP) · `PlaceOutgoingCallAsync` (OCRQ→OCRP) · `SendEchoRequestAsync`/`SendSetLinkInfoAsync` · `ClearCallAsync`/`StopControlConnectionAsync`; `ReadMessageAsync` auto-reply Echo-Request; lộ `LocalCallId`/`PeerCallId` (GRE Call-ID cho data plane sau) | [PptpControlConnection.cs:22](PptpControlConnection.cs#L22) |
| `IPptpControlMessage` | hợp đồng control message (tự biết `ControlMessageType`) — codec dùng để ghi header chung | [Interfaces/IPptpControlMessage.cs:10](Interfaces/IPptpControlMessage.cs#L10) |
| `PptpControlHeader` | header chung 8-byte + hằng `MagicCookie` (0x1A2B3C4D) | [Models/PptpControlHeader.cs:14](Models/PptpControlHeader.cs#L14) |
| `PptpControlMessageType` | enum Control Message Type (SCCRQ=1 … WAN-Error-Notify=14, Set-Link-Info=15) | [Enums/PptpControlMessageType.cs:7](Enums/PptpControlMessageType.cs#L7) |
| `PptpResultCode` | enum General Result Code (Successful=1, GeneralError=2, NotAuthorized=4, UnsupportedProtocolVersion=5) | [Enums/PptpResultCode.cs:9](Enums/PptpResultCode.cs#L9) |
| `PptpControlState` | enum trạng thái rút gọn (Idle/ControlConnectionEstablished/CallEstablished/Closed…) | [Enums/PptpControlState.cs:8](Enums/PptpControlState.cs#L8) |
| Model SCCRQ/SCCRP/OCRQ/OCRP/Echo/SetLinkInfo/CallClear/CDN/Stop-CC | POCO từng control message theo wire RFC 2637 §2.x | [Models/](Models/) |
| `MppeSupportedBits` | enum [Flags] field 32-bit supported-bits (40=0x20/128=0x40/56=0x80, Stateless=0x01000000, MPPC=0x01) | [Enums/MppeSupportedBits.cs:20](Enums/MppeSupportedBits.cs#L20) |
| `MppeConfigOption` | codec option MPPE: `EncodeValue`/`DecodeValue` (4-byte BE) ↔ `Strength` ([`MppeKeyStrength`](../TqkLibrary.VpnClient.Crypto/Mppe/Enums/MppeKeyStrength.cs))/`Stateless`; bit mạnh nhất thắng khi nhiều bit | [Ccp/MppeConfigOption.cs:19](Ccp/MppeConfigOption.cs#L19) |
| `CcpNegotiator` | negotiator CCP kế thừa [`PppNegotiator`](../TqkLibrary.VpnClient.Ppp/PppNegotiator.cs#L23): offer option MPPE, `OnNak` adopt cường độ server pin, `EvaluatePeerRequest` cap về cường độ tối đa + pin 1 bit, `OnReject` ⇒ `NotSupportedException`; lộ `NegotiatedStrength`/`NegotiatedStateless` sau `Opened` | [Ccp/CcpNegotiator.cs:22](Ccp/CcpNegotiator.cs#L22) |
| `MppeSessionFactory` | static `CreateClientSessions(password, ntResponse, negotiated)` → cặp [`MppeSession`](../TqkLibrary.VpnClient.Crypto/Mppe/MppeSession.cs#L16) send/receive (RFC 3079 asymmetric start keys) | [Ccp/MppeSessionFactory.cs:20](Ccp/MppeSessionFactory.cs#L20) |
| `PptpGrePacket` | model 1 gói Enhanced GRE: `ushort CallId`, `uint? SequenceNumber`, `uint? AckNumber`, `ReadOnlyMemory<byte> Payload` (`init`) | [Gre/PptpGrePacket.cs:11](Gre/PptpGrePacket.cs#L11) |
| `PptpGreCodec` | static `Encode(packet)`/`TryDecode(span, out packet)` Enhanced GRE (RFC 2637 §4.1): K=1, Ver=1, ProtocolType=0x880B, Key high=payload-len + low=Call ID, Seq (S=1)/Ack (A=1) tùy chọn; `TryDecode` reject sai version/proto-type/thiếu Key/truncated | [Gre/PptpGreCodec.cs:20](Gre/PptpGreCodec.cs#L20) |
| `PptpGreChannel` | `IPppFrameChannel`+`IAsyncDisposable` trên [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs) proto-47: `ctor(transport, localCallId, peerCallId, ILogger?)` · `Start()` chạy receive-loop · gửi strip `FF 03`, seq tăng/ack piggyback (§4.4); nhận lọc theo `localCallId`, re-prepend `FF 03` raise `FrameReceived` | [Gre/PptpGreChannel.cs:21](Gre/PptpGreChannel.cs#L21) |
| `MppePppFrameChannel` | decorator `IPppFrameChannel` giữa `PppEngine` ↔ GRE: `ctor(inner, keyProvider, preferredStrength=128, stateless=false)` · `StartCcp()` · `CcpOpenedTask`/`CcpOpened`/`IsActive`; LCP plaintext, còn lại mã hóa `MppeSession` → proto 0x00FD khi CCP Opened; nhận CCP (0x80FD) tự xử, Compressed (0x00FD) giải mã, còn lại pass-through | [Ccp/MppePppFrameChannel.cs:23](Ccp/MppePppFrameChannel.cs#L23) |

## Wire control RFC 2637 (header chung 12-byte)

```
Length(2 BE) | PPTP-Message-Type(2 BE) | Magic-Cookie(4 = 0x1A2B3C4D) | Control-Message-Type(2 BE) | Reserved0(2)
```

- **Length** = tổng độ dài gói (header + body). Mọi số nguyên đa-byte là **big-endian** (network order); field chuỗi cố định là ASCII NUL-pad.
- **Magic-Cookie** 0x1A2B3C4D cố định mọi gói control; sai ⇒ `FormatException` (desync).
- Kích thước gói các message (đã phủ test): SCCRQ/SCCRP = 156, OCRQ = 168, OCRP = 32, Echo-Request = 16, Echo-Reply = 20, Set-Link-Info = 24, Call-Clear-Request = 16, Call-Disconnect-Notify = 148, Stop-CC-Request/Reply = 16.
- **Reassembler** (`Append`+`TryReadMessage`): đọc Length 2-byte đầu rồi gom đủ `Length` byte mới decode — ráp gói nguyên qua mọi ranh đọc TCP (1 gói cắt nhiều read / nhiều gói gộp 1 read).

## CCP / MPPE (RFC 1962 + RFC 2118/3078)

- **Option MPPE** (CCP option type 18, length 6): 2-byte header TLV + **4-byte supported-bits** big-endian. `MppeConfigOption` map field ↔ `MppeKeyStrength` (40/56/128) + cờ `Stateless`.
- **Negotiate** (`CcpNegotiator` trên `PppNegotiator`): client offer cường độ ưu tiên (mặc định 128-bit, stateful); server thường **Nak** để pin một cường độ → client `OnNak` adopt; client `EvaluatePeerRequest` cap offer của peer về cường độ tối đa của mình + pin **đúng một bit** (RFC 3078 §3.1). Peer **reject** option MPPE ⇒ `NotSupportedException` (không có gì để mã hóa).
- **Ráp khóa data plane** (`MppeSessionFactory`): `MasterKey = MsChapV2.DeriveMppeMasterKey(password, ntResponse)` → `Send/ReceiveStartKey` (RFC 3079 §3.3 asymmetric) → cặp `MppeSession` (client encrypt bằng send, decrypt bằng receive). Khóa **đối xứng** với server (receive-start server = send-start client) — phủ test interop encrypt/decrypt 2 chiều cho cả 40/56/128-bit + stateless.

## GRE data plane (RFC 2637 §4 — Enhanced GRE, IP proto 47)

```
Byte0: C R K S s Recur(3)   → 0x30 khi có payload (K=1,S=1) / 0x20 ack-only (K=1,S=0)
Byte1: A Flags(4) Ver(3)    → 0x01 (no ack) / 0x81 (A=1); Ver=1 (enhanced)
Bytes2-3: ProtocolType      = 0x880B
Bytes4-5: Key high word     = Payload Length
Bytes6-7: Key low word      = Call ID
[Seq(4 BE) nếu S=1] [Ack(4 BE) nếu A=1] [Payload]
```

- **`PptpGreCodec`** (pure static): `Encode` ráp header trên + payload; `TryDecode` validate Ver==1, ProtocolType==0x880B, bit K set, bounds-check → `false` nếu malformed (sai version/proto-type/thiếu Key/truncated).
- **`PptpGreChannel`** (`IPppFrameChannel` trên `IDatagramTransport`): gửi strip `FF 03` (GRE chở PPP **không** HDLC Address/Control), stamp `peerCallId`, **seq tăng mỗi gói payload**, **ack piggyback** = seq cao nhất nhận được (§4.4); receive-loop kiểu native-ESP (identity-guard + dispose-để-unblock) lọc gói theo `localCallId`, re-prepend `FF 03` **idempotent** rồi raise `FrameReceived`. Gói ack-only (không payload) chỉ cập nhật sổ ack. **⚠️ Idempotent prepend (bug live V.6):** PAC thật (kernel `pptp`/accel-ppp GRE) **GIỮ** `FF 03` TRONG payload GRE (trái §4.3) — prepend vô điều kiện sẽ double thành `FF 03 FF 03 …` ⇒ PPP engine đọc proto = `0xFF03`, không dispatch ⇒ kẹt LCP; vì vậy chỉ thêm `FF 03` khi payload chưa có (regression test `PptpGreChannelTests`).
- **`MppePppFrameChannel`** (decorator): chạy CCP **bên trong** (PppEngine không thấy 0x80FD), khi CCP `Opened` thì `keyProvider()` → `MppeSessionFactory.CreateClientSessions` → bật MPPE; gửi LCP plaintext, còn lại `MppeSession.Encrypt` → `[FF 03][00 FD][cipher]`; nhận Compressed → `Decrypt` → raise lên, các proto khác pass-through. Cờ active + sessions khóa bằng `lock`.

## Luồng nội bộ (control plane, client)

1. **Control connection.** `EstablishControlConnectionAsync` gửi `StartControlConnectionRequest` → đọc `StartControlConnectionReply`; `ResultCode != Successful` ⇒ `InvalidOperationException` (server từ chối) — [PptpControlConnection.cs:68](PptpControlConnection.cs#L68).
2. **Place call.** `PlaceOutgoingCallAsync(callId)` gửi `OutgoingCallRequest` (CallID = GRE Call-ID ta nhận) → đọc `OutgoingCallReply`; thành công ghi `PeerCallId` = `reply.CallId` (Call-ID ta gắn lên gói GRE gửi đi) — [PptpControlConnection.cs:99](PptpControlConnection.cs#L99).
3. **Keep-alive & link-info.** `SendEchoRequestAsync` (peer phải Echo-Reply cùng Identifier) + `SendSetLinkInfoAsync` (ACCM) — [PptpControlConnection.cs:131](PptpControlConnection.cs#L131). `ReadMessageAsync` **auto-reply** mọi `Echo-Request` nhận được — [PptpControlConnection.cs:181](PptpControlConnection.cs#L181).
4. **Teardown.** `ClearCallAsync` (Call-Clear-Request → Call-Disconnect-Notify, về `ControlConnectionEstablished`) rồi `StopControlConnectionAsync` (Stop-Request → Stop-Reply, về `Closed`) — [PptpControlConnection.cs:147](PptpControlConnection.cs#L147).
5. **Data plane (offline xong, V6.b).** `PptpGreChannel` (dựng từ `LocalCallId`/`PeerCallId` trên `IDatagramTransport` proto-47) ↔ `MppePppFrameChannel` ↔ `PppEngine` (LCP/MS-CHAPv2/IPCP **tái dùng nguyên**). Decorator chạy `CcpNegotiator` nội bộ; khi CCP Opened → `MppeSessionFactory` dựng cặp `MppeSession` mã hóa payload PPP thành proto 0x00FD. **Còn lại — cần raw-IP F.9:** một `IDatagramTransport` proto-47 thật + project driver `Drivers.Pptp` (supervisor/reconnect + `UsePptp`) + validate live.

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| **RFC 2637** (PPTP) | toàn bộ control codec + state machine | §2.x control messages, §2.1 header + magic 0x1A2B3C4D, §3.1 FSM |
| **RFC 1962** (CCP) | `CcpNegotiator` | option-negotiation TLV trên PPP 0x80FD |
| **RFC 2118** (MPPC) / **RFC 3078** (MPPE) | `MppeConfigOption`, `CcpNegotiator` | option type 18, 4-byte supported-bits §3.1 |
| **RFC 3079** (suy khóa MPPE) | `MppeSessionFactory` | asymmetric Send/Receive start key §3.3 (qua [Crypto](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs)) |
| **RFC 2637 §4** (Enhanced GRE) | `PptpGreCodec`/`PptpGreChannel` | §4.1 header (K=1/Ver=1/0x880B, Key high=len + low=Call ID), §4.3 PPP không HDLC AC, §4.4 seq/ack |
| poptop / accel-ppp (behavior) | interop | re-implement từ spec/behavior — **không copy code GPL** |

## Trạng thái & ghi chú

- **Thuần protocol, thuần client (PNS):** codec không I/O; `PptpControlConnection` chạy I/O **qua seam `IByteStreamTransport`** (socket TCP/1723 do driver cấp), không tự mở socket. Re-implement từ RFC 2637 + behavior poptop/accel-ppp (**không copy GPL source**).
- **Phạm vi project này (protocol V6.a + V6.b):** control codec + state machine + CCP/MPPE negotiate + ráp khóa MPPE + **GRE codec/channel + decorator MPPE** (data plane, `IPppFrameChannel` trên `IDatagramTransport`). **Driver runtime đã ráp ở [Drivers.Pptp](../TqkLibrary.VpnClient.Drivers.Pptp)** (supervisor/reconnect + ráp control TCP/1723 + GRE proto-47), chạy trên transport raw-IP **F.9 `Transport.RawIp`** ([RawIpDatagramTransport](../TqkLibrary.VpnClient.Transport.RawIp/RawIpDatagramTransport.cs), raw socket, elevate). Khác biệt design ghi ở [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md).
- **Bảo mật:** MS-CHAPv2 + MPPE/RC4 **đã bị phá** — chỉ để tương thích server PPTP cũ.
- Build xanh cả `netstandard2.0` + `net8.0`. Codec dùng `BinaryPrimitives` + `Span` (cả 2 TFM qua `System.Memory`); reassembly dùng `List<byte>` (zero-alloc là Q.4). `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` ở [Directory.Build.props:16-25](../Directory.Build.props#L16-L25).
- Lộ trình V.6 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.6.
