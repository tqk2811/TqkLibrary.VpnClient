# TqkLibrary.Vpn.Drivers.Sstp

> Driver VPN **MS-SSTP**: TLS trên 443, handshake `SSTP_DUPLEX_POST`, control message theo `[MS-SSTP]`, PPP/MS-CHAPv2, crypto binding; **active keepalive + teardown sạch + auto-reconnect**. Đây là nơi lắp ráp toàn bộ stack SSTP thành một `IVpnConnection` hoàn chỉnh.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối control plane cho giao thức MS-SSTP. Nó dựng TLS, chạy handshake SSTP, đẩy PPP/MS-CHAPv2 qua kênh SSTP, gắn **crypto binding** (ràng buộc HLAK của PPP vào cert TLS để chống MITM), rồi bọc lại sau interface trung lập `IVpnConnection` để tầng `TqkLibrary.Vpn` ở trên tiêu thụ mà không cần biết giao thức cụ thể.

Driver MS-SSTP ([SstpDriver.cs:8](SstpDriver.cs#L8)) gồm: TLS trên 443 (**mặc định** chấp nhận mọi cert — xác thực bằng crypto binding chứ không PKI; tùy chọn truyền `RemoteCertificateValidationCallback` để validate cert — P0.6), handshake `SSTP_DUPLEX_POST`, control message `[MS-SSTP]`, PPP RAW (không HDLC) + MS-CHAPv2, và crypto binding `CMK = HMAC-SHA256(HLAK,…)`. Kèm **vòng đời đầy đủ mirror driver L2TP/IPsec**: active keepalive (SSTP Echo-Request), teardown sạch (Call-Disconnect), và auto-reconnect (exponential backoff) sau một facade kênh ổn định. SSTP **không** có khái niệm rekey SA (phiên TLS sống dài).

> Driver L2TP/IPsec nằm ở project anh em [TqkLibrary.Vpn.Drivers.L2tpIpsec](../TqkLibrary.Vpn.Drivers.L2tpIpsec). Trước đây hai driver chung một project `TqkLibrary.Vpn.Drivers` (subfolder `L2tpIpsec/`+`Sstp/`); đã tách thành 2 project, file phẳng ở gốc, namespace giữ nguyên.

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.Vpn` ở trên và các project PROTOCOL ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference) — CHỈ 2 project:**
  - [TqkLibrary.Vpn.Abstractions](../TqkLibrary.Vpn.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, typed exception...).
  - [TqkLibrary.Vpn.Ppp](../TqkLibrary.Vpn.Ppp) — `PppEngine`, `MsChapV2Authenticator` (+ `DeriveHlak`), `IPppFrameChannel`.
  - **Không** ref `Ipsec` / `L2tp` — SSTP tự cuộn TLS bằng BCL (`TcpClient` + `SslStream`, `HMACSHA256`, `SHA256`); TLS-over-TCP tách vào [`TlsByteStream`](Transport/TlsByteStream.cs#L20) sau seam [`ITlsByteStream`](Transport/ITlsByteStream.cs#L14) (impl đầu tiên của `IByteStreamTransport` — P0.1), `SstpTransport` chỉ còn handshake + framing.
- **Được dùng bởi:** [TqkLibrary.Vpn](../TqkLibrary.Vpn) (entry point — `VpnClientBuilder.UseSstp()` / `UseSstp(SstpReconnectOptions)` / `UseSstp(RemoteCertificateValidationCallback)` / `UseSstp(SstpReconnectOptions, RemoteCertificateValidationCallback)` đăng ký driver này).

## Cấu trúc thư mục

> File **phẳng ở gốc project** (không còn subfolder `Sstp/`); chỉ giữ `Enums/`+`Models/`.

```
TqkLibrary.Vpn.Drivers.Sstp/
├── SstpDriver.cs                IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
├── SstpConnection.cs            Bộ điều phối: TLS + control + PPP + crypto binding + keepalive + teardown + reconnect
├── SstpTransport.cs             SSTP_DUPLEX_POST handshake + framing gói SSTP 4-byte header (trên ITlsByteStream)
├── SstpControlCodec.cs          Encode/decode body control message ([MS-SSTP] §2.2.2–2.2.3)
├── SstpCryptoBinding.cs         CMK/Compound-MAC (HMAC-SHA256) cho Call Connected
├── SstpPppChannel.cs            Cầu nối SSTP data ↔ PPP (RAW PPP, không HDLC) + dispatch control
├── SstpConstants.cs             Hằng số [MS-SSTP] (version 0x10, DuplexUri, hash protocol...)
├── SstpReconnectOptions.cs      Chính sách auto-reconnect (backoff/jitter/max attempts)
├── SstpVpnConnection.cs         Adapter sang IVpnConnection (một session)
├── SstpVpnSession.cs            IVpnSession: facade ổn định + áp dụng reconnect vào TunnelConfig
├── Transport/                   Seam byte-stream TLS: ITlsByteStream + TlsByteStream (TcpClient+SslStream)
├── Enums/                       SstpMessageType, SstpAttributeId, SstpConnectionState
└── Models/                      SstpAttribute, SstpControlMessage, SstpReconnectInfo
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `SstpDriver` | `IVpnProtocolDriver`: capabilities + `ConnectAsync` → `IVpnConnection`; ctor nhận `SstpReconnectOptions` + `RemoteCertificateValidationCallback` (cert TLS, P0.6 — null ⇒ accept all); wire `Reconnected`→`ApplyReconnect` | [SstpDriver.cs:8](SstpDriver.cs#L8) |
| `SstpConnection` | Bộ điều phối: TLS + control + PPP + crypto binding + active Echo keepalive + teardown + supervisor reconnect; nhận `Func<ITlsByteStream>` factory (seam test offline) | [SstpConnection.cs:23](SstpConnection.cs#L23) |
| `SstpTransport` | `SSTP_DUPLEX_POST` handshake + framing gói SSTP 4-byte header trên `ITlsByteStream` (ctor seam + ctor back-compat `(host, port)`); **read-timeout** tùy chọn (P1.5 — cap read không-tiến-triển ⇒ `TimeoutException`) | [SstpTransport.cs:15](SstpTransport.cs#L15) |
| `ITlsByteStream` | Seam: `IByteStreamTransport` + `RemoteCertificate` (cert cho crypto binding) — cho phép fake stream test offline | [Transport/ITlsByteStream.cs:14](Transport/ITlsByteStream.cs#L14) |
| `TlsByteStream` | Hiện thực TLS-over-TCP (`TcpClient`+`SslStream`), bắt cert, callback validate cert TLS tùy chọn (P0.6 — null ⇒ accept all), honor `CancellationToken` cả 2 TFM — impl đầu tiên của `IByteStreamTransport` | [Transport/TlsByteStream.cs:20](Transport/TlsByteStream.cs#L20) |
| `SstpControlCodec` | Build/parse body control message (type + attributes) | [SstpControlCodec.cs:7](SstpControlCodec.cs#L7) |
| `SstpCryptoBinding` | Dựng attribute Crypto Binding (CMK + Compound-MAC) cho Call Connected | [SstpCryptoBinding.cs:13](SstpCryptoBinding.cs#L13) |
| `SstpPppChannel` | `IPppFrameChannel`: RAW PPP frame trong SSTP data packet + dispatch control | [SstpPppChannel.cs:11](SstpPppChannel.cs#L11) |
| `SstpConstants` | Hằng số `[MS-SSTP]` (Version 0x10, DuplexUri, hash protocol) | [SstpConstants.cs:4](SstpConstants.cs#L4) |
| `SstpReconnectOptions` | Chính sách auto-reconnect: backoff/jitter/max attempts + **`ReadTimeout`** (cap read không-tiến-triển, P1.5 — mặc định 60s, `Timeout.InfiniteTimeSpan` tắt) | [SstpReconnectOptions.cs:8](SstpReconnectOptions.cs#L8) |
| `SstpVpnConnection` / `SstpVpnSession` | Adapter `IVpnConnection` / `IVpnSession` (facade ổn định + `ApplyReconnect`) | [SstpVpnConnection.cs:6](SstpVpnConnection.cs#L6) · [SstpVpnSession.cs:10](SstpVpnSession.cs#L10) |
| `SstpMessageType` / `SstpAttributeId` / `SstpConnectionState` | Enum control type / attribute id / trạng thái vòng đời | [Enums/SstpMessageType.cs:4](Enums/SstpMessageType.cs#L4) · [Enums/SstpAttributeId.cs:4](Enums/SstpAttributeId.cs#L4) · [Enums/SstpConnectionState.cs:4](Enums/SstpConnectionState.cs#L4) |
| `SstpAttribute` / `SstpControlMessage` / `SstpReconnectInfo` | Model attribute / control message / kết quả reconnect | [Models/SstpAttribute.cs:4](Models/SstpAttribute.cs#L4) · [Models/SstpControlMessage.cs:6](Models/SstpControlMessage.cs#L6) · [Models/SstpReconnectInfo.cs:6](Models/SstpReconnectInfo.cs#L6) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|-------------------------|--------------------|---------|
| `[MS-SSTP]` §2.2.1, §3 (transport + framing) | `SstpTransport` | [SstpTransport.cs:11](SstpTransport.cs#L11) | Comment dẫn rõ tiết diện; TLS bên dưới là `ITlsByteStream` |
| `[MS-SSTP]` §2.2.2–2.2.3 (control message + attributes) | `SstpControlCodec` | [SstpControlCodec.cs:6](SstpControlCodec.cs#L6) | Comment dẫn rõ |
| `[MS-SSTP]` §2.2.2 (message types) | `SstpMessageType` | [Enums/SstpMessageType.cs:3](Enums/SstpMessageType.cs#L3) | Gồm Echo-Request/Response, Call-Disconnect/Abort... |
| `[MS-SSTP]` §2.2.3 (attribute ids) | `SstpAttributeId` | [Enums/SstpAttributeId.cs:3](Enums/SstpAttributeId.cs#L3) | Comment dẫn rõ |
| `[MS-SSTP]` §2.2.7, §3.2.5.2 (Crypto Binding) | `SstpCryptoBinding` | [SstpCryptoBinding.cs:9](SstpCryptoBinding.cs#L9) | CMK = HMAC-SHA256(HLAK, seed) |
| `[MS-SSTP]` (hằng số chung) | `SstpConstants` | [SstpConstants.cs:3](SstpConstants.cs#L3) | Version 0x10, DuplexUri |
| `[MS-SSTP]` (RAW PPP per packet, không HDLC) | `SstpPppChannel` | [SstpPppChannel.cs:6](SstpPppChannel.cs#L6) | Comment dẫn rõ |
| `[MS-SSTP]` (Echo keepalive + Call-Disconnect teardown) | `SstpConnection` (active Echo + clean teardown + reconnect) | [SstpConnection.cs:272](SstpConnection.cs#L272) | Echo-Request 30s, chết sau 3 lần thiếu Echo-Response; teardown gửi Call-Disconnect |
| FIPS PUB 198-1 / RFC 6234 (HMAC-SHA-256) | `SstpCryptoBinding` (`HMACSHA256` BCL) | [SstpCryptoBinding.cs:44](SstpCryptoBinding.cs#L44) | (suy luận) — dùng `System.Security.Cryptography.HMACSHA256` |
| FIPS PUB 180-4 (SHA-256, hash cert TLS) | `SstpConnection` (`SHA256.Create()`) | [SstpConnection.cs:178](SstpConnection.cs#L178) | (suy luận) |
| RFC 8446 / 5246 (TLS, qua `SslStream`) | `TlsByteStream` (seam `ITlsByteStream`) | [Transport/TlsByteStream.cs:71](Transport/TlsByteStream.cs#L71) | (suy luận) — BCL `SslStream.AuthenticateAsClientAsync`; net8.0 dùng overload có `CancellationToken`; cert validate qua `RemoteCertificateValidationCallback` tùy chọn (P0.6) |
| RFC 2759 (MS-CHAPv2) | `MsChapV2Authenticator` (dùng từ `Ppp`) | [SstpConnection.cs:166](SstpConnection.cs#L166) | (suy luận) — hiện thực nằm ở project `Ppp` |
| RFC 3079 (MPPE/HLAK key derivation) + `[MS-SSTP]` crypto binding | `MsChapV2Authenticator.DeriveHlak` (từ `Ppp`) | [SstpConnection.cs:176](SstpConnection.cs#L176) | (suy luận) — derive ở `Ppp`, dùng tại đây |
| RFC 1661 / 1332 (PPP LCP + IPCP) | `PppEngine` (từ `Ppp`) | [SstpConnection.cs:167](SstpConnection.cs#L167) | (suy luận) — hiện thực ở `Ppp` |

> Lưu ý: chuẩn được **hiện thực trực tiếp** trong project này là toàn bộ `[MS-SSTP]` (TLS handshake, control codec, crypto binding, framing, Echo keepalive, Call-Disconnect teardown); MS-CHAPv2/PPP/HLAK derive là **gọi** sang project `Ppp`.

## API / cách dùng

Điểm vào công khai là driver `SstpDriver` (`IVpnProtocolDriver`). Thông thường tầng `TqkLibrary.Vpn` (`VpnClientBuilder.UseSstp()`) đăng ký driver và gọi `ConnectAsync`; có thể dùng trực tiếp:

```csharp
// MS-SSTP — auto-reconnect bật mặc định; cert TLS mặc định chấp nhận mọi cert
var sstp = new SstpDriver(); // hoặc new SstpDriver(new SstpReconnectOptions { Enabled = false })
                             // hoặc new SstpDriver(certificateValidationCallback: (sender, cert, chain, errors) => /* validate */ true)  // P0.6
IVpnConnection conn = await sstp.ConnectAsync(
    new VpnEndpoint("sstp.example.com", 443),
    new VpnCredentials { Username = "user", Password = "pass" });

IVpnSession session = conn.Sessions[0];
IPacketChannel channel = session.PacketChannel;   // kênh L3 ổn định, sống qua reconnect
IPAddress myIp = session.Config.AssignedAddress;
await conn.DisposeAsync();                          // teardown sạch: gửi SSTP Call-Disconnect rồi đóng transport
```

Class hạ tầng `SstpConnection` cũng public nếu cần điều khiển chi tiết (sự kiện `StateChanged`/`Reconnected`, `DisconnectAsync`...). Lỗi kết nối ném typed exception (`VpnAuthenticationException` / `VpnServerRejectedException` / `VpnNetworkTimeoutException` — đều kế thừa `VpnConnectionException`).

## Luồng nội bộ

### Handshake (trong `SstpConnection.EstablishAsync` — clean-slate, dùng chung cho connect đầu và mọi reconnect)

1. `SstpTransport.ConnectAsync` (transport do `_transportFactory` cấp **mỗi attempt** — [SstpConnection.cs:69](SstpConnection.cs#L69), dựng tại [SstpConnection.cs:111](SstpConnection.cs#L111)): [`TlsByteStream.ConnectAsync`](Transport/TlsByteStream.cs#L38) làm TCP+TLS + bắt cert, rồi `SSTP_DUPLEX_POST` HTTP handshake — [SstpTransport.cs:40-79](SstpTransport.cs#L40-L79); gọi qua [SstpConnection.cs:117](SstpConnection.cs#L117). Lỗi transport tái phân loại thành typed exception (non-200 ⇒ reject; socket/TLS/IO ⇒ timeout; caller-cancel giữ nguyên) — [SstpConnection.cs:115-142](SstpConnection.cs#L115-L142).
2. Gửi `CallConnectRequest` (Encapsulated Protocol = PPP) → nhận `CallConnectAck`, lấy 32-byte nonce trong Crypto Binding Req; Nak / sai loại / crypto-binding thiếu-hoặc-ngắn ⇒ `VpnServerRejectedException` — [SstpConnection.cs:144-160](SstpConnection.cs#L144-L160).
3. `PppEngine` chạy trên `SstpPppChannel`; khi `AuthSucceeded`: lấy HLAK + SHA-256(cert) → dựng Crypto Binding → gửi `CallConnected` (auth fail ⇒ `VpnAuthenticationException`) — [SstpConnection.cs:166-186](SstpConnection.cs#L166-L186).
4. `LinkUp` (IPCP đã cấp IP) ⇒ cắm kênh PPP vào facade `SwappablePacketChannel` và bật keepalive — [SstpConnection.cs:200-205](SstpConnection.cs#L200-L205).

### Keepalive · teardown · reconnect (mirror L2TP/IPsec)

- **Active keepalive:** gửi **SSTP Echo-Request mỗi 30s**, coi peer chết sau **3 lần liên tiếp** thiếu Echo-Response (reset khi có bất kỳ control inbound); vẫn trả lời Echo-Request của server — [SstpConnection.cs:272-307](SstpConnection.cs#L272-L307) · [OnControlReceived @ :241](SstpConnection.cs#L241).
- **Phát hiện peer-dead (3 nguồn):** vòng đọc SSTP kết thúc (**chính**, lọc qua [`OnReadLoopEnded` @ :263](SstpConnection.cs#L263) — double-guard `_attemptId` + cancel vòng đọc chống vòng đọc cũ báo rớt giả), thiếu Echo-Response, và inbound **Call-Disconnect / Call-Abort** → tất cả gọi [`OnLinkLost` @ :312](SstpConnection.cs#L312).
- **Read-timeout chủ động (P1.5):** `SstpReconnectOptions.ReadTimeout` (mặc định 60s, > keepalive 30s nên im-lặng-giữa-Echo không trip; `Timeout.InfiniteTimeSpan` tắt) cấp xuống `SstpTransport` → mọi read (HTTP handshake + `ReadPacketAsync`) bị cap "không tiến triển trong ReadTimeout" ⇒ `TimeoutException`. Trong handshake map sang `VpnNetworkTimeoutException`; trong read-loop ⇒ vòng đọc kết thúc → `OnLinkLost` → reconnect (phát hiện server treo giữa chừng, không chỉ khi TLS đóng/cancel). Caller-cancel **không** bị remap (giữ `OperationCanceledException`).
- **Auto-reconnect:** `OnLinkLost` → [`ReconnectLoopAsync` @ :339](SstpConnection.cs#L339) exponential backoff + jitter (bật mặc định, cấu hình qua `SstpReconnectOptions`); thành công thì raise `Reconnected` (cập nhật `TunnelConfig` qua `SstpVpnSession.ApplyReconnect`). Tunnel mới chui sau facade ⇒ flow same-address sống sót không re-bind.
- **Teardown:** [`DisconnectAsync` @ :408](SstpConnection.cs#L408) hủy reconnect, gửi **SSTP Call-Disconnect** (best-effort, timeout 2s), rồi đóng transport.
- **Facade ổn định:** `SwappablePacketChannel` ([từ Abstractions](../TqkLibrary.Vpn.Abstractions)) cho phép tráo kênh PPP bên dưới khi reconnect mà socket trong tunnel ở tầng trên không bị đứt (nếu địa chỉ giữ nguyên).

## Trạng thái & ghi chú

- **Đã hiện thực đầy đủ:** handshake + crypto binding + **active keepalive + teardown sạch + auto-reconnect + read-timeout chủ động (P1.5)** (mirror mô hình L2TP/IPsec đã verify live). SSTP **không** rekey SA (phiên TLS sống dài), nên không có rekey timer như L2TP/IPsec.
- **netstandard2.0 vs net8.0:** `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`); dùng API BCL chung (`SslStream`, `HMACSHA256`, `SHA256`, `Timer`) khả dụng trên cả hai target.
- **Seam byte-stream (P0.1):** TLS-over-TCP tách vào [`TlsByteStream`](Transport/TlsByteStream.cs#L20) sau [`ITlsByteStream`](Transport/ITlsByteStream.cs#L14) (impl đầu tiên của `IByteStreamTransport`), inject qua `Func<ITlsByteStream>` ở `SstpConnection`; framing chạy offline qua fake stream trong [SstpTransportSeamTests](../../tests/TqkLibrary.Vpn.Sstp.Tests/SstpTransportSeamTests.cs). `ConnectAsync` nay **honor `CancellationToken`** cả 2 TFM (overload native net8.0; cancel-by-dispose netstandard2.0).
- **Hạn chế đã biết:**
  - SSTP **mặc định** chấp nhận mọi cert TLS (xác thực bằng crypto binding, không qua PKI); truyền `RemoteCertificateValidationCallback` qua `SstpDriver`/`UseSstp` để validate cert (P0.6 — callback vẫn nhận cert đã bắt giữ cho crypto binding) — [Transport/TlsByteStream.cs:62-68](Transport/TlsByteStream.cs#L62-L68).
  - Supervisor/keepalive/reconnect của SSTP hiện phủ ở mức transport (seam trên) + **live integration test**; test offline trọn vẹn supervisor sẽ cần giả lập **server** PPP (LCP+MS-CHAPv2 phía authenticator) — ngoài phạm vi thư viện client, không làm.
  - Mỗi connection chỉ một PPP session; `OpenSessionAsync` ném `NotSupportedException` — [SstpVpnConnection.cs:22-23](SstpVpnConnection.cs#L22-L23).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §7/§7.1 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md).
