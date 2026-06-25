# TqkLibrary.VpnClient.Drivers.Sstp

> Driver VPN **MS-SSTP**: TLS trên 443, handshake `SSTP_DUPLEX_POST`, control message theo `[MS-SSTP]`, PPP/MS-CHAPv2, crypto binding; **active keepalive + teardown sạch + auto-reconnect**. Đây là nơi lắp ráp toàn bộ stack SSTP thành một `IVpnConnection` hoàn chỉnh.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối control plane cho giao thức MS-SSTP. Nó dựng TLS, chạy handshake SSTP, đẩy PPP/MS-CHAPv2 qua kênh SSTP, gắn **crypto binding** (ràng buộc HLAK của PPP vào cert TLS để chống MITM), rồi bọc lại sau interface trung lập `IVpnConnection` để tầng `TqkLibrary.VpnClient` ở trên tiêu thụ mà không cần biết giao thức cụ thể.

Driver MS-SSTP ([SstpDriver.cs:11](SstpDriver.cs#L11)) gồm: TLS trên 443 (**mặc định** chấp nhận mọi cert — xác thực bằng crypto binding chứ không PKI; tùy chọn truyền `RemoteCertificateValidationCallback` để validate cert — P0.6), handshake `SSTP_DUPLEX_POST`, control message `[MS-SSTP]`, PPP RAW (không HDLC) + MS-CHAPv2, và crypto binding `CMK = HMAC-SHA256(HLAK,…)`. `SstpConnection` **kế thừa supervisor dùng chung** [`ReconnectingVpnConnection<SstpConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6): link-loss → auto-reconnect (exponential backoff + jitter), `StateChanged`, và facade kênh ổn định đều ở base — subclass chỉ giữ phần **SSTP-riêng**: active keepalive (SSTP Echo-Request) và teardown sạch (Call-Disconnect). SSTP **không** có khái niệm rekey SA (phiên TLS sống dài).

> Driver L2TP/IPsec nằm ở project anh em [TqkLibrary.VpnClient.Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec). Trước đây hai driver chung một project `TqkLibrary.VpnClient.Drivers` (subfolder `L2tpIpsec/`+`Sstp/`); đã tách thành 2 project, file phẳng ở gốc, namespace giữ nguyên.

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference) — 4 project:**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, typed exception...) + **`Diagnostics`** (`VpnEventIds`/`VpnLogExtensions` — log handshake/keepalive/reconnect, Q.2).
  - [TqkLibrary.VpnClient.Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) — supervisor dùng chung [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) + [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14) (F.6 — gom link-loss/auto-reconnect/backoff-jitter/state/facade; `SstpConnection`/`SstpReconnectOptions` kế thừa).
  - [TqkLibrary.VpnClient.Ppp](../TqkLibrary.VpnClient.Ppp) — `PppEngine`, `MsChapV2Authenticator` (+ `DeriveHlak`), `IPppFrameChannel`.
  - [TqkLibrary.VpnClient.Transport.Tls](../TqkLibrary.VpnClient.Transport.Tls) — TLS-over-TCP byte-stream **dùng chung** [`TlsByteStream`](../TqkLibrary.VpnClient.Transport.Tls/TlsByteStream.cs#L25) (F.1 — bọc `Transport.Tcp` `TcpByteStream` + `SslStream`); `SstpConnection`/`SstpTransport` cấp default cho `Func<ITlsByteStream>`.
  - **Không** ref `Ipsec` / `L2tp` — SSTP tự cuộn crypto bằng BCL (`HMACSHA256`, `SHA256`); TLS-over-TCP nay nằm ở project dùng chung [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) sau seam [`ITlsByteStream`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) ở **Abstractions** (**F.1 đã tách project**; trước P0.1 nằm trong driver SSTP), `SstpTransport` chỉ còn handshake + framing.
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — `VpnClientBuilder.UseSstp()` / `UseSstp(SstpReconnectOptions)` / `UseSstp(RemoteCertificateValidationCallback)` / `UseSstp(SstpReconnectOptions, RemoteCertificateValidationCallback)` đăng ký driver này).

## Cấu trúc thư mục

> File **phẳng ở gốc project** (không còn subfolder `Sstp/`); chỉ giữ `Enums/`+`Models/`.

```
TqkLibrary.VpnClient.Drivers.Sstp/
├── SstpDriver.cs                IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
├── SstpConnection.cs            Bộ điều phối (: ReconnectingVpnConnection<SstpConnectionState>, F.6): TLS + control + PPP + crypto binding + keepalive + teardown
├── SstpTransport.cs             SSTP_DUPLEX_POST handshake + framing gói SSTP 4-byte header (trên ITlsByteStream)
├── SstpControlCodec.cs          Encode/decode body control message ([MS-SSTP] §2.2.2–2.2.3)
├── SstpCryptoBinding.cs         CMK/Compound-MAC (HMAC-SHA256) cho Call Connected
├── SstpPppChannel.cs            Cầu nối SSTP data ↔ PPP (RAW PPP, không HDLC) + dispatch control
├── SstpConstants.cs             Hằng số [MS-SSTP] (version 0x10, DuplexUri, hash protocol...)
├── SstpReconnectOptions.cs      : VpnReconnectOptions (F.6) + knob ReadTimeout riêng SSTP (P1.5)
├── SstpVpnConnection.cs         Adapter sang IVpnConnection (một session)
├── SstpVpnSession.cs            IVpnSession: facade ổn định + áp dụng reconnect vào TunnelConfig
├── Enums/                       SstpMessageType, SstpAttributeId, SstpConnectionState
└── Models/                      SstpAttribute, SstpControlMessage, SstpReconnectInfo
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `SstpDriver` | `IVpnProtocolDriver`: capabilities + `ConnectAsync` → `IVpnConnection`; ctor nhận `SstpReconnectOptions` + `RemoteCertificateValidationCallback` (cert TLS, P0.6 — null ⇒ accept all) + `enableIpv6` (P1.1) + `ILoggerFactory?` (Q.2); wire `Reconnected`→`ApplyReconnect` | [SstpDriver.cs:11](SstpDriver.cs#L11) |
| `SstpConnection` | Bộ điều phối **kế thừa [`ReconnectingVpnConnection<SstpConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24)** (F.6): override `EstablishAsync` (TLS + control + PPP + crypto binding, bind kênh PPP sau `Facade`) + `CleanupAttemptResourcesAsync`/`StopAttemptLoop`; giữ SSTP-riêng active Echo keepalive + teardown Call-Disconnect; nhận `Func<ITlsByteStream>` factory (seam test offline) + `AddressFamilyPreference` (chọn họ IP outer, P1.2 — truyền vào `TlsByteStream` mặc định) + `enableIpv6` (P1.1) + `ILoggerFactory?` (Diagnostics Q.2, null ⇒ no-op) | [SstpConnection.cs:33](SstpConnection.cs#L33) |
| `SstpTransport` | `SSTP_DUPLEX_POST` handshake + framing gói SSTP 4-byte header trên `ITlsByteStream` (ctor seam + ctor back-compat `(host, port)`); **read-timeout** tùy chọn (P1.5 — cap read không-tiến-triển ⇒ `TimeoutException`) | [SstpTransport.cs:16](SstpTransport.cs#L16) |
| `ITlsByteStream` *(Abstractions)* | Seam: `IByteStreamTransport` + `RemoteCertificate` (cert cho crypto binding) — cho phép fake stream test offline; **dời lên Abstractions** (F.1) | [../Abstractions/…/ITlsByteStream.cs:13](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) |
| `TlsByteStream` *(Transport.Tls)* | Hiện thực TLS-over-TCP **dùng chung** (F.1 — bọc `Transport.Tcp` `TcpByteStream` + `SslStream`), bắt cert, callback validate cert TLS tùy chọn (P0.6 — null ⇒ accept all), honor `CancellationToken` cả 2 TFM. **Outer IPv6 (P1.2)**: `TcpByteStream` resolve host qua `IHostResolver` theo `AddressFamilyPreference` → connect theo `IPAddress` (giữ host gốc làm SNI `TargetHost`) | [../Transport.Tls/TlsByteStream.cs:25](../TqkLibrary.VpnClient.Transport.Tls/TlsByteStream.cs#L25) |
| `SstpControlCodec` | Build/parse body control message (type + attributes) | [SstpControlCodec.cs:7](SstpControlCodec.cs#L7) |
| `SstpCryptoBinding` | Dựng attribute Crypto Binding (CMK + Compound-MAC) cho Call Connected | [SstpCryptoBinding.cs:13](SstpCryptoBinding.cs#L13) |
| `SstpPppChannel` | `IPppFrameChannel`: RAW PPP frame trong SSTP data packet + dispatch control | [SstpPppChannel.cs:11](SstpPppChannel.cs#L11) |
| `SstpConstants` | Hằng số `[MS-SSTP]` (Version 0x10, DuplexUri, hash protocol) | [SstpConstants.cs:4](SstpConstants.cs#L4) |
| `SstpReconnectOptions` | **Kế thừa [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14)** (F.6 — backoff/jitter/max-attempts/Enabled ở base); thêm **`ReadTimeout`** riêng SSTP (cap read không-tiến-triển, P1.5 — mặc định 60s, `Timeout.InfiniteTimeSpan` tắt) | [SstpReconnectOptions.cs:14](SstpReconnectOptions.cs#L14) |
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
| `[MS-SSTP]` (Echo keepalive + Call-Disconnect teardown) | `SstpConnection` (active Echo + clean teardown; reconnect ở base F.6) | [SstpConnection.cs:360-386](SstpConnection.cs#L360-L386) | Echo-Request 30s, chết sau 3 lần thiếu Echo-Response; teardown gửi Call-Disconnect |
| FIPS PUB 198-1 / RFC 6234 (HMAC-SHA-256) | `SstpCryptoBinding` (`HMACSHA256` BCL) | [SstpCryptoBinding.cs:44](SstpCryptoBinding.cs#L44) | (suy luận) — dùng `System.Security.Cryptography.HMACSHA256` |
| FIPS PUB 180-4 (SHA-256, hash cert TLS) | `SstpConnection` (`SHA256.Create()`) | [SstpConnection.cs:223](SstpConnection.cs#L223) | (suy luận) |
| RFC 8446 / 5246 (TLS, qua `SslStream`) | `TlsByteStream` (Transport.Tls, seam `ITlsByteStream`) | [../Transport.Tls/TlsByteStream.cs:79](../TqkLibrary.VpnClient.Transport.Tls/TlsByteStream.cs#L79) | (suy luận) — BCL `SslStream.AuthenticateAsClientAsync`; net5+ dùng overload có `CancellationToken`; cert validate qua `RemoteCertificateValidationCallback` tùy chọn (P0.6) |
| RFC 2759 (MS-CHAPv2) | `MsChapV2Authenticator` (dùng từ `Ppp`) | [SstpConnection.cs:208](SstpConnection.cs#L208) | (suy luận) — hiện thực nằm ở project `Ppp` |
| RFC 3079 (MPPE/HLAK key derivation) + `[MS-SSTP]` crypto binding | `MsChapV2Authenticator.DeriveHlak` (từ `Ppp`) | [SstpConnection.cs:221](SstpConnection.cs#L221) | (suy luận) — derive ở `Ppp`, dùng tại đây |
| RFC 1661 / 1332 (PPP LCP + IPCP) | `PppEngine` (từ `Ppp`) | [SstpConnection.cs:209](SstpConnection.cs#L209) | (suy luận) — hiện thực ở `Ppp` |

> Lưu ý: chuẩn được **hiện thực trực tiếp** trong project này là toàn bộ `[MS-SSTP]` (TLS handshake, control codec, crypto binding, framing, Echo keepalive, Call-Disconnect teardown); MS-CHAPv2/PPP/HLAK derive là **gọi** sang project `Ppp`.

## API / cách dùng

Điểm vào công khai là driver `SstpDriver` (`IVpnProtocolDriver`). Thông thường tầng `TqkLibrary.VpnClient` (`VpnClientBuilder.UseSstp()`) đăng ký driver và gọi `ConnectAsync`; có thể dùng trực tiếp:

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

1. `SstpTransport.ConnectAsync` (transport do `_transportFactory` cấp **mỗi attempt** — [SstpConnection.cs:44](SstpConnection.cs#L44), dựng tại [SstpConnection.cs:139](SstpConnection.cs#L139) với `_opts.ReadTimeout`): [`TlsByteStream.ConnectAsync`](../TqkLibrary.VpnClient.Transport.Tls/TlsByteStream.cs#L64) làm TCP+TLS + bắt cert, rồi `SSTP_DUPLEX_POST` HTTP handshake — [SstpTransport.cs:47-67](SstpTransport.cs#L47-L67); gọi qua [SstpConnection.cs:146](SstpConnection.cs#L146). Lỗi transport tái phân loại thành typed exception (non-200 ⇒ reject; socket/TLS/IO ⇒ timeout; caller-cancel giữ nguyên) — [SstpConnection.cs:148-175](SstpConnection.cs#L148-L175).
2. Gửi `CallConnectRequest` (Encapsulated Protocol = PPP) → nhận `CallConnectAck`, lấy 32-byte nonce trong Crypto Binding Req; Nak / sai loại / crypto-binding thiếu-hoặc-ngắn ⇒ `VpnServerRejectedException` — [SstpConnection.cs:177-202](SstpConnection.cs#L177-L202).
3. `PppEngine` chạy trên `SstpPppChannel`; khi `AuthSucceeded`: lấy HLAK + SHA-256(cert) → dựng Crypto Binding → gửi `CallConnected` (auth fail ⇒ `VpnAuthenticationException`) — [SstpConnection.cs:217-236](SstpConnection.cs#L217-L236).
4. `LinkUp` (IPCP đã cấp IP) ⇒ (nếu bật IPv6) `AwaitIpv6GraceAsync` chờ ngắn 2s cho IPV6CP mở để lộ link-local `fe80::/64`, rồi `TryConfigureGlobalIpv6Async` chạy [`PppIpv6Autoconfigurator`](../TqkLibrary.VpnClient.Ppp/Ipv6/PppIpv6Autoconfigurator.cs#L20) trên `engine.PacketChannel` (RS → RA-SLAAC/DHCPv6) lấy địa chỉ **global** = prefix ‖ IID-IPV6CP; `AssignedAddressV6` nay trả **global-nếu-có-else-link-local** vào `TunnelConfig.AssignedAddressV6` ([SstpConnection.cs:97](SstpConnection.cs#L97)), fragment v6 (prefix/DNS/route `::/0`) đưa lên `Ipv6Config` ([:103](SstpConnection.cs#L103)) cho driver merge; `_ipv6Config` reset mỗi attempt ([:211](SstpConnection.cs#L211)). Best-effort (không RA ⇒ giữ link-local) → cắm kênh PPP vào facade `Facade` (`SwappablePacketChannel` của base) và bật keepalive — [AwaitIpv6GraceAsync @ :251](SstpConnection.cs#L251) (decl [:277](SstpConnection.cs#L277)), [TryConfigureGlobalIpv6Async @ :252](SstpConnection.cs#L252) (decl [:290](SstpConnection.cs#L290)), [Facade.SetInner @ :254](SstpConnection.cs#L254).

### Keepalive · teardown · reconnect (supervisor F.6 ở base)

- **Active keepalive (SSTP-riêng):** gửi **SSTP Echo-Request mỗi 30s**, coi peer chết sau **3 lần liên tiếp** thiếu Echo-Response (reset khi có bất kỳ control inbound); vẫn trả lời Echo-Request của server — [SstpConnection.cs:360-386](SstpConnection.cs#L360-L386) · [OnControlReceived @ :329](SstpConnection.cs#L329). Timer dừng qua override [`StopAttemptLoop` @ :368](SstpConnection.cs#L368) mà base gọi dưới state-lock khi link-loss/teardown.
- **Phát hiện peer-dead (3 nguồn):** vòng đọc SSTP kết thúc (**chính**, lọc qua [`OnReadLoopEnded` @ :351](SstpConnection.cs#L351) — double-guard `_attemptId` + cancel vòng đọc chống vòng đọc cũ báo rớt giả), thiếu Echo-Response, và inbound **Call-Disconnect / Call-Abort** → tất cả gọi `OnLinkLost` của base ([ReconnectingVpnConnection.cs:161](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L161)).
- **Read-timeout chủ động (P1.5):** `SstpReconnectOptions.ReadTimeout` (mặc định 60s, > keepalive 30s nên im-lặng-giữa-Echo không trip; `Timeout.InfiniteTimeSpan` tắt) cấp xuống `SstpTransport` ở `EstablishAsync` ([SstpConnection.cs:139](SstpConnection.cs#L139)) → mọi read (HTTP handshake + `ReadPacketAsync`) bị cap "không tiến triển trong ReadTimeout" ⇒ `TimeoutException`. Trong handshake map sang `VpnNetworkTimeoutException`; trong read-loop ⇒ vòng đọc kết thúc → `OnLinkLost` → reconnect (phát hiện server treo giữa chừng, không chỉ khi TLS đóng/cancel). Caller-cancel **không** bị remap (giữ `OperationCanceledException`).
- **Auto-reconnect (base F.6):** `OnLinkLost` arm vòng `ReconnectLoopAsync` của base ([ReconnectingVpnConnection.cs:189](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L189)) — exponential backoff + jitter (bật mặc định, cấu hình qua `SstpReconnectOptions` kế thừa `VpnReconnectOptions`); thành công gọi override [`OnReconnected` @ :403](SstpConnection.cs#L403) raise `Reconnected` (cập nhật `TunnelConfig` qua `SstpVpnSession.ApplyReconnect`). Tunnel mới chui sau facade ⇒ flow same-address sống sót không re-bind.
- **Teardown:** override [`DisconnectAsync` @ :418](SstpConnection.cs#L418) gửi **SSTP Call-Disconnect** (best-effort, timeout 2s) **trước**, rồi gọi `DisconnectCoreAsync` của base (hủy reconnect, dừng keepalive, đóng transport).
- **Logging/diagnostics (Q.2):** ctor `SstpConnection`/`SstpDriver` nhận `ILoggerFactory?` (mặc định [`NullLogger`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs) ⇒ no-op, **ADDITIVE không đổi hành vi**). Log qua [`VpnLogExtensions`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs): TLS/SSTP_DUPLEX_POST + Call-Connect + PPP auth-success→Handshake (auth fail→HandshakeFailed); bind facade→HandshakeCompleted; Echo-Request→Keepalive; `SetState`→StateChanged; `OnLinkLost`→LinkLost; reconnect attempt/success→ReconnectAttempt/Reconnected.
- **Facade ổn định:** `SwappablePacketChannel` ([từ Abstractions](../TqkLibrary.VpnClient.Abstractions)) cho phép tráo kênh PPP bên dưới khi reconnect mà socket trong tunnel ở tầng trên không bị đứt (nếu địa chỉ giữ nguyên).

## Trạng thái & ghi chú

- **Đã hiện thực đầy đủ:** handshake + crypto binding + **active keepalive + teardown sạch + auto-reconnect + read-timeout chủ động (P1.5)**. **Supervisor/reconnect đã gom về base dùng chung (F.6):** `SstpConnection : ReconnectingVpnConnection<SstpConnectionState>` + `SstpReconnectOptions : VpnReconnectOptions` (giữ knob `ReadTimeout`); link-loss/auto-reconnect/backoff-jitter/state/facade ở base, subclass chỉ giữ keepalive Echo + teardown Call-Disconnect — **không đổi hành vi** (test Sstp + Drivers.Core xanh). SSTP **không** rekey SA (phiên TLS sống dài), nên không có rekey timer như L2TP/IPsec.
- **Logging/diagnostics (Q.2) đã có:** luồng `ILoggerFactory?` qua driver/connection → trace handshake/HandshakeCompleted/keepalive/state/link-lost/reconnect (xem mục Keepalive·teardown·reconnect); mặc định no-op, không đổi hành vi runtime.
- **IPv6-in-tunnel (P1.1, opt-in `SstpDriver(enableIpv6: true)` / `SstpConnection(enableIpv6: true)`):** chạy IPV6CP song song IPCP → link-local `fe80::/64`; rồi (P1.1(2)) `TryConfigureGlobalIpv6Async` chạy [`PppIpv6Autoconfigurator`](../TqkLibrary.VpnClient.Ppp/Ipv6/PppIpv6Autoconfigurator.cs#L20) trên kênh PPP (RS → RA-SLAAC/DHCPv6) lấy địa chỉ **global** = prefix ‖ IID-IPV6CP → `AssignedAddressV6` trả global-nếu-có-else-link-local lên `TunnelConfig.AssignedAddressV6`, fragment v6 merge qua [`TunnelConfigIpv6.ApplyGlobalIpv6(config, connection.Ipv6Config)`](../TqkLibrary.VpnClient.Drivers.Core/TunnelConfigIpv6.cs#L19) ở [SstpDriver.cs:62](SstpDriver.cs#L62); PPP multiplex cả hai họ trên một `IPacketChannel` (xem [README Ppp](../TqkLibrary.VpnClient.Ppp/README-vi.md)) và `CreateTcpStack` dựng stack dual-stack khi có v6. **Mặc định tắt** (không đổi hành vi IPv4). Best-effort: server không cấp RA ⇒ giữ link-local (chưa định tuyến ra ngoài). **Còn lại: chưa test live** (đa số server VPN Gate chỉ cấp IPv4 — cần lab Q.1).
- **netstandard2.0 vs net8.0:** `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`); dùng API BCL chung (`SslStream`, `HMACSHA256`, `SHA256`, `Timer`) khả dụng trên cả hai target.
- **Seam byte-stream (P0.1 → F.1):** TLS-over-TCP nay ở project **dùng chung** [`TlsByteStream`](../TqkLibrary.VpnClient.Transport.Tls/TlsByteStream.cs#L25) (bọc `Transport.Tcp` `TcpByteStream`) sau [`ITlsByteStream`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) ở Abstractions, inject qua `Func<ITlsByteStream>` ở `SstpConnection`; framing chạy offline qua fake stream trong [SstpTransportSeamTests](../../tests/TqkLibrary.VpnClient.Sstp.Tests/SstpTransportSeamTests.cs). `ConnectAsync` nay **honor `CancellationToken`** cả 2 TFM (overload native net8.0; cancel-by-dispose netstandard2.0).
- **Hạn chế đã biết:**
  - SSTP **mặc định** chấp nhận mọi cert TLS (xác thực bằng crypto binding, không qua PKI); truyền `RemoteCertificateValidationCallback` qua `SstpDriver`/`UseSstp` để validate cert (P0.6 — callback vẫn nhận cert đã bắt giữ cho crypto binding) — [../Transport.Tls/TlsByteStream.cs:72-76](../TqkLibrary.VpnClient.Transport.Tls/TlsByteStream.cs#L72-L76).
  - Supervisor/keepalive/reconnect của SSTP hiện phủ ở mức transport (seam trên) + **live integration test**; test offline trọn vẹn supervisor sẽ cần giả lập **server** PPP (LCP+MS-CHAPv2 phía authenticator) — ngoài phạm vi thư viện client, không làm.
  - Mỗi connection chỉ một PPP session; `OpenSessionAsync` ném `NotSupportedException` — [SstpVpnConnection.cs:22-23](SstpVpnConnection.cs#L22-L23).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §7/§7.1 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md).
