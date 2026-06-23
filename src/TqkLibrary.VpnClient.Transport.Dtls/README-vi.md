# TqkLibrary.VpnClient.Transport.Dtls

> **Transport DTLS 1.2** — hiện thực [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L9) bằng **DTLS 1.2 client qua BouncyCastle** (`Org.BouncyCastle.Tls.DtlsClientProtocol`). Bọc một datagram pipe UDP "thô" rồi mã hóa/giải mã từng datagram thành một DTLS record. Đây là concrete transport dùng chung cho **đường dữ liệu DTLS của OpenConnect** (V.5c).

## Mục đích

`SslStream` của BCL **chỉ làm TLS, không làm DTLS** trên cả `net8.0` lẫn `netstandard2.0`. Vì vậy handshake + record layer chạy qua **BouncyCastle** (`DtlsClientProtocol`) — package `BouncyCastle.Cryptography` 2.4.0 đã ref ở project `Crypto`, ở đây ref **không điều kiện cho cả 2 TFM**.

Project chỉ phơi **một type công khai** [`DtlsDatagramTransport`](DtlsDatagramTransport.cs#L28): nhận một `IDatagramTransport` bên trong (pipe UDP plaintext), `ConnectAsync` chạy handshake DTLS 1.2 client, sau đó mỗi `SendAsync` = 1 DTLS record mã hóa, mỗi `ReceiveAsync` = 1 DTLS record giải mã (giữ nguyên ranh giới datagram giống UDP — drop-in thay UDP thô). Vì handshake/record layer của BouncyCastle là **đồng bộ (blocking)**, project bắc một cầu sync↔async nội bộ và offload mọi lời gọi blocking ra thread-pool.

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (concrete) — ngang hàng với `TlsByteStream` (F.1, hiện thực `IByteStreamTransport`); cả hai nằm dưới tầng DRIVER, chỉ phụ thuộc `Abstractions`.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference) — CHỈ Abstractions:**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — `IDatagramTransport`.
  - **PackageReference:** `BouncyCastle.Cryptography` 2.4.0 (không điều kiện cả 2 TFM — `Org.BouncyCastle.Tls` cho DTLS).
- **Được dùng bởi:** driver **OpenConnect** ([Drivers.OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) — V.5c, đường dữ liệu DTLS song song, fallback TLS). `OpenConnectConnection` dựng `DtlsDatagramTransport` (kèm `DtlsResumptionParameters` build từ `X-DTLS-*` + master secret in-band) trong `TryEstablishDtlsAsync`.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.Dtls/
├── DtlsDatagramTransport.cs                    IDatagramTransport: bọc UDP pipe → handshake DTLS 1.2 client → mã hóa/giải mã từng datagram (+ tham số resumption tùy chọn)
├── DefaultDtlsClient.cs                         (internal) TlsClient của BouncyCastle: pin DTLS 1.2 (full) / DTLS 1.2→1.0 (resume) + AEAD/CBC suites + wire cert-callback + legacy AnyConnect session resumption
├── DtlsResumptionParameters.cs                  POCO tham số resumption legacy AnyConnect (master secret 48B + session id + cipher) — đem in-band qua TLS CONNECT
├── DtlsCipherSuiteMap.cs                         map tên cipher OpenSSL của ocserv (X-DTLS-CipherSuite, vd AES256-SHA) → id BouncyCastle (chỉ CBC legacy ⇒ tín hiệu resume)
├── BouncyCastleDatagramBridge.cs                (internal) cầu sync↔async: IDatagramTransport ↔ Org.BouncyCastle.Tls.DatagramTransport
└── DtlsServerCertificateValidationCallback.cs   delegate xác thực/pin cert server (tùy chọn; null = chấp nhận mọi cert)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `DtlsDatagramTransport` | `IDatagramTransport` công khai: ctor nhận inner `IDatagramTransport` + `DtlsServerCertificateValidationCallback?` + `ownsInner` + `DtlsResumptionParameters?`; `ConnectAsync` chạy handshake DTLS 1.2 client (full hoặc resume legacy, blocking trên thread-pool, hủy bằng cancel→`Close()` bridge); `SendAsync`/`ReceiveAsync` = 1 DTLS record mã hóa/giải mã; phơi `SendLimit`/`ReceiveLimit`; `DisposeAsync` gửi close_notify + đóng bridge (+ inner nếu `ownsInner`) | [DtlsDatagramTransport.cs:28](DtlsDatagramTransport.cs#L28) |
| `DefaultDtlsClient` | (internal) `DefaultTlsClient`: **full handshake** ⇒ `GetSupportedVersions`=DTLS 1.2, AEAD suites (ECDHE/DHE-RSA + ECDSA + RSA key-transport, AES-GCM); **resume legacy** (`DtlsResumptionParameters≠null`) ⇒ dựng `TlsSession` qua `TlsUtilities.ImportSession` (session id + master secret + cipher CBC), `GetSessionToResume` trả session đó, `GetSupportedVersions`=DTLS 1.2→1.0, chào đúng cipher resume, **`AllowLegacyResumption`=true** (session không EMS); `GetAuthentication` bắc cert-callback (null⇒accept all; reject⇒`TlsFatalAlert`); client **không** cert (anonymous) | [DefaultDtlsClient.cs:26](DefaultDtlsClient.cs#L26) |
| `DtlsResumptionParameters` | POCO tham số resumption legacy AnyConnect: `MasterSecret` (48B client sinh + gửi `X-DTLS-Master-Secret`), `SessionId` (ocserv `X-DTLS-Session-ID` decode hex = ClientHello session_id), `CipherSuite` (id BouncyCastle từ `X-DTLS-CipherSuite`). null ⇒ full handshake | [DtlsResumptionParameters.cs:14](DtlsResumptionParameters.cs#L14) |
| `DtlsCipherSuiteMap` | `TryResolve(name, out id)`: map tên cipher OpenSSL legacy (`AES256-SHA`/`AES128-SHA`/`*-SHA256`) → id BouncyCastle (RSA-CBC). Tên CBC resolve được = **tín hiệu** gateway muốn resume legacy; tên AEAD/GCM hay rỗng ⇒ false ⇒ full handshake | [DtlsCipherSuiteMap.cs:16](DtlsCipherSuiteMap.cs#L16) |
| `BouncyCastleDatagramBridge` | (internal) cầu sync↔async: vòng nền pull datagram từ `IDatagramTransport.ReceiveAsync` vào hàng đợi mà `Receive(buf,off,len,waitMillis)` blocking rút (timeout⇒`-1` cho retransmit timer của DTLS chạy); `Send` chạy `SendAsync` đồng bộ | [BouncyCastleDatagramBridge.cs:19](BouncyCastleDatagramBridge.cs#L19) |
| `DtlsServerCertificateValidationCallback` | delegate `(TlsServerCertificate) → bool` xác thực/pin cert server lúc handshake (analogue của `RemoteCertificateValidationCallback` nhưng nhận cert BouncyCastle) | [DtlsServerCertificateValidationCallback.cs:15](DtlsServerCertificateValidationCallback.cs#L15) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|-------------------------|--------------------|---------|
| RFC 6347 (DTLS 1.2) | `DtlsDatagramTransport` + `DefaultDtlsClient` (qua `Org.BouncyCastle.Tls.DtlsClientProtocol`) | [DtlsDatagramTransport.cs:64](DtlsDatagramTransport.cs#L64) · [DefaultDtlsClient.cs:52](DefaultDtlsClient.cs#L52) | Handshake + record layer do BouncyCastle hiện thực; full handshake pin `ProtocolVersion.DTLSv12.Only()` |
| RFC 5288 / 5289 (AES-GCM cipher suites cho TLS/ECDHE) | `DefaultDtlsClient.GetSupportedCipherSuites` (full) | [DefaultDtlsClient.cs:67](DefaultDtlsClient.cs#L67) | Full handshake chỉ chào AEAD: ECDHE/DHE-RSA + ECDSA + RSA key-transport, AES-128/256-GCM |
| RFC 5246 §7.3 (abbreviated handshake / session resumption) | `DefaultDtlsClient.GetSessionToResume` + `TlsUtilities.ImportSession` | [DefaultDtlsClient.cs:80](DefaultDtlsClient.cs#L80) | Legacy AnyConnect/ocserv `dtls-legacy`: client chào ClientHello mang session_id của gateway + master secret pre-shared (đem in-band qua TLS CONNECT) ⇒ handshake rút gọn, không trao cert. RSA-CBC `AES256-SHA`, DTLS 1.0 |

## API / cách dùng

```csharp
// Bọc một datagram pipe UDP plaintext trong DTLS 1.2; cert mặc định chấp nhận mọi cert.
IDatagramTransport udp = /* UDP socket sau IDatagramTransport, vd UdpDatagramSocket của driver */;
var dtls = new DtlsDatagramTransport(udp,
    certificateValidationCallback: cert => /* pin/validate cert ở đây */ true); // null ⇒ accept all
await dtls.ConnectAsync(cancellationToken);       // chạy handshake DTLS 1.2 client

await dtls.SendAsync(payload);                     // 1 datagram = 1 DTLS record mã hóa
byte[] buf = new byte[dtls.ReceiveLimit];
int n = await dtls.ReceiveAsync(buf);              // 1 DTLS record giải mã
await dtls.DisposeAsync();                          // gửi close_notify + đóng (mặc định đóng cả inner pipe)
```

## Luồng nội bộ

### Handshake (`ConnectAsync` — [DtlsDatagramTransport.cs:58](DtlsDatagramTransport.cs#L58))

1. `inner.ConnectAsync` (bind/resolve UDP) → dựng [`BouncyCastleDatagramBridge`](BouncyCastleDatagramBridge.cs#L19) (khởi động vòng nền pull inbound).
2. Dựng `BcTlsCrypto` + [`DefaultDtlsClient`](DefaultDtlsClient.cs#L26) (kèm `DtlsResumptionParameters` nếu resume legacy) + `DtlsClientProtocol`.
3. Chạy `protocol.Connect(client, bridge)` **trên thread-pool** (`Task.Run`) — blocking, retransmit timer của DTLS chạy qua `waitMillis` của bridge. Cancel của caller → đăng ký `Close()` bridge để `Receive` blocking trả về → handshake hủy.
4. Cert server: BouncyCastle gọi `NotifyServerCertificate` → cert-callback (null⇒accept; false⇒`TlsFatalAlert(bad_certificate)` hủy handshake).

### Send / Receive (sau handshake)

- `SendAsync`: copy `ReadOnlyMemory` ra `byte[]` → `DtlsTransport.Send` (blocking, offload `Task.Run`) = 1 record mã hóa. **Lưu ý:** DTLS application_data record mang ≥1 byte — BouncyCastle **từ chối** gửi datagram rỗng.
- `ReceiveAsync`: `DtlsTransport.Receive(...,200ms)` trong vòng lặp (offload `Task.Run`); `-1` = timeout (chưa có record) → lặp tiếp để honor cancel mà không busy-spin; có record → copy ra buffer.

### Cầu sync↔async ([BouncyCastleDatagramBridge.cs:19](BouncyCastleDatagramBridge.cs#L19))

- Vòng nền `PumpInboundAsync`: `inner.ReceiveAsync` → `BlockingCollection` (`ConcurrentQueue`). 0-byte không phải EOF (UDP) → bỏ qua, nghe tiếp.
- `Receive(buf,off,len,waitMillis)`: `TryTake(waitMillis)`; rỗng → `-1` (để retransmit timer DTLS chạy).
- `Send`: `inner.SendAsync(...).GetAwaiter().GetResult()` (đồng bộ; chỉ chạy trên thread IO của handshake/loop, không trên đường async công khai).

## Trạng thái & ghi chú

- **Đã hiện thực:** DTLS 1.2 client transport hoàn chỉnh (handshake + round-trip 2 chiều), cert-callback tùy chọn, build xanh cả `netstandard2.0` + `net8.0`. Test **offline** [`DtlsDatagramTransportTests`](../../tests/TqkLibrary.VpnClient.Transport.Dtls.Tests/DtlsDatagramTransportTests.cs) dựng **server DTLS giả lập** bằng BouncyCastle (`DtlsServerProtocol` + cert RSA self-signed) qua loopback datagram pipe in-memory: handshake, round-trip nhiều datagram 2 chiều, cert-callback quan sát đúng cert, reject cert ⇒ abort handshake, **record loss** (drop flight đầu ⇒ DTLS retransmit ⇒ vẫn xong) + **reorder** (đảo 2 datagram đầu server ⇒ vẫn xong).
- **netstandard2.0 vs net8.0:** overload `Receive(Span<byte>,...)` + `Send(ReadOnlySpan<byte>)` của interface `DatagramTransport` **chỉ có trong build net6.0** của BouncyCastle (dùng cho target `net8.0`); build `netstandard2.0` chỉ có overload `byte[]`. `BouncyCastleDatagramBridge` rào 2 overload Span bằng `#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER` cho khớp từng build package.
- **Threading:** `DtlsTransport` của BouncyCastle là đồng bộ; record layer chịu **1 sender + 1 receiver** đồng thời (mô hình "1 write loop + 1 read loop" của driver), **không** an toàn khi gọi `SendAsync` (hoặc `ReceiveAsync`) từ 2 thread cùng lúc — giống socket thô.
- **Legacy AnyConnect DTLS resumption (V5.c — code, lộ qua validate live ocserv):** ocserv `dtls-legacy` **không** chạy full DTLS handshake — client đem master secret 48B in-band qua TLS CONNECT (`X-DTLS-Master-Secret`), gateway trả session id + cipher (`X-DTLS-Session-ID`/`X-DTLS-CipherSuite`), rồi client chào **handshake rút gọn** (ClientHello mang session_id đó + resume master secret pre-shared, không trao cert). Khi truyền `DtlsResumptionParameters`, `DefaultDtlsClient` dựng `TlsSession` qua `TlsUtilities.ImportSession` + `GetSessionToResume` + **`AllowLegacyResumption=true`** (bắt buộc: session không EMS, nếu thiếu BouncyCastle **xóa** session_id ⇒ ocserv báo `invalid session ID size (0)`). DTLS pin **1.0** cho nhánh resume (ocserv legacy resume qua DTLS 1.0).
- **Hạn chế đã biết / việc sau:**
  - **Chỉ DTLS 1.2** cho full handshake (pin `DTLSv12`; nhánh resume legacy chào 1.2→1.0); DTLS 1.3 chưa chào.
  - **Client anonymous** (không cert client) — DTLS ở OpenConnect được CSTP session ủy quyền, không mutual PKI.
  - **Validate live ocserv (2026-06-24, lab [openconnect](../../lab/openconnect)):** đường **full DTLS handshake** test offline xanh (server BouncyCastle giả lập). **Đường resume legacy** — **session_id correlation ĐÃ ĐÚNG** (ocserv nhận session_id của ta, log `setting up legacy DTLS (resumption) connection`, hết báo `invalid session ID size (0)`), nhưng **handshake rút gọn chưa hoàn tất** với ocserv thật: BouncyCastle ném `TlsFatalAlert: internal_error(80)` ⇒ ocserv `dtls_mainloop failed -1` ⇒ client **fallback CSTP-over-TLS** (đúng thiết kế). Residual = interop DTLS legacy GnuTLS↔BouncyCastle (đem master secret theo cách nonstandard của AnyConnect — openconnect client thật cũng cần patch GnuTLS/OpenSSL riêng cho đường này). Xem [.docs/10](../../.docs/10-codebase-architecture-and-flow.md) bảng "Khác biệt".

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5/§9 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md).
