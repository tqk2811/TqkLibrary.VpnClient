# TqkLibrary.VpnClient.Transport.Tls

> **Transport TLS-over-TCP** — hiện thực [`ITlsByteStream`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) (mở rộng `IByteStreamTransport`, phơi thêm `RemoteCertificate`) bằng cách **bọc một [`TcpByteStream`](../TqkLibrary.VpnClient.Transport.Tcp/TcpByteStream.cs#L22)** rồi chạy handshake TLS client. **2 bản:** (a) `TlsByteStream` (BCL `SslStream`) — dùng chung **SSTP / SoftEther / OpenConnect-TLS-only** (roadmap **F.1**); (b) `BouncyCastleTlsByteStream` (BouncyCastle `TlsClientProtocol`) — thêm **exporter RFC 5705** ([`ITlsKeyingMaterialExporter`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsKeyingMaterialExporter.cs#L16)) mà `SslStream` không có trên net8/ns2.0, dùng cho **OpenConnect DTLS 1.2 PSK** (PSK = EKM của CSTP TLS).

## Mục đích

Trước F.1, 3 driver TLS (SSTP, SoftEther, OpenConnect) mỗi cái nhúng một bản `SslStream`-over-`TcpClient` gần trùng nhau (cùng cách capture cert, cùng cách rào TFM). F.1 gom về đây: TLS **build trên** [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) (TcpByteStream lo resolve + connect TCP + phơi `Stream`; lớp này chỉ phủ `SslStream` lên). `RemoteCertificate` được phơi vì **SSTP crypto binding** ([MS-SSTP] §3.2.4) băm cert server; các giao thức khác bỏ qua. Mặc định chấp nhận **mọi cert** (định danh server do auth/crypto-binding của từng giao thức lo, không qua PKI), trừ khi truyền `RemoteCertificateValidationCallback` để validate (roadmap **P0.6**).

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (concrete) — trên `Transport.Tcp`, ngang hàng `Transport.Dtls`/`Transport.RawIp`; dưới tầng DRIVER.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):** `Abstractions` (`ITlsByteStream`/`ITlsKeyingMaterialExporter`/`IHostResolver`/`AddressFamilyPreference`) + [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) (`TcpByteStream`). **PackageReference:** `BouncyCastle.Cryptography` 2.4.0 (chỉ cho `BouncyCastleTlsByteStream`; `TlsByteStream` vẫn dùng `SslStream` của BCL).
- **Được dùng bởi:** [`Drivers.Sstp`](../TqkLibrary.VpnClient.Drivers.Sstp) (`SstpConnection`/`SstpTransport` default), [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) (`SoftEtherTlsTransportFactory`), [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect) (`OpenConnectSocketTransportFactory` dùng `TlsByteStream`; `OpenConnectBouncyCastleTransportFactory` dùng `BouncyCastleTlsByteStream` cho DTLS-PSK).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.Tls/
├── TlsByteStream.cs                ITlsByteStream: bọc TcpByteStream + SslStream; 2 ctor (resolve host / IPEndPoint sẵn), capture RemoteCertificate, cert-callback (P0.6), Read/Write/Connect/Dispose theo TFM
└── BouncyCastleTlsByteStream.cs    ITlsByteStream + ITlsKeyingMaterialExporter: bọc TcpByteStream + BouncyCastle TlsClientProtocol (TLS 1.2); exporter RFC 5705 (tính TLS 1.2 PRF tay, bỏ qua EMS-guard) — pre-register + tính trong NotifyHandshakeComplete rồi cache (master secret bị xóa sau handshake)
```
> `ITlsByteStream` + `ITlsKeyingMaterialExporter` **không** ở đây mà ở [Abstractions/Transport/Interfaces](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) (điểm chung đứng sau interface — driver chỉ phụ thuộc interface).

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `ITlsByteStream` | (Abstractions) `IByteStreamTransport` + `RemoteCertificate` (cert server, null tới khi connect) | [ITlsByteStream.cs:13](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsByteStream.cs#L13) |
| `ITlsKeyingMaterialExporter` | (Abstractions) `ExportKeyingMaterial(label, context, length)` — exporter RFC 5705 trên TLS session đã xong; chỉ `BouncyCastleTlsByteStream` hiện thực | [ITlsKeyingMaterialExporter.cs:16](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/ITlsKeyingMaterialExporter.cs#L16) |
| `TlsByteStream` | Bọc `TcpByteStream` + `SslStream`: ctor `(host, port, cb, afPref, resolver)` / `(host, IPEndPoint, cb)`; callback validate cert (null=accept any) + capture `RemoteCertificate`; `AuthenticateAsClient(TargetHost=host)`; cancel theo TFM (net8 token; ns2.0 cancel-by-dispose) | [TlsByteStream.cs:25](TlsByteStream.cs#L25) |
| `BouncyCastleTlsByteStream` | Bọc `TcpByteStream` + BouncyCastle `TlsClientProtocol` (pin TLS 1.2): cùng 2 ctor + cert-callback + capture cert; **thêm** `RequestKeyingMaterialExport(label,ctx,len)` (đăng ký TRƯỚC connect) + `ExportKeyingMaterial(...)` (RFC 5705). Vì `SslStream` không có exporter (chỉ net9+) và ocserv không bật extended_master_secret, lớp này **tính TLS 1.2 PRF tay** (`PRF(master_secret, label, client_random+server_random[+ctx])` như gnutls) trong `NotifyHandshakeComplete` (master secret bị BouncyCastle xóa ngay sau đó) rồi cache. Handshake/IO offload `Task.Run` qua `NetworkStream` đồng bộ | [BouncyCastleTlsByteStream.cs:36](BouncyCastleTlsByteStream.cs#L36) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class áp dụng | Ghi chú |
|-------|---------------|---------|
| TLS 1.2/1.3 (`SslStream`) | `TlsByteStream` | Handshake client qua BCL `SslStream.AuthenticateAsClientAsync`; SNI = host gốc (giữ khi connect bằng IPAddress). |
| TLS 1.2 (BouncyCastle) | `BouncyCastleTlsByteStream` | Handshake client qua `Org.BouncyCastle.Tls.TlsClientProtocol`, pin `ProtocolVersion.TLSv12`; client anonymous, accept-any/validate cert. |
| RFC 5705 (TLS keying-material exporter) | `BouncyCastleTlsByteStream.ExportKeyingMaterial` | Tính TLS 1.2 PRF tay (master_secret + client_random+server_random) — bỏ qua EMS-guard của BouncyCastle để khớp gnutls (ocserv không bật extended_master_secret). Consumer: OpenConnect DTLS-PSK (label `EXPORTER-openconnect-psk`, 32B). |
| RFC 6125 (SNI/TargetHost) | `TlsByteStream` | `SslClientAuthenticationOptions.TargetHost = host` (net8); `AuthenticateAsClientAsync(host)` (ns2.0). |

## API / cách dùng

```csharp
// Driver TLS (SSTP/SoftEther/OpenConnect) ráp transport TLS dùng chung:
ITlsByteStream tls = new TlsByteStream("vpn.example", 443,
    certificateValidationCallback: null,                 // null = accept any (định danh qua crypto binding)
    addressFamilyPreference: AddressFamilyPreference.Auto);
await tls.ConnectAsync(ct);
X509Certificate2? serverCert = tls.RemoteCertificate;    // SSTP crypto binding cần cert này

// Khi caller đã resolve sẵn endpoint (vd OpenConnect correlate DTLS):
var tls2 = new TlsByteStream("vpn.example", new IPEndPoint(addr, 443));
await tls2.ConnectAsync(ct);
```

## Luồng nội bộ

### `ConnectAsync` ([TlsByteStream.cs:64](TlsByteStream.cs#L64))
1. `_tcp.ConnectAsync` — `TcpByteStream` resolve (theo `AddressFamilyPreference`) + mở socket + phơi `Stream`.
2. `new SslStream(_tcp.Stream, leaveInnerStreamOpen: false, validationCb)` — callback **capture** cert (`RemoteCertificate = new X509Certificate2(cert)`) rồi uỷ quyết định cho `certificateValidationCallback` (null ⇒ `true`, accept any).
3. `AuthenticateAsClientAsync(TargetHost=host)` (net8 overload token; ns2.0 cancel-by-dispose).

### `Dispose`
- `_ssl.Dispose()` đóng inner `NetworkStream` (`leaveInnerStreamOpen:false`); `_tcp.Dispose()` đóng `TcpClient` (idempotent); `RemoteCertificate?.Dispose()`.

## Trạng thái & ghi chú

- **Đã hiện thực (code + test offline):** `TlsByteStream` hoàn chỉnh (2 ctor, capture cert, cert-callback), build xanh cả `netstandard2.0` + `net8.0`. Test offline [`TlsByteStreamTests`](../../tests/TqkLibrary.VpnClient.Transport.Tls.Tests/TlsByteStreamTests.cs): round-trip TLS qua loopback `TcpListener` + server `SslStream` cert tự ký runtime, `RemoteCertificate` được capture, callback từ chối ⇒ handshake ném, `ReadAsync` throw khi chưa connect.
- **netstandard2.0 vs net8.0:** ns2.0 không có `SslStream.AuthenticateAsClientAsync(options, token)`/`ReadAsync(Memory,token)` ⇒ cancel-by-dispose + overload mảng (`MemoryMarshal`); guard `#if NET5_0_OR_GREATER`. **DTLS không dùng `SslStream`** (BCL không hỗ trợ) — đường DTLS của OpenConnect ở [`Transport.Dtls`](../TqkLibrary.VpnClient.Transport.Dtls) qua BouncyCastle.
- **Ghi chú:** `TlsByteStream` thay 3 bản TLS-over-TCP nhúng-trong-driver cũ (SSTP, SoftEther, OpenConnect inlined) — F.1 đã gom. OpenVPN-TCP **không** dùng lớp này (TLS in-band, chỉ cần [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) trần).
- **`BouncyCastleTlsByteStream` (V.5 DTLS-PSK, VALIDATE LIVE ✅ ocserv 1.2.4):** chỉ OpenConnect dùng (qua `OpenConnectBouncyCastleTransportFactory`) để export PSK RFC 5705 từ CSTP TLS session — SSTP/SoftEther giữ `TlsByteStream` (`SslStream`), **không regression**. Validate live: CSTP-over-TLS (HTTP auth + CONNECT + CSTP read-loop byte-exact) + DTLS-PSK handshake completed + data 2 chiều qua UDP/443. **EMS-guard bypass:** `SslStream.ExportKeyingMaterial` chỉ có từ net9+, và BouncyCastle `TlsContext.ExportKeyingMaterial` từ chối session không extended_master_secret (ocserv không bật) ⇒ tính TLS 1.2 PRF tay như gnutls. **Timing:** master secret bị BouncyCastle xóa ngay khi handshake xong ⇒ export phải đăng ký TRƯỚC connect (`RequestKeyingMaterialExport`) + tính trong `NotifyHandshakeComplete` rồi cache. **OpenVPN `tls-ekm` (F.5)** dùng exporter RFC 5705 tương tự nhưng KHÔNG dùng lớp này — control channel OpenVPN chạy TLS trên bridge **in-memory** (không TCP) nên có engine riêng `OpenVpnBouncyCastleControlTls` ở [`OpenVpn`](../TqkLibrary.VpnClient.OpenVpn) (cùng cách capture-tại-`NotifyHandshakeComplete`, EMS-aware + fallback PRF).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) (F.1).
