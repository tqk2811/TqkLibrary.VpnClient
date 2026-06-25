# TqkLibrary.VpnClient.Transport.Tcp

> **Transport TCP trần** — hiện thực [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs#L4) bằng một `TcpClient` đọc/ghi thẳng `NetworkStream`, **không TLS**. Resolve `host:port` (theo [`AddressFamilyPreference`](../TqkLibrary.VpnClient.Abstractions/Net/AddressFamilyPreference.cs) → mở socket đúng họ IPv4/IPv6) hoặc connect một `IPEndPoint` đã resolve sẵn. Đây là nền của **Transport.Tls** (TLS phủ `SslStream` lên `Stream` này) và là transport **OpenVPN `proto tcp`** đi thẳng (OpenVPN làm TLS in-band trong control channel, không trên dây). Tách ra theo roadmap **F.1**.

## Mục đích

Trước F.1, mỗi driver tự nhúng một bản TCP/TLS-over-TCP gần trùng nhau (SSTP, SoftEther, OpenConnect, OpenVPN-TCP). F.1 gom điểm chung ra **2 project transport dùng chung**: `Transport.Tcp` (TCP trần — file này) và [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) (TLS build trên TCP). Driver chỉ còn cầm transport qua interface ở `Abstractions`, không nhân bản logic kết nối/hủy theo TFM.

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (concrete) — ngang hàng `Transport.Dtls`/`Transport.RawIp`; dưới tầng DRIVER, chỉ phụ thuộc `Abstractions`.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference) — CHỈ Abstractions** (`IByteStreamTransport` + `IHostResolver`/`AddressFamilyPreference`); **không package ngoài** (chỉ `System.Net.Sockets` của BCL).
- **Được dùng bởi:**
  - [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) — `TlsByteStream`/`BouncyCastleTlsByteStream` bọc `TcpByteStream`.
  - Driver chạy thẳng TCP qua một `*SocketTransportFactory` cầm `TcpByteStream`: [`Drivers.OpenVpn`](../TqkLibrary.VpnClient.Drivers.OpenVpn) (`proto tcp` — `OpenVpnSocketTransportFactory`), [`Drivers.Ssh`](../TqkLibrary.VpnClient.Drivers.Ssh) (`SshSocketTransportFactory`), [`Drivers.Tinc`](../TqkLibrary.VpnClient.Drivers.Tinc) (`TincSocketTransportFactory`), [`Drivers.Vtun`](../TqkLibrary.VpnClient.Drivers.Vtun) (`VtunSocketTransportFactory`).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.Tcp/
└── TcpByteStream.cs    IByteStreamTransport trên TcpClient: 2 ctor (resolve host / IPEndPoint sẵn), phơi Stream cho lớp TLS, Read/Write/Connect/Dispose theo TFM
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `TcpByteStream` | `IByteStreamTransport` + `IDisposable`: ctor `(host, port, afPref, resolver)` resolve rồi connect / ctor `(IPEndPoint)` đã resolve; `Host` (SNI cho lớp TLS) + `Stream` (NetworkStream đã nối, để TLS phủ lên); cancel theo TFM (net8 overload token; ns2.0 cancel-by-dispose) | [TcpByteStream.cs:22](TcpByteStream.cs#L22) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class áp dụng | Ghi chú |
|-------|---------------|---------|
| — (transport thuần TCP) | `TcpByteStream` | Không codec/giao thức riêng; chỉ là byte-pipe TCP. SNI/TLS thuộc `Transport.Tls`. |

## API / cách dùng

```csharp
// Resolve host theo họ địa chỉ:
IByteStreamTransport tcp = new TcpByteStream("vpn.example", 1194, AddressFamilyPreference.Auto);
await tcp.ConnectAsync(ct);

// Hoặc endpoint đã resolve (vd OpenVPN đã có IPEndPoint):
var tcp2 = new TcpByteStream(new IPEndPoint(addr, 443));
await tcp2.ConnectAsync(ct);
// TLS phủ lên: new TlsByteStream(host, remote) sẽ wrap tcp2.Stream — xem Transport.Tls.
```

## Luồng nội bộ

### `ConnectAsync` ([TcpByteStream.cs:22](TcpByteStream.cs#L22))
1. Nếu ctor nhận `IPEndPoint` → dùng thẳng; else `IHostResolver.ResolveAsync(host, afPref)` → `IPAddress` (mở socket đúng `AddressFamily`).
2. `new TcpClient(family)` → `ConnectAsync` (net8: overload token; ns2.0: `cancellationToken.Register(dispose)`).
3. `_stream = tcp.GetStream()` → phơi qua `Stream` cho lớp TLS bọc `SslStream`.

### `ReadAsync`/`WriteAsync`
- Đọc/ghi thẳng `NetworkStream`; net8 dùng overload `Memory<byte>`+token, ns2.0 `MemoryMarshal.TryGetArray` → overload mảng (fallback copy tạm khi không lấy được array).

## Trạng thái & ghi chú

- **Đã hiện thực (code + test offline):** `TcpByteStream` đầy đủ (2 ctor, phơi `Stream`), build xanh cả `netstandard2.0` + `net8.0`. Test offline [`TcpByteStreamTests`](../../tests/TqkLibrary.VpnClient.Transport.Tcp.Tests/TcpByteStreamTests.cs): round-trip loopback `TcpListener` (resolve-host + IPEndPoint), `Stream` throw khi chưa connect, dispose idempotent.
- **netstandard2.0 vs net8.0:** ns2.0 không có `TcpClient.ConnectAsync(token)`/`NetworkStream.ReadAsync(Memory,token)` ⇒ cancel-by-dispose + overload mảng (`MemoryMarshal`); guard `#if NET5_0_OR_GREATER`.
- **Ghi chú:** transport này **không mã hóa** — dùng trực tiếp chỉ cho protocol tự lo bảo mật (OpenVPN bọc TLS in-band). Cần TLS thì dùng [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) (F.1).
