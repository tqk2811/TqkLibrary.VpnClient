# TqkLibrary.VpnClient.Transport.IpsecTcp

> **TCP Encapsulation of IKE and ESP (RFC 8229)** — adapter đóng khung trình bày một [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10) (ranh giới datagram) trên một [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs#L4) (dòng byte). Cho IKE/ESP đi qua **TCP** (tùy chọn **TLS**) khi UDP/500+4500 bị firewall chặn. Bản chất = **decorator đóng/mở khung**: gửi stream-prefix `"IKETCP"` (§3) + length-prefix 16-bit (§2) để tái lập ranh giới datagram mà byte-stream đã xóa. **Demux IKE-vs-ESP KHÔNG thuộc đây** (RFC 3948 non-ESP marker do tầng NAT-T `Ipsec/Nat` lo); adapter này chỉ đóng/mở khung, mỗi datagram là opaque.

## Mục đích

Firewall doanh nghiệp thường chỉ mở TCP/443 và chặn UDP → IKE/ESP-over-UDP không đi được. RFC 8229 bọc mỗi bản tin IKE/ESP trong một khung length-prefixed trên một byte-stream tin cậy (TCP), tùy chọn bọc thêm TLS để "trông như HTTPS" (§5). Project này hiện thực **đúng phần đóng khung**, **tái dùng nguyên** [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp)/[`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) làm inner (không code TCP/TLS lại), và giữ codec IKE/ESP nguyên vẹn ở tầng trên (mỗi datagram opaque).

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (concrete) — ngang hàng `Transport.Dtls`/`Transport.RawIp`/`Transport.Tcp`/`Transport.Tls`; dưới tầng DRIVER.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):** [`Abstractions`](../TqkLibrary.VpnClient.Abstractions) (`IDatagramTransport`/`IByteStreamTransport`) + [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) (`TcpByteStream`) + [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) (`TlsByteStream`, biến thể §5). **Không package ngoài.**
- **Được dùng bởi:** *(chưa có — CHƯA wire vào driver)*. Dự kiến [`Drivers.Ikev2`](../TqkLibrary.VpnClient.Drivers.Ikev2)/`UseIkev2` chọn transport IKE/ESP UDP↔TCP (+ fallback tự động). Xem [Trạng thái & ghi chú](#trạng-thái--ghi-chú).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.IpsecTcp/
├── Rfc8229Framing.cs              codec static thuần: StreamPrefix "IKETCP" (§3) + Frame(message) → Length‖message (§2)
├── Rfc8229Reassembler.cs          reassembler instance (có trạng thái buffer): Append + TryReadMessage, tùy chọn strip stream-prefix
└── IpsecTcpDatagramTransport.cs   IDatagramTransport bọc IByteStreamTransport: connect+prefix, Send=Frame, Receive=reassemble
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `Rfc8229Framing` | Codec **static** thuần (pure): hằng `StreamPrefixLength`=6/`LengthFieldSize`=2/`MaxMessageLength`=65533, `StreamPrefix` (6 byte `"IKETCP"`), `Frame(message)` → `Length(2 BE, gồm-cả-field) ‖ message` | [Rfc8229Framing.cs:19](Rfc8229Framing.cs#L19), [`StreamPrefix`:36](Rfc8229Framing.cs#L36), [`Frame`:43](Rfc8229Framing.cs#L43) |
| `Rfc8229Reassembler` | Reassembler **instance** (buffer trạng thái): `Append(chunk)` + `TryReadMessage(out message)` ráp bản tin qua mọi ranh đọc; ctor `expectStreamPrefix` (responder strip `"IKETCP"` đầu stream); `HasBufferedData` (còn khung dở) | [Rfc8229Reassembler.cs:17](Rfc8229Reassembler.cs#L17), [ctor:27](Rfc8229Reassembler.cs#L27), [`TryReadMessage`:49](Rfc8229Reassembler.cs#L49) |
| `IpsecTcpDatagramTransport` | `IDatagramTransport` (instance sau interface) bọc inner `IByteStreamTransport`: ctor `(inner, sendStreamPrefix=true)` (inject để test) + ctor tiện dụng `(host, port, useTls=false)`; `ConnectAsync` (connect + ghi prefix nếu initiator), `SendAsync`=`Frame`+write, `ReceiveAsync`=reassemble, `DisposeAsync`=dispose inner | [IpsecTcpDatagramTransport.cs:19](IpsecTcpDatagramTransport.cs#L19), [ctor inject:36](IpsecTcpDatagramTransport.cs#L36), [ctor tiện dụng:49](IpsecTcpDatagramTransport.cs#L49), [`ReceiveAsync`:71](IpsecTcpDatagramTransport.cs#L71) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Điều | Class áp dụng | Ghi chú |
|-------|------|---------------|---------|
| RFC 8229 §3 | Stream prefix | `Rfc8229Framing.StreamPrefix` + `IpsecTcpDatagramTransport.ConnectAsync` | Ngay sau TCP connect, **initiator (client) MUST gửi 6 byte** `0x49 4B 45 54 43 50` (`"IKETCP"`) **đúng 1 lần** trước mọi bản tin. **Responder KHÔNG echo.** |
| RFC 8229 §2 | Length framing | `Rfc8229Framing.Frame` + `Rfc8229Reassembler.TryReadMessage` | Mỗi bản tin đứng sau **Length 16-bit network byte order**, **GỒM CẢ 2 byte của chính field** (đã đối chiếu RFC: min Length = 2 ⇒ bản tin rỗng). Bên nhận dùng Length để tái lập ranh giới datagram. |
| RFC 8229 §5 | TLS "trông như HTTPS" | inner = `TlsByteStream` | Chỉ cần inner `IByteStreamTransport` là TLS thay vì TCP (ctor `(host, port, useTls: true)`) — **KHÔNG** code TLS riêng, dùng lại `Transport.Tls`. |
| RFC 3948 | Non-ESP marker (demux) | — (KHÔNG thuộc project) | Demux IKE/ESP do tầng NAT-T `Ipsec/Nat` lo — adapter này chỉ đóng/mở khung, datagram opaque. |

## Bất đối xứng vai trò (RFC 8229 §3)

Chỉ **initiator** gửi prefix `"IKETCP"`; responder không. Từ đó suy ra: bên **gửi** prefix (initiator) **KHÔNG kỳ vọng** prefix inbound (đọc từ responder — không có), và ngược lại bên **không gửi** (responder) **kỳ vọng** prefix inbound (đọc từ initiator). Vì thế `IpsecTcpDatagramTransport` đặt `reassembler = new Rfc8229Reassembler(expectStreamPrefix: !sendStreamPrefix)` — một tham số `sendStreamPrefix` lái đủ cả hai chiều. Client thực tế luôn là initiator (`sendStreamPrefix: true`); chế độ responder chỉ dùng cho loopback test 2 đầu.

## API / cách dùng

```csharp
// Initiator qua TCP trần (RFC 8229 §2/§3):
await using var t = new IpsecTcpDatagramTransport("vpn.example", 4500, useTls: false);
await t.ConnectAsync(ct);                 // connect + gửi "IKETCP" prefix
await t.SendAsync(ikeOrEspDatagram, ct);  // Length‖datagram
int n = await t.ReceiveAsync(buffer, ct); // reassemble → 1 datagram

// Biến thể §5 "trông như HTTPS" (TLS) — chỉ đổi cờ:
await using var s = new IpsecTcpDatagramTransport("vpn.example", 443, useTls: true);

// Inject inner tùy ý (test/loopback, hoặc chọn TCP/TLS ngoài):
IByteStreamTransport inner = /* TcpByteStream / TlsByteStream / fake */;
await using var t2 = new IpsecTcpDatagramTransport(inner, sendStreamPrefix: true);
```

## Luồng nội bộ

### `ConnectAsync` ([IpsecTcpDatagramTransport.cs:55](IpsecTcpDatagramTransport.cs#L55))
1. `inner.ConnectAsync(ct)` (TCP/TLS handshake của inner).
2. Nếu `sendStreamPrefix` (initiator) → `inner.WriteAsync("IKETCP")` đúng 1 lần (§3).

### `SendAsync` ([IpsecTcpDatagramTransport.cs:64](IpsecTcpDatagramTransport.cs#L64))
- `Rfc8229Framing.Frame(datagram)` = `Length(2 BE = 2 + len) ‖ datagram` → `inner.WriteAsync(frame)`. Datagram > 65533 byte ⇒ `ArgumentOutOfRangeException` (Length 16-bit tràn).

### `ReceiveAsync` ([IpsecTcpDatagramTransport.cs:71](IpsecTcpDatagramTransport.cs#L71))
1. Lặp `reassembler.TryReadMessage`: nếu có 1 bản tin đủ → copy vào `buffer`, trả độ dài (`buffer` nhỏ hơn bản tin ⇒ `ArgumentException`).
2. Chưa đủ → `inner.ReadAsync(readBuffer 8192)` → `Append`. Inner đóng (`Read=0`): còn khung dở (`HasBufferedData`) ⇒ `EndOfStreamException` (truncated); đúng ranh khung ⇒ `EndOfStreamException` (EOF). *(Bản tin rỗng hợp lệ trả `0`, phân biệt với đóng stream bằng exception.)*

### `Rfc8229Reassembler.TryReadMessage` ([Rfc8229Reassembler.cs:49](Rfc8229Reassembler.cs#L49))
- (Nếu `expectStreamPrefix` + chưa strip) đủ 6 byte đầu → so `"IKETCP"`, sai ⇒ `FormatException`, đúng ⇒ bỏ 6 byte.
- Đủ 2 byte Length → đọc big-endian; `Length < 2` ⇒ `FormatException` (stream lệch). Đủ `Length` byte → tách `message = buffer[2 .. Length)`, bỏ `Length` byte; else trả `false` (chờ thêm).

## Trạng thái & ghi chú

- **Đã hiện thực (code + test offline):** `Rfc8229Framing` + `Rfc8229Reassembler` + `IpsecTcpDatagramTransport` đầy đủ, build xanh cả `netstandard2.0` + `net8.0`. **33 test** ở [`tests/TqkLibrary.VpnClient.Transport.IpsecTcp.Tests`](../../tests/TqkLibrary.VpnClient.Transport.IpsecTcp.Tests):
  - [`Rfc8229FramingTests.cs`](../../tests/TqkLibrary.VpnClient.Transport.IpsecTcp.Tests/Rfc8229FramingTests.cs) — `Frame` byte-exact (Length gồm-cả-field, đa cỡ tới 65533) + throw khi quá cỡ; reassembly nhiều bản tin qua **đa cỡ chunk** (1 byte / cắt giữa Length / cắt giữa message / cả stream 1 lần) byte-exact; strip stream-prefix (đúng/hỏng ⇒ `FormatException`); `Length < 2` ⇒ `FormatException`; `HasBufferedData` bám khung dở.
  - [`IpsecTcpDatagramTransportTests.cs`](../../tests/TqkLibrary.VpnClient.Transport.IpsecTcp.Tests/IpsecTcpDatagramTransportTests.cs) + harness [`InMemoryByteStreamPair.cs`](../../tests/TqkLibrary.VpnClient.Transport.IpsecTcp.Tests/InMemoryByteStreamPair.cs) — **loopback 2 đầu** (initiator⇄responder qua pipe byte-stream in-memory): round-trip datagram 2 chiều + đa cỡ (1..65533) + datagram rỗng + lớn (>read-buffer 8192, nhiều inner-read); connect ghi đúng prefix (initiator) / không ghi (responder); inner đóng giữa khung / đúng ranh ⇒ `EndOfStreamException`; buffer nhỏ ⇒ `ArgumentException`.
  - Chạy offline: `dotnet exec tests/TqkLibrary.VpnClient.Transport.IpsecTcp.Tests/bin/Debug/net8.0/TqkLibrary.VpnClient.Transport.IpsecTcp.Tests.dll -notrait "Category=Integration"`.
- **netstandard2.0 vs net8.0:** `BinaryPrimitives`/`Span`/`Channel` qua polyfill ns2.0 ([src/Directory.Build.props](../Directory.Build.props)); không `#if` guard nào cần trong project này.
- **Clean-room:** re-implement từ RFC 8229 (đã đối chiếu **§2 Length gồm cả 2 byte field** + **§3 prefix chỉ initiator, không echo**), **không copy code GPL/AGPL**.
- **Follow-up (CHƯA làm):**
  - **Wire vào [`Drivers.Ikev2`](../TqkLibrary.VpnClient.Drivers.Ikev2)/`UseIkev2`**: chọn transport IKE/ESP UDP↔TCP + **fallback tự động** UDP→TCP khi UDP/500+4500 bị chặn. Vì thế RFC 8229 **chưa** vào `VpnClientBuilder` ⇒ không line-ref drift ở facade.
  - **Live-validate** vs strongSwan (server bật `fragmentation`/`kernel-libipsec` TCP hoặc `charon` TCP-encap).
  - Roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) **V.15**.

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5/§9 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) (V.15).
