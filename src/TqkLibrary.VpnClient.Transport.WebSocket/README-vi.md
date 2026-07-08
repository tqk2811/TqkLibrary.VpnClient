# TqkLibrary.VpnClient.Transport.WebSocket

> **Client-side WebSocket (RFC 6455)** — một [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs#L4) bọc một `IByteStreamTransport` **inner** (TCP trần cho `ws://`, TLS cho `wss://`): khi connect chạy **§4 HTTP Upgrade** rồi tunnel byte ứng dụng dưới **§5 binary frame**. Framing **tự cài từ RFC** — **KHÔNG** dùng `System.Net.WebSockets.ClientWebSocket` — nên chạy được trên **mọi inner transport** và **giống hệt** trên `netstandard2.0` + `net8.0`. Đây là **nền cho wstunnel-style anti-DPI**: làm cho tunnel "trông như WebSocket/HTTPS" để vượt DPI.

## Mục đích

Nhiều mạng chỉ cho HTTP/HTTPS qua và chặn/DPI mọi giao thức lạ. Bọc data plane trong một WebSocket "thật" (HTTP Upgrade hợp lệ + framing RFC 6455) làm luồng trông như trình duyệt nối WebSocket qua TLS. Project này hiện thực **đúng phần client-side handshake + framing**, **tái dùng nguyên** [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp)/[`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) làm inner (không code TCP/TLS lại), và để lớp trên bơm byte opaque (mỗi `WriteAsync` = một binary message masked).

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (decorator byte-stream) — bọc một `IByteStreamTransport` và **cũng là** `IByteStreamTransport`, nên compose được **dưới** bất kỳ driver/transport chạy trên byte-stream (OpenVPN-over-TCP, SSTP, SoftEther, ...). Ngang hàng khái niệm với `Transport.IpsecTcp` (RFC 8229) nhưng cho **byte-stream** thay vì datagram.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):** [`Abstractions`](../TqkLibrary.VpnClient.Abstractions) (`IByteStreamTransport`) + [`Transport.Tcp`](../TqkLibrary.VpnClient.Transport.Tcp) (`TcpByteStream`, dùng bởi ctor tiện dụng `ws://`) + [`Transport.Tls`](../TqkLibrary.VpnClient.Transport.Tls) (`TlsByteStream`, ctor tiện dụng `wss://`). **Không package ngoài.**
- **Được dùng bởi:** *(chưa có — CHƯA wire vào `VpnClientBuilder`/driver)*. Dự kiến compose decorator WebSocket dưới OpenVPN / driver byte-stream khác. Xem [Trạng thái & ghi chú](#trạng-thái--ghi-chú).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.WebSocket/
├── WebSocketByteStream.cs         IByteStreamTransport: handshake §4 + tunnel §5 binary, auto-pong, close⇒0
├── Rfc6455Frame.cs                codec static thuần: EncodeClientFrame(masked)/EncodeServerFrame/TryDecodeFrame
├── Rfc6455FrameReassembler.cs     reassembler instance (buffer trạng thái): Append + TryReadFrame qua mọi ranh đọc
├── Rfc6455Opcode.cs               enum opcode §5.2 (Continuation/Text/Binary/Close/Ping/Pong)
├── WebSocketHandshake.cs          static §4: BuildClientRequest / ComputeAccept / TryParseResponse
├── IWebSocketRandom.cs            seam RNG (key 16-byte + mask 4-byte) — inject fake xác định cho test
└── CryptoWebSocketRandom.cs       default IWebSocketRandom = RandomNumberGenerator
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `WebSocketByteStream` | `IByteStreamTransport` (instance sau interface) bọc inner `IByteStreamTransport`: ctor inject `(inner, host, path="/", subProtocol=null, random=null, sendCloseOnDispose=true)` + ctor tiện dụng `(host, port, useTls, ...)`; `ConnectAsync` (§4 handshake), `WriteAsync` (1 masked binary frame/write), `ReadAsync` (un-mask + ráp fragment + auto-pong + close⇒0), `DisposeAsync` (best-effort close) | [WebSocketByteStream.cs:25](WebSocketByteStream.cs#L25), [ctor inject:55](WebSocketByteStream.cs#L55), [ctor tiện dụng:71](WebSocketByteStream.cs#L71), [`ConnectAsync`:79](WebSocketByteStream.cs#L79), [`WriteAsync`:116](WebSocketByteStream.cs#L116), [`ReadAsync`:125](WebSocketByteStream.cs#L125) |
| `Rfc6455Frame` | Codec khung **static** thuần (pure): `EncodeClientFrame(opcode, payload, maskKey)` (§5.3 masked, FIN=1) / `EncodeServerFrame(opcode, payload, fin=true)` (unmasked, cho test-server) / `TryDecodeFrame(buffer, …, out consumed)` (giải mã + un-mask, `false` khi khung dở); 3 kiểu length 7-bit/16-bit/64-bit; hằng `MaskingKeyLength`=4, `MaxControlPayloadLength`=125 | [Rfc6455Frame.cs:17](Rfc6455Frame.cs#L17), [`EncodeClientFrame`:31](Rfc6455Frame.cs#L31), [`EncodeServerFrame`:44](Rfc6455Frame.cs#L44), [`TryDecodeFrame`:108](Rfc6455Frame.cs#L108) |
| `Rfc6455FrameReassembler` | Reassembler **instance** (buffer trạng thái): `Append(chunk)` + `TryReadFrame(out fin, out opcode, out payload)` tách từng khung qua mọi ranh đọc (cắt giữa length/mask/payload · nhiều khung 1 lần); `HasBufferedData` | [Rfc6455FrameReassembler.cs:12](Rfc6455FrameReassembler.cs#L12), [`TryReadFrame`:31](Rfc6455FrameReassembler.cs#L31) |
| `Rfc6455Opcode` | enum §5.2: `Continuation`(0x0)/`Text`(0x1)/`Binary`(0x2)/`Close`(0x8)/`Ping`(0x9)/`Pong`(0xA) | [Rfc6455Opcode.cs:9](Rfc6455Opcode.cs#L9) |
| `WebSocketHandshake` | static §4: `BuildClientRequest(host, path, key, subProtocol=null)` (GET + Upgrade/Connection/Key/Version:13), `ComputeAccept(key)` = `base64(SHA1(key‖AcceptGuid))`, `TryParseResponse(response, expectedAccept)` (status 101 + accept khớp) | [WebSocketHandshake.cs:16](WebSocketHandshake.cs#L16), [`ComputeAccept`:26](WebSocketHandshake.cs#L26), [`BuildClientRequest`:41](WebSocketHandshake.cs#L41), [`TryParseResponse`:73](WebSocketHandshake.cs#L73) |
| `IWebSocketRandom` / `CryptoWebSocketRandom` | Seam RNG (`NextBytes(count)`): key 16-byte (§4.1) + mask 4-byte/frame (§5.3). Default `CryptoWebSocketRandom` = `RandomNumberGenerator`; fake đếm xác định trong test | [IWebSocketRandom.cs:9](IWebSocketRandom.cs#L9), [CryptoWebSocketRandom.cs:9](CryptoWebSocketRandom.cs#L9) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Điều | Class áp dụng | Ghi chú |
|-------|------|---------------|---------|
| RFC 6455 §1.3 | Sec-WebSocket-Accept vector | `WebSocketHandshake.ComputeAccept` | Ví dụ chuẩn: key `dGhlIHNhbXBsZSBub25jZQ==` ⇒ accept `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` (magic GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`). **Có test vector.** |
| RFC 6455 §4 | Opening handshake | `WebSocketHandshake` + `WebSocketByteStream.ConnectAsync` | Client gửi `GET` + `Upgrade: websocket`/`Connection: Upgrade`/`Sec-WebSocket-Key`(16-byte base64)/`Sec-WebSocket-Version: 13`; server MUST trả **101** + `Sec-WebSocket-Accept` khớp, sai/không-101 ⇒ `IOException`. Byte thừa sau CRLFCRLF (server pipeline frame ngay sau 101) được nạp thẳng vào reassembler. |
| RFC 6455 §5.2 | Frame format | `Rfc6455Frame` | byte0 = `FIN(1)‖RSV(3)=0‖opcode(4)`; byte1 = `MASK(1)‖len(7)`; len7 `126`⇒16-bit BE, `127`⇒64-bit BE. |
| RFC 6455 §5.3 | Client masking | `Rfc6455Frame.EncodeClientFrame` | **Client→server MUST masked**: mask key 4-byte, `transformed[i] = original[i] XOR maskKey[i%4]`. Server→client không mask (codec un-mask khi giải). |
| RFC 6455 §5.4 | Fragmentation | `WebSocketByteStream.ReadAsync` + `_fragmentBuffer` | Data frame `FIN=0` + các `Continuation` ⇒ ráp lại, `FIN=1` mới giao lên `ReadAsync`. Data mới xen giữa fragment dở ⇒ `InvalidOperationException`. |
| RFC 6455 §5.5.1 | Close | `WebSocketByteStream.ReadAsync` | Nhận **close** ⇒ echo close (best-effort) + `ReadAsync` trả **0** (end of stream). |
| RFC 6455 §5.5.2/§5.5.3 | Ping / Pong | `WebSocketByteStream.ReadAsync` | Nhận **ping** ⇒ tự trả **pong** cùng payload (masked); **pong** không mời ⇒ bỏ qua. |

## API / cách dùng

```csharp
// wss:// (WebSocket-over-TLS) — ctor tiện dụng tự dựng TlsByteStream:
await using var ws = new WebSocketByteStream("vpn.example", 443, useTls: true, path: "/tunnel");
await ws.ConnectAsync(ct);              // §4 HTTP Upgrade + verify Accept
await ws.WriteAsync(appBytes, ct);      // 1 masked binary frame (§5.3)
int n = await ws.ReadAsync(buffer, ct); // un-mask + ráp fragment; 0 = close (§5.5.1)

// ws:// (không TLS):
await using var plain = new WebSocketByteStream("host", 80, useTls: false);

// Inject inner tùy ý (test/loopback, hoặc chọn transport ngoài) + RNG xác định:
IByteStreamTransport inner = /* TcpByteStream / TlsByteStream / fake pipe */;
await using var t = new WebSocketByteStream(inner, "host", "/", random: myRng);
```

## Luồng nội bộ

### `ConnectAsync` ([WebSocketByteStream.cs:79](WebSocketByteStream.cs#L79))
1. `inner.ConnectAsync(ct)` (TCP/TLS handshake của inner).
2. Sinh `Sec-WebSocket-Key` = base64(16 byte RNG); `WebSocketHandshake.BuildClientRequest` → `inner.WriteAsync(request)` (§4.1).
3. Tính `expectedAccept = ComputeAccept(key)`; đọc response tới `CRLFCRLF` (giới hạn 16 KiB, đóng sớm ⇒ `IOException`).
4. `TryParseResponse(header, expectedAccept)` sai ⇒ `IOException`; byte thừa sau header ⇒ nạp vào reassembler; `_connected = true`.

### `WriteAsync` ([WebSocketByteStream.cs:116](WebSocketByteStream.cs#L116))
- Sinh mask 4-byte → `Rfc6455Frame.EncodeClientFrame(Binary, buffer, mask)` → `SendRawAsync` (qua `SemaphoreSlim` để auto-pong không xen giữa ghi app).

### `ReadAsync` ([WebSocketByteStream.cs:125](WebSocketByteStream.cs#L125))
1. Còn `_pendingData` (payload đã giải) → copy `min(buffer, pending)`, trả độ dài.
2. `_closed` ⇒ trả 0. Ngược lại `ReadFrameAsync` (lặp `reassembler.TryReadFrame`, thiếu thì `inner.ReadAsync` 8 KiB rồi `Append`; inner đóng ⇒ trả 0/end).
3. Demux opcode: `Binary/Text` (FIN⇒`_pendingData`, else mở fragment) · `Continuation` (ráp, FIN⇒giao) · `Ping`⇒gửi `Pong` cùng payload · `Pong`⇒bỏ · `Close`⇒`_closed`+echo close, trả 0.

### `Rfc6455Frame.TryDecodeFrame` ([Rfc6455Frame.cs:108](Rfc6455Frame.cs#L108))
- Đọc byte0/byte1 → FIN/opcode/mask/len7; len7 `126`⇒2 byte BE, `127`⇒8 byte BE (>`int.MaxValue` ⇒ `FormatException`); nếu masked đọc 4-byte key; thiếu byte ⇒ `false` (`consumed=0`); đủ ⇒ un-mask (nếu masked) + trả `payload`/`consumed`.

## Trạng thái & ghi chú

- **Đã hiện thực (code + test offline):** `WebSocketByteStream` + `Rfc6455Frame` + `Rfc6455FrameReassembler` + `WebSocketHandshake` + `IWebSocketRandom`/`CryptoWebSocketRandom` đầy đủ, build xanh cả `netstandard2.0` + `net8.0`. **46 test** ở [`tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests`](../../tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests):
  - [`Rfc6455FrameTests.cs`](../../tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests/Rfc6455FrameTests.cs) — encode↔decode masked round-trip đa cỡ length (7-bit/16-bit/64-bit) + FIN/MASK bit + XOR mask + server frame unmasked/non-final + partial-buffer + throw (mask sai/control quá cỡ) + reassembler cắt ranh byte/nhiều khung 1 lần.
  - [`WebSocketHandshakeTests.cs`](../../tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests/WebSocketHandshakeTests.cs) — **vector §1.3** `dGhlIHNhbXBsZSBub25jZQ==`→`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`, request well-formed + sub-protocol + parse 101 (byte/string) + reject accept sai/thiếu/non-101.
  - [`WebSocketByteStreamTests.cs`](../../tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests/WebSocketByteStreamTests.cs) + harness [`InMemoryByteStreamPair.cs`](../../tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests/InMemoryByteStreamPair.cs)/[`FakeWebSocketServer.cs`](../../tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests/FakeWebSocketServer.cs)/[`FakeWebSocketRandom.cs`](../../tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests/FakeWebSocketRandom.cs) — **loopback 2 đầu byte-stream in-memory**: handshake hoàn tất + `server.ReceivedKey` khớp key client; `WriteAsync`→server khôi phục byte-exact (frame masked); server→`ReadAsync` byte-exact; ping→pong cùng payload; fragment `[a,b,c]` ráp `a‖b‖c`; close⇒`ReadAsync`=0; handshake fail (non-101)⇒`IOException`; round-trip 2 chiều đa cỡ 0..20000 (vượt read-buffer 8192, nhiều inner-read).
  - Chạy offline: `dotnet exec tests/TqkLibrary.VpnClient.Transport.WebSocket.Tests/bin/Debug/net8.0/TqkLibrary.VpnClient.Transport.WebSocket.Tests.dll -notrait "Category=Integration"`.
- **netstandard2.0 vs net8.0:** `Span`/`Memory`/`BinaryPrimitives`/`SHA1` qua BCL + polyfill ns2.0 ([src/Directory.Build.props](../Directory.Build.props)); không `#if` guard nào cần. **Chủ đích không dùng `System.Net.WebSockets.ClientWebSocket`** để byte layout giống hệt 2 TFM và ride mọi inner transport.
- **Clean-room:** re-implement từ RFC 6455 (đã đối chiếu §1.3 vector + §5.3 masking), **không copy code GPL/AGPL**.
- **Follow-up (CHƯA làm):**
  - **Wire vào [`VpnClientBuilder`](../TqkLibrary.VpnClient/VpnClientBuilder.cs)**: compose decorator WebSocket **dưới** OpenVPN / driver byte-stream khác (chọn `ws://`/`wss://` + path). Vì thế RFC 6455 **chưa** vào facade ⇒ không line-ref drift.
  - **Live-validate** qua wstunnel server thật (erebe/wstunnel) hoặc WebSocket reverse-proxy.
  - Roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) **V.29**.

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5/§9 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) (V.29).
