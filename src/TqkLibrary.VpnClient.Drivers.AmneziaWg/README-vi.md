# TqkLibrary.VpnClient.Drivers.AmneziaWg

Lớp **che giấu chống-DPI AmneziaWG** (anti-DPI obfuscation) **bọc UDP dưới WireGuard** — **clean-room từ spec công khai awg, KHÔNG copy code** (kể cả bản MIT: re-implement từ mô tả wire). Mục tiêu: làm lưu lượng WireGuard **không còn giống WireGuard** trước DPI mà **KHÔNG đụng gì tới crypto WireGuard** — payload AEAD được chở **nguyên vẹn byte-for-byte**. Chỉ có phần **header/khung UDP** bị biến đổi:

1. **Đổi magic message-type**: WireGuard đặt message-type là **`uint32` little-endian ở offset 0** (byte0 = 1/2/3/4, byte1..3 = 0 reserved). AmneziaWG thay 4 byte đó bằng **H1/H2/H3/H4** (u32 tùy biến) theo type gốc 1/2/3/4 (init/response/cookie/data).
2. **Chèn junk trước handshake**: chèn **S1** byte ngẫu nhiên **trước** gói **initiation** (type 1) và **S2** byte trước gói **response** (type 2). Type 3/4 chỉ đổi magic, không chèn.
3. **Phát gói junk rác**: **ngay trước gói init đầu tiên**, phát **Jc** gói junk độc lập, mỗi gói cỡ ngẫu nhiên trong **[Jmin, Jmax]** byte nội dung ngẫu nhiên.

Hai peer **chia sẻ cùng `AmneziaWgParameters`** nên bên nhận đảo ngược biến đổi **xác định**; datagram không khớp magic nào ⇒ **junk → drop**.

## Vị trí kiến trúc — cắm vào seam WireGuard sẵn có (KHÔNG đụng builder)

Đây **KHÔNG phải driver mới**, mà là **decorator hai tầng** cắm vào seam transport của [`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard):

- **Factory-decorator** [`AmneziaWgTransportFactory`](AmneziaWgTransportFactory.cs) hiện thực [`IWireGuardTransportFactory`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/IWireGuardTransportFactory.cs) bọc factory nền (production [`WireGuardSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/WireGuardSocketTransportFactory.cs) hoặc loopback test). `ConnectAsync` gọi factory nền → bọc [`WireGuardTransportHandle`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/WireGuardTransportHandle.cs): `Datagram` bọc obfuscate (outbound), `SetReceiver` bọc deobfuscate-rồi-gọi-handler (inbound, junk drop), `ReceivePump` **giữ nguyên**.
- **Datagram-decorator** [`AmneziaWgDatagramTransport`](AmneziaWgDatagramTransport.cs) hiện thực [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs) bọc pipe UDP nền: `SendAsync` obfuscate (+ phát Jc junk trước init đầu tiên, cờ 1 lần), `ReceiveAsync` deobfuscate vòng lặp bỏ junk; `ConnectAsync`/`DisposeAsync` ủy thác inner. Mẫu decorator học từ [`DtlsDatagramTransport`](../TqkLibrary.VpnClient.Transport.Dtls/DtlsDatagramTransport.cs).

Vì cắm ở seam transport, **`VpnClientBuilder` và driver WireGuard KHÔNG bị đụng**. Wire `UseAmneziaWg(...)` vào builder là **follow-up** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.29).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs) (seam pipe UDP để decorate) |
| Dùng | [WireGuard](../TqkLibrary.VpnClient.WireGuard) | [`WireGuardConstants`](../TqkLibrary.VpnClient.WireGuard/WireGuardConstants.cs) — hằng message-type 1/2/3/4 (single source, không cứng số) |
| Dùng | [Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard) | [`IWireGuardTransportFactory`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/IWireGuardTransportFactory.cs) + [`WireGuardTransportHandle`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/WireGuardTransportHandle.cs) — seam để bọc factory |

RNG mặc định = [`RandomNumberGenerator`](https://learn.microsoft.com/dotnet/api/system.security.cryptography.randomnumbergenerator) (BCL, cả 2 TFM); **cho phép inject** [`IAmneziaWgRandom`](Interfaces/IAmneziaWgRandom.cs) để test xác định cỡ/nội dung junk.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.AmneziaWg/
├─ AmneziaWgObfuscator.cs            Codec thuần: Obfuscate/TryDeobfuscate/GenerateJunkPackets (đọc/ghi u32 LE offset 0, swap magic, chèn/bóc S1/S2, sinh Jc junk)
├─ AmneziaWgDatagramTransport.cs     IDatagramTransport decorator: SendAsync obfuscate (+ Jc junk trước init đầu, cờ 1 lần) / ReceiveAsync deobfuscate loop bỏ junk / ConnectAsync·DisposeAsync ủy thác inner
├─ AmneziaWgTransportFactory.cs      IWireGuardTransportFactory decorator: ConnectAsync gọi base → bọc handle (Datagram outbound + SetReceiver inbound-drop-junk + giữ ReceivePump)
├─ Models/AmneziaWgParameters.cs     record required (Jc/Jmin/Jmax/S1/S2/H1..H4) + Validate() (H1..H4 >4 & phân biệt; Jmin≤Jmax; S1/S2/Jc≥0) ⇒ ArgumentException
├─ Interfaces/IAmneziaWgRandom.cs    Nguồn ngẫu nhiên inject được: NextBytes(count) + NextInt(min,max) inclusive
├─ Helpers/CryptoAmneziaWgRandom.cs  Hiện thực mặc định qua RandomNumberGenerator (NextInt rejection-sampling không bias; Shared)
└─ Properties/AssemblyInfo.cs        InternalsVisibleTo test assembly
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `AmneziaWgObfuscator` | Codec thuần (stateless, share được 2 chiều): `Obfuscate(wgDatagram)` đọc type u32 LE @0 → swap H1..H4 + chèn S1/S2; `TryDeobfuscate(wire, out wg)` đảo ngược theo thứ tự cố định (H4→H3→H1@S1→H2@S2), không khớp ⇒ `false` (junk); `GenerateJunkPackets()` sinh Jc gói [Jmin,Jmax] | [AmneziaWgObfuscator.cs:30](AmneziaWgObfuscator.cs#L30) |
| `AmneziaWgParameters` | Config 2 peer chia sẻ — `record` với `required` Jc/Jmin/Jmax/S1/S2/H1..H4; `Validate()` ném `ArgumentException` nếu H≤4/H trùng/Jmin>Jmax/S1·S2·Jc<0 | [Models/AmneziaWgParameters.cs:19](Models/AmneziaWgParameters.cs#L19) |
| `AmneziaWgDatagramTransport` | `IDatagramTransport` decorator: `SendAsync` obfuscate + Jc junk trước init đầu (cờ `Interlocked`); `ReceiveAsync` loop deobfuscate bỏ junk; `ConnectAsync`/`DisposeAsync` ủy thác inner (dispose theo `ownsInner`) | [AmneziaWgDatagramTransport.cs:25](AmneziaWgDatagramTransport.cs#L25) |
| `AmneziaWgTransportFactory` | `IWireGuardTransportFactory` decorator: `ConnectAsync` gọi base → 1 `AmneziaWgObfuscator`/connection, bọc `Datagram` (outbound) + `SetReceiver` (inbound deobf-rồi-handler, junk drop) + giữ `ReceivePump` | [AmneziaWgTransportFactory.cs:26](AmneziaWgTransportFactory.cs#L26) |
| `IAmneziaWgRandom` / `CryptoAmneziaWgRandom` | Seam ngẫu nhiên inject được (`NextBytes`/`NextInt` inclusive) + hiện thực RNG crypto mặc định | [Interfaces/IAmneziaWgRandom.cs:8](Interfaces/IAmneziaWgRandom.cs#L8) / [Helpers/CryptoAmneziaWgRandom.cs:13](Helpers/CryptoAmneziaWgRandom.cs#L13) |

## Tham số AmneziaWG (clean-room từ spec awg)

| Tham số | Kiểu | Ý nghĩa |
|---------|------|---------|
| **Jc** | int ≥0 | Số gói junk độc lập phát **ngay trước** gói handshake initiation **đầu tiên** |
| **Jmin / Jmax** | int, 0≤Jmin≤Jmax | Cỡ mỗi gói junk = ngẫu nhiên trong **[Jmin, Jmax]** byte (nội dung ngẫu nhiên) |
| **S1** | int ≥0 | Số byte junk chèn **trước** gói **initiation** (type 1) |
| **S2** | int ≥0 | Số byte junk chèn **trước** gói **response** (type 2) |
| **H1 / H2 / H3 / H4** | uint | Magic u32 **thay** message-type gốc 1/2/3/4 (init/response/cookie/data). **Phải >4 và phân biệt** — nếu không, `Validate()` ném (để deobf không nhập nhằng) |

## Luồng obfuscate / deobfuscate (as-built)

**Outbound** ([`Obfuscate`](AmneziaWgObfuscator.cs#L57)):
1. Đọc `type = uint32 LE @0` của gói WireGuard.
2. **type=1 (init)** → gói ra = `[S1 byte ngẫu nhiên]` ++ gói gốc, rồi ghi **H1** (u32 LE) đè lên 4 byte type ở offset S1.
3. **type=2 (response)** → tương tự với **S2** + **H2**.
4. **type=3 (cookie)** / **type=4 (data)** → copy gói gốc, ghi **H3/H4** đè 4 byte @0 (không chèn).
5. Gói init **đầu tiên** đi qua [`AmneziaWgDatagramTransport.SendAsync`](AmneziaWgDatagramTransport.cs#L47) → phát trước **Jc** gói junk ([`GenerateJunkPackets`](AmneziaWgObfuscator.cs#L151)) như các datagram riêng (cờ 1 lần bằng `Interlocked`).

**Inbound** ([`TryDeobfuscate`](AmneziaWgObfuscator.cs#L112)) — thử theo **thứ tự cố định** (H1..H4 đã validate phân biệt nên không nhập nhằng dù S1/S2 chồng offset):
1. `wire[0..4] == H4` ⇒ **data** (type 4): ghi type 4 (‖ 0 0 0) @0, trả gói.
2. `wire[0..4] == H3` ⇒ **cookie** (type 3): tương tự.
3. `len ≥ S1+4 && wire[S1..S1+4] == H1` ⇒ **init** (type 1): bỏ S1 byte đầu, khôi phục type 1.
4. `len ≥ S2+4 && wire[S2..S2+4] == H2` ⇒ **response** (type 2): bỏ S2 byte đầu, khôi phục type 2.
5. Không khớp ⇒ **`false`** (junk → drop, không đẩy lên WireGuard).

Khôi phục luôn ghi type dạng `uint32 LE` (`type ‖ 0 0 0`) nên 3 byte reserved về 0 ⇒ khớp **byte-for-byte** gói WireGuard gốc.

## Trạng thái & ghi chú

- **Đã có (V.29 — offline)**: codec + 2 decorator + params/validate **XONG**, test **offline 29 case** (`dotnet exec`, xUnit v3, 29/29 pass): round-trip mỗi message-type byte-exact; magic swap đúng u32 LE + offset; chèn/bóc S1/S2; type 3/4 không chèn; Jc junk đúng số + cỡ trong [Jmin,Jmax] + biên Jmin==Jmax + Jc=0 rỗng; junk qua deobf ⇒ drop; params sai ⇒ throw; loopback datagram-transport round-trip + bỏ junk; factory bọc handle (inbound deobf/drop-junk + outbound obfuscate + Jc-burst + giữ ReceivePump). Build xanh cả `netstandard2.0` + `net8.0`.
- **Chưa wire builder**: AmneziaWG **CHƯA có method builder** (`UseAmneziaWg`) ⇒ chưa gắn vào driver WireGuard runtime; dùng bằng cách tự bọc factory qua `AmneziaWgTransportFactory`. Không có line-ref drift ở facade.
- **Còn lại (residual live-validate)**: (1) wire `UseAmneziaWg(config)` vào [`VpnClientBuilder`](../TqkLibrary.VpnClient/VpnClientBuilder.cs) để chọn factory-decorator quanh WireGuard; (2) live-validate vs server **AmneziaWG thật** (awg / amnezia-wg-go) round-trip handshake + data qua obfuscation.
- **Tham chiếu**: spec công khai awg (clean-room) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.29 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. `record`/`required` chạy 2 TFM nhờ `TqkLibrary.CompilerServices`. Crypto WireGuard **KHÔNG đụng** — đây chỉ là lớp obfuscation bọc UDP.
