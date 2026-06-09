# TqkLibrary.Vpn.Transport.Udp

> Tầng TRANSPORT của TqkLibrary.Vpn: một UDP socket duy nhất ghép kênh IKE và ESP về một gateway theo NAT-Traversal (RFC 3947/3948), tự chuyển cổng 500 → 4500 khi phát hiện NAT.

> Mô tả trong `.csproj` (`<Description>`): *"IDatagramTransport over UDP + EspIkeDemuxTransport (RFC 3948 NAT-T, port 4500)."* — đây là mô tả design-intent; hiện thực thực tế là `NatTraversal` + `NatTraversalChannel` (xem [Trạng thái & ghi chú](#trạng-thái--ghi-chú)).

## Mục đích

L2TP/IPsec hầu như luôn chạy sau NAT, nên IPsec phải dùng **UDP-encapsulation** (RFC 3948): IKE và ESP cùng đi qua **một** cổng UDP. Project này cung cấp:

- **Framing NAT-T** ([NatTraversal.cs](NatTraversal.cs)): quy tắc "Non-ESP Marker" để phân biệt IKE với ESP khi cả hai dùng chung cổng 4500, cùng các hằng số cổng (500/4500) và độ dài marker.
- **Kênh UDP có trạng thái cổng** ([NatTraversalChannel.cs](NatTraversalChannel.cs)): bọc một `UdpClient`, gửi/nhận IKE và ESP, tự thêm/bóc marker theo cổng đích hiện tại, và hỗ trợ "đổi cổng" 500 → 4500 sau khi IKE_SA_INIT/Main Mode phát hiện NAT.

Project cố tình bind một **cổng local ephemeral** (không phải 500/4500) để (1) không đụng dịch vụ IKE của OS và (2) khiến gateway "thấy" nguồn như đã bị NAT → đẩy phiên sang UDP/4500 với ESP-encapsulation, đúng hành vi mà client userspace cần.

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (giữa PROTOCOL/`Ipsec` và socket OS thật).
- **Target frameworks:** `netstandard2.0; net8.0` (theo [Directory.Build.props:4](../Directory.Build.props#L4)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.Vpn.Abstractions](../TqkLibrary.Vpn.Abstractions/TqkLibrary.Vpn.Abstractions.csproj) — chỉ tham chiếu, các type hiện tại chưa dùng interface nào của Abstractions.
  - Không có PackageReference đặc thù; trên `netstandard2.0` kế thừa polyfill chung (`System.Memory`, ...) từ [Directory.Build.props:16-21](../Directory.Build.props#L16-L21).
- **Được dùng bởi:** [TqkLibrary.Vpn.Drivers](../TqkLibrary.Vpn.Drivers/TqkLibrary.Vpn.Drivers.csproj) — cụ thể driver L2TP/IPsec ([L2tpIpsecConnection.cs:124](../TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L124)).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Transport.Udp/
├── NatTraversal.cs          # static helper: hằng số cổng + framing Non-ESP Marker + Classify/Wrap/Unwrap
└── NatTraversalChannel.cs   # kênh UDP có trạng thái: gửi/nhận IKE & ESP, đổi cổng 500->4500
```

Toàn bộ nằm trong namespace duy nhất `TqkLibrary.Vpn.Transport.Udp` (không có sub-namespace).

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `NatTraversal` (static class) | Hằng số cổng (`IkePort`=500, `NatTPort`=4500, `MarkerLength`=4) + framing IKE/ESP trên 4500 | [NatTraversal.cs:20](NatTraversal.cs#L20) |
| `NatTPacketKind` (enum) | Phân loại datagram nhận trên 4500: `Invalid` / `Ike` / `Esp` | [NatTraversal.cs:4](NatTraversal.cs#L4) |
| `NatTraversal.WrapIke` | Thêm 4 byte Non-ESP Marker (0x00000000) vào trước IKE message | [NatTraversal.cs:32](NatTraversal.cs#L32) |
| `NatTraversal.Classify` | Quyết định IKE/ESP/Invalid theo 4 byte đầu (zero ⇒ IKE; khác zero ⇒ ESP=SPI) | [NatTraversal.cs:40](NatTraversal.cs#L40) |
| `NatTraversal.UnwrapIke` | Bóc Non-ESP Marker, trả về phần thân IKE | [NatTraversal.cs:50](NatTraversal.cs#L50) |
| `NatTraversalChannel` (sealed, `IAsyncDisposable`) | Kênh UDP một-gateway: bind cổng ephemeral, gửi/nhận IKE+ESP, đổi cổng | [NatTraversalChannel.cs:12](NatTraversalChannel.cs#L12) |
| `NatTraversalChannel.SwitchToNatTPort` | Chuyển đích sang UDP/4500 sau khi phát hiện NAT | [NatTraversalChannel.cs:33](NatTraversalChannel.cs#L33) |
| `NatTraversalChannel.SendIkeAsync` | Gửi IKE; tự thêm marker khi đích là 4500 | [NatTraversalChannel.cs:36](NatTraversalChannel.cs#L36) |
| `NatTraversalChannel.SendEspAsync` | Gửi ESP đã UDP-encapsulate (không marker) | [NatTraversalChannel.cs:45](NatTraversalChannel.cs#L45) |
| `NatTraversalChannel.ReceiveAsync` | Nhận 1 datagram, phân loại + bóc marker, trả `(Kind, Payload)` | [NatTraversalChannel.cs:55](NatTraversalChannel.cs#L55) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| **RFC 3948** — *UDP Encapsulation of IPsec ESP Packets* | `NatTraversal` (toàn bộ framing IKE/ESP trên cổng 4500) | [NatTraversal.cs:17](NatTraversal.cs#L17) | RFC ghi rõ trong comment |
| **RFC 3948 §2.2** — *Non-ESP Marker* (4 byte zero phân biệt IKE với ESP) | `NatTraversal.Classify` / `NatTPacketKind` | [NatTraversal.cs:3](NatTraversal.cs#L3), [NatTraversal.cs:40](NatTraversal.cs#L40) | §2.2 ghi rõ trong comment |
| **RFC 3948** (UDP-encapsulation, port 4500) | `NatTraversalChannel` (ghép kênh IKE/ESP về một gateway) | [NatTraversalChannel.cs:7](NatTraversalChannel.cs#L7) | RFC ghi rõ trong comment |
| **RFC 3947** — *Negotiation of NAT-Traversal in the IKE* (phát hiện NAT trong IKE_SA_INIT/Main Mode → đổi cổng) | Trigger `SwitchToNatTPort`; logic phát hiện NAT nằm ở tầng IKE (`Ipsec`), kênh chỉ thực thi việc đổi cổng | [NatTraversalChannel.cs:32-33](NatTraversalChannel.cs#L32-L33) | (suy luận) RFC 3947 không ghi trong comment project này; quyết định NAT do `IkeV1Client` đưa ra, channel chỉ nhận lệnh đổi cổng |
| Cổng IKE/NAT-T cố định 500 / 4500 | `NatTraversal.IkePort` / `NatTraversal.NatTPort` | [NatTraversal.cs:22-26](NatTraversal.cs#L22-L26) | Hằng số IANA cho ISAKMP/IPsec-NAT-T |

> Phần phát hiện NAT thực sự (so HASH của NAT-D payload) thuộc về tầng IKEv1 ở project `Ipsec`; project này chỉ chịu trách nhiệm **framing UDP** và **đổi cổng** theo lệnh.

## API / cách dùng

Các điểm vào public chính: tạo `NatTraversalChannel`, chạy handshake IKE qua `SendIkeAsync`/`ReceiveAsync`, gọi `SwitchToNatTPort` khi sang 4500, rồi gửi data plane qua `SendEspAsync`.

```csharp
await using var natt = new NatTraversalChannel(serverIp, NatTraversal.IkePort);

// Main Mode 1-4 trên UDP/500 (chưa marker)
await natt.SendIkeAsync(ike.BuildMainMode1());
var (kind, reply) = await natt.ReceiveAsync(ct);   // kind == NatTPacketKind.Ike

// Phát hiện NAT trong MM3/MM4 → chuyển sang UDP/4500 (từ đây IKE có marker)
natt.SwitchToNatTPort();
await natt.SendIkeAsync(ike.BuildMainMode5());

// Sau Quick Mode: data plane ESP (không marker; SPI là 4 byte đầu)
await natt.SendEspAsync(espDatagram);

// Vòng nhận chung cho cả IKE và ESP
var (k, payload) = await natt.ReceiveAsync(ct);
if (k == NatTPacketKind.Ike) { /* DPD / Delete / rekey reply */ }
else if (k == NatTPacketKind.Esp) { /* đẩy vào EspSession */ }
```

Tham khảo cách dùng thật trong driver L2TP/IPsec: [L2tpIpsecConnection.cs:124-149](../TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L124-L149).

## Luồng nội bộ

**1. Khởi tạo (cổng 500):** constructor bind một `UdpClient` cổng ephemeral và đặt đích = `serverIp:500` ([NatTraversalChannel.cs:19-24](NatTraversalChannel.cs#L19-L24)). `LocalPort` không bao giờ là 500/4500 nên gateway xem nguồn như đã NAT.

**2. Gửi IKE theo cổng hiện tại:** `SendIkeAsync` kiểm tra `_remote.Port` — nếu là 4500 thì `WrapIke` (thêm marker), ngược lại gửi nguyên IKE message ([NatTraversalChannel.cs:36-42](NatTraversalChannel.cs#L36-L42)).

**3. Đổi cổng sau khi phát hiện NAT:** tầng IKE gọi `SwitchToNatTPort` đổi đích thành `serverIp:4500` ([NatTraversalChannel.cs:33](NatTraversalChannel.cs#L33)); driver gọi đúng sau Main Mode 3/4 ([L2tpIpsecConnection.cs:137-138](../TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L137-L138)).

**4. Nhận + phân loại:**
- Trên **cổng 500**: payload luôn là IKE; chỉ kiểm tra độ dài tối thiểu 28 byte (header ISAKMP) → `Ike`/`Invalid`, không bóc marker ([NatTraversalChannel.cs:64-65](NatTraversalChannel.cs#L64-L65)).
- Trên **cổng 4500**: `Classify` đọc 4 byte đầu — toàn 0 ⇒ `Ike` (sau đó `UnwrapIke` bóc marker), khác 0 ⇒ `Esp` (SPI không bao giờ bằng 0) ([NatTraversalChannel.cs:67-69](NatTraversalChannel.cs#L67-L69), [NatTraversal.cs:40-47](NatTraversal.cs#L40-L47)).

**5. Demux phía consumer:** driver có một `ReceiveLoopAsync` đọc liên tục từ kênh và rẽ nhánh theo `Kind`: IKE → waiter handshake / rekey / DPD-Delete; ESP → `EspSession` ([L2tpIpsecConnection.cs:220-239](../TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L220-L239)).

**6. Dispose:** `DisposeAsync` chỉ dispose `UdpClient` ([NatTraversalChannel.cs:73-77](NatTraversalChannel.cs#L73-L77)).

## Trạng thái & ghi chú

- **Sai lệch design ↔ code:** `<Description>` nêu `IDatagramTransport` + `EspIkeDemuxTransport`, nhưng hiện thực thực tế là `NatTraversal` + `NatTraversalChannel`. Không có type `IDatagramTransport`/`EspIkeDemuxTransport` nào trong project; tên đó là design-intent. Project hiện **không** triển khai interface nào của Abstractions — channel là một lớp cụ thể, không trừu tượng hoá qua interface transport.
- **Phạm vi:** chỉ phục vụ **L2TP/IPsec** (IKEv1). Logic phát hiện NAT (NAT-D / RFC 3947) nằm ở `Ipsec`; project này chỉ làm framing UDP và đổi cổng theo lệnh.
- **Một gateway / một kênh:** mỗi `NatTraversalChannel` chỉ nói chuyện với một remote endpoint; không multiplex nhiều peer.
- **Khác biệt `netstandard2.0` vs `net8.0`:** chỉ ở `ReceiveAsync` — `net8.0` dùng overload `UdpClient.ReceiveAsync(CancellationToken)` (hủy thật); `netstandard2.0` chỉ `ThrowIfCancellationRequested()` trước rồi `ReceiveAsync()` **không** truyền token → một receive đang chờ trên netstandard2.0 không bị hủy giữa chừng ([NatTraversalChannel.cs:57-62](NatTraversalChannel.cs#L57-L62)).
- **Cấp phát:** `WrapIke`/`UnwrapIke`/`SendEspAsync` đều copy sang `byte[]` mới (`ToArray`/`new byte[]`) — đơn giản, không zero-copy; chấp nhận được với nhịp datagram của IKE/ESP.
- Xem thêm tài liệu as-built: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
