# TqkLibrary.VpnClient.Transport.RawIp

> **Transport raw-IP** — hiện thực [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10) bằng **raw socket** (`SocketType.Raw`) chở một **IP protocol number tùy ý** (ESP-50, GRE-47…) **thẳng trên IP, không bọc UDP/TCP**. Đây là **đường DUY NHẤT trong userspace** để gửi/nhận protocol tùy chọn, **bắt buộc elevate** (Windows Administrator / Linux root hoặc `CAP_NET_RAW`). Consumer đầu tiên: **native ESP proto-50** của driver L2TP/IPsec (roadmap **P0.8c**).

## Mục đích

NAT-T thông thường bọc ESP trong UDP/4500 (chạy không cần admin). Nhưng gateway **IP-public không sau NAT** từ chối forced-NAT-T và mong **native ESP** (IP proto-50). Userspace **không có** đường nào gửi/nhận protocol tùy chọn ngoài raw socket. Project này cung cấp đúng nền đó — generic theo `ipProtocol` nên cùng dùng được cho **GRE-47 (PPTP, V6.b)** và **IP-in-IP (V.8)** về sau.

**Ràng buộc design `01` đã nới: no-admin → no-install.** Mặc định client vẫn no-admin; raw socket/elevate là **tùy chọn hạng nhất**, chỉ kích hoạt khi consumer (vd P0.8c) cần. Driver phụ thuộc **interface** [`IRawIpTransportFactory`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12) (đặt ở `Abstractions`), concrete ở project này → driver/builder **không** phải ProjectReference Transport.RawIp; chỉ app tự `new RawIpTransportFactory()` mới kéo vào.

## Vị trí trong kiến trúc

- **Tầng:** TRANSPORT (concrete) — ngang hàng `Transport.Dtls`; nằm dưới tầng DRIVER, chỉ phụ thuộc `Abstractions`.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference) — CHỈ Abstractions** (`IDatagramTransport` + `IRawIpTransportFactory`); **không package ngoài** (chỉ `System.Net.Sockets` của BCL).
- **Được dùng bởi:** driver **L2TP/IPsec** ([`Drivers.L2tpIpsec`](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) — P0.8c native ESP, đã wire qua `IRawIpTransportFactory`). Dự kiến: **PPTP-GRE proto-47** (V6.b), **IP-in-IP/EtherIP/L2TPv3** (V.8).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Transport.RawIp/
├── RawIpDatagramTransport.cs              IDatagramTransport: SendTo (OS gắn IP header) / ReceiveFrom (strip IPv4 header + drop fragment + lọc source)
├── RawIpTransportFactory.cs               IRawIpTransportFactory production: probe quyền thật + mở raw socket, ném RawIpNotPermittedException khi thiếu
├── RawIpPrivilegeChecker.cs               IPrivilegeChecker mặc định: Windows Admin / Linux geteuid (chỉ để soạn message lỗi)
├── RawIpProtocols.cs                      hằng IANA: Esp=50, Gre=47
├── Helpers/
│   └── RawIpv4.cs                         codec thuần: PayloadOffset (IHL, validate) / IsFragment / Protocol / SourceAddress
├── Interfaces/
│   └── IPrivilegeChecker.cs               seam check elevation (mock được trong test)
└── Exceptions/
    └── RawIpNotPermittedException.cs      ném khi không mở được raw socket (thiếu quyền / OS từ chối)
```
> `IRawIpTransportFactory` **không** ở đây mà ở [Abstractions/Transport/Interfaces](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12) (điểm chung đứng sau interface trong Abstractions).

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `IRawIpTransportFactory` | (Abstractions) seam tạo transport: `IsAvailable` (probe quyền thật) + `Create(remote, ipProtocol, localBind?)` | [IRawIpTransportFactory.cs:12](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12) |
| `RawIpTransportFactory` | Production: `IsAvailable` mở+đóng thử raw socket (mở được = đủ quyền thực tế, **không** đoán từ uid); `Create` mở `Socket(family, Raw, (ProtocolType)ipProtocol)` + `Bind(localBind)` (đồng bộ source với IKE), thất bại ⇒ `RawIpNotPermittedException` (message dùng `IPrivilegeChecker`) | [RawIpTransportFactory.cs:18](RawIpTransportFactory.cs#L18) |
| `RawIpDatagramTransport` | `IDatagramTransport`: `SendAsync` → `SendTo` (OS gắn IP header, không HDRINCL); `ReceiveAsync` → poll `ReceiveFrom` (timeout 250ms để honor cancel), **lọc source==gateway**, **strip IPv4 header** (`RawIpv4`), **drop fragment**; `DisposeAsync` đóng socket (unblock blocking-receive trên ns2.0) | [RawIpDatagramTransport.cs:20](RawIpDatagramTransport.cs#L20) |
| `RawIpv4` | codec thuần (pure): `PayloadOffset` (IHL×4, validate `ihl≥20` & `len≥ihl`), `IsFragment` (MF flag/offset≠0), `Protocol` (byte 9), `SourceAddress` (byte 12-15) | [Helpers/RawIpv4.cs:11](Helpers/RawIpv4.cs#L11) |
| `RawIpPrivilegeChecker` | `IPrivilegeChecker` mặc định: Windows `WindowsPrincipal.IsInRole(Administrator)` (net5+), Linux/macOS `geteuid()==0` qua một P/Invoke libc (không Mono.Posix) — **chỉ best-effort cho message**, không phải cổng quyết định | [RawIpPrivilegeChecker.cs:14](RawIpPrivilegeChecker.cs#L14) |
| `RawIpNotPermittedException` | ném khi raw socket không mở được; message nêu cần elevate + cảnh báo Windows có thể nuốt proto-50 | [Exceptions/RawIpNotPermittedException.cs:9](Exceptions/RawIpNotPermittedException.cs#L9) |
| `RawIpProtocols` | hằng IANA: `Esp=50`, `Gre=47` | [RawIpProtocols.cs:4](RawIpProtocols.cs#L4) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class áp dụng | Vị trí | Ghi chú |
|-------|---------------|--------|---------|
| RFC 791 (IPv4 header) | `RawIpv4` | [Helpers/RawIpv4.cs:11](Helpers/RawIpv4.cs#L11) | IHL (byte 0 nibble thấp ×4), flags/offset (byte 6-7: MF=0x2000, offset mask 0x1FFF), protocol (byte 9), source (byte 12-15) |
| IANA Protocol Numbers | `RawIpProtocols` | [RawIpProtocols.cs:4](RawIpProtocols.cs#L4) | ESP=50, GRE=47 |

## API / cách dùng

```csharp
// App ráp: bật native ESP proto-50 cho gateway no-NAT (cần chạy elevated).
var rawIp = new RawIpTransportFactory();           // probe quyền ở IsAvailable
VpnClient client = new VpnClientBuilder()
    .UseL2tpIpsec(rawIp)                            // mode mặc định HonestFirst; null = no-admin như cũ
    .Build();

// Hoặc dùng trực tiếp transport (vd consumer khác):
if (rawIp.IsAvailable)
{
    IDatagramTransport esp = rawIp.Create(gatewayIp, RawIpProtocols.Esp, localBind: myLocalIp);
    await esp.ConnectAsync();                       // no-op: raw IP không có handshake
    await esp.SendAsync(espPacket);                 // gửi gói ESP thô (SPI ở 4 byte đầu); OS gắn IP header proto-50
    int n = await esp.ReceiveAsync(buffer);         // nhận: lọc source + strip IPv4 header → gói ESP thô
    await esp.DisposeAsync();
}
```

## Luồng nội bộ

### Gửi (`SendAsync` — [RawIpDatagramTransport.cs:20](RawIpDatagramTransport.cs#L20))
- Copy payload ra `byte[]` → `Socket.SendTo(payload, gatewayEndPoint)` (offload `Task.Run`). **Không** set `IP_HDRINCL` ⇒ OS tự dựng IP header với protocol = protocol của socket. Payload là gói ESP thô (bắt đầu bằng SPI).

### Nhận (`ReceiveAsync` — [RawIpDatagramTransport.cs:20](RawIpDatagramTransport.cs#L20))
1. `ReceiveFrom` poll với `ReceiveTimeout=250ms` (timeout ⇒ lặp lại để honor cancel, không busy-spin; ns2.0 không có overload nhận `CancellationToken`).
2. **Lọc source**: bỏ qua mọi gói không phải từ gateway (raw socket thấy MỌI gói proto-50 tới host).
3. **Strip header (chỉ IPv4)**: raw IPv4 socket trả **kèm IPv4 header** (cả Windows lẫn Linux) → `RawIpv4.PayloadOffset` (validate IHL) cắt ra gói ESP thô. **Drop fragment** (`RawIpv4.IsFragment`) — raw socket không đảm bảo reassembly. IPv6 raw **không** kèm header → chưa hỗ trợ (chỉ v4).

### Quyết định quyền (`IsAvailable` — [RawIpTransportFactory.cs:18](RawIpTransportFactory.cs#L18))
- **Probe thật**: thử mở+đóng một raw socket của protocol — mở được = đủ quyền **thực tế**. Không suy từ uid/role (process có `CAP_NET_RAW` mà không phải root vẫn mở được). `IPrivilegeChecker` chỉ để soạn message khi `Create` thất bại.

## Trạng thái & ghi chú

- **Đã hiện thực (code + test offline):** transport raw-IP hoàn chỉnh (send/receive proto tùy ý), strip IPv4 header + drop fragment + lọc source, factory probe quyền + typed exception, build xanh cả `netstandard2.0` + `net8.0`. Đã wire làm carrier **native ESP P0.8c** ở driver L2TP/IPsec. Test offline: [`RawIpv4Tests`](../../tests/TqkLibrary.VpnClient.Transport.RawIp.Tests/RawIpv4Tests.cs) (codec: IHL/options/truncated/fragment/source), [`RawIpReceivePipelineTests`](../../tests/TqkLibrary.VpnClient.Transport.RawIp.Tests/RawIpReceivePipelineTests.cs) (strip header → `EspSession.TryUnprotect` decrypt được; fragment nhận diện để drop), [`RawIpTransportFactoryTests`](../../tests/TqkLibrary.VpnClient.Transport.RawIp.Tests/RawIpTransportFactoryTests.cs) (probe không throw; denied-open ⇒ `RawIpNotPermittedException`).
- **netstandard2.0 vs net8.0:** ns2.0 không có `Socket.ReceiveFrom(..., CancellationToken)` ⇒ cancel/teardown unblock bằng **dispose socket** (như cầu DTLS). `WindowsIdentity`/`WindowsPrincipal` ngoài surface ns2.0 ⇒ admin-detect Windows rào `#if NET5_0_OR_GREATER` (ns2.0 dựa probe socket). `IPAddress(ReadOnlySpan<byte>)` rào `#if NET6_0_OR_GREATER` (else `.ToArray()`).
- **Hạn chế đã biết / việc sau:**
  - **Windows best-effort:** raw socket có thể mở được nhưng OS **không giao** proto-50 inbound (dịch vụ IPsec/IKEEXT/PolicyAgent claim) hoặc firewall chặn ⇒ `IsAvailable=true` **không** đảm bảo proto reachable. **Linux `CAP_NET_RAW` là môi trường tham chiếu.**
  - **Chỉ IPv4 receive** (strip header v4); IPv6 native ESP (raw v6 không kèm header) chưa làm.
  - **Drop fragment** (không tự reassembly) — gói ESP lớn bị phân mảnh sẽ rớt; cần giảm MTU hoặc dựa OS reassembly (Q.4/Q.1).
  - **Validate live** (raw socket thật, lab strongSwan no-NAT + `CAP_NET_RAW`) chờ **Q.1**.

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §2/§5/§8/§9 + bảng "Khác biệt" · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) (F.9 / P0.8c).
