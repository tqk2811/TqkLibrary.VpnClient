# TqkLibrary.VpnClient.IpEncap

> **Tunnel IP-in-IP / GRE / EtherIP thuần (TRẦN — KHÔNG mã hóa)** — các kiểu encapsulation chở gói IP (hoặc khung Ethernet) **thẳng trên số hiệu giao thức IP riêng** (không bọc UDP/TCP) qua một [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10) raw-IP (F.9): **GRE** (RFC 2784/2890, proto-47), **IPIP** (RFC 2003, proto-4), **SIT/6in4** (RFC 4213, proto-41) — mỗi kiểu phơi một [`IPacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) (L3); và **EtherIP** (RFC 3378, proto-97) — cầu **L2-over-IP** phơi một [`IEthernetChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/Interfaces/IEthernetChannel.cs#L7). GRE/IPIP/SIT là **V.8 phase (a)** đã validate live (xem [`Drivers.IpEncap`](../TqkLibrary.VpnClient.Drivers.IpEncap)); **EtherIP codec/kênh = V.8(c) offline** (transport raw-IP proto-97 = live follow-up); L2TPv3-over-IP tái dùng chung header data đã có (xem ghi chú cuối).

## Mục đích

Nhóm encapsulation đơn giản nhất: bọc một gói IP trong một gói IP khác bằng một số hiệu giao thức IP riêng. Khác native ESP (P0.8c) và PPTP-GRE (V.6) ở chỗ payload **không mã hóa** — chỉ dùng trong mạng tin cậy hoặc **kèm IPsec ESP** ở trên. Vì là proto IP tùy ý nên **bắt buộc raw socket** ([`Transport.RawIp`](../TqkLibrary.VpnClient.Transport.RawIp) F.9, elevate) — nhưng các kênh ở đây **chỉ phụ thuộc `IDatagramTransport`** (abstraction), không kéo Transport.RawIp.

⚠️ **GRE/IPIP/SIT TRẦN không mã hóa.** Codec/kênh ở đây chỉ là tầng vận chuyển; bảo mật (nếu cần) đặt ở tầng trên (ESP).

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (data-plane encapsulation) — phơi `IPacketChannel`, nằm dưới tầng DRIVER ([`Drivers.IpEncap`](../TqkLibrary.VpnClient.Drivers.IpEncap) — đã có, phase b).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference) — CHỈ Abstractions** (`IDatagramTransport`, `IPacketChannel`, `LinkMedium`, [`Net/InternetChecksum`](../TqkLibrary.VpnClient.Abstractions/Net/InternetChecksum.cs#L6) cho GRE checksum RFC 1071; `ILogger`/`NullLogger` lấy qua transitive `Microsoft.Extensions.Logging.Abstractions` của Abstractions). **Không** ref Transport.RawIp.
- **Được dùng bởi:** [`TqkLibrary.VpnClient.Drivers.IpEncap`](../TqkLibrary.VpnClient.Drivers.IpEncap) (V.8 phase b — ráp các kênh này trên raw-IP transport theo proto-number), [`TqkLibrary.VpnClient.Drivers.GreInUdp`](../TqkLibrary.VpnClient.Drivers.GreInUdp) (V.8d — tái dùng `GreTunnelChannel`/`GreCodec` qua transport **UDP/4754** thay raw-IP, GRE-in-UDP RFC 8086, KHÔNG elevate) và [IpEncap.Tests](../../tests/TqkLibrary.VpnClient.IpEncap.Tests) (test offline).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.IpEncap/
├── RawIpPassthroughChannel.cs        IPacketChannel header-less cho CẢ IPIP (proto-4) + SIT (proto-41): gửi/nhận gói IP verbatim
├── Gre/
│   ├── GrePacket.cs                   model: ProtocolType + Key?/SequenceNumber?/Checksum? + IncludeChecksum + Payload
│   ├── GreCodec.cs                    codec thuần (static): Encode / TryDecode — RFC 2784 base + RFC 2890 Key/Seq + checksum RFC 1071 (tái dùng InternetChecksum.Compute ở Abstractions.Net)
│   ├── GreTunnelOptions.cs           options outbound: Mtu + Key? + EmitSequenceNumber + EmitChecksum
│   └── GreTunnelChannel.cs           IPacketChannel GRE proto-47 trên IDatagramTransport (chọn proto-type theo version nibble)
└── EtherIp/
    ├── EtherIpCodec.cs               codec thuần (static): Encapsulate / TryDecapsulate — RFC 3378 header 2B cố định (0x30 0x00 = Version 3 + Reserved 0) + khung Ethernet
    ├── EtherIpTunnelOptions.cs       options: Mtu + LinkAddress (MAC 6B của endpoint)
    └── EtherIpTunnelChannel.cs       IEthernetChannel EtherIP proto-97 trên IDatagramTransport (cầu L2-over-IP; mirror cấu trúc GreTunnelChannel)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `GrePacket` | Model một gói GRE chuẩn (v0): `ProtocolType` (0x0800/0x86DD), `Key?`/`SequenceNumber?`/`Checksum?` (RFC 2890/2784), `IncludeChecksum`, `Payload` | [Gre/GrePacket.cs:12](Gre/GrePacket.cs#L12) |
| `GreCodec` | Codec thuần (`static`): `Encode(GrePacket)→byte[]` / `TryDecode(ReadOnlySpan<byte>, out GrePacket?)→bool`. Header v0, thứ tự field cố định; validate Version==0, bounds, checksum | [Gre/GreCodec.cs:24](Gre/GreCodec.cs#L24) |
| `GreTunnelOptions` | Options outbound: `Mtu` (default 1400), `Key?` (bật K bit), `EmitSequenceNumber` (S bit, đếm tăng), `EmitChecksum` (C bit) | [Gre/GreTunnelOptions.cs:9](Gre/GreTunnelOptions.cs#L9) |
| `GreTunnelChannel` | `IPacketChannel` proto-47: outbound chọn proto-type theo version nibble (4→0x0800, 6→0x86DD) → `GreCodec.Encode` → `SendAsync`; receive-loop `TryDecode` drop non-GRE/malformed → raise `InboundIpPacket`; `Start()` + dispose (identity-guard + dispose-to-unblock như PPTP-GRE/native-ESP) | [Gre/GreTunnelChannel.cs:21](Gre/GreTunnelChannel.cs#L21) |
| `RawIpPassthroughChannel` | `IPacketChannel` header-less cho **CẢ** IPIP (proto-4) + SIT (proto-41): outbound gửi gói IP verbatim làm datagram; inbound raise payload verbatim. Family-agnostic (proto-number do caller chọn khi tạo transport) | [RawIpPassthroughChannel.cs:20](RawIpPassthroughChannel.cs#L20) |
| `EtherIpCodec` | Codec thuần (`static`) EtherIP RFC 3378: `Encapsulate(ReadOnlySpan<byte>)→byte[]` = `[0x30,0x00]‖frame`; `TryDecapsulate(ReadOnlySpan<byte>, out byte[])→bool` (Version==3 strict, Reserved lenient, drop cụt/<14B). Hằng `ProtocolNumber=97`, `HeaderSize=2`, `EthernetHeaderLength=14` | [EtherIp/EtherIpCodec.cs:24](EtherIp/EtherIpCodec.cs#L24) |
| `EtherIpTunnelOptions` | Options: `Mtu` (default 1400), `LinkAddress` (MAC 6B của endpoint → `IEthernetChannel.LinkAddress`). EtherIP không có field header tùy chọn nên options tối giản | [EtherIp/EtherIpTunnelOptions.cs:10](EtherIp/EtherIpTunnelOptions.cs#L10) |
| `EtherIpTunnelChannel` | `IEthernetChannel` proto-97 (L2-over-IP): outbound `EtherIpCodec.Encapsulate` khung Ethernet → `SendAsync`; receive-loop `TryDecapsulate` drop malformed/version≠3 → raise `InboundFrame`; `Start()` + dispose (identity-guard + dispose-to-unblock **mirror `GreTunnelChannel`**). `Medium=Ethernet`, `MaxHeaderLength=14`, `RequiresLinkAddressResolution=true` | [EtherIp/EtherIpTunnelChannel.cs:27](EtherIp/EtherIpTunnelChannel.cs#L27) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class áp dụng | Vị trí | Ghi chú |
|-------|---------------|--------|---------|
| RFC 2784 (GRE base) | `GreCodec` | [Gre/GreCodec.cs:24](Gre/GreCodec.cs#L24) | byte0 `C R0 K S s Recur(3)`, byte1 `Reserved0(5) Version(3)`=0, ProtocolType(2); C ⇒ Checksum(2)+Reserved1(2). Receiver bỏ qua Reserved0/routing/recursion (leniency) |
| RFC 2890 (Key/Seq) | `GreCodec` | [Gre/GreCodec.cs:24](Gre/GreCodec.cs#L24) | K ⇒ Key(4) opaque flow-id; S ⇒ Sequence(4). Thứ tự field: Checksum → Key → Sequence |
| RFC 1071 (Internet checksum) | `GreCodec` — tái dùng [`InternetChecksum.Compute`](../TqkLibrary.VpnClient.Abstractions/Net/InternetChecksum.cs) | [../TqkLibrary.VpnClient.Abstractions/Net/InternetChecksum.cs:6](../TqkLibrary.VpnClient.Abstractions/Net/InternetChecksum.cs#L6) | one's-complement 16-bit trên toàn header+payload (field checksum = 0 khi tính); **không tự cài lại** — dùng chung codec RFC 1071 ở Abstractions.Net (IpEncap đã ref Abstractions) |
| RFC 2003 (IPIP) | `RawIpPassthroughChannel` | [RawIpPassthroughChannel.cs:20](RawIpPassthroughChannel.cs#L20) | IPv4-in-IPv4, không header — gói trong IS payload raw-IP |
| RFC 4213 (SIT/6in4) | `RawIpPassthroughChannel` | [RawIpPassthroughChannel.cs:20](RawIpPassthroughChannel.cs#L20) | IPv6-in-IPv4, cùng shape passthrough |
| RFC 3378 (EtherIP) | `EtherIpCodec` / `EtherIpTunnelChannel` | [EtherIp/EtherIpCodec.cs:24](EtherIp/EtherIpCodec.cs#L24) | Ethernet-in-IP proto-97: header 2B `Version(4)=3 ‖ Reserved(12)=0` (byte 0=`0x30`, byte 1=`0x00`) + khung Ethernet đầy đủ. Decode: Version==3 strict; Reserved lenient (chấp nhận≠0, bỏ qua — mirror leniency GRE) |
| IANA Protocol Numbers | (caller) | [../TqkLibrary.VpnClient.Transport.RawIp/RawIpProtocols.cs:4](../TqkLibrary.VpnClient.Transport.RawIp/RawIpProtocols.cs#L4) | `Gre=47`, `IpIp=4`, `Sit=41` — caller chọn khi tạo `IDatagramTransport`; `EtherIp=97` (hằng ở `EtherIpCodec.ProtocolNumber`; thêm vào `RawIpProtocols` = live follow-up) |

## API / cách dùng

```csharp
// GRE proto-47 (cần raw-IP transport elevate, vd RawIpTransportFactory.Create(gw, RawIpProtocols.Gre, localBind)).
var gre = new GreTunnelChannel(transport, new GreTunnelOptions { Key = 0x1234, EmitSequenceNumber = true });
gre.InboundIpPacket += ip => stack.Inject(ip);   // gói IP trong tunnel
gre.Start();
await gre.WriteIpPacketAsync(outerIpPacket);     // chọn 0x0800/0x86DD theo version nibble
await gre.DisposeAsync();

// IPIP proto-4 hoặc SIT proto-41: cùng một kênh, khác proto-number lúc tạo transport.
var ipip = new RawIpPassthroughChannel(transport);  // transport tạo với RawIpProtocols.IpIp (hoặc .Sit)
ipip.InboundIpPacket += ip => stack.Inject(ip);
ipip.Start();
await ipip.WriteIpPacketAsync(innerIpPacket);       // gửi verbatim, không header
await ipip.DisposeAsync();
```

## Luồng nội bộ

### GRE — gửi ([`GreTunnelChannel.WriteIpPacketAsync`](Gre/GreTunnelChannel.cs#L69) / [`BuildGre`](Gre/GreTunnelChannel.cs#L78))
1. Đọc version nibble (`ipPacket[0] >> 4`) → proto-type `0x0800` (v4) / `0x86DD` (v6); nibble khác ⇒ **drop** (null).
2. Nếu `EmitSequenceNumber` lấy `_nextSeq++` (lock). Dựng `GrePacket` (Key/Checksum theo options) → `GreCodec.Encode` → `_transport.SendAsync`.

### GRE — nhận ([`GreTunnelChannel.ReceiveLoopAsync`](Gre/GreTunnelChannel.cs#L107))
- Loop `ReceiveAsync` → `GreCodec.TryDecode`; malformed/version≠0/checksum-sai ⇒ drop (log Trace); proto-type không phải v4/v6 ⇒ drop; payload rỗng ⇒ bỏ; còn lại raise `InboundIpPacket(payload)`. Identity-guard (`_loopCts`) + dispose transport để unblock receive (như [`PptpGreChannel`](../TqkLibrary.VpnClient.Pptp/Gre/PptpGreChannel.cs#L21)).

### IPIP/SIT — passthrough ([`RawIpPassthroughChannel`](RawIpPassthroughChannel.cs#L20))
- Gửi: `SendAsync(ipPacket)` verbatim. Nhận: loop `ReceiveAsync` → raise payload verbatim. Không codec — gói IP trong IS payload raw-IP.

## Trạng thái & ghi chú

- **Đã hiện thực (code + test offline):** GRE codec (RFC 2784 base + RFC 2890 Key/Seq + checksum RFC 1071 **tái dùng [`InternetChecksum.Compute`](../TqkLibrary.VpnClient.Abstractions/Net/InternetChecksum.cs)** — không tự cài lại) + `GreTunnelChannel` (proto-47, chọn family theo version nibble) + `RawIpPassthroughChannel` (IPIP proto-4 **và** SIT proto-41, header-less). Build xanh cả `netstandard2.0` + `net8.0`. Test offline ([IpEncap.Tests](../../tests/TqkLibrary.VpnClient.IpEncap.Tests)): [`GreCodecTests`](../../tests/TqkLibrary.VpnClient.IpEncap.Tests/GreCodecTests.cs) (round-trip plain/+Key/+Seq/+Checksum/combined + thứ tự byte + v4/v6 proto-type + malformed version/truncated/bad-checksum/leniency), [`GreTunnelChannelTests`](../../tests/TqkLibrary.VpnClient.IpEncap.Tests/GreTunnelChannelTests.cs) (loopback `IDatagramTransport`: inner v4/v6 round-trip byte-for-byte + garbage dropped), [`RawIpPassthroughChannelTests`](../../tests/TqkLibrary.VpnClient.IpEncap.Tests/RawIpPassthroughChannelTests.cs) (v4/v6 verbatim).
- **GRE chuẩn (v0) ≠ PPTP Enhanced GRE (v1).** Đây là codec **riêng, sạch** — Key ở đây là flow-id 32-bit opaque (RFC 2890), KHÔNG phải payload-length+call-id của PPTP ([`PptpGreCodec`](../TqkLibrary.VpnClient.Pptp/Gre/PptpGreCodec.cs#L20)). Không tái dùng codec PPTP.
- **netstandard2.0 vs net8.0:** không có API mới — `record`/`init` qua polyfill `TqkLibrary.CompilerServices`; loop dùng `Span`/`BinaryPrimitives` (System.Memory polyfill ns2.0). Identity-guard/dispose-to-unblock như các kênh datagram khác.
- **EtherIP (RFC 3378) — codec + kênh XONG offline (V.8c):** [`EtherIpCodec`](EtherIp/EtherIpCodec.cs#L24) (header 2B `0x30 0x00` + khung Ethernet; Version==3 strict, Reserved lenient) + [`EtherIpTunnelChannel`](EtherIp/EtherIpTunnelChannel.cs#L27) (`IEthernetChannel` proto-97, cầu L2-over-IP, mirror cấu trúc `GreTunnelChannel`). Test offline ([IpEncap.Tests](../../tests/TqkLibrary.VpnClient.IpEncap.Tests)): [`EtherIpCodecTests`](../../tests/TqkLibrary.VpnClient.IpEncap.Tests/EtherIpCodecTests.cs) (round-trip byte-exact nhiều cỡ khung + header đúng + reject version≠3/cụt<2B/<14B + accept reserved≠0 + hằng) + [`EtherIpTunnelChannelTests`](../../tests/TqkLibrary.VpnClient.IpEncap.Tests/EtherIpTunnelChannelTests.cs) (loopback `IDatagramTransport`: khung round-trip byte-for-byte + garbage dropped + L2 traits). Build xanh cả `netstandard2.0` + `net8.0`. **Transport raw-IP proto-97 = live follow-up** (cần IP public — NAT chặn proto lạ); **chưa wire builder**; hằng `RawIpProtocols.EtherIp=97` chưa thêm (thuộc phần live).
- **VALIDATE LIVE — cả 3 kênh 2 CHIỀU XONG (2026-06-24)** — lab [`lab/ipencap`](../../lab/ipencap/README-vi.md) (peer Linux `ip tunnel` thuần, 2 container bridge no-NAT; driver [Drivers.IpEncap](../TqkLibrary.VpnClient.Drivers.IpEncap) ráp các kênh này trên raw socket). `GreTunnelChannel` proto-47 (pcap `GREv0 Flags [none]` khớp Linux gre no-key byte-for-byte) + `RawIpPassthroughChannel` proto-4 (`proto IPIP (4)` inner-IP verbatim) **và** proto-41 (`proto IPv6 (41)` IPv6 inner verbatim) — ICMP/UDP 2 chiều xác nhận qua pcap + link stats. **0 bug** (codec đúng ngay lần đầu — encap trần connectionless).
- **Còn lại (V.8 ngoài phase a):** **EtherIP** validate live (proto-97, cần IP public + gắn [Ethernet L2 fabric](../TqkLibrary.VpnClient.Ethernet) + driver L2) + **L2TPv3-over-IP** (proto-115): **tái dùng chung** [`L2tpv3DataHeader`](../TqkLibrary.VpnClient.Drivers.L2tpv3Eth/L2tpv3DataHeader.cs#L24) sẵn có (biến thể no-admin đã chạy header đó trong UDP; L2TPv3-over-IP chỉ khác **transport ngoài** = raw-IP proto-115) nên **không cần codec mới**. GRE Key/Sequence/Checksum (RFC 2890) chưa kiểm live với gateway có key (lab dùng GRE no-key).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §5/§9 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md) (V.8).
