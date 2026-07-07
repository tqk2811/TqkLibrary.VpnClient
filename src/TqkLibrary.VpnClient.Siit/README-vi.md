# TqkLibrary.VpnClient.Siit

Engine **dịch header IPv4↔IPv6 stateless (SIIT — RFC 7915)** + **địa chỉ IPv4-embedded-IPv6 (RFC 6052)** + **Explicit Address Mapping (RFC 7757)**. Đây là **thư viện thuần** (không phải VPN driver): nhận vào một gói IPv4/IPv6 nguyên gói và trả về gói họ kia đã dịch header + fix checksum, hoặc `null` khi không dịch được an toàn. **KHÔNG wire vào [`VpnClientBuilder`](../TqkLibrary.VpnClient)** — là **nền dùng chung** để về sau **MAP-T (RFC 7599)** và **464XLAT/CLAT (RFC 6877)** tiêu thụ. Mục tiêu: round-trip **byte-exact** + đối chiếu **test-vector RFC 6052 §2.4**.

Clean-room từ RFC (không copy code GPL/AGPL).

## Vị trí kiến trúc

Tầng **IP-stack helper** (không tự chạy, không cầm socket). Tái dùng **nguyên** codec/parser của [`IpStack`](../TqkLibrary.VpnClient.IpStack) ([`Ipv4`](../TqkLibrary.VpnClient.IpStack/Ipv4.cs)/[`Ipv6`](../TqkLibrary.VpnClient.IpStack/Ipv6.cs)/[`Icmpv4`](../TqkLibrary.VpnClient.IpStack/Icmpv4.cs)/[`Icmpv6`](../TqkLibrary.VpnClient.IpStack/Icmpv6.cs)) + Internet checksum của [`Abstractions.Net`](../TqkLibrary.VpnClient.Abstractions/Net/InternetChecksum.cs) — **KHÔNG viết lại** build/parse header hay checksum. Chỉ đóng góp: quy tắc dịch trường header giữa 2 họ (RFC 7915), ánh xạ địa chỉ (RFC 6052/7757), và fix-up checksum tầng trên (RFC 1624/recompute).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [IpStack](../TqkLibrary.VpnClient.IpStack) | `Ipv4`/`Ipv6` (Build/BuildFragment + parser: `HeaderLength`/`Protocol`/`Source`/`Destination`/`Identification`/`FragmentOffset`/`MoreFragments`/`DontFragment`/`TryGetFragment`/`TryGetUpperLayer`/`HopLimit`/`PayloadLength`), `Icmpv4`/`Icmpv6` (Type/Code/BuildEcho/BuildDestinationUnreachable/BuildPacketTooBig/BuildFragmentationNeeded/VerifyChecksum) — **TÁI DÙNG, KHÔNG viết lại** |
| Dùng (bắc cầu qua IpStack) | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | [`InternetChecksum`](../TqkLibrary.VpnClient.Abstractions/Net/InternetChecksum.cs) (`Compute`/`PseudoHeaderSum`/`AddData`/`Finish`) cho recompute + incremental RFC 1624 |
| Được dùng bởi | *(chưa có)* | Về sau: **MAP-T** (RFC 7599) + **464XLAT/CLAT** (RFC 6877). **KHÔNG** dùng bởi façade builder |

Không dùng `Crypto`/`Drivers.*`/`Transport.*` — SIIT là phép biến đổi header thuần, không mã hóa/không mạng.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Siit/
├─ SiitTranslator.cs             Engine RFC 7915: Translate4to6 / Translate6to4 (header + ICMP + checksum + Fragment header) + drop-an-toàn (LastDropReason)
├─ Rfc6052AddressMapper.cs       IAddressTranslator: nhúng/trích IPv4 trong IPv6 (RFC 6052 §2.2, PL 32/40/48/56/64/96, WKP 64:ff9b::/96)
├─ ExplicitAddressMap.cs         IAddressTranslator: bảng EAM (RFC 7757) longest-prefix-match, copy suffix bit
├─ SiitAddressTranslator.cs      IAddressTranslator composite: thử chuỗi theo thứ tự (EAM trước → RFC 6052 fallback)
├─ Interfaces/
│  └─ IAddressTranslator.cs      Hợp đồng TryTranslate4to6 / TryTranslate6to4
├─ Enums/
│  └─ SiitDropReason.cs          Lý do drop (HopLimitExceeded / UnsupportedProtocol / AddressNotMapped / Multicast / ...)
├─ Models/
│  └─ EamEntry.cs                record 1 dòng EAM: (IPv4 prefix+len ↔ IPv6 prefix+len)
└─ Helpers/
   ├─ AddressBits.cs             Bit-string MSB-first: PrefixMatches / CopyBits (cho EAM prefix không byte-aligned)
   └─ SiitChecksum.cs            RFC 1624 AdjustForAddressChange (incremental) + ComputeTransport (recompute pseudo-header)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `IAddressTranslator` | Hợp đồng dịch địa chỉ 1 chiều mỗi hàm: `bool TryTranslate4to6(IPAddress, out IPAddress)` + `TryTranslate6to4` | [IAddressTranslator.cs:10](Interfaces/IAddressTranslator.cs#L10) |
| `Rfc6052AddressMapper` | RFC 6052 §2.2: nhúng 32-bit IPv4 quanh **u-octet (byte 8) = 0** cho PL ∈ {32,40,48,56,64,96}; mặc định **WKP `64:ff9b::/96`**; 6→4 kiểm prefix-match + u-octet=0. **Đúng test-vector §2.4** | [Rfc6052AddressMapper.cs:13](Rfc6052AddressMapper.cs#L13) (4→6 [:44](Rfc6052AddressMapper.cs#L44) / 6→4 [:65](Rfc6052AddressMapper.cs#L65)) |
| `ExplicitAddressMap` | RFC 7757: bảng (IPv4-prefix ↔ IPv6-prefix), **longest-prefix-match**, strip prefix → prepend prefix họ kia → **pad zero** (4→6) / **truncate 32-bit** (6→4); validate ràng buộc §3.3 `(32−L4) ≤ (128−L6)` khi `Add` | [ExplicitAddressMap.cs:15](ExplicitAddressMap.cs#L15) ([Add :38](ExplicitAddressMap.cs#L38)) |
| `SiitAddressTranslator` | Composite `IAddressTranslator`: thử chuỗi theo thứ tự, trả kết quả đầu tiên khớp — dùng `new SiitAddressTranslator(eam, rfc6052)` cho **EAM trước → RFC 6052 fallback** | [SiitAddressTranslator.cs:11](SiitAddressTranslator.cs#L11) |
| `SiitTranslator` | Engine RFC 7915: `byte[]? Translate4to6(ReadOnlySpan<byte>)` (§4) + `byte[]? Translate6to4(...)` (§5); dịch version/TTL↔hop-limit(−1)/TOS↔traffic-class/protocol↔next-header/địa chỉ (qua `IAddressTranslator`); ICMP↔ICMPv6 (echo + Dest-Unreachable + Packet-Too-Big/Frag-Needed + Time-Exceeded, **dịch gói IP nhúng**); chèn/gỡ **IPv6 Fragment header**; fix checksum TCP/UDP + ICMPv6 pseudo-header; drop-an-toàn → `null` + `LastDropReason` | [SiitTranslator.cs:18](SiitTranslator.cs#L18) (4→6 [:56](SiitTranslator.cs#L56) / 6→4 [:242](SiitTranslator.cs#L242) / ICMP [:166](SiitTranslator.cs#L166),[:352](SiitTranslator.cs#L352)) |
| `EamEntry` | record dữ liệu 1 entry EAM: `Ipv4Prefix`/`Ipv4PrefixLength`/`Ipv6Prefix`/`Ipv6PrefixLength` | [EamEntry.cs:13](Models/EamEntry.cs#L13) |
| `SiitDropReason` | enum lý do drop: `Malformed`/`HopLimitExceeded`/`UnsupportedProtocol`/`UnsupportedExtensionHeader`/`AddressNotMapped`/`Multicast`/`UnsupportedIcmp`/`FragmentedIcmp`/`UdpZeroChecksumFragment` | [SiitDropReason.cs:4](Enums/SiitDropReason.cs#L4) |
| `AddressBits` | Static thuần: `PrefixMatches`/`GetBit`/`SetBit`/`CopyBits` (MSB-first) cho EAM prefix không byte-aligned | [AddressBits.cs:7](Helpers/AddressBits.cs#L7) |
| `SiitChecksum` | Static thuần: `AdjustForAddressChange` (RFC 1624 incremental — chỉ đổi địa chỉ pseudo-header, dùng cho fragment) + `ComputeTransport` (recompute pseudo-header khi có nguyên datagram) | [SiitChecksum.cs:13](Helpers/SiitChecksum.cs#L13) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Địa chỉ nhúng | **RFC 6052** §2.2/§2.4 | IPv4 32-bit đặt quanh u-octet (byte 8) = 0; PL 32/40/48/56/64/96; WKP `64:ff9b::/96`. **KAT byte-exact bảng §2.4** |
| EAM | **RFC 7757** §3.3 | LPM, strip/prepend prefix + copy suffix, pad(4→6)/truncate(6→4); ràng buộc `(32−L4) ≤ (128−L6)` |
| Dịch header 4→6 | **RFC 7915 §4** | version=6, traffic-class←TOS, flow-label=0, payload-length, **hop-limit=TTL−1** (drop TTL≤1), next-header←protocol (1→58, 6/17 giữ), Fragment header khi (MF∨offset>0∨DF=0), id 32-bit = id 16-bit v4 |
| Dịch header 6→4 | **RFC 7915 §5** | version=4, TOS←traffic-class, **TTL=hop-limit−1** (drop hop≤1), DF=1 (nếu không có Fragment header) hoặc id/offset/MF từ Fragment header, protocol←next-header (58→1) |
| ICMP | **RFC 7915 §4.2/§5.2** + RFC 792/4443 | Echo/Reply (8/0↔128/129), Dest-Unreachable (map code, port→4/3), Packet-Too-Big↔Frag-Needed (MTU ±20), Time-Exceeded (11↔3); **dịch header gói nhúng** (offending packet) |
| Checksum | **RFC 1624** + RFC 1071 | TCP/UDP: recompute pseudo-header khi có nguyên datagram, **incremental (đổi địa chỉ)** cho fragment; UDP checksum 0 (v4) → tính bắt buộc cho v6 (drop nếu fragment); ICMP↔ICMPv6 recompute (ICMPv6 **có** pseudo-header, ICMPv4 không) |

## Luồng dịch (as-built)

**4→6** [`Translate4to6` @ :56](SiitTranslator.cs#L56):
1. Validate version/IHL/độ dài; TTL≤1 → drop `HopLimitExceeded`.
2. Đọc TOS/protocol; nếu src/dst **multicast** (224/4) → drop `Multicast`; dịch src4/dst4 qua `IAddressTranslator` (drop `AddressNotMapped`).
3. Xác định fragment (MF/offset/DF) → `needFragmentHeader = fragmented ∨ ¬DF` (RFC 7915 §4).
4. Theo protocol: ICMP → [`TranslateIcmp4to6` @ :166](SiitTranslator.cs#L166) (drop nếu ICMP bị fragment); TCP/UDP → copy segment + fix checksum ([recompute nếu nguyên datagram, incremental nếu fragment đầu](SiitTranslator.cs#L128); UDP-checksum-0 → tính); protocol khác → drop `UnsupportedProtocol`.
5. Dựng gói IPv6 bằng [`Ipv6.Build`](../TqkLibrary.VpnClient.IpStack/Ipv6.cs) hoặc [`Ipv6.BuildFragment`](../TqkLibrary.VpnClient.IpStack/Ipv6.cs) (hop-limit=TTL−1) → **vá traffic-class từ TOS**.

**6→4** [`Translate6to4` @ :242](SiitTranslator.cs#L242): nghịch đảo — hop≤1 → drop; multicast (ff00::/8) → drop; **chỉ chấp nhận 1 Fragment header** (ext-header khác → drop `UnsupportedExtensionHeader`); protocol 58→1; dựng bằng [`Ipv4.Build`](../TqkLibrary.VpnClient.IpStack/Ipv4.cs) (DF=1, id=0) hoặc [`Ipv4.BuildFragment`](../TqkLibrary.VpnClient.IpStack/Ipv4.cs) (id/offset/MF từ Fragment header) → **vá TTL=hop−1 + TOS + recompute IPv4 header checksum**.

**Địa chỉ**: `SiitAddressTranslator` thử `ExplicitAddressMap` (EAM) trước, rơi về `Rfc6052AddressMapper` (WKP hoặc prefix cấu hình).

## Trạng thái & ghi chú

- **Đã có**: SIIT header-translation 2 chiều **offline code + test XONG** — **55 test** (số CASE runtime, mỗi `[Fact]`/`[InlineData]` = 1): RFC 6052 §2.4 embed+extract 12 vector + u-octet/prefix reject; EAM LPM/pad/truncate/constraint; composite EAM→6052; header 4↔6 round-trip **byte-exact** (UDP/TCP/traffic-class), UDP-checksum-0, first-fragment + atomic-fragment (DF=0), drop (TTL/hop/protocol/địa chỉ/multicast/ext-header/malformed); ICMP echo + Dest-Unreachable(port) + Frag-Needed→Packet-Too-Big + Packet-Too-Big→Frag-Needed + Time-Exceeded + **dịch gói nhúng** + drop khi gói nhúng không map được.
- **⚠️ Round-trip & TTL**: dịch 2 chiều **giảm TTL 2 lần** (mỗi chiều là 1 hop, đúng hành vi router) — test "byte-exact" so với gói gốc **đã trừ TTL 2 + recompute header checksum**. `identification` chỉ round-trip khi có Fragment header (DF=0); gói DF=1 non-fragment mất id (→ id=0 chiều ngược, đúng RFC 7915 atomic).
- **Cố tình DROP / chưa hỗ trợ** (ghi `LastDropReason`, corner hiếm theo yêu cầu):
  - **IPv6 extension header** ngoài **một** Fragment header (Hop-by-Hop/Routing/Dest-Options/nhiều header) → `UnsupportedExtensionHeader`. IPv4 **options** (IHL>5) được bỏ qua (dùng IHL định vị payload) chứ không dịch.
  - **ICMP trong gói phân mảnh** → `FragmentedIcmp` (checksum ICMP trải trên toàn datagram).
  - **ICMP type/code hiếm**: chỉ Echo/Reply, Dest-Unreachable, Packet-Too-Big/Frag-Needed, Time-Exceeded. `Dest-Unreachable code 2` (protocol-unreachable, đáng ra → ICMPv6 Parameter-Problem) → drop `UnsupportedIcmp`. Không phát ICMP khi drop (chỉ trả `null`).
  - **Multicast** (v4 224/4, v6 ff00::/8) → drop `Multicast`. **Địa chỉ không map** → `AddressNotMapped`.
  - **UDP checksum 0 (v4) + fragment** → `UdpZeroChecksumFragment` (không đủ dữ liệu tính checksum bắt buộc cho v6).
  - **Gói nhúng trong ICMP error**: dịch **chỉ header** (không recompute checksum tầng trên của quote, chịu quote bị cắt cụt — RFC 7915 §4.2/§5.2); `PayloadLength`/`TotalLength` của gói nhúng lấy theo số byte quote thực có (không suy lại độ dài gốc).
  - **`LastDropReason` là state per-instance** → dùng 1 `SiitTranslator` mỗi luồng/thread (không thread-safe cho field chẩn đoán).
- **Chưa wire**: SIIT **KHÔNG** cắm vào `VpnClientBuilder` (đúng thiết kế — là engine nền). Consumer tương lai: MAP-T (RFC 7599 double-translation) + 464XLAT/CLAT (RFC 6877 + PREF64 discovery RFC 7050/8781).
- **Tham chiếu**: RFC 7915 + RFC 6052 + RFC 7757 + RFC 1624; roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.19 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. `record` (`EamEntry`) dùng được 2 TFM nhờ `TqkLibrary.CompilerServices` (ref ở [`src/Directory.Build.props`](../Directory.Build.props)). Không `#if` — API dùng chỉ `Span`/`IPAddress`/checksum có sẵn cả 2 TFM.
