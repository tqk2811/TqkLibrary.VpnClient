# TqkLibrary.VpnClient.Clat

Engine **464XLAT CLAT — customer-side stateless translator (RFC 6877)** + **PREF64 discovery** (RFC 8781 RA option + RFC 7050 `ipv4only.arpa`). 464XLAT = **CLAT** (phía thiết bị, dịch stateless SIIT 1:1) + **PLAT** (NAT64 phía server — NGOÀI phạm vi). Project này làm **phần client**: (1) **CLAT translator** = ghép lại engine SIIT sẵn có; (2) **PREF64 discovery** để tự học prefix NAT64 thay vì cấu hình tĩnh. Đây là **thư viện thuần** (không phải VPN driver): nhận gói IPv4/IPv6 nguyên gói, trả về gói họ kia đã dịch header + fix checksum, hoặc `null` khi drop an toàn.

Điểm cốt lõi: **tiêu thụ lại nguyên [`SiitTranslator`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs)** qua seam [`IAddressTranslator`](../TqkLibrary.VpnClient.Siit/Interfaces/IAddressTranslator.cs) — CLAT **CHỈ** đóng góp cách ghép địa chỉ (EAM device-source + RFC 6052 NAT64 dst), **KHÔNG** viết lại bất kỳ code dịch header/checksum/ICMP/fragment nào. CLAT là "**consumer thật thứ 3**" của seam SIIT (sau NAT64/EAM và MAP-T).

**KHÔNG wire vào [`VpnClientBuilder`](../TqkLibrary.VpnClient)** — là engine nền, không phải driver. Mục tiêu: test **offline** (parse-vector PREF64 + round-trip byte-exact). **NAT64/DNS64 stateful server-side KHÔNG làm**; **truy vấn DNS thật `ipv4only.arpa` là live** — ở đây chỉ có parser/trích prefix offline.

Clean-room từ RFC (không copy code GPL/AGPL).

## Vị trí kiến trúc

Tầng **IP-stack helper** (không tự chạy, không cầm socket). Xếp **trên** [`Siit`](../TqkLibrary.VpnClient.Siit) — tái dùng:
- [`SiitTranslator`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs) cho **toàn bộ** việc dịch header RFC 7915 (version/TTL↔hop-limit/TOS↔traffic-class/protocol↔next-header, TCP/UDP checksum, ICMP↔ICMPv6, Fragment header, drop-an-toàn).
- [`SiitAddressTranslator`](../TqkLibrary.VpnClient.Siit/SiitAddressTranslator.cs) (composite, thử chuỗi) — ghép **EAM device-source** trước → **RFC 6052 NAT64** fallback.
- [`ExplicitAddressMap`](../TqkLibrary.VpnClient.Siit/ExplicitAddressMap.cs) (RFC 7757 EAM) cho **nguồn** CLAT 1:1 (device IPv4 ↔ CLAT IPv6 /96) — dùng nguyên.
- [`Rfc6052AddressMapper`](../TqkLibrary.VpnClient.Siit/Rfc6052AddressMapper.cs) cho **đích** NAT64 (nhúng IPv4-in-IPv6 RFC 6052) — dùng nguyên, và **tái dùng lại** trong `Rfc7050WellKnownPrefix` để dò offset nhúng.

CLAT **chỉ** đóng góp: cách gộp 2 address-translator từ config + 2 codec discovery — không đụng packet.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Siit](../TqkLibrary.VpnClient.Siit) | `SiitTranslator` (dịch header), `SiitAddressTranslator`/`IAddressTranslator` (seam + composite), `ExplicitAddressMap` (EAM device-source), `Rfc6052AddressMapper` (NAT64 dst + dò offset RFC 6052) — **TÁI DÙNG NGUYÊN, KHÔNG viết lại** |
| Dùng (bắc cầu qua Siit) | [IpStack](../TqkLibrary.VpnClient.IpStack) / [Abstractions](../TqkLibrary.VpnClient.Abstractions) | chỉ dùng gián tiếp trong test (`Ipv4`/`Ipv6`/`InternetChecksum` dựng gói) |
| Được dùng bởi | *(chưa có)* | Engine nền; **KHÔNG** dùng bởi façade builder |

Không dùng `Crypto`/`Drivers.*`/`Transport.*` — CLAT là phép biến đổi header/địa chỉ thuần, không mã hóa/không mạng.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Clat/
├─ Pref64Prefix.cs            record NAT64 prefix học được: Prefix + PrefixLength (32/40/48/56/64/96) + LifetimeSeconds
├─ Rfc8781Pref64Option.cs     Codec static RFC 8781: TryParse 1 option RA type 38 (16 byte) + ParseRaOptions duyệt chuỗi TLV
├─ Rfc7050WellKnownPrefix.cs  Codec static RFC 7050: TryExtractNat64Prefix — dò 192.0.0.170/171 ở các offset nhúng RFC 6052 (tái dùng Rfc6052AddressMapper)
├─ ClatConfig.cs              record config CLAT: device IPv4 + CLAT IPv6 /96 + NAT64 prefix/len; tính sẵn EAM + Rfc6052 mapper; FromDiscoveredPrefix
└─ ClatTranslator.cs          Entry point mỏng: SiitTranslator(SiitAddressTranslator(EAM, Rfc6052)) → Translate4to6 / Translate6to4
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `Pref64Prefix` | **record** kết quả discovery: `Prefix` (IPv6) + `PrefixLength` (một trong 32/40/48/56/64/96, RFC 6052 §2.2) + `LifetimeSeconds` (RFC 8781 Scaled-Lifetime×8; 0 cho prefix từ DNS) | [Pref64Prefix.cs:13](Pref64Prefix.cs#L13) |
| `Rfc8781Pref64Option` | **static codec** RFC 8781: `TryParse(ReadOnlySpan<byte>, out Pref64Prefix)` đọc 1 option 16-byte (`Type=38 · Length=2 · Scaled-Lifetime(13b)‖PLC(3b) · Highest-96-bits(12B)`), map **PLC→len** (0→96/1→64/2→56/3→48/4→40/5→32, khác→false), lifetime = scaled×8; `ParseRaOptions(ReadOnlySpan<byte>)` duyệt chuỗi option TLV (RFC 4861, length đơn vị 8 byte) lấy mọi option type 38 | [Rfc8781Pref64Option.cs:11](Rfc8781Pref64Option.cs#L11) (`TryParse` [:24](Rfc8781Pref64Option.cs#L24) / `ParseRaOptions` [:49](Rfc8781Pref64Option.cs#L49)) |
| `Rfc7050WellKnownPrefix` | **static codec** RFC 7050: `TryExtractNat64Prefix(ReadOnlySpan<byte> aaaa, out IPAddress prefix, out int prefixLength)` — dò IPv4 well-known `192.0.0.170`/`192.0.0.171` ở **các offset nhúng RFC 6052** (32/40/48/56/64/96, longest-first) bằng cách **tái dùng** [`Rfc6052AddressMapper`](../TqkLibrary.VpnClient.Siit/Rfc6052AddressMapper.cs) (không tự viết lại layout u-octet). **CHỈ parse offline** — không truy vấn DNS thật | [Rfc7050WellKnownPrefix.cs:13](Rfc7050WellKnownPrefix.cs#L13) (`TryExtractNat64Prefix` [:30](Rfc7050WellKnownPrefix.cs#L30)) |
| `ClatConfig` | **record config**: `DeviceIpv4` (+ len, mặc định /32) + `ClatIpv6Prefix` (+ len, mặc định /96) + `Nat64Prefix`/`Nat64PrefixLength`; ctor validate family + **tính sẵn** `ClatSourceMap` (EAM `device ↔ CLAT /96`) + `Nat64Mapper` (`Rfc6052AddressMapper`) → `CreateAddressTranslator()` = `SiitAddressTranslator(EAM, Rfc6052)`. Factory `FromDiscoveredPrefix(Pref64Prefix, ...)` | [ClatConfig.cs:14](ClatConfig.cs#L14) (`CreateAddressTranslator` [:85](ClatConfig.cs#L85) / `FromDiscoveredPrefix` [:90](ClatConfig.cs#L90)) |
| `ClatTranslator` | **entry point** mỏng: giữ `SiitTranslator(config.CreateAddressTranslator())`, expose `Translate4to6`/`Translate6to4` + `LastDropReason` + static `FromDiscoveredPrefix`. Không thread-safe (như `SiitTranslator`) | [ClatTranslator.cs:15](ClatTranslator.cs#L15) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| 464XLAT | **RFC 6877** | CLAT (client stateless SIIT 1:1) + PLAT (NAT64 server). Ta làm **CLAT client**; PLAT/NAT64 ngoài phạm vi |
| CLAT source (1:1) | **RFC 7757** (EAM) | device IPv4 (`192.0.0.1`/dải CLAT, RFC 7335) ↔ CLAT IPv6 /96 dành riêng — [`ExplicitAddressMap`](../TqkLibrary.VpnClient.Siit/ExplicitAddressMap.cs) nguyên |
| CLAT destination | **RFC 6052** §2.2 | IPv4 xa → NAT64 prefix (PL 32/40/48/56/64/96) — [`Rfc6052AddressMapper`](../TqkLibrary.VpnClient.Siit/Rfc6052AddressMapper.cs) nguyên |
| Dịch header | **RFC 7915** | **Toàn bộ** do [`SiitTranslator`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs) lo (không viết lại) |
| PREF64 (RA) | **RFC 8781** | ICMPv6 RA option **Type=38 · Length=2** (16 byte); Scaled-Lifetime 13-bit ‖ PLC 3-bit; PLC→len 0/96·1/64·2/56·3/48·4/40·5/32; lifetime = scaled×8 |
| PREF64 (DNS) | **RFC 7050** | AAAA cho `ipv4only.arpa` nhúng `192.0.0.170`/`192.0.0.171` (`C0 00 00 AA/AB`) theo RFC 6052 → trích prefix + độ dài. **Chỉ parser offline** (truy vấn thật = live) |

## Luồng (as-built)

**Compose**: `new ClatTranslator(config)` → `new SiitTranslator(config.CreateAddressTranslator())` với `CreateAddressTranslator()` = `new SiitAddressTranslator(ClatSourceMap /*EAM*/, Nat64Mapper /*RFC 6052*/)`. Toàn bộ dịch header là của SIIT; CLAT chỉ thay hàm ánh xạ địa chỉ.

**4→6 (device→NAT64)** [`Translate4to6`](ClatTranslator.cs#L30) → [`SiitTranslator.Translate4to6`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs#L56): với mỗi địa chỉ src/dst gọi `SiitAddressTranslator` (thử EAM trước) — **src = device IPv4** khớp EAM ⇒ **CLAT IPv6 /96**; **dst = IPv4 xa** không khớp EAM ⇒ rơi về **NAT64 nhúng RFC 6052**. SIIT lo checksum/TTL/traffic-class.

**6→4 (NAT64→device)** [`Translate6to4`](ClatTranslator.cs#L33) → [`SiitTranslator.Translate6to4`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs#L242): đối xứng — **dst = CLAT IPv6** khớp EAM ⇒ device IPv4; **src = NAT64-embedded** không khớp EAM ⇒ trích RFC 6052; địa chỉ không thuộc CLAT/NAT64 ⇒ `false` ⇒ SIIT drop `AddressNotMapped`.

**PREF64 discovery** (thay cấu hình NAT64 tĩnh):
- **RA option** [`Rfc8781Pref64Option.TryParse`](Rfc8781Pref64Option.cs#L24): kiểm type 38 + length 2 → đọc PLC (→độ dài) + Scaled-Lifetime (×8) + 96-bit prefix → `Pref64Prefix`; [`ParseRaOptions`](Rfc8781Pref64Option.cs#L49) duyệt cả vùng option của RA.
- **DNS `ipv4only.arpa`** [`Rfc7050WellKnownPrefix.TryExtractNat64Prefix`](Rfc7050WellKnownPrefix.cs#L30): với mỗi độ dài RFC 6052 (longest-first), dựng `Rfc6052AddressMapper` prefix = 96-bit đầu của AAAA rồi `TryTranslate6to4` — nếu IPv4 trích ra == well-known `192.0.0.170`/`171` ⇒ suy prefix + độ dài.
- **Ráp**: `ClatTranslator.FromDiscoveredPrefix(pref64, deviceIpv4, clatIpv6Prefix)` → `ClatConfig.FromDiscoveredPrefix` → dùng `pref64.Prefix`/`pref64.PrefixLength` làm NAT64 dst.

## Trạng thái & ghi chú

- **Đã có (offline code + test XONG)**: CLAT translator (compose SIIT: EAM device-source + RFC 6052 NAT64 dst), PREF64 discovery 2 nguồn (RA option RFC 8781 + DNS `ipv4only.arpa` RFC 7050), `ClatConfig`/`FromDiscoveredPrefix`. **30 test** (số CASE runtime, mỗi `[Fact]`/`[InlineData]` = 1): `Rfc8781Pref64Option` parse đủ **6 PLC** (/96../32) ra prefix+len+lifetime + reject type≠38/length-sai/PLC-reserved/too-short + `ParseRaOptions` nhặt đúng option 38 giữa các option khác / nhiều PREF64 / dừng ở option 0-length; `Rfc7050WellKnownPrefix` trích đúng prefix+len ở **6 độ dài RFC 6052** (dựng AAAA tổng hợp bằng `Rfc6052AddressMapper`) + `.171` + reject no-well-known / non-16-byte; `ClatTranslator` gói device→host xa **4→6→4 byte-exact** (UDP+TCP, src=CLAT IPv6 / dst=NAT64-embedded / checksum + TTL−2) + 4→6 kiểm src/dst/checksum + `FromDiscoveredPrefix` + drop source không map + validate config sai⇒throw.
- **Phạm vi (cố tình gọn — client-only)**:
  - **CHỈ client (CLAT)** — **KHÔNG** NAT64/DNS64 stateful **server-side** (RFC 6146/6147: bảng session/BIB, phân bổ port, tổng hợp AAAA). Đủ cho thiết bị IPv6-only chạy ứng dụng IPv4.
  - **PREF64 discovery = parser/trích offline**: **KHÔNG** thực hiện truy vấn DNS thật `ipv4only.arpa` (đó là live) — chỉ dò prefix từ AAAA đã có; RA option cũng chỉ parse mảng byte (không tự nhận RA từ mạng ở đây).
  - **Địa chỉ-only** (khớp seam `IAddressTranslator`): device IPv4 (host/dải) là **config** — không kiểm port/flow từng gói (CLAT stateless 1:1).
- **Chưa wire**: CLAT **KHÔNG** cắm vào `VpnClientBuilder` (đúng thiết kế — engine nền, không line-ref drift). Không đụng facade/root README/driver khác.
- **Tái sử dụng tối đa**: 0 dòng dịch header/checksum/ICMP/fragment — tất cả là `SiitTranslator`. EAM = `ExplicitAddressMap` nguyên; NAT64 = `Rfc6052AddressMapper` nguyên (và **cùng type** dùng lại để dò offset RFC 7050). Chỉ code mới = 2 codec discovery + config ghép.
- **Tham chiếu**: RFC 6877 + RFC 8781 + RFC 7050 + RFC 6052 + RFC 7757 + RFC 7915; nền [Siit](../TqkLibrary.VpnClient.Siit); roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.19 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9. Test: [`TqkLibrary.VpnClient.Clat.Tests`](../../tests/TqkLibrary.VpnClient.Clat.Tests).

> Build xanh cả `netstandard2.0` + `net8.0`. `record` (`Pref64Prefix`/`ClatConfig`) dùng được 2 TFM nhờ `TqkLibrary.CompilerServices` (ref ở [`src/Directory.Build.props`](../Directory.Build.props)). Không `#if` — chỉ dùng `Span`/`IPAddress`/bit-ops có sẵn cả 2 TFM.
