# TqkLibrary.VpnClient.MapT

Engine **MAP-T — Mapping of Address and Port using Translation (RFC 7599)**: **double stateless translation** = dịch header IPv4↔IPv6 kiểu SIIT (RFC 7915) **với địa chỉ tính theo thuật toán MAP** (RFC 7597 §5). Đây là **thư viện thuần** (không phải VPN driver): nhận gói IPv4/IPv6 nguyên gói, trả về gói họ kia đã dịch header + fix checksum, hoặc `null` khi drop an toàn.

Điểm cốt lõi: **tiêu thụ lại nguyên [`SiitTranslator`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs) sẵn có** qua seam [`IAddressTranslator`](../TqkLibrary.VpnClient.Siit/Interfaces/IAddressTranslator.cs) — project này **CHỈ** đóng góp thuật toán địa chỉ MAP ([`MapAddressTranslator`](MapAddressTranslator.cs) + config domain), **KHÔNG** viết lại bất kỳ code dịch header/checksum/ICMP/fragment nào. MAP-T là "**consumer thật thứ 2**" (sau NAT64/EAM) validate thiết kế seam SIIT.

**KHÔNG wire vào [`VpnClientBuilder`](../TqkLibrary.VpnClient)** — là engine nền, không phải driver. Mục tiêu: test **offline**, đối chiếu **vector RFC 7597 Appendix A** (bằng chứng đúng khi không có peer thật).

Clean-room từ RFC (không copy code GPL/AGPL).

## Vị trí kiến trúc

Tầng **IP-stack helper** (không tự chạy, không cầm socket). Xếp **trên** [`Siit`](../TqkLibrary.VpnClient.Siit) — tái dùng:
- [`SiitTranslator`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs) cho **toàn bộ** việc dịch header RFC 7915 (version/TTL↔hop-limit/TOS↔traffic-class/protocol↔next-header, TCP/UDP checksum, ICMP↔ICMPv6, Fragment header, drop-an-toàn).
- [`IAddressTranslator`](../TqkLibrary.VpnClient.Siit/Interfaces/IAddressTranslator.cs) — seam địa chỉ (2 hàm `TryTranslate4to6`/`TryTranslate6to4`) mà [`MapAddressTranslator`](MapAddressTranslator.cs) hiện thực.
- [`Rfc6052AddressMapper`](../TqkLibrary.VpnClient.Siit/Rfc6052AddressMapper.cs) cho **DMR** (Default Mapping Rule = nhúng IPv4-in-IPv6 RFC 6052) — dùng nguyên, không viết lại.
- [`AddressBits`](../TqkLibrary.VpnClient.Siit/Helpers/AddressBits.cs) (MSB-first bit copy) cho EA-bits/prefix không byte-aligned.

MAP-T **chỉ** đóng góp: thuật toán ánh xạ địa chỉ MAP (RFC 7597 §5.2) — không đụng packet.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Siit](../TqkLibrary.VpnClient.Siit) | `SiitTranslator` (dịch header), `IAddressTranslator` (seam), `Rfc6052AddressMapper` (DMR), `AddressBits` (bit copy) — **TÁI DÙNG NGUYÊN, KHÔNG viết lại** |
| Dùng (bắc cầu qua Siit) | [IpStack](../TqkLibrary.VpnClient.IpStack) / [Abstractions](../TqkLibrary.VpnClient.Abstractions) | chỉ dùng gián tiếp trong test (`Ipv4`/`Ipv6`/`InternetChecksum` dựng gói) |
| Được dùng bởi | *(chưa có)* | Về sau có thể tham chiếu từ 464XLAT/CLAT nếu cần MAP; **KHÔNG** dùng bởi façade builder |

Không dùng `Crypto`/`Drivers.*`/`Transport.*` — MAP-T là phép biến đổi header/địa chỉ thuần, không mã hóa/không mạng.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.MapT/
├─ MapRule.cs               record BMR (Basic Mapping Rule): Rule IPv6/IPv4 prefix + EA-bits + PSID offset; suy diễn + validate PSID length k / sharing ratio
├─ MapAddressMapping.cs     Thuật toán thuần RFC 7597 §5.2: DeriveMapIpv6 / TryParseMapIpv6 (đọc IID) / TryDeriveCe (từ End-user IPv6 prefix)
├─ MapTConfig.cs            record config CE domain: BMR + CE IPv4 + PSID + DMR prefix; tính sẵn CeMapIpv6 + reuse Rfc6052AddressMapper cho DMR
├─ MapAddressTranslator.cs  IAddressTranslator: CE-side (v4==CE ⇔ CE-MAP-IPv6) + DMR-side (RFC 6052) + drop v6 lạ
└─ MapTTranslator.cs        Entry point mỏng: SiitTranslator(new MapAddressTranslator(config)) → Translate4to6 / Translate6to4 (double translation)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `MapRule` | **record BMR**: Rule IPv6 prefix (/n) + Rule IPv4 prefix (/o) + EA-bits length + PSID offset (mặc định 6). Suy diễn `PsidLength k = EA − (32−o)` + `SharingRatio = 2^k`; validate nhất quán (EA≥suffix, a+k≤16, n+EA≤64, family/range). Hỗ trợ override `psidLength` cho ca "EA=0 + explicit PSID" (Appendix A Example 5) | [MapRule.cs:15](MapRule.cs#L15) |
| `MapAddressMapping` | **static thuần** thuật toán RFC 7597 §5.2: `DeriveMapIpv6(rule, ipv4, psid)` (prefix‖EA‖subnet-id‖IID, IID=`0x0000‖IPv4(32)‖PSID(16 phải-căn)`); `TryParseMapIpv6(rule, v6, out ipv4, out psid)` (đọc IID, kiểm prefix + PSID width); `TryDeriveCe(rule, endUserPrefix, out ipv4, out psid)` (đọc EA-bits ⇒ IPv4 suffix + PSID). Bit-copy MSB-first qua `AddressBits` | [MapAddressMapping.cs:14](MapAddressMapping.cs#L14) (Derive [:20](MapAddressMapping.cs#L20) / Parse [:63](MapAddressMapping.cs#L63) / DeriveCe [:88](MapAddressMapping.cs#L88)) |
| `MapTConfig` | **record config CE**: `Rule` + `CeIpv4` + `Psid` + `DmrPrefix`/`DmrPrefixLength`; ctor validate (CE trong Rule IPv4 prefix, PSID trong sharing ratio, DMR length hợp lệ) + **tính sẵn** `CeMapIpv6` + tạo `Rfc6052AddressMapper` DMR. Factory `FromEndUserIpv6Prefix` tự suy CE IPv4/PSID | [MapTConfig.cs:15](MapTConfig.cs#L15) |
| `MapAddressTranslator` | **instance sau `IAddressTranslator`**: `TryTranslate4to6` = CE-IPv4→CE-MAP-IPv6, còn lại→DMR (RFC 6052); `TryTranslate6to4` = CE-MAP-IPv6→CE-IPv4, DMR-prefix→trích RFC 6052, còn lại→`false` (drop). Đây là seam để `SiitTranslator` làm MAP-T | [MapAddressTranslator.cs:15](MapAddressTranslator.cs#L15) |
| `MapTTranslator` | **entry point** mỏng: giữ `SiitTranslator(new MapAddressTranslator(config))`, expose `Translate4to6`/`Translate6to4` (double translation) + `LastDropReason`. Không thread-safe (như `SiitTranslator`) | [MapTTranslator.cs:16](MapTTranslator.cs#L16) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| MAP-T | **RFC 7599** | Double stateless **translation** (dịch, không bọc) — khác MAP-E (encapsulation). Tái dùng SIIT thay vì tunnel |
| Thuật toán MAP | **RFC 7597 §5** | BMR = {Rule IPv6 prefix /n, Rule IPv4 prefix /o, EA-bits}; `EA = (32−o) + k`; PSID offset a (mặc định 6); MAP IPv6 = prefix‖EA‖subnet-id‖IID; **IID = 0x0000‖IPv4(32)‖PSID(16 phải-căn)** (§5.2) |
| DMR | **RFC 6052** §2.2 | Default Mapping Rule nhúng IPv4-in-IPv6 → **tái dùng nguyên** [`Rfc6052AddressMapper`](../TqkLibrary.VpnClient.Siit/Rfc6052AddressMapper.cs) (PL 32/40/48/56/64/96) |
| Dịch header | **RFC 7915** | **Toàn bộ** do [`SiitTranslator`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs) lo (không viết lại) |
| Vector | **RFC 7597 Appendix A** | Example 1/4/5 — đối chiếu địa chỉ + PSID (xem *Trạng thái*) |

## Vector RFC 7597 Appendix A (bằng chứng đúng)

**Example 1** (chính): End-user IPv6 prefix `2001:db8:0012:3400::/56`, BMR = Rule IPv6 `2001:db8::/40` + Rule IPv4 `192.0.2.0/24` + EA-bits `16` + PSID offset `6` ⇒ **IPv4 `192.0.2.18`**, **PSID `0x34`**, k=8, sharing ratio 256, **MAP CE IPv6 `2001:db8:0012:3400:0000:c000:0212:0034`**. Test kiểm cả 3: `TryDeriveCe` (prefix→IPv4/PSID), `DeriveMapIpv6` (IPv4/PSID→MAP IPv6 khớp byte), `TryParseMapIpv6` (MAP IPv6→IPv4/PSID).
**Example 4** (EA=0, no sharing): Rule IPv4 `192.0.2.18/32` ⇒ MAP IPv6 `…:c000:0212:0000` (PSID=0, ratio 1).
**Example 5** (EA=0, explicit PSID k=8): ⇒ MAP IPv6 `…:c000:0212:0034` (ratio 256) — dùng override `psidLength`.

## Luồng (as-built)

**Compose**: `new MapTTranslator(config)` → `new SiitTranslator(new MapAddressTranslator(config))`. Toàn bộ dịch header là của SIIT; MAP-T chỉ thay hàm ánh xạ địa chỉ.

**4→6 (CE→BR)** [`Translate4to6`](MapTTranslator.cs#L37) → [`SiitTranslator.Translate4to6`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs#L56): với mỗi địa chỉ src/dst gọi [`MapAddressTranslator.TryTranslate4to6`](MapAddressTranslator.cs#L28) — nếu == CE IPv4 ⇒ **CE-MAP-IPv6 cố định** (tính sẵn lúc config); ngược lại ⇒ **DMR nhúng RFC 6052** (native host). SIIT lo checksum/TTL/traffic-class.

**6→4 (BR→CE)** [`Translate6to4`](MapTTranslator.cs#L40) → [`SiitTranslator.Translate6to4`](../TqkLibrary.VpnClient.Siit/SiitTranslator.cs#L242): [`TryTranslate6to4`](MapAddressTranslator.cs#L38) — nếu == CE-MAP-IPv6 ⇒ CE IPv4; nếu thuộc DMR prefix ⇒ **trích RFC 6052**; ngược lại ⇒ `false` ⇒ SIIT drop `AddressNotMapped`.

**Địa chỉ CE cố định**: tính 1 lần lúc config qua [`MapAddressMapping.DeriveMapIpv6`](MapAddressMapping.cs#L20) từ BMR + CE IPv4 + PSID (port/PSID là chuyện config, **không** per-packet) ⇒ translate chỉ cần địa chỉ.

## Trạng thái & ghi chú

- **Đã có (offline code + test XONG)**: BMR + thuật toán MAP RFC 7597 §5.2 (2 chiều: IPv4+PSID ↔ MAP IPv6; End-user prefix → CE), `MapAddressTranslator` (CE + DMR) sau `IAddressTranslator`, `MapTTranslator` (double translation qua SIIT). **29 test** (số CASE runtime, mỗi `[Fact]`/`[InlineData]` = 1): **vector RFC 7597 Appendix A Example 1/4/5** (địa chỉ + PSID khớp byte), round-trip IPv4+PSID↔MAP IPv6 nhiều sharing-ratio (256/16/1 + /16 rule), reject prefix sai / PSID vượt k; `MapAddressTranslator` CE 2 chiều + DMR 2 chiều + drop v6 lạ + `FromEndUserIpv6Prefix`; **double translation qua `SiitTranslator`** UDP/TCP CE→native round-trip **4→6→4 byte-exact** (địa chỉ + checksum đúng, TTL−2) + 4→6 kiểm src=CE-MAP-IPv6 / dst=DMR / checksum + drop source không map; validate `MapRule` sai ⇒ throw (EA<suffix, a+k>16, n+EA>64, family/range, explicit-PSID mâu thuẫn).
- **Phạm vi (cố tình gọn)**:
  - **CHỈ BMR + DMR** — 1 rule cho CE nội bộ + 1 DMR ra native. **KHÔNG** có **FMR (Forwarding Mapping Rule)** / multi-rule mesh CE↔CE (mọi non-CE đi qua DMR tới BR). Đủ cho MAP-T CE điển hình.
  - **Địa chỉ-only** (khớp seam `IAddressTranslator`): PSID/port-set là **config** (validate `a+k≤16`, PSID ∈ `[0, 2^k)`, CE trong Rule IPv4 prefix) — **KHÔNG** kiểm port từng gói (port-set/PSID không per-packet; đúng vì địa chỉ CE cố định). Không có logic chọn port nguồn theo PSID.
  - **CE-side** (client): `MapAddressTranslator` mô hình CE (1 IPv4+PSID). Không mô phỏng BR-side (BR = nhiều CE + FMR).
- **Chưa wire**: MAP-T **KHÔNG** cắm vào `VpnClientBuilder` (đúng thiết kế — engine nền, không line-ref drift). Không đụng facade/root README/driver khác.
- **Tái sử dụng tối đa**: 0 dòng dịch header/checksum/ICMP/fragment — tất cả là `SiitTranslator`. DMR = `Rfc6052AddressMapper` nguyên. Bit-copy = `AddressBits`. Chỉ code mới = thuật toán địa chỉ MAP.
- **Tham chiếu**: RFC 7599 + RFC 7597 §5/Appendix A + RFC 6052 + RFC 7915; nền [Siit](../TqkLibrary.VpnClient.Siit); roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.19 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9. Test: [`TqkLibrary.VpnClient.MapT.Tests`](../../tests/TqkLibrary.VpnClient.MapT.Tests).

> Build xanh cả `netstandard2.0` + `net8.0`. `record` (`MapRule`/`MapTConfig`) dùng được 2 TFM nhờ `TqkLibrary.CompilerServices` (ref ở [`src/Directory.Build.props`](../Directory.Build.props)). Không `#if` — chỉ dùng `Span`/`IPAddress`/bit-ops có sẵn cả 2 TFM.
