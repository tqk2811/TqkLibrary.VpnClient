# TqkLibrary.VpnClient.OpenConnect

Thư viện **protocol OpenConnect** (Cisco AnyConnect SSL-VPN; server opensource **ocserv**) thuần .NET — **không dùng PPP**, gói IP đi thẳng L3 trên kênh CSTP-over-TLS. Đây là project protocol-level cho driver **V.5** (data plane + driver thuộc V5.b; xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.5).

> **Trạng thái:** **V5.a (CSTP framing + HTTP auth/CONNECT codec) xong** (code + test offline). Đã có: (1) **CSTP framing 8-byte** — `CstpFraming` encode/decode header `STF 0x01 | length(2 BE) | type(1) | 0x00` cho **mọi** loại gói (DATA/DPD-REQ/DPD-RESP/DISCONNECT/KEEPALIVE/COMPRESSED/TERMINATE) + reassembler streaming qua mọi ranh đọc TLS — đây là hiện thực OpenConnect của seam **F.2 `IPacketEncapsulator`** (đối xứng SSTP 4-byte / OpenVPN 2-byte TCP); (2) **HTTP auth ocserv** — `OpenConnectAuthCodec` dựng/đọc XML `<config-auth>` (init → form → auth-reply), parse `<auth>` form ra `OpenConnectAuthForm` (username/password/select), nhận diện `id="success"`, trích cookie `webvpn=…` từ `Set-Cookie`; (3) **HTTP CONNECT** — `OpenConnectConnectCodec` dựng `CONNECT /CSCOSSLC/tunnel` (kèm cookie + MTU) và parse response header `X-CSTP-*` (Address/Address-IP6/Netmask/DNS/Split-Include/MTU/DPD/Keepalive/Rekey-Method/Rekey-Time) ra `OpenConnectTunnelInfo` → `TunnelConfig`, **reject** mọi status ≠200. **Pure codec, không I/O.** **Chưa** (V5.b): data plane CSTP-over-TLS + DTLS (F.3) + driver + DPD/keepalive/rekey + validate live (ocserv Docker, Q.1).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[OpenVpn](../TqkLibrary.VpnClient.OpenVpn)/[SoftEther](../TqkLibrary.VpnClient.SoftEther)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)): các khối giao thức thuần, **không** I/O socket — driver `Drivers.OpenConnect` (V5.b, chưa có) sẽ lắp lên byte-stream TLS thật (F.1) + DTLS (F.3) thành tunnel sống. CSTP gán địa chỉ **in-band** qua header CONNECT (`AddressAssignment.ConfigPush`) nên gói data ride L3 thẳng — **không PPP/IPCP** (khác SSTP/L2TP).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `TunnelConfig` (đích của X-CSTP-* CONNECT response) |
| Được dùng bởi | `Drivers.OpenConnect` (V.5b, **chưa có**) | driver lắp ráp control/data plane CSTP+DTLS |

> Không phụ thuộc [Crypto](../TqkLibrary.VpnClient.Crypto): V5.a là codec framing + HTTP text thuần (mã hóa do TLS/DTLS lo ở tầng transport V5.b). `System.Xml.Linq` (auth XML) có sẵn cả 2 TFM.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.OpenConnect/
├─ CstpFraming.cs                  Codec framing CSTP 8-byte (encode/decode + reassembler streaming) — seam F.2
├─ OpenConnectAuthCodec.cs         HTTP auth ocserv: build/parse XML config-auth (init/reply/success) + cookie
├─ OpenConnectConnectCodec.cs      HTTP CONNECT: build request + parse response X-CSTP-* → OpenConnectTunnelInfo
├─ Enums/
│  └─ CstpPacketType.cs            Loại payload CSTP (byte 7): DATA/DPD-REQ/DPD-RESP/DISCONNECT/KEEPALIVE/COMPRESSED/TERMINATE
└─ Models/
   ├─ CstpPacket.cs                Gói CSTP đã decode (Type + Payload; IsData cho DATA/COMPRESSED)
   ├─ OpenConnectTunnelInfo.cs     Cấu hình tunnel parse từ X-CSTP-* → ToTunnelConfig()
   └─ OpenConnectAuthForm.cs       Form auth ocserv (AuthId + danh sách OpenConnectAuthField) + SetValue
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `CstpPacketType` | enum loại payload CSTP (byte thứ 7): DATA(0x00)/DPD-REQ(0x03)/DPD-RESP(0x04)/DISCONNECT(0x05)/KEEPALIVE(0x07)/COMPRESSED(0x08)/TERMINATE(0x09) | [Enums/CstpPacketType.cs:9](Enums/CstpPacketType.cs#L9) |
| `CstpPacket` | model gói đã decode: `Type`/`Payload`; `IsData` cho DATA/COMPRESSED | [Models/CstpPacket.cs:10](Models/CstpPacket.cs#L10) |
| `CstpFraming` | framing 8-byte (seam F.2): static `Encode(type,payload)`/`Encode(packet)`/`Decode(frame)` + decoder instance `Append(chunk)`+`TryReadPacket(out)` ráp gói qua mọi ranh đọc; `ValidateHeader` reject magic sai | [CstpFraming.cs:21](CstpFraming.cs#L21) |
| `OpenConnectAuthForm` / `OpenConnectAuthField` | form auth: `AuthId`/`Message`/`Fields`; field `Name`/`Type`/`Label`/`Value`; `SetValue(name,value)` | [Models/OpenConnectAuthForm.cs:11](Models/OpenConnectAuthForm.cs#L11) |
| `OpenConnectAuthCodec` | static: `BuildInitRequest`/`BuildReplyRequest(form)` (XML config-auth) · `TryParseForm(body,out)` (form→fields, false khi success/không-form) · `IsSuccess(body)` · `ExtractCookie(setCookieLine,name)` | [OpenConnectAuthCodec.cs:16](OpenConnectAuthCodec.cs#L16) |
| `OpenConnectTunnelInfo` | config tunnel: `Address`/`AddressV6`/`Netmask`/`PrefixLengthV6`/`DnsServers`/`Routes`/`Mtu`/`Dpd`/`Keepalive`/`RekeyMethod`/`RekeyTime`/`SessionCookie`; `ToTunnelConfig()` | [Models/OpenConnectTunnelInfo.cs:16](Models/OpenConnectTunnelInfo.cs#L16) |
| `OpenConnectConnectCodec` | static: `BuildConnectRequest(host,cookie,mtu?)` (CONNECT /CSCOSSLC/tunnel) · `ParseConnectResponse(text)` → `OpenConnectTunnelInfo` (X-CSTP-*), non-200 ⇒ `UnauthorizedAccessException`, status hỏng ⇒ `FormatException` | [OpenConnectConnectCodec.cs:17](OpenConnectConnectCodec.cs#L17) |

## CSTP framing (8-byte header)

```
0x53 'S' | 0x54 'T' | 0x46 'F' | 0x01 | length(2, big-endian) | type(1) | 0x00
```

- **Magic** bytes 0–2 = `"STF"`, byte 3 cố định `0x01`, byte 7 cố định `0x00`.
- **length** (bytes 4–5, big-endian uint16) = độ dài payload sau header (≤65535).
- **type** (byte 6) = `CstpPacketType` (xem bảng enum). Gói control (DPD/keepalive/disconnect/terminate) payload rỗng; DATA/COMPRESSED mang datagram L3.
- **Reassembler** (`Append`+`TryReadPacket`): ráp gói nguyên qua **mọi ranh đọc TLS** (1 gói cắt nhiều read, hoặc nhiều gói gộp 1 read). Magic header hỏng ⇒ `FormatException` (stream desync). UDP/DTLS không cần length-prefix (1 datagram = 1 gói) — V5.b.

## HTTP auth (ocserv config-auth) + CONNECT

Luồng OpenConnect (re-implement từ behavior — **không copy GPL source**):

1. **Auth** ([`OpenConnectAuthCodec`](OpenConnectAuthCodec.cs)) — client POST XML `<config-auth type="init">` lên `/`; server trả `<auth id="…"><form>…</form></auth>`. `TryParseForm` tách input (`username`/`password`/`select`) ra `OpenConnectAuthForm`; client điền giá trị (`SetValue`) rồi `BuildReplyRequest` POST `<config-auth type="auth-reply">`. Lặp tới khi server trả `<auth id="success">` (`IsSuccess`) kèm `Set-Cookie: webvpn=…` (`ExtractCookie`).
2. **CONNECT** ([`OpenConnectConnectCodec`](OpenConnectConnectCodec.cs)) — client gửi `CONNECT /CSCOSSLC/tunnel HTTP/1.1` kèm `Cookie: webvpn=…` + tùy chọn CSTP; server đáp `HTTP/1.1 200 …` với header `X-CSTP-*`. `ParseConnectResponse` map sang [`OpenConnectTunnelInfo`](Models/OpenConnectTunnelInfo.cs) → [`TunnelConfig`](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/TunnelConfig.cs) (netmask→prefix, `X-CSTP-MTU` thắng `X-CSTP-Base-MTU`, DNS/Split-Include nhiều dòng). Status ≠200 ⇒ `UnauthorizedAccessException` (gateway từ chối).

Sau 200 OK, cùng byte-stream TLS chuyển sang CSTP framing (data plane V5.b).

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| draft-mavrogiannopoulos-openconnect-04 | toàn bộ | https://www.ietf.org/archive/id/draft-mavrogiannopoulos-openconnect-04.html |
| OpenConnect / ocserv (behavior) | CSTP + auth | https://www.infradead.org/openconnect/ ; https://gitlab.com/openconnect/ocserv |
| CSTP 8-byte framing | `CstpFraming` | magic `STF 0x01`, length BE, type byte; seam F.2 `IPacketEncapsulator` |
| HTTP CONNECT + X-CSTP-* | `OpenConnectConnectCodec` | `/CSCOSSLC/tunnel`; Address/Netmask/DNS/Split-Include/MTU/DPD/Keepalive/Rekey-Method/Rekey-Time |
| ocserv config-auth (XML) | `OpenConnectAuthCodec` | `<config-auth>` init/auth-reply; `<auth><form><input/></form></auth>`; cookie `webvpn=` |

## Trạng thái & ghi chú

- **Thuần client**, thuần protocol: không I/O, không server. Đọc spec/behavior từ draft IETF + OpenConnect/ocserv (**không copy GPL source**).
- Build xanh cả `netstandard2.0` + `net8.0`. `CstpFraming` dùng `System.Buffers.Binary.BinaryPrimitives` (cả 2 TFM qua `System.Memory`) + `Span`/`stackalloc` trong method non-async (an toàn C# 12); reassembly dùng `List<byte>` (zero-alloc là việc Q.4). Auth codec dùng `System.Xml.Linq` (`XElement.Parse`, có cả 2 TFM). CONNECT codec là text/ASCII thuần.
- Lộ trình V.5 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.5.
