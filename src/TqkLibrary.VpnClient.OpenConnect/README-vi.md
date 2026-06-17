# TqkLibrary.VpnClient.OpenConnect

Thư viện **protocol OpenConnect** (Cisco AnyConnect SSL-VPN; server opensource **ocserv**) thuần .NET — **không dùng PPP**, gói IP đi thẳng L3 trên kênh CSTP-over-TLS. Đây là project protocol-level cho driver **V.5**; data plane + driver lắp ráp ở [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect) (V5.b; xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.5).

> **Trạng thái:** **V5.a (CSTP framing + HTTP auth/CONNECT codec) + V5.b (data plane CSTP-over-TLS + DPD/keepalive) + V5.c (data plane CSTP-over-DTLS song song) xong** (code + test offline). Đã có:
> **V5.a (pure codec):** (1) **CSTP framing 8-byte** — `CstpFraming` encode/decode header `STF 0x01 | length(2 BE) | type(1) | 0x00` cho **mọi** loại gói (DATA/DPD-REQ/DPD-RESP/DISCONNECT/KEEPALIVE/COMPRESSED/TERMINATE) + reassembler streaming qua mọi ranh đọc TLS — đây là hiện thực OpenConnect của seam **F.2 `IPacketEncapsulator`** (đối xứng SSTP 4-byte / OpenVPN 2-byte TCP); (2) **HTTP auth ocserv** — `OpenConnectAuthCodec` dựng/đọc XML `<config-auth>` (init → form → auth-reply), parse `<auth>` form ra `OpenConnectAuthForm` (username/password/select), nhận diện `id="success"`, trích cookie `webvpn=…` từ `Set-Cookie`; (3) **HTTP CONNECT** — `OpenConnectConnectCodec` dựng `CONNECT /CSCOSSLC/tunnel` (kèm cookie + MTU) và parse response header `X-CSTP-*` (Address/Address-IP6/Netmask/DNS/Split-Include/MTU/DPD/Keepalive/Rekey-Method/Rekey-Time) ra `OpenConnectTunnelInfo` → `TunnelConfig`, **reject** mọi status ≠200.
> **V5.b (data plane, ráp lên `IByteStreamTransport` F.1):** (4) **`CstpChannel`** — `IPacketChannel` CSTP-over-TLS bọc byte-stream + `CstpFraming`: `WriteIpPacketAsync` đóng khung DATA, `RunReceiveLoopAsync` đọc/demux (DATA→`InboundIpPacket`, DPD-REQ→event reply, DISCONNECT/TERMINATE→`PeerClosed`) + event `PacketSent`/`PacketReceived` bơm timer; (5) **`OpenConnectHttpTransactor`** — chạy auth POST + CONNECT **byte-exact** trên byte-stream (đọc header tới CRLFCRLF rồi đúng `Content-Length` body — **không nuốt** gói CSTP đầu sau CONNECT 200) ra `OpenConnectHttpResponse`; (6) **`CstpDpdState`** — DPD/keepalive **clock-inject** (`ShouldSendDpd`/`IsPeerDead` theo `X-CSTP-DPD` dead-window 2× + `ShouldSendKeepalive` theo `X-CSTP-Keepalive`), cùng shape `OpenVpnKeepalive`/`WireGuardPeerState`.
> **V5.c (data plane CSTP-over-DTLS song song, ráp lên `IDatagramTransport`):** (7) **`CstpDatagramFraming`** — framing CSTP cho DTLS: header **1-byte type** (không STF magic/length, 1 datagram = 1 gói), `Encode`/`Decode`; (8) **`CstpDatagramChannel`** — `IPacketChannel` CSTP-over-DTLS bọc `IDatagramTransport` + `CstpDatagramFraming`, raise **cùng event** với `CstpChannel` (DPD/peer-close/liveness) ⇒ driver dùng chung `CstpDpdState`; (9) `OpenConnectConnectCodec` parse thêm **`X-DTLS-*`** (Session-ID/CipherSuite/Port/DPD/Keepalive) + `OpenConnectTunnelInfo.HasDtls` + advertise DTLS trong CONNECT request. Driver [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect) bọc `DtlsDatagramTransport` (F.3) + fallback TLS. **Chưa**: rekey `X-CSTP-Rekey-Method` (đã parse, chưa wire timer), tương quan session-id qua DTLS ClientHello thật + validate live (ocserv Docker, Q.1).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[OpenVpn](../TqkLibrary.VpnClient.OpenVpn)/[SoftEther](../TqkLibrary.VpnClient.SoftEther)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)): các khối giao thức thuần, **không** I/O socket — driver [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect) (V5.b) lắp các khối này lên byte-stream TLS thật (F.1) thành tunnel sống; DTLS (F.3) là V5.c. CSTP gán địa chỉ **in-band** qua header CONNECT (`AddressAssignment.ConfigPush`) nên gói data ride L3 thẳng — **không PPP/IPCP** (khác SSTP/L2TP).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `TunnelConfig` (đích của X-CSTP-* CONNECT response), `IByteStreamTransport`/`IPacketChannel`/`LinkMedium` (V5.b data plane), `IDatagramTransport` (V5.c data plane DTLS) |
| Được dùng bởi | [Drivers.OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) | driver lắp ráp control/data plane CSTP-over-TLS |

> Không phụ thuộc [Crypto](../TqkLibrary.VpnClient.Crypto): mã hóa do TLS/DTLS lo ở tầng transport. `System.Xml.Linq` (auth XML) + `System.Threading.Channels` (test) có sẵn cả 2 TFM.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.OpenConnect/
├─ CstpFraming.cs                  Codec framing CSTP 8-byte (encode/decode + reassembler streaming) — seam F.2 (V5.a)
├─ OpenConnectAuthCodec.cs         HTTP auth ocserv: build/parse XML config-auth (init/reply/success) + cookie (V5.a)
├─ OpenConnectConnectCodec.cs      HTTP CONNECT: build request + parse response X-CSTP-* → OpenConnectTunnelInfo (V5.a)
├─ CstpChannel.cs                  IPacketChannel CSTP-over-TLS bọc IByteStreamTransport + CstpFraming (V5.b)
├─ CstpDatagramFraming.cs          Codec framing CSTP cho DTLS: 1-byte type (không magic/length, 1 datagram = 1 gói) (V5.c)
├─ CstpDatagramChannel.cs          IPacketChannel CSTP-over-DTLS bọc IDatagramTransport + CstpDatagramFraming (V5.c)
├─ OpenConnectHttpTransactor.cs    Chạy auth POST + CONNECT byte-exact trên byte-stream → OpenConnectHttpResponse (V5.b)
├─ CstpDpdState.cs                 DPD/keepalive clock-inject theo X-CSTP-DPD/X-CSTP-Keepalive (V5.b, dùng chung TLS+DTLS)
├─ Enums/
│  └─ CstpPacketType.cs            Loại payload CSTP (byte 7): DATA/DPD-REQ/DPD-RESP/DISCONNECT/KEEPALIVE/COMPRESSED/TERMINATE
└─ Models/
   ├─ CstpPacket.cs                Gói CSTP đã decode (Type + Payload; IsData cho DATA/COMPRESSED)
   ├─ OpenConnectTunnelInfo.cs     Cấu hình tunnel parse từ X-CSTP-* → ToTunnelConfig()
   ├─ OpenConnectAuthForm.cs       Form auth ocserv (AuthId + danh sách OpenConnectAuthField) + SetValue
   └─ OpenConnectHttpResponse.cs   Response HTTP đã parse (status/headers/body) cho auth/CONNECT (V5.b)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `CstpPacketType` | enum loại payload CSTP (byte thứ 7): DATA(0x00)/DPD-REQ(0x03)/DPD-RESP(0x04)/DISCONNECT(0x05)/KEEPALIVE(0x07)/COMPRESSED(0x08)/TERMINATE(0x09) | [Enums/CstpPacketType.cs:9](Enums/CstpPacketType.cs#L9) |
| `CstpPacket` | model gói đã decode: `Type`/`Payload`; `IsData` cho DATA/COMPRESSED | [Models/CstpPacket.cs:10](Models/CstpPacket.cs#L10) |
| `CstpFraming` | framing 8-byte (seam F.2): static `Encode(type,payload)`/`Encode(packet)`/`Decode(frame)` + decoder instance `Append(chunk)`+`TryReadPacket(out)` ráp gói qua mọi ranh đọc; `ValidateHeader` reject magic sai | [CstpFraming.cs:21](CstpFraming.cs#L21) |
| `OpenConnectAuthForm` / `OpenConnectAuthField` | form auth: `AuthId`/`Message`/`Fields`; field `Name`/`Type`/`Label`/`Value`; `SetValue(name,value)` | [Models/OpenConnectAuthForm.cs:11](Models/OpenConnectAuthForm.cs#L11) |
| `OpenConnectAuthCodec` | static: `BuildInitRequest`/`BuildReplyRequest(form)` (XML config-auth) · `TryParseForm(body,out)` (form→fields, false khi success/không-form) · `IsSuccess(body)` · `ExtractCookie(setCookieLine,name)` | [OpenConnectAuthCodec.cs:16](OpenConnectAuthCodec.cs#L16) |
| `OpenConnectTunnelInfo` | config tunnel: `Address`/`AddressV6`/`Netmask`/`PrefixLengthV6`/`DnsServers`/`Routes`/`Mtu`/`Dpd`/`Keepalive`/`RekeyMethod`/`RekeyTime`/`SessionCookie`; **DTLS** `DtlsSessionId`/`DtlsCipherSuite`/`DtlsPort`/`DtlsKeepalive`/`DtlsDpd`/`HasDtls` (V5.c); `ToTunnelConfig()` | [Models/OpenConnectTunnelInfo.cs:16](Models/OpenConnectTunnelInfo.cs#L16) |
| `OpenConnectConnectCodec` | static: `BuildConnectRequest(host,cookie,mtu?,requestDtls?,dtlsMasterSecretHex?)` (CONNECT /CSCOSSLC/tunnel + advertise `X-DTLS-*` khi `requestDtls`) · `ParseConnectResponse(text)` → `OpenConnectTunnelInfo` (X-CSTP-* + X-DTLS-*), non-200 ⇒ `UnauthorizedAccessException`, status hỏng ⇒ `FormatException` | [OpenConnectConnectCodec.cs:17](OpenConnectConnectCodec.cs#L17) |
| `CstpChannel` *(V5.b)* | `IPacketChannel` CSTP-over-TLS: `WriteIpPacketAsync` (đóng khung DATA) · `SendDpdRequest/Response`/`SendKeepalive`/`SendDisconnect` · `RunReceiveLoopAsync` (đọc→demux); event `DpdRequestReceived`/`PeerClosed`/`PacketReceived`/`PacketSent`; `Medium=Ip`/`MaxHeaderLength=0` | [CstpChannel.cs:24](CstpChannel.cs#L24) |
| `CstpDatagramFraming` *(V5.c)* | static: `Encode(type,payload)`/`Decode(datagram)` — header **1-byte type** cho DTLS (không STF magic/length, 1 datagram = 1 gói); `Decode` reject datagram rỗng ⇒ `FormatException` | [CstpDatagramFraming.cs:13](CstpDatagramFraming.cs#L13) |
| `CstpDatagramChannel` *(V5.c)* | `IPacketChannel` CSTP-over-DTLS bọc `IDatagramTransport` + `CstpDatagramFraming`: cùng API/event như `CstpChannel`; `RunReceiveLoopAsync` drop datagram hỏng (UDP unreliable, không desync); `Medium=Ip`/`MaxHeaderLength=0` | [CstpDatagramChannel.cs:24](CstpDatagramChannel.cs#L24) |
| `OpenConnectHttpTransactor` *(V5.b)* | `PostAsync(path,xml,cookie?)` (auth POST) · `ConnectTunnelAsync(requestText)` (CONNECT) — đọc **byte-exact** (header tới CRLFCRLF + đúng `Content-Length`, không nuốt gói CSTP đầu) → `OpenConnectHttpResponse` | [OpenConnectHttpTransactor.cs:18](OpenConnectHttpTransactor.cs#L18) |
| `OpenConnectHttpResponse` *(V5.b)* | response đã parse: `StatusCode`/`Reason`/`Headers`/`RawHeaderText`/`Body` + `GetHeader`/`GetHeaders(name)` | [Models/OpenConnectHttpResponse.cs:11](Models/OpenConnectHttpResponse.cs#L11) |
| `CstpDpdState` *(V5.b)* | DPD/keepalive **clock-inject**: `OnDataSent`/`OnDataReceived`/`OnDpdSent`; `ShouldSendDpd`/`IsPeerDead` (X-CSTP-DPD, dead-window ×2) · `ShouldSendKeepalive` (X-CSTP-Keepalive) | [CstpDpdState.cs:17](CstpDpdState.cs#L17) |

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

Sau 200 OK, cùng byte-stream TLS chuyển sang CSTP framing — đây là **data plane V5.b**: [`CstpChannel`](CstpChannel.cs) cắm vào byte-stream để gửi/nhận gói IP qua DATA frame, demux DPD/keepalive/disconnect; [`OpenConnectHttpTransactor`](OpenConnectHttpTransactor.cs) lo phần auth POST + CONNECT byte-exact để **không nuốt** gói CSTP đầu tiên ngay sau CONNECT 200; [`CstpDpdState`](CstpDpdState.cs) đếm nhịp DPD/keepalive. Driver lắp ráp ở [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect).

## Data plane CSTP-over-TLS (V5.b)

1. **`OpenConnectHttpTransactor`** chạy auth POST (`PostAsync`) + CONNECT (`ConnectTunnelAsync`) trên cùng `IByteStreamTransport`. Reader **byte-exact**: đọc từng byte tới `\r\n\r\n` (kết thúc header) rồi đọc **đúng** `Content-Length` body — auth body parse được, còn CONNECT 200 không body ⇒ stream dừng ngay đầu gói CSTP, không đọc lố.
2. **`CstpChannel`** (`IPacketChannel`) bọc byte-stream + `CstpFraming`: `WriteIpPacketAsync` → khung DATA; `RunReceiveLoopAsync` đọc stream → `Append`/`TryReadPacket` → demux: DATA/COMPRESSED→`InboundIpPacket` (COMPRESSED drop, chưa giải nén — V5.c), DPD-REQ→event `DpdRequestReceived` (driver trả DPD-RESP), DISCONNECT/TERMINATE/EOF→`PeerClosed`. Event `PacketSent`/`PacketReceived` báo cho driver bơm timer.
3. **`CstpDpdState`** (clock-inject): `ShouldSendDpd` (im `X-CSTP-DPD` giây → gửi DPD-REQ), `IsPeerDead` (im `2×X-CSTP-DPD` → coi peer chết), `ShouldSendKeepalive` (không gửi gì `X-CSTP-Keepalive` giây → gửi keepalive). Mỗi vế tắt khi interval = 0.

## Data plane CSTP-over-DTLS (V5.c)

Song song đường TLS, khi server đẩy `X-DTLS-*` driver có thể mở đường DTLS (mã hóa do **DTLS 1.2** lo ở transport [`Transport.Dtls`](../TqkLibrary.VpnClient.Transport.Dtls) F.3). Khác đường TLS ở **framing**:

```
TLS : [ STF | 0x01 | length(2 BE) | type | 0x00 ] + payload   (CstpFraming, 8-byte, stream cần length)
DTLS: [ type ] + payload                                        (CstpDatagramFraming, 1-byte, 1 datagram = 1 gói)
```

1. **`CstpDatagramFraming`** — `Encode(type,payload)` = `[type byte] ‖ payload`; `Decode(datagram)` tách type byte + phần còn lại làm payload. Không magic, không length: DTLS giữ ranh giới datagram nên 1 datagram = đúng 1 gói CSTP (không cần reassembler như TLS). Datagram rỗng ⇒ `FormatException`.
2. **`CstpDatagramChannel`** (`IPacketChannel`) bọc `IDatagramTransport` + `CstpDatagramFraming`: `WriteIpPacketAsync` → 1 datagram DATA; `RunReceiveLoopAsync` nhận datagram → `Decode` → demux **giống** `CstpChannel` (DATA→`InboundIpPacket`, DPD-REQ→event reply, DISCONNECT/TERMINATE→`PeerClosed`), raise **cùng event** (`DpdRequestReceived`/`PeerClosed`/`PacketReceived`/`PacketSent`). Datagram hỏng/rỗng **drop** (UDP unreliable — không desync vì không có stream để mất). Vì event giống hệt, driver bơm **chung một** `CstpDpdState` cho cả hai kênh.
3. Header CONNECT mang `X-DTLS-Session-ID` (cookie tương quan UDP/DTLS↔CSTP), `X-DTLS-Port`, `X-DTLS-CipherSuite`, `X-DTLS-DPD`/`X-DTLS-Keepalive`. Driver [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect) mở UDP → `DtlsDatagramTransport` → handshake → swap data plane sang `CstpDatagramChannel`; **fallback** giữ `CstpChannel` (TLS) khi DTLS không-offer/fail.

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| draft-mavrogiannopoulos-openconnect-04 | toàn bộ | https://www.ietf.org/archive/id/draft-mavrogiannopoulos-openconnect-04.html |
| OpenConnect / ocserv (behavior) | CSTP + auth | https://www.infradead.org/openconnect/ ; https://gitlab.com/openconnect/ocserv |
| CSTP 8-byte framing (TLS) | `CstpFraming` | magic `STF 0x01`, length BE, type byte; seam F.2 `IPacketEncapsulator` |
| CSTP 1-byte framing (DTLS) | `CstpDatagramFraming` | chỉ type byte, 1 datagram = 1 gói (V5.c) |
| HTTP CONNECT + X-CSTP-*/X-DTLS-* | `OpenConnectConnectCodec` | `/CSCOSSLC/tunnel`; X-CSTP Address/Netmask/DNS/Split-Include/MTU/DPD/Keepalive/Rekey-* + X-DTLS Session-ID/CipherSuite/Port/DPD/Keepalive |
| ocserv config-auth (XML) | `OpenConnectAuthCodec` | `<config-auth>` init/auth-reply; `<auth><form><input/></form></auth>`; cookie `webvpn=` |

## Trạng thái & ghi chú

- **Thuần client**, thuần protocol: V5.a là codec không I/O; V5.b (`CstpChannel`/`OpenConnectHttpTransactor`) + V5.c (`CstpDatagramChannel`) chạy I/O **qua seam `IByteStreamTransport`/`IDatagramTransport`** (socket thật do `Drivers.OpenConnect` cung cấp), không tự mở socket. Đọc spec/behavior từ draft IETF + OpenConnect/ocserv (**không copy GPL source**).
- **TLS + DTLS**: mã hóa do TLS/DTLS lo ở tầng transport (DTLS qua `Transport.Dtls` F.3, V5.c). **rekey `X-CSTP-Rekey-Method`** đã parse vào `OpenConnectTunnelInfo` nhưng **chưa wire** timer rekey.
- Build xanh cả `netstandard2.0` + `net8.0`. `CstpFraming` dùng `System.Buffers.Binary.BinaryPrimitives` (cả 2 TFM qua `System.Memory`) + `Span`/`stackalloc` trong method non-async (an toàn C# 12); reassembly dùng `List<byte>` (zero-alloc là việc Q.4). Auth codec dùng `System.Xml.Linq` (`XElement.Parse`, có cả 2 TFM). CONNECT codec là text/ASCII thuần. `CstpDpdState` clock-inject `Interlocked` (đối xứng `OpenVpnKeepalive`).
- Lộ trình V.5 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.5; data plane/driver as-built ở [`Drivers.OpenConnect`](../TqkLibrary.VpnClient.Drivers.OpenConnect/README-vi.md).
