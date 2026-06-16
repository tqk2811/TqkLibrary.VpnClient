# TqkLibrary.VpnClient.SoftEther

Thư viện **protocol SoftEther SSL-VPN** thuần .NET. Gồm **PACK codec** (V4.a — định dạng nhị phân typed key-value cho **mọi** trao đổi control/RPC) và **control handshake** (V4.b — watermark POST + hello/login + auth SHA-0). Re-implement **từ spec/behavior** (xem [`.docs/07`](../../.docs/07-softether.md)) — **KHÔNG copy source GPL** (`Pack.c`/`Pack.h`/`Watermark.c`/`Protocol.c`). Đây là driver **V.4** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.4); data plane Ethernet-over-TLS + driver L2 (V4.c) sẽ thêm sau.

> **Trạng thái:**
> - **V4.a (PACK codec) xong** (code + test offline). PACK = **list `PackElement`**; mỗi element có **name** (≤63 ký tự), một **`PackValueType`** (int/data/str/unistr/int64), và **mảng `PackValue`** (≥1) cùng kiểu. Encode/decode **big-endian** đúng wire SoftEther: `uint32(num_elements)` → mỗi element `BufStr(name) · uint32(type) · uint32(num_value) · value[]`. Codec **thuần, không I/O**. Helper `Set*`/`Get*` theo tên (single + array), tra cứu **case-insensitive**, chống input lỗi ⇒ `FormatException`.
> - **V4.b (watermark POST + hello/login handshake + auth SHA-0) xong** (code + test offline). **Tách phần codec/state thuần khỏi I/O**: `SoftEtherWatermark` dựng byte POST watermark; `SoftEtherAuth` tính `secure_password` SHA-0 (tái dùng [`Sha0`](../TqkLibrary.VpnClient.Crypto/Sha0.cs) F.5a); `SoftEtherHandshake` có **3 hàm thuần** `ParseHello`/`BuildLoginPack`/`ParseWelcome` (test trực tiếp) + driver `RunAsync` lắp chúng lên [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) (F.1/TLS). PACK đi trong thân HTTP qua `SoftEtherHttpPackCodec` (`uint32 len` + PACK bytes). Test chạy **offline** với server giả lập in-memory.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[OpenVpn](../TqkLibrary.VpnClient.OpenVpn)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)): khối giao thức thuần, **không** I/O socket trực tiếp (chỉ phụ thuộc seam `IByteStreamTransport`). PACK là *framing nền* — mọi message SoftEther được dựng/đọc qua codec này; handshake codec dựng/đọc hello/login/welcome. Driver `Drivers.SoftEther` (V4.c, chưa có) sẽ lắp `SoftEtherHandshake` lên TLS transport thật (F.1) + L2 fabric DHCP/ARP ([Ethernet](../TqkLibrary.VpnClient.Ethernet)).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [`Abstractions`](../TqkLibrary.VpnClient.Abstractions) | seam transport [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) (F.1) mà `SoftEtherHandshake.RunAsync` ghi/đọc |
| Dùng | [`Crypto`](../TqkLibrary.VpnClient.Crypto) | `SoftEtherAuth` nhận [`IHashAlgo`](../TqkLibrary.VpnClient.Crypto/Interfaces/IHashAlgo.cs) (SHA-0 [`Sha0`](../TqkLibrary.VpnClient.Crypto/Sha0.cs), F.5a) để tính `secure_password` |
| Được dùng bởi (tương lai) | `Drivers.SoftEther` (V4.c) | chạy `SoftEtherHandshake.RunAsync` trên TLS thật → data plane Ethernet-over-TLS |

> PACK codec (V4.a) vẫn **thuần BCL** (`System.Buffers.Binary`/`System.Text`), không phụ thuộc 2 project trên; chỉ phần handshake (V4.b) mới dùng tới.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.SoftEther/
├─ Pack/                       — V4.a PACK codec
│  ├─ Pack.cs                 PACK = list element + codec top-level (ToBytes/Parse) + helper Set*/Get* theo tên (single + array) + tra cứu case-insensitive
│  ├─ PackElement.cs          Một element {name ≤63, type, mảng value ≥1}; codec 1 element (BufStr name · type · num_value · value[])
│  ├─ PackValue.cs            Một value typed (Int/Int64/Data/Str/UniStr); factory From* + codec 1 value theo type
│  ├─ PackConstants.cs        Giới hạn wire 64-bit (name 63, element/value 262144, value-size 384MB) để chặn alloc từ input xấu
│  ├─ PackBufferWriter.cs     Sink byte growable: WriteUInt32/64 big-endian + WriteBytes + WriteBufStr (prefix len+1, KHÔNG ghi NUL)
│  ├─ PackBufferReader.cs     Cursor forward-only: ReadUInt32/64 big-endian + ReadBytes + ReadBufStr (prefix len+1) + chống underrun
│  ├─ SoftEtherAnsi.cs        Codec STR "ANSI" = Latin-1 8-bit thủ công (đồng nhất 2 TFM; Encoding.Latin1 chỉ có từ net5)
│  └─ Enums/
│     └─ PackValueType.cs     enum tag value: Int=0/Data=1/Str=2/UniStr=3/Int64=4 (số cố định theo spec)
├─ SoftEtherProtocol.cs        — V4.b hằng: HTTP target + tên element hello/login/welcome + size cố định
├─ SoftEtherWatermark.cs       — V4.b builder POST /vpnsvc/connect.cgi watermark (signature placeholder + padding + Matches)
├─ SoftEtherAuth.cs            — V4.b codec auth: secure_password = SHA0(SHA0(pw‖UPPER(user))‖random) qua IHashAlgo
├─ SoftEtherHttpPackCodec.cs   — V4.b framing PACK trong thân HTTP (uint32 len + PACK; build POST/200 + parse body)
├─ SoftEtherHandshake.cs       — V4.b state machine: ParseHello/BuildLoginPack/ParseWelcome (thuần) + RunAsync(IByteStreamTransport)
├─ SoftEtherProtocolException.cs — V4.b lỗi protocol (hello hỏng / login bị từ chối, mang ErrorCode)
├─ Enums/
│  └─ SoftEtherAuthType.cs     — V4.b authtype: Anonymous=0/Password=1/PlainPassword=2/Certificate=3
└─ Models/
   ├─ SoftEtherSessionParams.cs — V4.b max_connection/use_encrypt/use_compress/half_connection/unique_id
   ├─ SoftEtherLoginRequest.cs  — V4.b input login: hub/user/authtype/password + session params
   ├─ SoftEtherHelloInfo.cs     — V4.b hello đã parse: hello/version/build/random(20B)
   └─ SoftEtherWelcomeInfo.cs   — V4.b welcome đã parse: session_key(20B) + session_key_32
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `Pack` | PACK = list `PackElement`; `Add`/`GetElement`/`Contains` + helper `SetInt/SetInt64/SetData/SetStr/SetUniStr/SetBool` (single) và `Set*Array` (đa-value) + `GetInt/GetInt64/GetData/GetStr/GetUniStr/GetBool` (theo tên + index, fallback) + codec `ToBytes()`/`Parse()` | [Pack/Pack.cs:17](Pack/Pack.cs#L17) |
| `PackElement` | element {`Name` ≤63, `Type`, `Values` ≥1}; validate name/count ở ctor; codec `Write`/`Read` 1 element | [Pack/PackElement.cs:12](Pack/PackElement.cs#L12) |
| `PackValue` | một value typed (`IntValue`/`Int64Value`/`Data`/`StringValue`); factory `FromInt/FromInt64/FromData/FromString`; codec `Write`/`Read` 1 value theo `PackValueType` | [Pack/PackValue.cs:11](Pack/PackValue.cs#L11) |
| `PackValueType` | enum tag wire (uint): `Int=0`/`Data=1`/`Str=2`/`UniStr=3`/`Int64=4` | [Pack/Enums/PackValueType.cs:9](Pack/Enums/PackValueType.cs#L9) |
| `PackConstants` | giới hạn wire 64-bit: `MaxElementNameLength`(63)/`MaxElementCount`/`MaxValueCount`(262144)/`MaxValueSize`(384MB) | [Pack/PackConstants.cs:8](Pack/PackConstants.cs#L8) |
| `PackBufferWriter` | sink byte growable: `WriteUInt32`/`WriteUInt64` big-endian, `WriteBytes`, `WriteBufStr` (prefix len+1) | [Pack/PackBufferWriter.cs:11](Pack/PackBufferWriter.cs#L11) |
| `PackBufferReader` | `ref struct` cursor forward-only: `ReadUInt32`/`ReadUInt64` big-endian, `ReadBytes`, `ReadBufStr`, chống underrun | [Pack/PackBufferReader.cs:12](Pack/PackBufferReader.cs#L12) |
| `SoftEtherAnsi` | codec STR "ANSI" = Latin-1 8-bit (`GetBytes`/`GetString`), đồng nhất 2 TFM | [Pack/SoftEtherAnsi.cs:10](Pack/SoftEtherAnsi.cs#L10) |
| `SoftEtherProtocol` | hằng V4.b: HTTP target (`/vpnsvc/connect.cgi`/`vpn.cgi`) + tên element hello/login/welcome + `RandomSize`(20) | [SoftEtherProtocol.cs:9](SoftEtherProtocol.cs#L9) |
| `SoftEtherWatermark` | builder POST watermark: `BuildRequest(host)` (POST line + headers + signature‖padding), `Matches(body)`, `WithSignature`/`WithRandomPadding` | [SoftEtherWatermark.cs:23](SoftEtherWatermark.cs#L23) |
| `SoftEtherAuth` | codec auth (nhận `IHashAlgo`=SHA-0): `HashPassword`/`SecureFromHashedPassword`/`ComputeSecurePassword` (password gốc **không** qua wire) | [SoftEtherAuth.cs:21](SoftEtherAuth.cs#L21) |
| `SoftEtherHttpPackCodec` | framing PACK trong thân HTTP: `FrameBody`/`ParseBody` (uint32 len + PACK) + `BuildPostRequest`/`BuildOkResponse` | [SoftEtherHttpPackCodec.cs:15](SoftEtherHttpPackCodec.cs#L15) |
| `SoftEtherHandshake` | state machine: `ParseHello`/`BuildLoginPack`/`ParseWelcome` (thuần) + `RunAsync(IByteStreamTransport)` + reader HTTP nội bộ | [SoftEtherHandshake.cs:24](SoftEtherHandshake.cs#L24) |
| `SoftEtherProtocolException` | lỗi protocol (hello hỏng / login từ chối), mang `ErrorCode` từ field `error` của server | [SoftEtherProtocolException.cs:9](SoftEtherProtocolException.cs#L9) |
| `SoftEtherAuthType` | enum authtype: `Anonymous=0`/`Password=1`/`PlainPassword=2`/`Certificate=3` | [Enums/SoftEtherAuthType.cs:10](Enums/SoftEtherAuthType.cs#L10) |
| `SoftEtherSessionParams` | record session: `MaxConnection`/`UseEncrypt`/`UseCompress`/`HalfConnection`/`UniqueId` | [Models/SoftEtherSessionParams.cs:11](Models/SoftEtherSessionParams.cs#L11) |
| `SoftEtherLoginRequest` | record input login: `HubName`/`UserName`/`AuthType`/`Password`/`Session` | [Models/SoftEtherLoginRequest.cs:14](Models/SoftEtherLoginRequest.cs#L14) |
| `SoftEtherHelloInfo` | record hello đã parse: `Hello`/`Version`/`Build`/`Random`(20B) | [Models/SoftEtherHelloInfo.cs:10](Models/SoftEtherHelloInfo.cs#L10) |
| `SoftEtherWelcomeInfo` | record welcome đã parse: `SessionKey`(20B)/`SessionKey32` | [Models/SoftEtherWelcomeInfo.cs:10](Models/SoftEtherWelcomeInfo.cs#L10) |

## Wire format (PACK)

Mọi số nguyên **big-endian**. Tên element là **BufStr** (prefix = `len + 1`, sau đó `len` byte thô — **không** NUL trên wire; `+1` là quirk SoftEther). Các kiểu value:

```
PACK:
  uint32(num_elements) · element[num_elements]

ELEMENT:
  BufStr(name)          = uint32(name_len + 1) · name_bytes        (name_len byte, KHÔNG NUL)
  uint32(type)          = PackValueType (0..4)
  uint32(num_value)
  value[num_value]                                                 (mọi value cùng type)

VALUE theo type:
  INT    (0): uint32                                               (big-endian 4 byte)
  DATA   (1): uint32(len) · data_bytes                             (len byte thô)
  STR    (2): uint32(len) · ansi_bytes                            (len = đúng byte length, KHÔNG +1; Latin-1)
  UNISTR (3): uint32(utf8_len + 1) · utf8_bytes · NUL              (utf8_len byte + 1 byte NUL trên wire)
  INT64  (4): uint64                                               (big-endian 8 byte)
```

- **Bất đối xứng then chốt**: name BufStr (prefix `+1`, **không** ghi NUL) vs **UNISTR** value (prefix `+1`, **có** ghi 1 NUL theo sau). `STR` thì prefix = đúng byte-length, **không** `+1`. Đây là chỗ dễ sai nhất khi byte-exact — test [`PackCodecTests`](../../tests/TqkLibrary.VpnClient.SoftEther.Tests/PackCodecTests.cs) khẳng định cả 3 layout.
- **STR là "ANSI"** (8-bit/Latin-1, dùng cho hub/user name ASCII), **UNISTR là Unicode** lưu UTF-8 — đúng phân biệt `VALUE_STR`/`VALUE_UNISTR` của SoftEther.
- **bool** map về INT 1/0 (quy ước SoftEther) qua `SetBool`/`GetBool`.

## Luồng codec

- **Encode** ([`Pack.ToBytes`](Pack/Pack.cs#L147)): ghi `num_elements` → mỗi [`PackElement.Write`](Pack/PackElement.cs#L43) ghi BufStr(name)/type/num_value rồi [`PackValue.Write`](Pack/PackValue.cs#L40) từng value theo type.
- **Decode** ([`Pack.Parse`](Pack/Pack.cs#L160)): đọc `num_elements` (vượt `MaxElementCount` ⇒ `FormatException`) → mỗi [`PackElement.Read`](Pack/PackElement.cs#L53) đọc name/type/count rồi [`PackValue.Read`](Pack/PackValue.cs#L72) từng value; trùng tên (case-insensitive) ⇒ `FormatException`. Mọi `Read*` chặn **underrun** ([`PackBufferReader.Take`](Pack/PackBufferReader.cs#L30)) và **size vượt giới hạn** trước khi cấp phát.
- **Tra cứu** ([`Pack.GetValue`](Pack/Pack.cs#L136) qua các `Get*`): theo tên (case-insensitive) + đúng type + index hợp lệ; sai/thiếu ⇒ fallback (`0`/null/`false`) thay vì ném — tiện cho consumer đọc field tùy chọn.

## Luồng handshake (V4.b)

`SoftEtherHandshake.RunAsync` trên một [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) đã connect + TLS (F.1):

1. **Watermark POST** ([`SoftEtherWatermark.BuildRequest`](SoftEtherWatermark.cs#L80)): ghi `POST /vpnsvc/connect.cgi HTTP/1.1` + headers (`Host`/`Content-Type: image/jpeg`/`Content-Length`/`Connection: Keep-Alive`) + thân = signature ‖ padding. **Signature** mặc định là blob **placeholder** byte-exact tái tạo được ([`DefaultSignature`](SoftEtherWatermark.cs#L36)) — **KHÔNG** phải blob GPL `Watermark.c`; nối server thật thì truyền blob thật qua [`WithSignature`](SoftEtherWatermark.cs#L60).
2. **Đọc hello** ([`ReadHttpPackAsync`](SoftEtherHandshake.cs#L161) → [`ParseHello`](SoftEtherHandshake.cs#L43)): đọc 1 message HTTP (header tới `\r\n\r\n` + `Content-Length`), parse thân qua [`SoftEtherHttpPackCodec.ParseBody`](SoftEtherHttpPackCodec.cs#L41) → PACK `hello`/`version`/`build`/`random`(20B challenge).
3. **Dựng & gửi login** ([`BuildLoginPack`](SoftEtherHandshake.cs#L74) → [`SoftEtherHttpPackCodec.BuildPostRequest`](SoftEtherHttpPackCodec.cs#L52)): PACK `method=login`/`hubname`/`username`/`authtype` + credential + session params. **Auth password**: [`SoftEtherAuth.ComputeSecurePassword`](SoftEtherAuth.cs#L82) = `SHA0(SHA0(password‖UPPER(username))‖server_random)` (tái dùng [`Sha0`](../TqkLibrary.VpnClient.Crypto/Sha0.cs) qua `IHashAlgo`) — password gốc **không** qua wire. POST tới `/vpnsvc/vpn.cgi`.
4. **Đọc welcome / lỗi** ([`ParseWelcome`](SoftEtherHandshake.cs#L110)): field `error` ≠ 0 ⇒ `SoftEtherProtocolException(ErrorCode)`; else trả `session_name`(20B handle) + `session_key_32`.

**Tách codec/state khỏi I/O**: bước 1/3 (dựng byte) và 2/4 (parse PACK) là **hàm thuần** test offline trực tiếp; `RunAsync` chỉ ghép chúng với `WriteAsync`/`ReadAsync` của transport. Reader HTTP nội bộ (`HttpMessageReader`) buffer phần thân đã đọc lố qua ranh header để ráp đúng `Content-Length`.

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| SoftEther PACK spec | `Pack`/`PackElement`/`PackValue` | [`.docs/07`](../../.docs/07-softether.md) §"Wire framing: PACK"; re-implement từ behavior — **không copy GPL** |
| SoftEther value type enum | `PackValueType` | `VALUE_INT=0`/`VALUE_DATA=1`/`VALUE_STR=2`/`VALUE_UNISTR=3`/`VALUE_INT64=4` (số cố định protocol) |
| Big-endian length-prefix | `PackBufferReader`/`PackBufferWriter` | `BufFromPack`/`PackFromBuf` của SoftEther (`WriteBufStr` quirk `+1`) |
| SoftEther handshake (watermark/hello/login) | `SoftEtherWatermark`/`SoftEtherHandshake`/`SoftEtherHttpPackCodec` | [`.docs/07`](../../.docs/07-softether.md) §"Handshake"; **watermark blob thật ở GPL `Watermark.c` — KHÔNG copy**, dùng placeholder |
| SHA-0 password auth | `SoftEtherAuth` | [`.docs/07`](../../.docs/07-softether.md) §"Auth password — SHA-0"; tái dùng [`Sha0`](../TqkLibrary.VpnClient.Crypto/Sha0.cs) (F.5a) |

## Trạng thái & ghi chú

- **Tách lớp**: PACK codec (V4.a) **thuần, không I/O, không ref project khác**. Handshake (V4.b) tách phần thuần codec/state khỏi I/O — chỉ phụ thuộc seam `IByteStreamTransport` (Abstractions) + `IHashAlgo` (Crypto), **không** đụng socket thật → test offline qua server giả lập in-memory.
- **Watermark placeholder**: blob mặc định byte-exact reproducible cho test offline, **không mang byte nào từ GPL `Watermark.c`**; interop server thật cần truyền blob thật qua `WithSignature`. Framing request (POST line/headers/length) **đúng protocol** bất kể blob.
- Build xanh cả `netstandard2.0` + `net8.0`. Dùng `System.Buffers.Binary.BinaryPrimitives` (cả 2 TFM qua `System.Memory`); `record`/`init`/`required` qua `TqkLibrary.CompilerServices`. `PackBufferReader` là `ref struct` (zero-copy đọc span).
- **Namespace**: type codec ở namespace gốc `TqkLibrary.VpnClient.SoftEther` (KHÔNG đặt segment `.Pack` để tránh tên type `Pack` bị namespace cùng tên che khuất — bài học `~/.claude/csharp.md`); thư mục vẫn là `Pack/`. Enum ở `.Enums`, model ở `.Models`.
- **Còn lại (V4.c)**: data plane Ethernet-over-TLS (length-prefixed frame + optional deflate/RC4 + keep-alive) + driver L2 (DHCP/ARP qua fabric Ethernet) → `IPacketChannel`; multi-connection (`additional_connect`/`session_key`). Lộ trình V.4 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.4; design-intent SoftEther ở [`.docs/07`](../../.docs/07-softether.md).
