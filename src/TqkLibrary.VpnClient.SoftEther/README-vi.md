# TqkLibrary.VpnClient.SoftEther

Thư viện **protocol SoftEther SSL-VPN** thuần .NET. Gồm **PACK codec** (V4.a — định dạng nhị phân typed key-value cho **mọi** trao đổi control/RPC), **control handshake** (V4.b — watermark POST + hello/login + auth SHA-0), và **data plane Ethernet-over-TLS** (V4.c — block frame codec + `IEthernetChannel`). Re-implement **từ spec/behavior** (xem [`.docs/07`](../../.docs/07-softether.md)) — **KHÔNG copy source GPL** (`Pack.c`/`Pack.h`/`Watermark.c`/`Protocol.c`/`Connection.c`). Đây là protocol của driver **V.4** ([`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) ráp end-to-end; xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.4).

> **Trạng thái:**
> - **V4.a (PACK codec) xong** (code + test offline). PACK = **list `PackElement`**; mỗi element có **name** (≤63 ký tự), một **`PackValueType`** (int/data/str/unistr/int64), và **mảng `PackValue`** (≥1) cùng kiểu. Encode/decode **big-endian** đúng wire SoftEther: `uint32(num_elements)` → mỗi element `BufStr(name) · uint32(type) · uint32(num_value) · value[]`. Codec **thuần, không I/O**. Helper `Set*`/`Get*` theo tên (single + array), tra cứu **case-insensitive**, chống input lỗi ⇒ `FormatException`.
> - **V4.b (watermark POST + hello/login handshake + auth SHA-0) xong** (code + test offline). **Tách phần codec/state thuần khỏi I/O**: `SoftEtherWatermark` dựng byte POST watermark; `SoftEtherAuth` tính `secure_password` SHA-0 (tái dùng [`Sha0`](../TqkLibrary.VpnClient.Crypto/Sha0.cs) F.5a); `SoftEtherHandshake` có **3 hàm thuần** `ParseHello`/`BuildLoginPack`/`ParseWelcome` (test trực tiếp) + driver `RunAsync` lắp chúng lên [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) (F.1/TLS). PACK đi trong thân HTTP qua `SoftEtherHttpPackCodec` (`uint32 len` + PACK bytes). Test chạy **offline** với server giả lập in-memory.
> - **V4.c (data plane Ethernet-over-TLS) xong** (code + test offline). Sau `welcome`, cùng byte-stream chuyển sang **session data**: codec block thuần `SoftEtherDataFrameCodec` (`uint32(num_frames)` + mỗi frame `uint32(size)·bytes`), reader streaming `SoftEtherDataBlockReader` (ráp block qua partial read), và `SoftEtherEthernetChannel` (`IEthernetChannel`: encode frame ra block / `Deliver` block vào, drop keep-alive). Driver L2 thật ([`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther)) cắm channel này vào fabric DHCP/ARP/VirtualHost.
> - **V.4 multi-connection xong** (code + test offline). `welcome` đọc `max_connection`/`half_connection`; `additional_connect` codec + I/O (`RunAdditionalConnectAsync`) reattach socket phụ bằng session key; `SoftEtherMultiConnectionMux` gộp 1–32 socket = 1 data path (round-robin egress + N decode loop merge ingress, one-shot link-lost); `SoftEtherConnectionDirectionPlanner` chia full/half-duplex.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[OpenVpn](../TqkLibrary.VpnClient.OpenVpn)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)): khối giao thức thuần, **không** I/O socket trực tiếp (chỉ phụ thuộc seam `IByteStreamTransport`). PACK là *framing nền* — mọi message SoftEther được dựng/đọc qua codec này; handshake codec dựng/đọc hello/login/welcome; data plane codec dựng/đọc block Ethernet-frame. Driver [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) (V4.c) lắp `SoftEtherHandshake` + `SoftEtherEthernetChannel` lên TLS transport thật (F.1) + L2 fabric DHCP/ARP ([Ethernet](../TqkLibrary.VpnClient.Ethernet)).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [`Abstractions`](../TqkLibrary.VpnClient.Abstractions) | seam transport [`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) (F.1) mà `SoftEtherHandshake.RunAsync` ghi/đọc |
| Dùng | [`Crypto`](../TqkLibrary.VpnClient.Crypto) | `SoftEtherAuth` nhận [`IHashAlgo`](../TqkLibrary.VpnClient.Crypto/Interfaces/IHashAlgo.cs) (SHA-0 [`Sha0`](../TqkLibrary.VpnClient.Crypto/Sha0.cs), F.5a) để tính `secure_password` |
| Được dùng bởi | [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) (V4.c) | chạy `SoftEtherHandshake.RunAsync` trên TLS thật → `SoftEtherEthernetChannel` data plane → L2 fabric DHCP/ARP |

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
├─ DataChannel/                — V4.c data plane Ethernet-over-TLS + V.4 multi-connection
│  ├─ SoftEtherDataConstants.cs    keep-alive string + guard MaxFramesPerBlock/MaxFrameSize
│  ├─ SoftEtherDataFrameCodec.cs   codec block thuần: EncodeBlock/EncodeSingle/DecodeBlock + IsKeepAlive
│  ├─ SoftEtherDataBlockReader.cs  reader streaming: ráp 1 block qua partial read của IByteStreamTransport
│  ├─ SoftEtherEthernetChannel.cs  IEthernetChannel: WriteFrameAsync (encode block) + Deliver (raise InboundFrame, drop keep-alive)
│  ├─ SoftEtherMultiConnectionMux.cs   V.4 gộp 1-32 socket = 1 session: round-robin egress + N decode loop merge ingress, one-shot link-lost
│  ├─ SoftEtherConnectionDirectionPlanner.cs  V.4 chia hướng full/half-duplex (Both / Send-only / Receive-only)
│  └─ Enums/
│     └─ SoftEtherConnectionDirection.cs   V.4 hướng 1 connection: Both=0 / Send=1 / Receive=2
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
| `SoftEtherHandshake` | state machine: `ParseHello`/`BuildLoginPack`/`ParseWelcome` (thuần) + `RunAsync(IByteStreamTransport)` + reader HTTP nội bộ; **V.4 multi-connection**: `BuildAdditionalConnectPack`/`ParseAdditionalConnectReply` (thuần) + `RunAdditionalConnectAsync` (watermark→hello→`additional_connect`+session key→ack) | [SoftEtherHandshake.cs:24](SoftEtherHandshake.cs#L24) |
| `SoftEtherProtocolException` | lỗi protocol (hello hỏng / login từ chối), mang `ErrorCode` từ field `error` của server | [SoftEtherProtocolException.cs:9](SoftEtherProtocolException.cs#L9) |
| `SoftEtherDataFrameCodec` | V4.c codec block thuần: `EncodeBlock`/`EncodeSingle` (`uint32(n)·{uint32(size)·bytes}`), `DecodeBlock`, `IsKeepAlive` | [DataChannel/SoftEtherDataFrameCodec.cs:15](DataChannel/SoftEtherDataFrameCodec.cs#L15) |
| `SoftEtherDataBlockReader` | V4.c reader streaming: `ReadBlockAsync` ráp 1 block qua partial read; EOF ranh block ⇒ list rỗng, EOF giữa block ⇒ `SoftEtherProtocolException` | [DataChannel/SoftEtherDataBlockReader.cs:16](DataChannel/SoftEtherDataBlockReader.cs#L16) |
| `SoftEtherEthernetChannel` | V4.c `IEthernetChannel`: `WriteFrameAsync` (encode block 1-frame → sink), `Deliver` (raise `InboundFrame`, drop keep-alive); MAC + `MaxHeaderLength`=14 + `RequiresLinkAddressResolution` | [DataChannel/SoftEtherEthernetChannel.cs:23](DataChannel/SoftEtherEthernetChannel.cs#L23) |
| `SoftEtherMultiConnectionMux` | V.4 gộp 1-32 `IByteStreamTransport` = 1 data path: `SendBlockAsync` round-robin các connection gửi-được, `StartReceiveLoops` 1 decode loop/connection nhận-được → merge `InboundFrame`, `linkLost` callback **một lần** (one-shot), `DisposeAsync` hủy loop + đóng mọi socket | [DataChannel/SoftEtherMultiConnectionMux.cs:34](DataChannel/SoftEtherMultiConnectionMux.cs#L26) |
| `SoftEtherConnectionDirectionPlanner` | V.4 thuần: `Plan(count, halfConnection)` → mảng `SoftEtherConnectionDirection` (full-duplex ⇒ mọi `Both`; half ⇒ floor(n/2) `Send` + còn lại `Receive`, ≥1 mỗi hướng; 1 connection ⇒ `Both`) | [DataChannel/SoftEtherConnectionDirectionPlanner.cs:20](DataChannel/SoftEtherConnectionDirectionPlanner.cs#L19) |
| `SoftEtherConnectionDirection` | V.4 enum hướng 1 connection: `Both=0`/`Send=1`/`Receive=2` | [DataChannel/Enums/SoftEtherConnectionDirection.cs:11](DataChannel/Enums/SoftEtherConnectionDirection.cs#L9) |
| `SoftEtherDataConstants` | V4.c keep-alive string `"Internet Connection Keep Alive Packet"` + guard `MaxFramesPerBlock`/`MaxFrameSize` | [DataChannel/SoftEtherDataConstants.cs:11](DataChannel/SoftEtherDataConstants.cs#L11) |
| `SoftEtherAuthType` | enum authtype: `Anonymous=0`/`Password=1`/`PlainPassword=2`/`Certificate=3` | [Enums/SoftEtherAuthType.cs:10](Enums/SoftEtherAuthType.cs#L10) |
| `SoftEtherSessionParams` | record session: `MaxConnection`/`UseEncrypt`/`UseCompress`/`HalfConnection`/`UniqueId` | [Models/SoftEtherSessionParams.cs:11](Models/SoftEtherSessionParams.cs#L11) |
| `SoftEtherLoginRequest` | record input login: `HubName`/`UserName`/`AuthType`/`Password`/`Session` | [Models/SoftEtherLoginRequest.cs:14](Models/SoftEtherLoginRequest.cs#L14) |
| `SoftEtherHelloInfo` | record hello đã parse: `Hello`/`Version`/`Build`/`Random`(20B) | [Models/SoftEtherHelloInfo.cs:10](Models/SoftEtherHelloInfo.cs#L10) |
| `SoftEtherWelcomeInfo` | record welcome đã parse: `SessionKey`(20B)/`SessionKey32` + **V.4** `MaxConnection`(server cấp 1–32, default 1)/`HalfConnection` | [Models/SoftEtherWelcomeInfo.cs:9](Models/SoftEtherWelcomeInfo.cs#L9) |

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
4. **Đọc welcome / lỗi** ([`ParseWelcome`](SoftEtherHandshake.cs#L110)): field `error` ≠ 0 ⇒ `SoftEtherProtocolException(ErrorCode)`; else trả `session_name`(20B handle) + `session_key_32` + **`max_connection`** (server cấp 1–32, mặc định 1) + **`half_connection`**.

**Tách codec/state khỏi I/O**: bước 1/3 (dựng byte) và 2/4 (parse PACK) là **hàm thuần** test offline trực tiếp; `RunAsync` chỉ ghép chúng với `WriteAsync`/`ReadAsync` của transport. Reader HTTP nội bộ (`HttpMessageReader`) buffer phần thân đã đọc lố qua ranh header để ráp đúng `Content-Length`.

## Luồng multi-connection (V.4)

SoftEther cho phép 1 session logic chạy trên **1–32 TCP/TLS song song** để gộp throughput. Sau khi login lấy `session_key` + `max_connection` (server cấp), client mở thêm connection phụ và gộp lại:

1. **Mở connection phụ** ([`RunAdditionalConnectAsync`](SoftEtherHandshake.cs#L209)): mỗi connection phụ chạy watermark POST → đọc hello (bỏ qua challenge — không auth lại) → POST PACK `method=additional_connect` + `session_name`=session key (server `GetSessionFromKey` gắn socket vào session đã login) → đọc ack (`error`≠0 ⇒ từ chối, vd session key sai/hết hạn). Codec thuần: [`BuildAdditionalConnectPack`](SoftEtherHandshake.cs#L140)/[`ParseAdditionalConnectReply`](SoftEtherHandshake.cs#L155).
2. **Chia hướng** ([`SoftEtherConnectionDirectionPlanner.Plan`](DataChannel/SoftEtherConnectionDirectionPlanner.cs#L19)): full-duplex ⇒ mọi connection `Both`; **half_connection** ⇒ nửa đầu `Send`-only (client→server) + nửa sau `Receive`-only (server→client), ≥1 mỗi hướng; 1 connection thì luôn `Both`.
3. **Gộp data path** ([`SoftEtherMultiConnectionMux`](DataChannel/SoftEtherMultiConnectionMux.cs#L26)): **egress** [`SendBlockAsync`](DataChannel/SoftEtherMultiConnectionMux.cs#L97) spread block **round-robin** các connection gửi-được; **ingress** [`StartReceiveLoops`](DataChannel/SoftEtherMultiConnectionMux.cs#L82) chạy 1 decode loop ([`SoftEtherDataBlockReader`](DataChannel/SoftEtherDataBlockReader.cs#L16)) trên mỗi connection nhận-được, gộp `InboundFrame`. Frame SoftEther **self-contained** (không sequencing chéo connection ở tầng block) ⇒ reassemble = **hợp** mọi connection; thứ tự **trong-1-connection** giữ nguyên, tầng IP/TCP trên chịu reorder nhẹ giữa các connection. Fault/peer-close ⇒ `linkLost` **một lần** (one-shot guard). Driver gắn [`SoftEtherEthernetChannel`](DataChannel/SoftEtherEthernetChannel.cs#L23) lên mux (egress = `mux.SendBlockAsync`, ingress = `mux.InboundFrame += channel.Deliver`).

**Degenerate 1 connection**: mux với N=1 hành xử y hệt data path 1-socket cũ (round-robin chọn luôn index 0, 1 decode loop). `additional_connect` lỗi = **best-effort**: session vẫn chạy trên số connection đã gắn.

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
- **Data plane (V4.c) đã có**: block frame codec (`SoftEtherDataFrameCodec`/`SoftEtherDataBlockReader`) + `SoftEtherEthernetChannel`; driver L2 thật ([`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther)) cắm vào fabric DHCP/ARP/VirtualHost → `IPacketChannel` (bridge **1-host**).
- **Multi-connection (V.4) đã có**: `welcome` PACK đọc `max_connection`/`half_connection`; `additional_connect` codec + I/O (`RunAdditionalConnectAsync`) reattach socket phụ bằng session key; `SoftEtherMultiConnectionMux` gộp 1–32 socket = 1 data path (round-robin egress + N decode loop merge ingress, frame self-contained ⇒ reassemble = hợp mọi connection, thứ tự trong-1-connection giữ nguyên), one-shot link-lost; `SoftEtherConnectionDirectionPlanner` chia full/half-duplex. Driver [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) lắp ráp + clamp số connection. Test offline (mux/planner/codec + driver N-connection round-trip không mất gói + half-duplex).
- **Còn lại (sau V.4 multi-connection)**: deflate/RC4 payload (`use_compress`/`use_encrypt`); IPv6 trong tunnel. Lộ trình V.4 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.4; design-intent SoftEther ở [`.docs/07`](../../.docs/07-softether.md).
