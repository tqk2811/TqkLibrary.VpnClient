# TqkLibrary.VpnClient.SoftEther

Thư viện **protocol SoftEther SSL-VPN** thuần .NET. Hiện mới có **PACK codec** — định dạng nhị phân typed key-value mà SoftEther dùng cho **mọi** trao đổi control/RPC (hello, login, welcome…). Re-implement **từ spec/behavior** (xem [`.docs/07`](../../.docs/07-softether.md)) — **KHÔNG copy source GPL** (`Pack.c`/`Pack.h`). Đây là phần đầu của driver **V.4** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.4); watermark/hello/login handshake (V4.b) + data plane Ethernet-over-TLS (V4.c) sẽ thêm sau.

> **Trạng thái:** **V4.a (PACK codec) xong** (code + test offline). PACK = **list `PackElement`**; mỗi element có **name** (≤63 ký tự), một **`PackValueType`** (int/data/str/unistr/int64), và **mảng `PackValue`** (≥1) cùng kiểu. Encode/decode **big-endian** đúng wire SoftEther: `uint32(num_elements)` → mỗi element `BufStr(name) · uint32(type) · uint32(num_value) · value[]`. Codec **thuần, không I/O**. Có helper `Set*`/`Get*` theo tên (single + array), tra cứu **case-insensitive**, chống input lỗi (underrun/đếm vượt giới hạn/trùng tên/kiểu lạ ⇒ `FormatException`).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[OpenVpn](../TqkLibrary.VpnClient.OpenVpn)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)): khối giao thức thuần, **không** I/O socket. PACK là *framing nền* — mọi message SoftEther được dựng/đọc qua codec này; driver `Drivers.SoftEther` (V4.b/c, chưa có) sẽ lắp lên trên TLS transport (F.1) + auth SHA-0 ([Crypto](../TqkLibrary.VpnClient.Crypto), F.5a) + L2 fabric DHCP/ARP ([Ethernet](../TqkLibrary.VpnClient.Ethernet)).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | (không) | PACK codec thuần BCL (`System.Buffers.Binary`/`System.Text`) — `System.Memory` polyfill cho `Span` trên netstandard2.0 đã có ở [`Directory.Build.props`](../Directory.Build.props) |
| Được dùng bởi (tương lai) | `Drivers.SoftEther` (V4.b/c) | dựng/đọc hello/login/welcome PACK; auth field qua [`Sha0`](../TqkLibrary.VpnClient.Crypto/Sha0.cs) |

> Test ([`SoftEther.Tests`](../../tests/TqkLibrary.VpnClient.SoftEther.Tests)) tham chiếu thêm [Crypto](../TqkLibrary.VpnClient.Crypto) chỉ để dựng field `secure_password` = SHA-0 trong PACK login mẫu — bản thân project SoftEther **không** ref Crypto.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.SoftEther/
└─ Pack/
   ├─ Pack.cs                 PACK = list element + codec top-level (ToBytes/Parse) + helper Set*/Get* theo tên (single + array) + tra cứu case-insensitive
   ├─ PackElement.cs          Một element {name ≤63, type, mảng value ≥1}; codec 1 element (BufStr name · type · num_value · value[])
   ├─ PackValue.cs            Một value typed (Int/Int64/Data/Str/UniStr); factory From* + codec 1 value theo type
   ├─ PackConstants.cs        Giới hạn wire 64-bit (name 63, element/value 262144, value-size 384MB) để chặn alloc từ input xấu
   ├─ PackBufferWriter.cs     Sink byte growable: WriteUInt32/64 big-endian + WriteBytes + WriteBufStr (prefix len+1, KHÔNG ghi NUL)
   ├─ PackBufferReader.cs     Cursor forward-only: ReadUInt32/64 big-endian + ReadBytes + ReadBufStr (prefix len+1) + chống underrun
   ├─ SoftEtherAnsi.cs        Codec STR "ANSI" = Latin-1 8-bit thủ công (đồng nhất 2 TFM; Encoding.Latin1 chỉ có từ net5)
   └─ Enums/
      └─ PackValueType.cs     enum tag value: Int=0/Data=1/Str=2/UniStr=3/Int64=4 (số cố định theo spec)
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

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| SoftEther PACK spec | `Pack`/`PackElement`/`PackValue` | [`.docs/07`](../../.docs/07-softether.md) §"Wire framing: PACK"; re-implement từ behavior — **không copy GPL** |
| SoftEther value type enum | `PackValueType` | `VALUE_INT=0`/`VALUE_DATA=1`/`VALUE_STR=2`/`VALUE_UNISTR=3`/`VALUE_INT64=4` (số cố định protocol) |
| Big-endian length-prefix | `PackBufferReader`/`PackBufferWriter` | `BufFromPack`/`PackFromBuf` của SoftEther (`WriteBufStr` quirk `+1`) |

## Trạng thái & ghi chú

- **Thuần codec**: không I/O, không server, không phụ thuộc project khác. Encode/decode đối xứng, round-trip mọi kiểu + đa-value array.
- Build xanh cả `netstandard2.0` + `net8.0`. Dùng `System.Buffers.Binary.BinaryPrimitives` (cả 2 TFM qua `System.Memory`); `record`/`init` qua `TqkLibrary.CompilerServices`. `PackBufferReader` là `ref struct` (zero-copy đọc span).
- **Namespace**: type codec ở namespace gốc `TqkLibrary.VpnClient.SoftEther` (KHÔNG đặt segment `.Pack` để tránh tên type `Pack` bị namespace cùng tên che khuất — bài học `~/.claude/csharp.md`); thư mục vẫn là `Pack/`. Enum ở `.Enums`.
- Lộ trình V.4 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.4; design-intent SoftEther ở [`.docs/07`](../../.docs/07-softether.md).
