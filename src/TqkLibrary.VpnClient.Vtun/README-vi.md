# TqkLibrary.VpnClient.Vtun

Lớp **protocol thuần** của **vtun** (Virtual Tunnel daemon legacy, Maxim Krasnyansky) — các codec wire **không sockets, không state máy chủ**, để driver [`Drivers.Vtun`](../TqkLibrary.VpnClient.Drivers.Vtun) ráp thành tunnel sống. Gồm 3 mảng: (1) **xác thực challenge-response** (khối message ASCII 50-byte cố định, challenge mã hoá `a..p`, response = Blowfish-ECB(MD5(password)) trên challenge); (2) **host-flags codec** (chuỗi `<Tu...>` server gửi quyết định tun/tap, tcp/udp, compress/encrypt/keepalive); (3) **frame codec data-plane** (word 2-byte big-endian = flags|length). Đối chiếu **clean-room** từ behavior vtun 3.0.4 (KHÔNG copy GPL).

## Vị trí kiến trúc

`PROTOCOL`-layer (như [`Tinc`](../TqkLibrary.VpnClient.Tinc)/[`N2n`](../TqkLibrary.VpnClient.N2n)): codec thuần + pure function, không I/O. Ref **chỉ** `Abstractions` (hằng/exception nhẹ) + `Crypto` (MD5 BCL + `Blowfish` BouncyCastle).

- **Auth** [`VtunMessageCodec`](Auth/VtunMessageCodec.cs): khối 50-byte (`VTUN_MESG_SIZE`) NUL-pad — mỗi dòng handshake (`VTUN server ver…`, `HOST:`, `OK CHAL:`, `CHAL:`, `OK FLAGS:`, `ERR`) là ASCII + `\n` rồi pad 0 đủ 50 byte (vtund đọc đúng 50 byte/message — sai framing = fail interop). [`VtunChallengeCodec`](Auth/VtunChallengeCodec.cs): encode/decode challenge `a..p` (`cl2cs`/`cs2cl` — mỗi byte → 2 ký tự `a..p`, bọc `<…>`, **không** base64/hex) + `EncryptChallenge` = Blowfish-ECB(key = MD5(password)) trên 16-byte challenge (`encrypt_chal`).
- **Flags** [`VtunHostFlagsCodec`](Wire/VtunHostFlagsCodec.cs): parse/encode chuỗi `<…>` (`cf2bf`/`bf2cf`) — `T/U`=tcp/udp, `t/p/e/u`=tty/pipe/ether/tun, `K`=keepalive, `C<n>/L<n>`=zlib/lzo, `E[n]`=encrypt cipher, `S<n>`=shape. Server dictates.
- **Frame** [`VtunFrameCodec`](Wire/VtunFrameCodec.cs): word 2-byte big-endian — top nibble = flags, low 12 bit (`VTUN_FSIZE_MASK` 0x0fff) = length. Data frame = `[len][payload]`; control frame = 2 byte (length 0): `ECHO_REQ`(0x2000)/`ECHO_REP`(0x4000)/`CONN_CLOSE`(0x1000)/`BAD_FRAME`(0x8000).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | (rỗng runtime — chỉ cùng cây 2 TFM; codec không cần type Abstractions) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | **`Blowfish`** (BouncyCastle `BlowfishEngine` ECB) cho `encrypt_chal`; MD5 lấy từ BCL |
| Được dùng bởi | [Drivers.Vtun](../TqkLibrary.VpnClient.Drivers.Vtun) | ráp codec thành tunnel runtime (handshake + frame I/O) |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Vtun/
├─ Auth/
│  ├─ VtunMessageCodec.cs      Khối auth 50-byte NUL-pad (print_p/readn_t): Encode(line)→50B, Decode(50B)→line
│  └─ VtunChallengeCodec.cs    Encode/TryDecode challenge a..p (cl2cs/cs2cl) + EncryptChallenge/DecryptChallenge = Blowfish-ECB(MD5(pwd))
└─ Wire/
   ├─ VtunConstants.cs         Port 5000, MESG 50, CHAL 16, FSIZE_MASK 0x0fff, FRAME 2048+100, ECHO_REQ/REP/CONN_CLOSE/BAD_FRAME
   ├─ VtunHostFlagsCodec.cs    TryParse/Encode chuỗi <…> (cf2bf/bf2cf): tun/tap, tcp/udp, compress/encrypt/keepalive/shape
   ├─ VtunFrameCodec.cs        EncodeData/EncodeControl/DecodeHeader — word 2-byte BE (flags|length)
   ├─ VtunFrameHeader.cs       struct (VtunFrameType Type, int Length)
   └─ Enums/
      ├─ VtunHostFlags.cs      [Flags] khớp vtun.h (Tcp 0x10, Tun 0x800, KeepAlive 0x40, Encrypt 0x08, Zlib/Lzo/Shape…)
      └─ VtunFrameType.cs      Data/EchoRequest/EchoReply/ConnClose/BadFrame
```

## Bảng chuẩn / nguồn (clean-room, KHÔNG copy GPL)

| Khía cạnh | Nguồn vtun 3.0.4 | Ghi chú |
|-----------|------------------|---------|
| Khối auth 50-byte | `lib.c` (`print_p`/`readn_t`), `vtun.h` (`VTUN_MESG_SIZE`) | mỗi message = đúng 50 byte NUL-pad; dòng kết `\n` |
| Trình tự handshake | `auth.c` (`auth_server`/`auth_client`) | server greet → client `HOST:` → server `OK CHAL:` → client `CHAL:` → server `OK FLAGS:`/`ERR` |
| Challenge encode a..p | `auth.c` (`cl2cs`/`cs2cl`) | alphabet `abcdefghijklmnop` (a=0..p=15), byte→2 char, bọc `<…>` (32 char) |
| Challenge transform | `auth.c` (`encrypt_chal`/`decrypt_chal`) | `BF_set_key(16, MD5(pwd))` → `BF_ecb_encrypt` 2 block 8-byte; **luôn dùng kể cả `encrypt no`** |
| Host flags | `auth.c` (`bf2cf`/`cf2bf`), `vtun.h` | server dictates; client `VTUN_CLNT_MASK 0xf000` xoá cờ riêng trước connect |
| Frame data-link | `generic/tcp_proto.c`/`udp_proto.c`, `vtun.h`/`linkfd.h` | `htons(len)` prefix; flags top nibble, length low 12 bit; control = 0-payload |

## Trạng thái & ghi chú

- **OFFLINE**: 24 test [`Vtun.Tests`](../../tests/TqkLibrary.VpnClient.Vtun.Tests) — message 50-byte round-trip, challenge a..p encode/decode, **golden vector OpenSSL** (`MD5("pass")` → `BF-ECB(0x00..0x0f)` = `7416f64c8c4581f8a271117a81d15366`, byte-for-byte), flags parse/encode (`<Tu>`/`<TuE1>`/`<TuC6K>`/`<TuS256>`), frame data/control header (ECHO_REQ 0x2000/ECHO_REP 0x4000/CONN_CLOSE/BAD_FRAME/oversized). Build XANH ns2.0 + net8.
- **VALIDATE LIVE** (qua [`Drivers.Vtun`](../TqkLibrary.VpnClient.Drivers.Vtun) tới vtund 3.0.4 thật): handshake + frame codec khớp byte-for-byte (tcpdump: khối 50-byte auth + frame 62-byte data + control 2-byte echo). Chi tiết ở [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md) §9 + lab [`vtun`](../../lab/vtun).
- ⚠️ **Bảo mật legacy**: Blowfish-ECB (không chaining, không xác thực) + challenge MD5 — **yếu**, chỉ interop với vtund. Compression (zlib/lzo) + encryption data-plane (Blowfish/AES nhiều mode) **CHƯA hiện thực** (driver yêu cầu `encrypt no` + `compress no`).
