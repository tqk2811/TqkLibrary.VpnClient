# TqkLibrary.VpnClient.Vtun

Lớp **protocol thuần** của **vtun** (Virtual Tunnel daemon legacy, Maxim Krasnyansky) — các codec wire **không sockets, không state máy chủ**, để driver [`Drivers.Vtun`](../TqkLibrary.VpnClient.Drivers.Vtun) ráp thành tunnel sống. Gồm 4 mảng: (1) **xác thực challenge-response** (khối message ASCII 50-byte cố định, challenge mã hoá `a..p`, response = Blowfish-ECB(MD5(password)) trên challenge); (2) **host-flags codec** (chuỗi `<Tu...>` server gửi quyết định tun/tap, tcp/udp, compress/encrypt/keepalive); (3) **frame codec data-plane** (word 2-byte big-endian = flags|length); (4) **data-plane encryptor** (`encrypt yes` = Blowfish-128-ECB mỗi frame). Đối chiếu **clean-room** từ behavior vtun 3.0.4 (KHÔNG copy GPL).

## Vị trí kiến trúc

`PROTOCOL`-layer (như [`Tinc`](../TqkLibrary.VpnClient.Tinc)/[`N2n`](../TqkLibrary.VpnClient.N2n)): codec thuần + pure function, không I/O. Ref **chỉ** `Abstractions` (hằng/exception nhẹ) + `Crypto` (MD5 BCL + `Blowfish` BouncyCastle).

- **Auth** [`VtunMessageCodec`](Auth/VtunMessageCodec.cs): khối 50-byte (`VTUN_MESG_SIZE`) NUL-pad — mỗi dòng handshake (`VTUN server ver…`, `HOST:`, `OK CHAL:`, `CHAL:`, `OK FLAGS:`, `ERR`) là ASCII + `\n` rồi pad 0 đủ 50 byte (vtund đọc đúng 50 byte/message — sai framing = fail interop). [`VtunChallengeCodec`](Auth/VtunChallengeCodec.cs): encode/decode challenge `a..p` (`cl2cs`/`cs2cl` — mỗi byte → 2 ký tự `a..p`, bọc `<…>`, **không** base64/hex) + `EncryptChallenge` = Blowfish-ECB(key = MD5(password)) trên 16-byte challenge (`encrypt_chal`).
- **Flags** [`VtunHostFlagsCodec`](Wire/VtunHostFlagsCodec.cs): parse/encode chuỗi `<…>` (`cf2bf`/`bf2cf`) — `T/U`=tcp/udp, `t/p/e/u`=tty/pipe/ether/tun, `K`=keepalive, `C<n>/L<n>`=zlib/lzo, `E[n]`=encrypt cipher, `S<n>`=shape. Server dictates.
- **Frame** [`VtunFrameCodec`](Wire/VtunFrameCodec.cs): word 2-byte big-endian — top nibble = flags, low 12 bit (`VTUN_FSIZE_MASK` 0x0fff) = length. Data frame = `[len][payload]`; control frame = 2 byte (length 0): `ECHO_REQ`(0x2000)/`ECHO_REP`(0x4000)/`CONN_CLOSE`(0x1000)/`BAD_FRAME`(0x8000).
- **Data-plane encrypt** [`VtunBlowfishEcbTransform`](Wire/VtunBlowfishEcbTransform.cs) (sau [`IVtunFrameTransform`](Wire/Interfaces/IVtunFrameTransform.cs)): cipher mặc định của vtund `encrypt yes` (`VTUN_ENC_BF128ECB`) — mỗi frame payload = `BF-ECB(MD5(password), PKCS7-pad-to-8(payload))`. **KHÔNG IV/sequence** (mode ECB của `lfd_encrypt` chạy `cipher_enc_state=CIPHER_CODE` nên `send_msg`/`send_ib_mesg` không prepend gì). [`VtunFrameTransformFactory`](Wire/VtunFrameTransformFactory.cs) map cipher id (`E<n>`) → transform (chỉ BF128ECB + legacy bare-`E` supported). [`VtunKeyDerivation`](Auth/VtunKeyDerivation.cs) = `MD5(password)` 16-byte (hoặc `MD5(half)‖MD5(half)` 32-byte cho key 256-bit) — share giữa challenge auth và encryptor (`prep_key`). [`VtunCipher`](Wire/Enums/VtunCipher.cs) liệt kê toàn bộ `VTUN_ENC_*` id để báo lỗi cipher chưa hỗ trợ chính xác.

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
│  ├─ VtunChallengeCodec.cs    Encode/TryDecode challenge a..p (cl2cs/cs2cl) + EncryptChallenge/DecryptChallenge = Blowfish-ECB(MD5(pwd))
│  └─ VtunKeyDerivation.cs     prep_key: MD5(pwd) 16-byte / MD5(half)‖MD5(half) 32-byte — share challenge↔encryptor
└─ Wire/
   ├─ VtunConstants.cs         Port 5000, MESG 50, CHAL 16, FSIZE_MASK 0x0fff, FRAME 2048+100, ECHO_REQ/REP/CONN_CLOSE/BAD_FRAME
   ├─ VtunHostFlagsCodec.cs    TryParse/Encode chuỗi <…> (cf2bf/bf2cf): tun/tap, tcp/udp, compress/encrypt/keepalive/shape
   ├─ VtunFrameCodec.cs        EncodeData/EncodeControl/DecodeHeader — word 2-byte BE (flags|length)
   ├─ VtunFrameHeader.cs       struct (VtunFrameType Type, int Length)
   ├─ VtunBlowfishEcbTransform.cs  Data-plane BF128ECB: BF-ECB(MD5(pwd), PKCS7-pad-to-8) — không IV/seq (lfd_encrypt)
   ├─ VtunFrameTransformFactory.cs Cipher id (E<n>) → IVtunFrameTransform (chỉ BF128ECB + legacy E supported)
   ├─ Interfaces/
   │  └─ IVtunFrameTransform.cs    Encrypt(payload)/Decrypt(frame) một data-frame payload
   └─ Enums/
      ├─ VtunHostFlags.cs      [Flags] khớp vtun.h (Tcp 0x10, Tun 0x800, KeepAlive 0x40, Encrypt 0x08, Zlib/Lzo/Shape…)
      ├─ VtunCipher.cs         VTUN_ENC_* id (BF128ECB=1 … AES256OFB=16, Legacy=999)
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
| Data-plane encrypt | `lib/lfd_encrypt.c` (`alloc_encrypt`/`encrypt_buf`/`decrypt_buf`), `vtun.h` (`VTUN_ENC_*`) | mặc định `default:` = BF128ECB (id 1, legacy bare-`E`=999 cũng rơi vào đây); ECB không sideband init (`cipher_enc_state=CIPHER_CODE`); pad = `8 - len%8` mọi byte = pad (PKCS#7), block-aligned thì random `blocksize-1` byte đầu (byte cuối = pad); key = `prep_key` MD5 |
| Cipher id (`E<n>`) | `auth.c` (`bf2cf` `E%d`/`cf2bf`), `vtun.h` | server gửi `E1` cho BF128ECB; `E` trần (id 0) = `VTUN_LEGACY_ENCRYPT` 999 → vtund resolve về BF128ECB |

## Trạng thái & ghi chú

- **OFFLINE**: 32 test [`Vtun.Tests`](../../tests/TqkLibrary.VpnClient.Vtun.Tests) — message 50-byte round-trip, challenge a..p encode/decode, **golden vector OpenSSL challenge** (`MD5("pass")` → `BF-ECB(0x00..0x0f)` = `7416f64c8c4581f8a271117a81d15366`, byte-for-byte), flags parse/encode (`<Tu>`/`<TuE1>`/`<TuC6K>`/`<TuS256>`), frame data/control header (ECHO_REQ 0x2000/ECHO_REP 0x4000/CONN_CLOSE/BAD_FRAME/oversized), **+8 test encryptor**: 3 golden vector OpenSSL legacy-provider BF-ECB byte-exact (`"pass"` 5B→`771cf8354baedcbf`, 3B→`93f42f60588e4ffa`; `"secret123"` "Hi"→`871286fb039e78f3`) + round-trip mọi length + block-aligned full-pad + reject frame lỗi (rỗng/sai bội block) + factory resolve + key-derivation 32-byte. Build XANH ns2.0 + net8.
- **VALIDATE LIVE** (qua [`Drivers.Vtun`](../TqkLibrary.VpnClient.Drivers.Vtun) tới vtund 3.0.4 thật): handshake + frame codec khớp byte-for-byte (tcpdump: khối 50-byte auth + frame 62-byte data + control 2-byte echo); **DATA-PLANE ENCRYPT BF128ECB**: ICMP 2 chiều, server `Blowfish-128-ECB encryption initialized`, frame ciphertext-on-wire (0 plaintext IP). Chi tiết ở [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md) §9 + lab [`vtun`](../../lab/vtun).
- ⚠️ **Bảo mật legacy**: Blowfish-ECB (không chaining, không IV, không xác thực — lộ cấu trúc plaintext, malleable) + challenge MD5 — **yếu**, chỉ interop với vtund. Cipher khác BF128ECB (CBC/CFB/OFB + AES — cần sideband `ivec`/`seq#` framing) + compression (zlib/lzo) **CHƯA hiện thực** (driver yêu cầu `compress no`).
