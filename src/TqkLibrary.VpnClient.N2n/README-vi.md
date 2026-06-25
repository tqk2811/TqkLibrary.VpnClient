# TqkLibrary.VpnClient.N2n

Thư viện **protocol n2n v3 (ntop)** thuần .NET — hiện thực **codec wire** cho các thông điệp control/data của mạng mesh
L2 n2n: **supernode** + **edge**. Mỗi gói = **common header 24B** (`version=3 ‖ ttl ‖ flags(2B BE) ‖ community(20B
null-pad)`, packet-type nằm ở 5 bit thấp của `flags`) nối với body theo từng loại:
**REGISTER_SUPER / REGISTER_SUPER_ACK / PEER_INFO / REGISTER / REGISTER_ACK / PACKET** — tất cả **big-endian**. Đây là
project protocol-level cho driver **V.7.4** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.4).
Driver runtime (UDP transport, REGISTER_SUPER lifecycle, `IEthernetChannel` ghép L2 fabric, supervisor F.6, `UseN2n`) là
phase (b) — **XONG**, VALIDATE LIVE L2 full-tunnel ICMP 2 chiều ([`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n)).
Header encryption (`-H`) **XONG + VALIDATE LIVE** ([`N2nHeaderEncryption`](N2nHeaderEncryption.cs#L24) — SPECK + Pearson từ Crypto). P2P UDP hole-punching còn lại (future).

> **Trạng thái:** **phase (a) protocol XONG — REGISTER_SUPER VALIDATE LIVE** (2026-06-24) — 21 test offline xanh,
> build xanh ns2.0 + net8. **Đối chiếu với `n2n` v3.1.1 thật** (lab [`lab/n2n`](../../lab/n2n)): supernode thật **CHẤP
> NHẬN REGISTER_SUPER** của client .NET (community `labnet`, transform NULL, header-enc OFF) — supernode log
> `Rx REGISTER_SUPER` + `created edge` + `Tx REGISTER_SUPER_ACK`; client **decode REGISTER_SUPER_ACK** thật: cookie
> echoed đúng, supernode gán `dev_addr` 10.209.172.184/24, lifetime, supernode MAC, public socket của edge. **3 KAT
> golden byte-exact** (REGISTER_SUPER edge thật 79B + REGISTER_SUPER_ACK supernode thật 58B). **Tái dùng**
> [`AesCbcCipher`](../TqkLibrary.VpnClient.Crypto/AesCbcCipher.cs#L10) cho transform AES — **không** viết lại AES.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [Nebula](../TqkLibrary.VpnClient.Nebula)/[Tinc](../TqkLibrary.VpnClient.Tinc)/[ZeroTier](../TqkLibrary.VpnClient.ZeroTier)):
khối codec thuần, **không** I/O socket. Codec là **encode/decode đối xứng** cho từng message type (driver bơm datagram
vào/ra UDP). Giống ZeroTier, n2n là **overlay L2** — PACKET chở khung Ethernet để driver ghép vào
[Ethernet fabric](../TqkLibrary.VpnClient.Ethernet) (`IEthernetChannel`). Khác ZeroTier (Salsa20/Poly1305 trên từng
gói): n2n tách rời — **control message không mã hóa khi `-H` off** (registration/ACK cleartext), chỉ **payload
PACKET** được transform (NULL/AES-CBC/ChaCha20/Speck) bảo vệ. Bản này hiện thực transform **NULL** và **AES-CBC**, và
**header-encryption (`-H`) ON** qua [`N2nHeaderEncryption`](N2nHeaderEncryption.cs#L24) (SPECK + Pearson, key từ community) —
mã hóa + checksum + chống replay phần common header (validate live vs n2n v3.1.1 `-H`).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`AesCbcCipher`](../TqkLibrary.VpnClient.Crypto/AesCbcCipher.cs#L10) cho transform AES (`N2nAesTransform`) |
| Được dùng bởi | [`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n) (V.7.4 phase b — XONG, VALIDATE LIVE L2 full-tunnel) | driver lắp UDP transport + REGISTER_SUPER lifecycle + keepalive quanh codec này, ghép L2 fabric (ARP + VirtualHost) → facade L3 |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.N2n/
├─ N2nPacketCodec.cs                   encode/decode mọi message type (common header 24B + body, big-endian)
├─ Wire/
│  ├─ N2nConstants.cs                  hằng số (version 3, ttl, community 20B, mac 6B, desc 16B, cookie 4B, header 24B)
│  ├─ Enums/
│  │  ├─ N2nPacketType.cs              packet-type (low 5 bit flags): RegisterSuper=5/ACK=7/PeerInfo=10/Register=1/PACKET=3…
│  │  ├─ N2nFlags.cs                   bit cao flags: TypeMask 0x1f / FromSupernode 0x20 / Socket 0x40 / Options 0x80
│  │  └─ N2nTransformId.cs             transform id PACKET body: Null=1 / Aes=3 / ChaCha20=4 / Speck=5 (chỉ Null/Aes hiện thực)
│  └─ Models/
│     ├─ N2nCommonHeader.cs            header 24B clear (version/ttl/flags BE/community null-pad)
│     ├─ N2nSock.cs                    n2n_sock_t (family marker v4/v6 + port BE + addr 4/16B)
│     ├─ N2nAuth.cs                    n2n_auth_t (scheme 2B + token_size 2B + token); simple-id challenge 16B mặc định
│     ├─ N2nIpSubnet.cs                n2n_ip_subnet_t (net_addr 4B BE + bitlen 1B)
│     ├─ N2nRegisterSuper.cs           body REGISTER_SUPER (cookie/edgeMac/sock?/devAddr/devDesc/auth/keyTime)
│     ├─ N2nRegisterSuperAck.cs        body REGISTER_SUPER_ACK (cookie/srcMac/devAddr/lifetime/sock/auth/numSn/keyTime)
│     ├─ N2nRegister.cs                body REGISTER edge↔edge (cookie/src/dstMac/sock?/devAddr/devDesc)
│     ├─ N2nRegisterAck.cs             body REGISTER_ACK edge↔edge (cookie/src/dstMac/sock?)
│     ├─ N2nPeerInfo.cs                body PEER_INFO (aflags/mac/sock/preferredSock/load/uptime)
│     └─ N2nPacket.cs                  body PACKET (src/dstMac/sock?/compression/transform + payload Ethernet frame)
├─ N2nHeaderEncryption.cs            header-encryption (-H): SPECK + Pearson (key từ community) mã hóa/checksum common header
└─ Transform/
   ├─ Interfaces/IN2nTransform.cs      Encode/Decode payload PACKET + Id
   ├─ N2nNullTransform.cs              transform NULL (identity, frame clear)
   └─ N2nAesTransform.cs               transform AES-CBC null-IV + 16B random preamble (tái dùng AesCbcCipher)
```

## Bảng type

| Type | Kind | Vai trò |
|------|------|---------|
| [`N2nPacketCodec`](N2nPacketCodec.cs#L19) | class | Encode/Decode tất cả message type; stateless, dùng lại |
| [`N2nCommonHeader`](Wire/Models/N2nCommonHeader.cs#L14) | class | Header 24B (cleartext khi `-H` off; SPECK-encrypted khi `-H` on) |
| [`N2nHeaderEncryption`](N2nHeaderEncryption.cs#L24) | class | header-encryption `-H`: `Encrypt`/`Decrypt` common header (SPECK + Pearson, key từ community) |
| [`N2nSock`](Wire/Models/N2nSock.cs#L12) | class | sock v4/v6, `FromEndPoint`/`ToEndPoint` |
| [`N2nAuth`](Wire/Models/N2nAuth.cs#L11) | class | auth block; `SimpleIdRandom()` token 16B |
| [`N2nIpSubnet`](Wire/Models/N2nIpSubnet.cs#L10) | struct | subnet (addr 4B + bitlen 1B), `Unset` |
| [`N2nRegisterSuper`](Wire/Models/N2nRegisterSuper.cs#L9) | class | body edge→supernode |
| [`N2nRegisterSuperAck`](Wire/Models/N2nRegisterSuperAck.cs#L10) | class | body supernode→edge |
| [`N2nRegister`](Wire/Models/N2nRegister.cs#L8) | class | body REGISTER edge↔edge |
| [`N2nRegisterAck`](Wire/Models/N2nRegisterAck.cs#L7) | class | body REGISTER_ACK edge↔edge |
| [`N2nPeerInfo`](Wire/Models/N2nPeerInfo.cs#L10) | class | body PEER_INFO (P2P setup) |
| [`N2nPacket`](Wire/Models/N2nPacket.cs#L9) | class | body PACKET (khung Ethernet) |
| [`IN2nTransform`](Transform/Interfaces/IN2nTransform.cs#L8) | interface | transform payload PACKET |
| [`N2nNullTransform`](Transform/N2nNullTransform.cs#L10) | class | transform NULL (clear) |
| [`N2nAesTransform`](Transform/N2nAesTransform.cs#L17) | class | transform AES-CBC (null-IV + preamble) |
| [`N2nConstants`](Wire/N2nConstants.cs#L7) | static class | hằng số wire (version 3, ttl, kích thước community/mac/desc/cookie/header) |
| [`N2nPacketType`](Wire/Enums/N2nPacketType.cs#L8) / [`N2nFlags`](Wire/Enums/N2nFlags.cs#L9) / [`N2nTransformId`](Wire/Enums/N2nTransformId.cs#L7) | enum | type / flag bits / transform id |

## Bảng chuẩn / wire format (n2n v3, đối chiếu source `n2n_typedefs.h` + `wire.c` — đọc spec, KHÔNG copy GPL)

| Thành phần | Layout on-wire |
|-----------|----------------|
| Common header (24B) | `version(1)=3 ‖ ttl(1) ‖ flags(2 BE) ‖ community(20 null-pad)`; `flags = (pkt-type & 0x1f) \| flag-bits` |
| REGISTER_SUPER | `…header ‖ cookie(4) ‖ edgeMac(6) ‖ [sock — nếu SOCKET flag] ‖ devAddr(5) ‖ devDesc(16) ‖ auth ‖ keyTime(4)` |
| REGISTER_SUPER_ACK | `…header ‖ cookie(4) ‖ srcMac(6) ‖ devAddr(5) ‖ lifetime(2) ‖ sock ‖ auth ‖ numSn(1) ‖ sock×numSn ‖ keyTime(4)` |
| REGISTER / _ACK | `…header ‖ cookie(4) ‖ srcMac(6) ‖ dstMac(6) ‖ [sock] ‖ (REGISTER: devAddr(5) ‖ devDesc(16))` |
| PEER_INFO | `…header ‖ aflags(2) ‖ mac(6) ‖ sock ‖ preferredSock ‖ load(4) ‖ uptime(4)` |
| PACKET | `…header ‖ srcMac(6) ‖ dstMac(6) ‖ [sock] ‖ compression(1) ‖ transform(1) ‖ payload(transform-encoded)` |
| sock | `family(2 BE: 0=v4, 0x8000=v6) ‖ port(2 BE) ‖ addr(4 v4 / 16 v6)` |
| auth | `scheme(2 BE) ‖ token_size(2 BE) ‖ token(token_size)`; simple-id (1) + 16B token |
| Transform AES (id 3) | `AES-CBC(null IV)` của `random preamble(16) ‖ frame ‖ zero-pad→block`; output = ciphertext (preamble = IV ngầm) |
| Header encryption (`-H`) | key SPECK = `pearson128(community pad-20)`, IV key = `pearson128(key)`. Encrypt: checksum Pearson-64(toàn packet) → pre-IV (`b0..7`=checksum, `b4..7`⊕high-stamp, `b8..11`=low-stamp, `b12..15`=rand) → SPECK-128 ECB(IV key) → magic `n2__`+header_len ở `b16..19` → SPECK-CTR(key, IV=`b0..15`) từ offset 16. header_len = full (control) / header-only (PACKET). timestamp = left-bound `(s<<32)\|(µs<<12)` |

## Luồng nội bộ (REGISTER_SUPER → ACK)

1. [`EncodeRegisterSuper`](N2nPacketCodec.cs#L27) ghi common header (type 5, no Socket flag nếu sock null) + cookie +
   edgeMac + devAddr `Unset` + devDesc + auth `SimpleIdRandom` + keyTime 0 → 79B.
2. Driver/harness gửi UDP tới supernode `:7654`.
3. Supernode đáp REGISTER_SUPER_ACK (58B, flags = FromSupernode|Socket).
4. [`TryDecodeRegisterSuperAck`](N2nPacketCodec.cs#L93) đọc cookie (đối chiếu cái đã gửi), srcMac (supernode MAC),
   devAddr (IP gán), lifetime, sock (public socket của edge), auth, numSn + extra supernodes, keyTime.

## Trạng thái & ghi chú

- **Phase (a) protocol XONG + REGISTER_SUPER validate live** (2026-06-24). Build xanh **ns2.0 + net8**; 26 test offline
  (round-trip mọi pkt-type + wire-layout invariants + AES self-pair 2 chiều + 3 KAT golden live + 6 header-enc).
- **Header encryption (`-H`) XONG + VALIDATE LIVE** (2026-06-25) qua [`N2nHeaderEncryption`](N2nHeaderEncryption.cs#L24): hiện
  thực `packet_header_encrypt`/`packet_header_decrypt` byte-exact dùng **SPECK-128/128** + **block-Pearson** mới trong
  [Crypto](../TqkLibrary.VpnClient.Crypto) (key SPECK = `pearson128(community)`, IV key = `pearson128(key)`; **lưu ý n2n
  dùng Pearson-128 no-table — KHÔNG phải Pearson-256/bảng 256-byte như giả định ban đầu**). **Golden vector từ n2n v3.1.1
  `libn2n.a` TRƯỚC khi live** (decrypt golden recover cleartext+stamp; encrypt với random captured reproduce golden byte-
  exact). Validate live vs n2n v3.1.1 `-H`: supernode chấp nhận REGISTER mã hóa + ICMP 2 chiều + header ciphertext on-wire.
- **Transform key-derivation KHÔNG hiện thực**: `N2nAesTransform` nhận AES key sẵn (16/24/32B); n2n derive key bằng
  Pearson của password (transform stretch out of scope). Validate transform dùng NULL (header-enc đã ON live).
- **Driver runtime (phase b) XONG** ([`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n)): UDP transport + REGISTER_SUPER
  lifecycle + keepalive + ghép `IEthernetChannel` vào L2 fabric (ARP + VirtualHost static-IP) + supervisor F.6 + `UseN2n`
  + demo scheme `.n2n` + **header-enc `-H`** — **VALIDATE LIVE L2 full-tunnel ICMP 2 chiều** vs n2n v3.1.1 (3 bug interop
  keepalive-auth + dev_addr-static + timestamp-left-bound sửa qua live). **Còn lại (future)**: P2P UDP hole-punching (QUERY_PEER/PEER_INFO).
- Mỗi type 1 file; instance method (codec/transform) sau interface (`IN2nTransform`). Codec stateless.
