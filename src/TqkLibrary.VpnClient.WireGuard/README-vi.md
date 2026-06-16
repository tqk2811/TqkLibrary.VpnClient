# TqkLibrary.VpnClient.WireGuard

Thư viện **protocol WireGuard** thuần .NET — hiện thực handshake `Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s` (initiation + response + transport keys), timestamp TAI64N và codec gói type-1/type-2 đúng từng byte. Đây là project protocol-level cho driver **V.3** (đang xây theo phase, xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.3).

> **Trạng thái:** **V3.a (NoiseSymmetricState, ở [Crypto](../TqkLibrary.VpnClient.Crypto)) + V3.b handshake Noise_IKpsk2 + V3.c mac1/mac2 + cookie-reply xong.** Đã có: (1) [`WireGuardConstants`](WireGuardConstants.cs#L17) — hằng `CONSTRUCTION`/`IDENTIFIER` (re-export từ `NoiseSymmetricState` để không lệch) + `LABEL_MAC1`/`LABEL_COOKIE` + kích thước/offset gói; (2) [`WireGuardTai64n`](Handshake/WireGuardTai64n.cs#L19) — encode thời điểm thành timestamp TAI64N 12B (8B giây TAI big-endian + 4B nanosecond) + `Compare` đơn điệu; (3) [`WireGuardMessageCodec`](Handshake/WireGuardMessageCodec.cs#L13) — dựng/đọc gói type-1 initiation (148B) + type-2 response (92B) + **type-3 cookie-reply (64B)** đúng từng byte, cộng `ApplyMacs`/`VerifyMac1`/`ReadMac1` thao tác mac1/mac2 in-place trên buffer đã encode; (4) [`WireGuardHandshake`](Handshake/WireGuardHandshake.cs#L23) — chạy 1 phía handshake (initiator `CreateInitiation`→`ConsumeResponse`, responder `ConsumeInitiation`→`CreateResponse`) + `DeriveTransportKeys` (Split + hoán đổi theo role) + **wire mac/cookie** (`StampOutgoingMacs`/`VerifyIncomingMac1`/`CreateCookieReply`/`ConsumeCookieReply`), tái dùng nguyên `NoiseSymmetricState` (V3.a) + `Curve25519DhGroup` (F.4) + `ChaCha20Poly1305Cipher`; (5) [`WireGuardMac`](Handshake/WireGuardMac.cs#L24) — keyed-BLAKE2s-128 cho mac1/mac2 (so sánh constant-time); (6) [`WireGuardCookie`](Handshake/WireGuardCookie.cs#L21) — cookie `MAC(secret, addr)` + cookie-reply XChaCha20-Poly1305 (build/read). **Chưa**: data channel type-4 + counter nonce + anti-replay (V3.d), timers/state machine (V3.e), UDP transport + driver + config tĩnh end-to-end (V3.f).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [OpenVpn](../TqkLibrary.VpnClient.OpenVpn)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)/[L2tp](../TqkLibrary.VpnClient.L2tp)): các khối giao thức thuần, **không** I/O socket — driver `Drivers.WireGuard` (V3.f, chưa có) sẽ lắp ráp thành tunnel sống. Handshake là **state machine đối xứng thuần** (không socket/timer): driver bơm gói vào/ra, test chạy initiator↔responder cùng tiến trình.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`NoiseSymmetricState`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs) (V3.a), [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs)/[`HmacBlake2sPrf`](../TqkLibrary.VpnClient.Crypto/Noise/HmacBlake2sPrf.cs)/[`Blake2s`](../TqkLibrary.VpnClient.Crypto/Noise/Blake2s.cs)/[`Blake2sKeyedMac`](../TqkLibrary.VpnClient.Crypto/Noise/Blake2sKeyedMac.cs) (F.4), [`ChaCha20Poly1305Cipher`](../TqkLibrary.VpnClient.Crypto/Aead/ChaCha20Poly1305Cipher.cs), [`XChaCha20Poly1305Cipher`](../TqkLibrary.VpnClient.Crypto/Aead/XChaCha20Poly1305Cipher.cs) (V3.c cookie-reply) |
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | (chuẩn bị cho V3.d–f: `TunnelConfig`, `IDatagramTransport`, `IPacketChannel`) |
| Được dùng bởi | `Drivers.WireGuard` (V3.f, **chưa có**) | driver lắp ráp control/data plane |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.WireGuard/
├─ WireGuardConstants.cs              Hằng CONSTRUCTION/IDENTIFIER/LABEL_MAC1/LABEL_COOKIE + kích thước/offset gói + message type 1–4
└─ Handshake/
   ├─ WireGuardTai64n.cs             Encode thời điểm → TAI64N 12B (8B giây TAI BE + 4B ns BE) + Compare đơn điệu
   ├─ WireGuardMessageCodec.cs       Dựng/đọc gói type-1 (148B) + type-2 (92B) + type-3 cookie-reply (64B) + mac1/mac2 in-place
   ├─ WireGuardHandshake.cs          State machine Noise_IKpsk2 1 phía + DeriveTransportKeys (Split) + wire mac/cookie
   ├─ WireGuardMac.cs                keyed-BLAKE2s-128 mac1 (key HASH(LABEL_MAC1‖pub)) + mac2 (key cookie), so sánh constant-time
   ├─ WireGuardCookie.cs             cookie MAC(secret, addr) + cookie-reply XChaCha20-Poly1305 (CreateReply/TryReadCookie)
   └─ Models/
      ├─ WireGuardInitiationMessage.cs  POCO gói type-1 (sender, ephemeral, enc_static, enc_timestamp, mac1, mac2)
      ├─ WireGuardResponseMessage.cs    POCO gói type-2 (sender, receiver, ephemeral, enc_empty, mac1, mac2)
      ├─ WireGuardCookieReplyMessage.cs POCO gói type-3 (receiver, nonce 24B, encrypted_cookie 16+16)
      ├─ WireGuardKeyPair.cs            Cặp khóa X25519 (private 32 + public 32)
      └─ WireGuardTransportKeys.cs      Cặp transport key cuối handshake (send/receive 32B mỗi chiều)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `WireGuardConstants` | hằng `CONSTRUCTION`/`IDENTIFIER` (re-export `NoiseSymmetricState`) + `LabelMac1`/`LabelCookie`; kích thước (`KeyLength`/`TagLength`/`TimestampLength`/`MacLength`/`IndexLength`); message type 1–4; `InitiationMessageLength`(148)/`ResponseMessageLength`(92) | [WireGuardConstants.cs:17](WireGuardConstants.cs#L17) |
| `WireGuardTai64n` | encode TAI64N: `Now()`/`Encode(instant)` ra 12B (giây TAI base `0x400000000000000A` BE + ns BE), `Compare` lexicographic đơn điệu | [Handshake/WireGuardTai64n.cs:19](Handshake/WireGuardTai64n.cs#L19) |
| `WireGuardMessageCodec` | `EncodeInitiation`/`TryDecodeInitiation` (type-1) + `EncodeResponse`/`TryDecodeResponse` (type-2) + `EncodeCookieReply`/`TryDecodeCookieReply` (type-3, 64B); `ApplyMacs`/`VerifyMac1`/`ReadMac1` thao tác mac1/mac2 in-place; `InitiationMaccedLength`/`ResponseMaccedLength`/`CookieReplyMessageLength` | [Handshake/WireGuardMessageCodec.cs:13](Handshake/WireGuardMessageCodec.cs#L13) |
| `WireGuardHandshake` | state machine 1 phía: `CreateInitiation`/`ConsumeResponse` (initiator), `ConsumeInitiation`/`CreateResponse` (responder), `DeriveTransportKeys` (Split + swap theo role); wire mac/cookie `StampOutgoingMacs`/`VerifyIncomingMac1`/`CreateCookieReply`/`ConsumeCookieReply`/`CurrentCookie`; `GenerateKeyPair`/`KeyPairFromPrivate`; ctor nhận static keypair + remote static + PSK + primitive DI | [Handshake/WireGuardHandshake.cs:23](Handshake/WireGuardHandshake.cs#L23) |
| `WireGuardMac` | keyed-BLAKE2s-128 mac1/mac2; `ForRecipient(pub)` tiền-hash `mac1Key=HASH(LABEL_MAC1‖pub)` + `CookieKey=HASH(LABEL_COOKIE‖pub)`; `ComputeMac1`/`VerifyMac1` + `ComputeMac2`/`VerifyMac2` (cookie-keyed), so sánh constant-time | [Handshake/WireGuardMac.cs:22](Handshake/WireGuardMac.cs#L22) |
| `WireGuardCookie` | cookie machinery: `ComputeCookie(secret, addr)` = MAC keyed-BLAKE2s-128; `CreateReply` (responder seal cookie XChaCha20-Poly1305, AAD = mac1) / `TryReadCookie` (initiator mở) ; nonce 24B từ RNG (inject được) | [Handshake/WireGuardCookie.cs:21](Handshake/WireGuardCookie.cs#L21) |
| `WireGuardInitiationMessage` | record gói type-1 đã decode: `SenderIndex`/`UnencryptedEphemeral`/`EncryptedStatic`/`EncryptedTimestamp`/`Mac1`/`Mac2` | [Handshake/Models/WireGuardInitiationMessage.cs:11](Handshake/Models/WireGuardInitiationMessage.cs#L11) |
| `WireGuardResponseMessage` | record gói type-2 đã decode: `SenderIndex`/`ReceiverIndex`/`UnencryptedEphemeral`/`EncryptedNothing`/`Mac1`/`Mac2` | [Handshake/Models/WireGuardResponseMessage.cs:10](Handshake/Models/WireGuardResponseMessage.cs#L10) |
| `WireGuardCookieReplyMessage` | record gói type-3 đã decode: `ReceiverIndex`/`Nonce`(24B)/`EncryptedCookie`(16+16) | [Handshake/Models/WireGuardCookieReplyMessage.cs:11](Handshake/Models/WireGuardCookieReplyMessage.cs#L11) |
| `WireGuardKeyPair` | record cặp khóa X25519 `PrivateKey`(32)/`PublicKey`(32) | [Handshake/Models/WireGuardKeyPair.cs:9](Handshake/Models/WireGuardKeyPair.cs#L9) |
| `WireGuardTransportKeys` | record cặp transport key cuối handshake `SendKey`/`ReceiveKey` (32B); chéo nhau giữa 2 peer | [Handshake/Models/WireGuardTransportKeys.cs:11](Handshake/Models/WireGuardTransportKeys.cs#L11) |

## Wire format (handshake message)

```
Type-1 initiation (148B):
  type(1) | reserved(3) | sender(4 LE) | ephemeral(32) | enc_static(32+16) | enc_timestamp(12+16) | mac1(16) | mac2(16)

Type-2 response (92B):
  type(1) | reserved(3) | sender(4 LE) | receiver(4 LE) | ephemeral(32) | enc_empty(0+16) | mac1(16) | mac2(16)

Type-3 cookie-reply (64B):
  type(1) | reserved(3) | receiver(4 LE) | nonce(24) | encrypted_cookie(16+16)
```

- **type byte** = 1 (initiation) / 2 (response) / 3 (cookie-reply); 3 byte reserved phải 0; index 32-bit **little-endian**.
- `enc_*` = AEAD ChaCha20-Poly1305 (ciphertext || tag 16B), nonce counter 0 (mỗi `MixKey` reset nonce), AAD = transcript hash `h` hiện tại.
- **mac1** = keyed-BLAKE2s-128(`HASH(LABEL_MAC1‖recipient.static_public)`, msg[0:mac1_offset]) — chứng minh người gửi biết public-key người nhận; verify rẻ trước mọi DH (drop nếu sai).
- **mac2** = keyed-BLAKE2s-128(cookie, msg[0:mac2_offset]) khi đã có cookie từ cookie-reply; **0** khi chưa có.
- **cookie-reply** (type-3): `encrypted_cookie = XChaCha20-Poly1305(HASH(LABEL_COOKIE‖responder.static_public), nonce, cookie, AAD=triggering.mac1)`; `cookie = MAC(responder.changing_secret, source_address)` (16B). Initiator giải cookie với mac1 nó vừa gửi làm AAD rồi nạp mac2 cho lần gửi kế.

## Luồng handshake Noise_IKpsk2 (whitepaper §5.4)

Hai phía tái dùng [`NoiseSymmetricState`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs) cho phần đối xứng + [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs) cho DH; class chỉ **xếp thứ tự** mix/DH/AEAD đúng whitepaper. Mỗi `KDF1(ck, x)` của whitepaper hiện thực bằng [`MixKey`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs#L115) (KDF2) — output đầu (chaining key mới) **giống hệt** KDF1, cipher key thừa luôn bị ghi đè trước AEAD kế nên transcript không đổi; bước PSK `KDF3` là [`MixKeyAndHash`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs#L127).

- **Initiation** ([`CreateInitiation`](Handshake/WireGuardHandshake.cs#L96) ↔ [`ConsumeInitiation`](Handshake/WireGuardHandshake.cs#L137)): `InitializeWireGuard` (seed ck/h) → `MixHash(Sresp^pub)` → gen ephemeral, `MixKey(Ei^pub)`+`MixHash(Ei^pub)` → `MixKey(DH(Ei,Sresp))`+`EncryptAndHash(Sinit^pub)` → `MixKey(DH(Sinit,Sresp))`+`EncryptAndHash(TAI64N)`. Responder mở ngược lại, recover được static public + timestamp của initiator (sai tag ⇒ trả false).
- **Response** ([`CreateResponse`](Handshake/WireGuardHandshake.cs#L177) ↔ [`ConsumeResponse`](Handshake/WireGuardHandshake.cs#L207)): gen ephemeral, `MixKey(Er^pub)`+`MixHash(Er^pub)` → `MixKey(DH(Er,Ei))` → `MixKey(DH(Er,Si))` → `MixKeyAndHash(PSK)` → `EncryptAndHash(ε)` (gói rỗng, chỉ tag). Initiator mở `enc_empty` (sai PSK/tag ⇒ false).
- **Transport keys** ([`DeriveTransportKeys`](Handshake/WireGuardHandshake.cs#L250)): `Split` ra (T1, T2); initiator lấy `send=T1, recv=T2`, responder hoán đổi `send=T2, recv=T1` ⇒ `send` bên này = `recv` bên kia.

## Luồng mac1/mac2 + cookie-reply (whitepaper §5.4.4/§5.4.7, V3.c)

DoS-mitigation chồng lên handshake — gắn vào **gói đã encode** chứ không vào transcript:

1. **Gửi**: encode gói (`EncodeInitiation`/`EncodeResponse`) → [`StampOutgoingMacs`](Handshake/WireGuardHandshake.cs#L266) gọi [`WireGuardMessageCodec.ApplyMacs`](Handshake/WireGuardMessageCodec.cs) — stamp mac1 (key của **peer**) lên `msg[0:mac1]`, mac2 lên `msg[0:mac2]` nếu đã có cookie (ngược lại để 0), lưu lại mac1 vừa gửi để khớp cookie-reply.
2. **Nhận**: [`VerifyIncomingMac1`](Handshake/WireGuardHandshake.cs#L279) verify mac1 bằng key của **chính mình** ([`WireGuardMessageCodec.VerifyMac1`](Handshake/WireGuardMessageCodec.cs)) → sai ⇒ drop trước DH.
3. **Responder quá tải**: [`CreateCookieReply`](Handshake/WireGuardHandshake.cs#L288) tính `cookie=MAC(secret, addr)` rồi seal vào cookie-reply (AAD = mac1 gói kích hoạt) thay vì làm response.
4. **Initiator**: [`ConsumeCookieReply`](Handshake/WireGuardHandshake.cs#L302) mở cookie với mac1 nó vừa gửi làm AAD (sai ⇒ false, không đổi state), cache cookie → lần `StampOutgoingMacs` kế mang mac2 hợp lệ mà responder recompute cùng cookie verify được.

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| WireGuard whitepaper §5.4 | `WireGuardHandshake`/`WireGuardMessageCodec` | "WireGuard: Next Generation Kernel Network Tunnel" — initiation/response/transport keys + format gói |
| WireGuard whitepaper §5.4.4/§5.4.7 | `WireGuardMac`/`WireGuardCookie`/`WireGuardMessageCodec` | mac1/mac2 + cookie-reply (DoS mitigation) |
| Noise Protocol Framework | `NoiseSymmetricState` (V3.a) | `Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s` |
| TAI64N | `WireGuardTai64n` | https://cr.yp.to/libtai/tai64.html — 8B giây TAI + 4B ns |
| X25519 (RFC 7748) | `Curve25519DhGroup` (F.4) | DH 32B |
| ChaCha20-Poly1305 (RFC 8439) | `ChaCha20Poly1305Cipher` | AEAD handshake (nonce counter 0) |
| keyed BLAKE2s (RFC 7693) | `WireGuardMac`/`WireGuardCookie` | mac1/mac2 + cookie = keyed-BLAKE2s-128 |
| XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) | `WireGuardCookie` (qua `XChaCha20Poly1305Cipher`) | seal/open cookie trong cookie-reply (nonce 24B) |

## Trạng thái & ghi chú

- **Thuần protocol**: không I/O, không server. State machine đối xứng — vai trò responder dùng được cả test lẫn (sau này) driver. Đọc spec từ whitepaper WireGuard (**không copy GPL/kernel source**).
- Build xanh cả `netstandard2.0` + `net8.0`. Codec dùng `System.Buffers.Binary.BinaryPrimitives` (cả 2 TFM qua `System.Memory`); `record`/`init`/`required` dùng qua `TqkLibrary.CompilerServices`. TAI64N tính ns từ tick .NET (1 tick = 100 ns) nên độ phân giải tối đa 100 ns — đủ cho mục đích đơn điệu của responder.
- `WireGuardConstants.Construction` re-export `NoiseSymmetricState.Construction` (`Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s`, tên cipher đầy đủ) — đây là hằng **authoritative** seed chaining key; whitepaper viết tắt `ChaChaPoly`. Vì interop V3.b là initiator↔responder cùng hằng nên tự nhất quán; đối chiếu interop với WireGuard kernel/userspace thật chờ lab Q.1.
- Lộ trình V.3 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.3; design-intent crypto Noise ở [`.docs/08`](../../.docs/08-crypto-primitives.md), taxonomy ở [`.docs/02`](../../.docs/02-protocol-taxonomy.md).
