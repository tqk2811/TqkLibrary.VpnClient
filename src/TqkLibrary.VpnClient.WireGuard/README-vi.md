# TqkLibrary.VpnClient.WireGuard

Thư viện **protocol WireGuard** thuần .NET — hiện thực handshake `Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s` (initiation + response + transport keys), timestamp TAI64N, codec gói type-1/type-2 đúng từng byte, **data channel type-4** (transport-data + counter u64 + anti-replay), **state machine timer** (rekey/reject/keepalive theo whitepaper), và **config tĩnh + L3 channel** (`WireGuardConfig`/`WireGuardChannel`) cho driver tiêu thụ. Đây là project protocol-level cho driver **V.3** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.3) — driver lắp ráp ở [`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard).

> **Trạng thái:** **V3.a (NoiseSymmetricState, ở [Crypto](../TqkLibrary.VpnClient.Crypto)) + V3.b handshake Noise_IKpsk2 + V3.c mac1/mac2 + cookie-reply + V3.d data channel type-4 + V3.e timers/state machine + V3.f config tĩnh/L3 channel xong.** Đã có: (1) [`WireGuardConstants`](WireGuardConstants.cs#L17) — hằng `CONSTRUCTION`/`IDENTIFIER` (re-export từ `NoiseSymmetricState` để không lệch) + `LABEL_MAC1`/`LABEL_COOKIE` + kích thước/offset gói; (2) [`WireGuardTai64n`](Handshake/WireGuardTai64n.cs#L19) — encode thời điểm thành timestamp TAI64N 12B (8B giây TAI big-endian + 4B nanosecond) + `Compare` đơn điệu; (3) [`WireGuardMessageCodec`](Handshake/WireGuardMessageCodec.cs#L13) — dựng/đọc gói type-1 initiation (148B) + type-2 response (92B) + **type-3 cookie-reply (64B)** đúng từng byte, cộng `ApplyMacs`/`VerifyMac1`/`ReadMac1` thao tác mac1/mac2 in-place trên buffer đã encode; (4) [`WireGuardHandshake`](Handshake/WireGuardHandshake.cs#L23) — chạy 1 phía handshake (initiator `CreateInitiation`→`ConsumeResponse`, responder `ConsumeInitiation`→`CreateResponse`) + `DeriveTransportKeys` (Split + hoán đổi theo role) + **wire mac/cookie** (`StampOutgoingMacs`/`VerifyIncomingMac1`/`CreateCookieReply`/`ConsumeCookieReply`), tái dùng nguyên `NoiseSymmetricState` (V3.a) + `Curve25519DhGroup` (F.4) + `ChaCha20Poly1305Cipher`; (5) [`WireGuardMac`](Handshake/WireGuardMac.cs#L22) — keyed-BLAKE2s-128 cho mac1/mac2 (so sánh constant-time); (6) [`WireGuardCookie`](Handshake/WireGuardCookie.cs#L21) — cookie `MAC(secret, addr)` + cookie-reply XChaCha20-Poly1305 (build/read); (7) [`WireGuardDataCodec`](DataChannel/WireGuardDataCodec.cs#L17) — dựng/đọc gói transport-data type-4 (header `receiver|counter` + nonce `0^4‖counter LE`); (8) [`WireGuardTransport`](DataChannel/WireGuardTransport.cs#L24) — `Seal`/`TryOpen`/`Keepalive` theo cặp transport key, ChaCha20-Poly1305 AAD rỗng, counter u64 đơn điệu; (9) [`WireGuardReplayProtector`](DataChannel/WireGuardReplayProtector.cs#L19) — anti-replay 64-gói trên counter u64 đầy đủ (tái dùng `AntiReplayWindow` cho 32-bit thấp); (10) [`WireGuardTimers`](WireGuardTimers.cs#L14) — hằng timer whitepaper (Rekey/Reject-After-Time 120s/180s, Rekey-Attempt 90s, Rekey-Timeout 5s, Keepalive-Timeout 10s, Rekey/Reject-After-Messages, persistent-keepalive tùy chọn) ở đơn vị ms; (11) [`WireGuardPeerState`](WireGuardPeerState.cs#L22) — state machine clock-inject (mirror `OpenVpnKeepalive`) quyết định `Evaluate(nowMs)` → [`WireGuardSessionAction`](Enums/WireGuardSessionAction.cs#L8) (cần handshake mới? rekey? phiên chết? resend/abandon handshake? keepalive?); (12) **V3.f config tĩnh + channel**: [`WireGuardConfig`](Config/WireGuardConfig.cs#L18) point-to-point (private key, peer pubkey, PSK tùy chọn, address/DNS, allowed-ips, persistent-keepalive, MTU 1420) + `ToTunnelConfig()` → `TunnelConfig` **tĩnh** (không IPCP/DHCP); [`WireGuardChannel`](Transport/WireGuardChannel.cs#L24) `IPacketChannel` (Medium=Ip, MaxHeaderLength=0) bọc `WireGuardTransport` (`WriteIpPacketAsync`=Seal+send / `Deliver`=TryOpen→raise, drop keepalive rỗng / `SendKeepaliveAsync`; callback `onPacketSealed`/`onPacketReceived` cho driver bơm timer). **Driver** I/O socket + handshake loop nằm ở [`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard) (V3.f).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [OpenVpn](../TqkLibrary.VpnClient.OpenVpn)/[Ipsec](../TqkLibrary.VpnClient.Ipsec)/[L2tp](../TqkLibrary.VpnClient.L2tp)): các khối giao thức thuần, **không** I/O socket — driver `Drivers.WireGuard` (V3.f, chưa có) sẽ lắp ráp thành tunnel sống. Handshake là **state machine đối xứng thuần** (không socket/timer): driver bơm gói vào/ra, test chạy initiator↔responder cùng tiến trình.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`NoiseSymmetricState`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs) (V3.a), [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs)/[`HmacBlake2sPrf`](../TqkLibrary.VpnClient.Crypto/Noise/HmacBlake2sPrf.cs)/[`Blake2s`](../TqkLibrary.VpnClient.Crypto/Noise/Blake2s.cs)/[`Blake2sKeyedMac`](../TqkLibrary.VpnClient.Crypto/Noise/Blake2sKeyedMac.cs) (F.4), [`ChaCha20Poly1305Cipher`](../TqkLibrary.VpnClient.Crypto/Aead/ChaCha20Poly1305Cipher.cs) (handshake + data channel V3.d), [`XChaCha20Poly1305Cipher`](../TqkLibrary.VpnClient.Crypto/Aead/XChaCha20Poly1305Cipher.cs) (V3.c cookie-reply), [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs) (V3.d anti-replay, dùng chung ESP/OpenVPN) |
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `TunnelConfig` (`WireGuardConfig.ToTunnelConfig`), `IPacketChannel`/`LinkMedium` (`WireGuardChannel`) |
| Được dùng bởi | [`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard) (V3.f) | driver lắp ráp control/data plane: UDP transport + handshake loop + timer/rekey/reconnect |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.WireGuard/
├─ WireGuardConstants.cs              Hằng CONSTRUCTION/IDENTIFIER/LABEL_MAC1/LABEL_COOKIE + kích thước/offset gói + message type 1–4 + DefaultMtu 1420
├─ Config/
│  └─ WireGuardConfig.cs             (V3.f) config tĩnh point-to-point (keys/PSK/address/DNS/allowed-ips/keepalive/MTU) + ToTunnelConfig()
├─ Transport/
│  └─ WireGuardChannel.cs            (V3.f) IPacketChannel (Medium=Ip, header 0) bọc WireGuardTransport: Seal/Deliver/SendKeepalive + callback timer
├─ WireGuardTimers.cs                 (V3.e) hằng timer whitepaper (Rekey/Reject-After-Time/-Messages, Rekey-Attempt/Timeout, Keepalive-Timeout, persistent-keepalive) ở ms
├─ WireGuardPeerState.cs             (V3.e) state machine clock-inject: ghi sự kiện phiên + Evaluate(nowMs) → WireGuardSessionAction
├─ Enums/
│  └─ WireGuardSessionAction.cs      (V3.e) hành động state machine: None/SendKeepalive/InitiateHandshake/ResendHandshake/AbandonHandshake/SessionDead
├─ Handshake/
│  ├─ WireGuardTai64n.cs             Encode thời điểm → TAI64N 12B (8B giây TAI BE + 4B ns BE) + Compare đơn điệu
│  ├─ WireGuardMessageCodec.cs       Dựng/đọc gói type-1 (148B) + type-2 (92B) + type-3 cookie-reply (64B) + mac1/mac2 in-place
│  ├─ WireGuardHandshake.cs          State machine Noise_IKpsk2 1 phía + DeriveTransportKeys (Split) + wire mac/cookie
│  ├─ WireGuardMac.cs                keyed-BLAKE2s-128 mac1 (key HASH(LABEL_MAC1‖pub)) + mac2 (key cookie), so sánh constant-time
│  ├─ WireGuardCookie.cs             cookie MAC(secret, addr) + cookie-reply XChaCha20-Poly1305 (CreateReply/TryReadCookie)
│  └─ Models/
│     ├─ WireGuardInitiationMessage.cs  POCO gói type-1 (sender, ephemeral, enc_static, enc_timestamp, mac1, mac2)
│     ├─ WireGuardResponseMessage.cs    POCO gói type-2 (sender, receiver, ephemeral, enc_empty, mac1, mac2)
│     ├─ WireGuardCookieReplyMessage.cs POCO gói type-3 (receiver, nonce 24B, encrypted_cookie 16+16)
│     ├─ WireGuardKeyPair.cs            Cặp khóa X25519 (private 32 + public 32)
│     └─ WireGuardTransportKeys.cs      Cặp transport key cuối handshake (send/receive 32B mỗi chiều)
└─ DataChannel/                       (V3.d) data channel type-4
   ├─ WireGuardDataCodec.cs          Dựng/đọc header type-4 (type|reserved|receiver 4 LE|counter 8 LE) + WriteNonce (0^4‖counter LE)
   ├─ WireGuardTransport.cs          Seal/TryOpen/Keepalive theo cặp transport key (ChaCha20-Poly1305 AAD rỗng, counter u64 từ 0)
   └─ WireGuardReplayProtector.cs    Anti-replay 64-gói trên counter u64 (bọc AntiReplayWindow cho 32-bit thấp + theo dõi high-32)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `WireGuardConstants` | hằng `CONSTRUCTION`/`IDENTIFIER` (re-export `NoiseSymmetricState`) + `LabelMac1`/`LabelCookie`; kích thước (`KeyLength`/`TagLength`/`TimestampLength`/`MacLength`/`IndexLength`); message type 1–4; `InitiationMessageLength`(148)/`ResponseMessageLength`(92); `DefaultMtu`(1420) | [WireGuardConstants.cs:17](WireGuardConstants.cs#L17) |
| `WireGuardConfig` | (V3.f) config tĩnh point-to-point: `PrivateKey`/`PeerPublicKey`/`PresharedKey?` + `Address`/`AddressV6`/`PrefixLength*` + `DnsServers` + `AllowedIps` (mặc định `0.0.0.0/0,::/0`) + `PersistentKeepaliveSeconds` + `Mtu`(1420); `ToTunnelConfig()` → `TunnelConfig` tĩnh (allowed-ips thành routes) | [Config/WireGuardConfig.cs:18](Config/WireGuardConfig.cs#L18) |
| `WireGuardChannel` | (V3.f) `IPacketChannel` (Medium=Ip, MaxHeaderLength=0) bọc `WireGuardTransport`: `WriteIpPacketAsync`=Seal+send, `Deliver`=TryOpen→`InboundIpPacket` (drop payload rỗng=keepalive), `SendKeepaliveAsync`; callback `onPacketSealed`/`onPacketReceived` cho driver bơm timer; một channel = một thế hệ key (rekey thay nguyên qua `SwappablePacketChannel`) | [Transport/WireGuardChannel.cs:24](Transport/WireGuardChannel.cs#L24) |
| `WireGuardTai64n` | encode TAI64N: `Now()`/`Encode(instant)` ra 12B (giây TAI base `0x400000000000000A` BE + ns BE), `Compare` lexicographic đơn điệu | [Handshake/WireGuardTai64n.cs:19](Handshake/WireGuardTai64n.cs#L19) |
| `WireGuardMessageCodec` | `EncodeInitiation`/`TryDecodeInitiation` (type-1) + `EncodeResponse`/`TryDecodeResponse` (type-2) + `EncodeCookieReply`/`TryDecodeCookieReply` (type-3, 64B); `ApplyMacs`/`VerifyMac1`/`ReadMac1` thao tác mac1/mac2 in-place; `InitiationMaccedLength`/`ResponseMaccedLength`/`CookieReplyMessageLength` | [Handshake/WireGuardMessageCodec.cs:13](Handshake/WireGuardMessageCodec.cs#L13) |
| `WireGuardHandshake` | state machine 1 phía: `CreateInitiation`/`ConsumeResponse` (initiator), `ConsumeInitiation`/`CreateResponse` (responder), `DeriveTransportKeys` (Split + swap theo role); wire mac/cookie `StampOutgoingMacs`/`VerifyIncomingMac1`/`CreateCookieReply`/`ConsumeCookieReply`/`CurrentCookie`; `GenerateKeyPair`/`KeyPairFromPrivate`; ctor nhận static keypair + remote static + PSK + primitive DI | [Handshake/WireGuardHandshake.cs:23](Handshake/WireGuardHandshake.cs#L23) |
| `WireGuardMac` | keyed-BLAKE2s-128 mac1/mac2; `ForRecipient(pub)` tiền-hash `mac1Key=HASH(LABEL_MAC1‖pub)` + `CookieKey=HASH(LABEL_COOKIE‖pub)`; `ComputeMac1`/`VerifyMac1` + `ComputeMac2`/`VerifyMac2` (cookie-keyed), so sánh constant-time | [Handshake/WireGuardMac.cs:22](Handshake/WireGuardMac.cs#L22) |
| `WireGuardCookie` | cookie machinery: `ComputeCookie(secret, addr)` = MAC keyed-BLAKE2s-128; `CreateReply` (responder seal cookie XChaCha20-Poly1305, AAD = mac1) / `TryReadCookie` (initiator mở) ; nonce 24B từ RNG (inject được) | [Handshake/WireGuardCookie.cs:21](Handshake/WireGuardCookie.cs#L21) |
| `WireGuardDataCodec` | codec gói transport-data type-4: `WriteHeader`/`TryReadHeader` (type|reserved|receiver 4 LE|counter 8 LE) + `WriteNonce` (nonce 12B = `0^4‖counter 8 LE`); `HeaderLength`16/`MinimumLength`32/`NonceLength`12; length/type/reserved sai ⇒ false | [DataChannel/WireGuardDataCodec.cs:17](DataChannel/WireGuardDataCodec.cs#L17) |
| `WireGuardTransport` | data channel stateful theo `WireGuardTransportKeys`: `Seal`(counter u64 từ 0, ChaCha20-Poly1305 AAD rỗng, overflow⇒ném)/`TryOpen`(kiểm receiver-index→anti-replay→AEAD)/`Keepalive`(payload rỗng); `SentPacketCount`/`HighestReceivedCounter`; cipher mặc định ChaCha20-Poly1305 | [DataChannel/WireGuardTransport.cs:24](DataChannel/WireGuardTransport.cs#L24) |
| `WireGuardReplayProtector` | anti-replay 64-gói trên counter u64 đầy đủ: `Check`/`Commit`/`Highest`; bọc `AntiReplayWindow` (Crypto) cho 32-bit thấp (counter 0-based → window 1-based) + tự theo dõi high-32 (epoch tiến⇒reset, epoch cũ⇒replay) | [DataChannel/WireGuardReplayProtector.cs:19](DataChannel/WireGuardReplayProtector.cs#L19) |
| `WireGuardTimers` | hằng timer whitepaper §6.2 ở ms: `RekeyAfterTimeMs`(120s)/`RejectAfterTimeMs`(180s)/`RekeyAttemptTimeMs`(90s)/`RekeyTimeoutMs`(5s)/`KeepaliveTimeoutMs`(10s) + `RekeyAfterMessages`(2⁶⁰)/`RejectAfterMessages`(2⁶⁴−2¹³−1) + `PersistentKeepaliveMs`(0=tắt); bất biến, override được cho test; `Default` singleton | [WireGuardTimers.cs:14](WireGuardTimers.cs#L14) |
| `WireGuardPeerState` | state machine timer clock-inject (mirror `OpenVpnKeepalive`): ghi sự kiện `OnHandshakeInitiated`/`OnHandshakeCompleted`/`OnDataSent`/`OnDataReceived`/`Reset`; quyết định thuần `NeedsHandshake`/`NeedsRekey`/`IsSessionDead`/`ShouldResendHandshake`/`ShouldAbandonHandshake`/`ShouldSendKeepalive`/`SessionAge` + `Evaluate(nowMs)` chọn 1 `WireGuardSessionAction` theo độ khẩn; jitter resend inject qua delegate (mặc định 0); không giữ key/crypto, không thread-safe | [WireGuardPeerState.cs:22](WireGuardPeerState.cs#L22) |
| `WireGuardSessionAction` | enum hành động state machine: `None`/`SendKeepalive`/`InitiateHandshake`/`ResendHandshake`/`AbandonHandshake`/`SessionDead` | [Enums/WireGuardSessionAction.cs:8](Enums/WireGuardSessionAction.cs#L8) |
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

Type-4 transport-data (16 + N + 16):
  type(1) | reserved(3) | receiver(4 LE) | counter(8 LE) | enc_packet(N+16)
  nonce(12) = 0^4 ‖ counter(8 LE)     (4 byte 0 rồi counter little-endian)
  AAD       = ∅                        (rỗng)
```

- **type byte** = 1 (initiation) / 2 (response) / 3 (cookie-reply) / 4 (transport-data); 3 byte reserved phải 0; index 32-bit **little-endian**.
- **transport-data** (type-4): `receiver` = sender-index phía nhận đã quảng cáo trong handshake (để định tuyến session); `counter` = u64 little-endian đơn điệu **từ 0**, vừa là trường wire vừa là phần đếm của nonce nên **không bao giờ lặp** cho một key (overflow ⇒ ném, phải rekey trước). `enc_packet` = ChaCha20-Poly1305(send-key, nonce, inner-packet, AAD=∅) → ciphertext‖tag16; **keepalive** = payload rỗng ⇒ `enc_packet` chỉ còn tag (gói 32B). Anti-replay 64-gói trên counter u64 đầy đủ.
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

## Luồng data channel type-4 (whitepaper §5.4.6, V3.d)

Sau handshake, mỗi phía dựng một [`WireGuardTransport`](DataChannel/WireGuardTransport.cs#L24) trên cặp [`WireGuardTransportKeys`](Handshake/Models/WireGuardTransportKeys.cs#L11) từ `Split` (send-key bên này = receive-key bên kia). State machine đối xứng thuần, không socket:

1. **Gửi** ([`Seal`](DataChannel/WireGuardTransport.cs#L70)): lấy `counter` u64 hiện tại (đơn điệu từ 0, overflow ⇒ ném), [`WireGuardDataCodec.WriteHeader`](DataChannel/WireGuardDataCodec.cs#L39) ghi `type 4|reserved|receiver(peer-index)|counter LE`, `WriteNonce` ra `0^4‖counter LE`, rồi ChaCha20-Poly1305 seal inner-packet với **AAD rỗng** → ciphertext‖tag sau header. [`Keepalive`](DataChannel/WireGuardTransport.cs#L96) = `Seal(empty)`.
2. **Nhận** ([`TryOpen`](DataChannel/WireGuardTransport.cs#L104)): `TryReadHeader` (length/type/reserved sai ⇒ drop) → kiểm `receiver` == index của mình → [`WireGuardReplayProtector.Check`](DataChannel/WireGuardReplayProtector.cs#L32) (replay/ngoài cửa sổ ⇒ drop) → ChaCha20-Poly1305 open (tag sai ⇒ drop) → `Commit` counter. Keepalive mở ra payload rỗng (caller không forward).
3. **Anti-replay u64** ([`WireGuardReplayProtector`](DataChannel/WireGuardReplayProtector.cs#L19)): vì [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L7) (dùng chung ESP/OpenVPN) chỉ nhận `uint` và đánh số từ 1, protector ánh xạ counter-0-based → window-1-based (`low+1`) trong một **epoch** high-32 và tự theo dõi high-32: epoch tiến (counter vượt 2³²) ⇒ reset window mới; epoch cũ ⇒ luôn loại như replay. Thực tế WG rekey trước `2⁶⁰` gói nên epoch hầu như không đổi, nhưng vẫn đúng spec u64.

## Luồng timers + state machine (whitepaper §6.2, V3.e)

[`WireGuardPeerState`](WireGuardPeerState.cs#L22) là **state machine thuần clock-inject** (mirror [`OpenVpnKeepalive`](../TqkLibrary.VpnClient.OpenVpn/DataChannel/OpenVpnKeepalive.cs#L11): mỗi quyết định nhận `nowMs` ms đơn điệu) — driver bơm từ timer, test chạy offline xác định. Ngưỡng lấy từ [`WireGuardTimers`](WireGuardTimers.cs#L14). Class **không** giữ key/crypto, chỉ quyết định *khi nào* gọi handshake/keepalive.

1. **Ghi sự kiện**: [`OnHandshakeInitiated`](WireGuardPeerState.cs#L74) (lần đầu của một lượt khởi tạo `REKEY_ATTEMPT_TIME` clock; lần sau chỉ refresh `REKEY_TIMEOUT` resend clock + jitter), [`OnHandshakeCompleted`](WireGuardPeerState.cs#L89) (phiên mới bắt đầu, reset đếm gói), [`OnDataSent`](WireGuardPeerState.cs#L101)/[`OnDataReceived`](WireGuardPeerState.cs#L112) (cập nhật last-send/last-recv; nhận data ⇒ nợ passive keepalive sau `KEEPALIVE_TIMEOUT` nếu không gửi lại), [`Reset`](WireGuardPeerState.cs#L123) (sau teardown/give-up).
2. **Quyết định thuần** (hàm của `now` + sự kiện đã ghi): [`NeedsRekey`](WireGuardPeerState.cs#L137) (phiên ≥ `REKEY_AFTER_TIME` 120s **hoặc** đếm gói ≥ `REKEY_AFTER_MESSAGES`), [`IsSessionDead`](WireGuardPeerState.cs#L142) (≥ `REJECT_AFTER_TIME` 180s hoặc `REJECT_AFTER_MESSAGES`), [`NeedsHandshake`](WireGuardPeerState.cs#L147) (chưa có phiên/cần rekey/phiên chết và không có handshake đang bay), [`ShouldResendHandshake`](WireGuardPeerState.cs#L151) (đang bay + qua `REKEY_TIMEOUT` 5s+jitter), [`ShouldAbandonHandshake`](WireGuardPeerState.cs#L155) (đang bay + qua `REKEY_ATTEMPT_TIME` 90s ⇒ bỏ cuộc, teardown), [`ShouldSendKeepalive`](WireGuardPeerState.cs#L162) (persistent-keepalive đúng nhịp khi bật, hoặc passive keepalive đến hạn).
3. **`Evaluate(nowMs)`** ([WireGuardPeerState.cs:175](WireGuardPeerState.cs#L175)) chọn **một** [`WireGuardSessionAction`](Enums/WireGuardSessionAction.cs#L8) theo độ khẩn: handshake đang bay ⇒ `AbandonHandshake` > `ResendHandshake` > `None`; không bay ⇒ `InitiateHandshake` (cold/rekey/dead) > `SessionDead` > `SendKeepalive` > `None`.

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| WireGuard whitepaper §5.4 | `WireGuardHandshake`/`WireGuardMessageCodec` | "WireGuard: Next Generation Kernel Network Tunnel" — initiation/response/transport keys + format gói |
| WireGuard whitepaper §5.4.4/§5.4.7 | `WireGuardMac`/`WireGuardCookie`/`WireGuardMessageCodec` | mac1/mac2 + cookie-reply (DoS mitigation) |
| WireGuard whitepaper §6.2 (+ reference `timers.c`) | `WireGuardTimers`/`WireGuardPeerState` | Rekey/Reject-After-Time 120s/180s, Rekey-Attempt 90s, Rekey-Timeout 5s+jitter, Keepalive-Timeout 10s, Rekey/Reject-After-Messages, persistent/passive keepalive |
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
