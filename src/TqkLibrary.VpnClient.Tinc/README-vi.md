# TqkLibrary.VpnClient.Tinc

Thư viện **protocol tinc 1.1** thuần .NET — hiện thực **SPTPS** (Simple Peer-to-Peer Security): handshake
**KEX → SIG** (**ECDH có khóa Ed25519** kiểu tinc + chữ ký Ed25519 + key expansion **TLS-1.0 P_hash XOR HMAC-SHA-512**),
**record cipher ChaCha-Poly1305 biến thể tinc** (KHÔNG phải RFC 8439), codec **meta-connection** (request line TCP),
**base64 little-endian phi chuẩn của tinc** và parser **host-config / khóa Ed25519**. Đây là project protocol-level cho
driver **V.7.2** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.2). Driver runtime (TCP meta auto-mesh, UDP
data, bảng route, `IPacketChannel`/`IEthernetChannel`, supervisor F.6) là phase (b) — **chưa làm**.

> **Trạng thái:** **phase (a) protocol XONG + VALIDATE LIVE SPTPS handshake & record layer với `tincd` 1.1pre18 THẬT**
> (2026-06-24) — 35 test offline xanh, build xanh ns2.0 + net8. tincd báo `server SIG VERIFIED` và client giải mã đúng
> record meta đầu của server (ACK request) qua record layer mã hóa. Lab + harness ở [`lab/tinc`](../../lab/tinc).
> **4 bug interop self-pair offline KHÔNG bắt đã được phát hiện & sửa qua live** (xem mục Trạng thái cuối file).
> **Tái dùng** [`Ed25519Signer`](../TqkLibrary.VpnClient.Crypto/Noise/Ed25519Signer.cs#L15) (KEX SIG) +
> BouncyCastle `Ed25519`/`X25519` (ECDH có khóa Ed25519, qua [`SptpsEcdh`](Sptps/SptpsEcdh.cs#L33)) +
> [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L8) (data plane). Cipher ChaCha-Poly1305
> biến thể tinc tự viết trên BouncyCastle `ChaChaEngine` + `Poly1305` (nền cipher đã KAT chuẩn djb/RFC 8439).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[Nebula](../TqkLibrary.VpnClient.Nebula)):
các khối giao thức thuần, **không** I/O socket. Handshake SPTPS là **state machine đối xứng thuần** (driver bơm
record vào/ra; test + harness chạy initiator↔responder/tincd). Khác Nebula: KHÔNG dùng Noise — SPTPS là sơ đồ riêng
kiểu TLS rút gọn (KEX/SIG/ACK record, **TLS-1.0 P_hash XOR** HMAC-SHA-512), **ECDH có khóa Ed25519** (public Edwards trên
wire, shared qua ladder Montgomery — KHÔNG phải X25519 thuần), cipher **ChaCha-Poly1305 phi chuẩn** (nonce = seqno
8-byte BE kiểu djb, tag chỉ trên ciphertext — không AAD/độn-độ-dài như RFC 8439).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`ISignatureAlgo`](../TqkLibrary.VpnClient.Crypto/Interfaces/ISignatureAlgo.cs)/[`Ed25519Signer`](../TqkLibrary.VpnClient.Crypto/Noise/Ed25519Signer.cs#L15) (ký/verify SIG), [`IDhGroup`](../TqkLibrary.VpnClient.Crypto/Interfaces/IDhGroup.cs) (interface ECDH cho [`SptpsEcdh`](Sptps/SptpsEcdh.cs#L33)), [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L8) (replay UDP data), `BouncyCastle` `Ed25519`/`X25519` (ECDH có khóa Ed25519), `ChaChaEngine`/`Poly1305` (record cipher), `HMACSHA512` BCL (PRF) |
| Được dùng bởi | [`Drivers.Tinc`](../TqkLibrary.VpnClient.Drivers.Tinc) (V.7.2 phase b — XONG) | driver lắp ráp TCP meta + data-plane SPTPS + UDP data quanh các codec/handshake này (`BuildMetaLabel`/`BuildUdpLabel`, `SptpsRecordLayer` meta, `SptpsDatagramRecordLayer` data + handshake framing, `TincMetaRequest`, `TincHostConfig`/`TincBase64`) |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Tinc/
├─ Sptps/
│  ├─ SptpsConstants.cs            hằng wire (version/ECDH/sig size/cipher key/"key expansion")
│  ├─ SptpsHandshake.cs            state machine SPTPS 1 phía (CreateKex/ConsumeKex/CreateSig/ConsumeSig + keys)
│  ├─ SptpsEcdh.cs                 ECDH có khóa Ed25519 kiểu tinc (public Edwards, shared = X25519 ladder trên Montgomery-x)
│  ├─ SptpsPrf.cs                  TLS-1.0 P_hash XOR HMAC-SHA-512 key expansion (2 HMAC/khối, XOR-fold vào output)
│  ├─ TincChaChaPoly1305.cs        record cipher biến thể tinc (nonce seqno 8B BE djb, poly key block0, tag-on-ciphertext)
│  ├─ SptpsRecordLayer.cs          framing TCP stream (len(2)‖type‖data; mã hóa sau handshake; seqno đếm CẢ handshake record)
│  ├─ SptpsDatagramRecordLayer.cs  framing UDP data (seqno(4 BE)‖encrypt(type‖data)‖tag(16); anti-replay)
│  ├─ Enums/
│  │  ├─ SptpsRecordType.cs        Handshake=128/Alert=129/Close=130
│  │  └─ SptpsDecodeResult.cs      Ok/NeedMore/AuthFailed
│  └─ Models/SptpsKex.cs           KEX 65B = version(1)‖nonce(32)‖pubkey(32)
├─ Meta/
│  ├─ TincMetaRequest.cs           codec request line ("0 name 17.7\n", ADD_EDGE/ADD_SUBNET/ACK…)
│  └─ Enums/TincRequestType.cs     request_t (ID=0…MTU_INFO=23, protocol.h)
└─ Hosts/
   ├─ TincBase64.cs                base64 little-endian phi chuẩn của tinc (b64encode/b64decode) — KHÁC RFC 4648
   └─ TincHostConfig.cs            parse hosts/<name>: Ed25519PublicKey (base64 tinc 32B)/Address/Port/Subnet, skip RSA PEM
```

## Bảng type chính

| Type | Vai trò |
|------|---------|
| [`SptpsHandshake`](Sptps/SptpsHandshake.cs#L20) | KEX→SIG→derive: tạo/đọc KEX, ký/verify SIG (transcript `fill_msg`), seed KDF, tách khóa hướng |
| [`SptpsEcdh`](Sptps/SptpsEcdh.cs#L33) | ECDH có khóa Ed25519 kiểu tinc (`IDhGroup`): public = Ed25519 Edwards, shared = X25519 ladder trên Edwards→Montgomery-x |
| [`SptpsPrf`](Sptps/SptpsPrf.cs#L29) | TLS-1.0 P_hash XOR HMAC-SHA-512 — expand shared secret + seed → 128B key material |
| [`TincChaChaPoly1305`](Sptps/TincChaChaPoly1305.cs#L21) | cipher record (Encrypt/Decrypt theo seqno; biến thể tinc, không RFC 8439) |
| [`SptpsRecordLayer`](Sptps/SptpsRecordLayer.cs#L14) | record TCP stream (handshake plaintext + app encrypted, seqno đếm cả handshake record) |
| [`SptpsDatagramRecordLayer`](Sptps/SptpsDatagramRecordLayer.cs#L22) | record UDP data plane (seqno prefix + replay window) + handshake framing plaintext (`EncodeHandshake`/`DecodeHandshake`) cho data-plane SPTPS |
| [`SptpsKex`](Sptps/Models/SptpsKex.cs#L8) | codec KEX 65B |
| [`TincMetaRequest`](Meta/TincMetaRequest.cs#L13) | codec request line meta (ID/ADD_EDGE/…) |
| [`TincBase64`](Hosts/TincBase64.cs#L15) | base64 little-endian phi chuẩn của tinc (encode/decode khóa host file) |
| [`TincHostConfig`](Hosts/TincHostConfig.cs#L11) | parse host file (Ed25519PublicKey/Address/Subnet) qua [`TincBase64`](Hosts/TincBase64.cs#L15) |

## Bảng chuẩn / behavior tinc (clean-room — đọc spec + behavior, KHÔNG copy GPL)

| Hạng mục | Giá trị (tinc 1.1pre18, suite Ed25519/Curve25519) — **đối chiếu live `sptps.c`/`prf.c`/`ecdh.c`/`key_exchange.c`/`utils.c`** |
|----------|----------------------------------------------|
| ECDH | **Ed25519-keyed** (orlp `ed25519_create_keypair`/`ed25519_key_exchange`): KEX public = Ed25519 **Edwards** (32B); shared = X25519 Montgomery ladder với scalar `clamp(SHA512(seed)[0..32])` trên `montgomeryX = (1+y)/(1−y) mod p` của peer pubkey. **KHÔNG phải X25519 thuần.** |
| Chữ ký | Ed25519 (orlp = RFC 8032-compatible), `ECDSA_SIZE`=64; ký từ **seed 32B** (file `ed25519_key.priv` của tinc là expanded 96B) |
| Cipher | ChaCha-Poly1305 biến thể tinc, key 64B (`CHACHA_POLY1305_KEYLEN`) |
| PRF | **TLS-1.0 P_hash XOR-fold** trên HMAC-SHA-512 (`prf_xor`) — 2 HMAC/khối, XOR vào output |
| KEX (65B) | `version(0) ‖ nonce(32) ‖ pubkey(32)` |
| SIG transcript | `fill_msg`: `initiator_flag(1) ‖ kex0(65) ‖ kex1(65) ‖ label`; ký dùng `my_kex` trước, verify peer dùng `his_kex` trước + cờ đảo |
| KDF seed | `"key expansion"(13, không NUL) ‖ initiator_nonce(32) ‖ responder_nonce(32) ‖ label` |
| PRF expand | `A[0]=zeros(64)`; mỗi khối: `A[n]=HMAC(secret, A[n-1]‖seed)` (inner) + `block=HMAC(secret, A[n]‖seed)` (outer); output (pre-zero) `^=` block |
| Key split | initiator out=key1/in=key0; responder out=key0/in=key1 (set ở `receive_ack`/`set_state`) |
| Cipher nonce | seqno (uint64) big-endian vào IV 8-byte djb; poly key = keystream block 0; message từ counter 1; tag = Poly1305(ciphertext) |
| Record TCP | `len(2 BE) ‖ type(1)` (handshake plaintext) / `len(2 BE) ‖ encrypt(type‖data) ‖ tag(16)` (sau handshake). **Mọi record (gồm KEX/SIG plaintext) tăng seqno** → record mã hóa đầu = seqno 2 |
| Record UDP | `seqno(4 BE) ‖ encrypt(seqno, type‖data) ‖ tag(16)`, overhead 21 |
| Meta flow | TCP → ID cleartext `"0 <name> 17.7\n"` → đọc peer ID → SPTPS (outgoing = initiator); label `"tinc TCP key expansion <init> <resp>"` + NUL (labellen = 25+len(init)+len(resp), gồm NUL) |
| Request codes | ID=0, METAKEY=1, …, ADD_SUBNET=10, ADD_EDGE=12, KEY_CHANGED=14, …, MTU_INFO=23 (protocol.h) |
| Host file | `Ed25519PublicKey` = **base64 little-endian phi chuẩn của tinc** (`TincBase64`, KHÁC RFC 4648), không padding (43 ký tự = 32B); `Address`/`Port`/`Subnet`; bỏ qua RSA PEM legacy |

## Luồng SPTPS handshake (initiator = client của ta)

1. [`CreateKex`](Sptps/SptpsHandshake.cs#L77) → ephemeral **Ed25519** (Edwards public) + nonce → gửi KEX (record handshake plaintext).
2. Nhận KEX server → [`ConsumeKex`](Sptps/SptpsHandshake.cs#L92): [`SptpsEcdh`](Sptps/SptpsEcdh.cs#L33) shared secret (Edwards→Montgomery ladder) + [`SptpsPrf.Expand`](Sptps/SptpsPrf.cs#L29) → 128B key material.
3. [`CreateSig`](Sptps/SptpsHandshake.cs#L104) → Ed25519 ký transcript `[1‖my_kex‖his_kex‖label]` → gửi SIG.
4. Nhận SIG server → [`ConsumeSig`](Sptps/SptpsHandshake.cs#L116): verify `[0‖server_kex‖client_kex‖label]` bằng pubkey server.
5. [`EnableEncryption`](Sptps/SptpsRecordLayer.cs#L30) với [`OutCipherKey`](Sptps/SptpsHandshake.cs#L128)/[`InCipherKey`](Sptps/SptpsHandshake.cs#L131) → record app mã hóa 2 chiều (record đầu = seqno 2, sau KEX+SIG).

## Trạng thái & ghi chú

- **Phase (a) protocol**: XONG + **VALIDATE LIVE** với `tincd` 1.1pre18 THẬT (Docker VM). 35 test offline (handshake
  self-interop + crossed keys, cipher round-trip/tamper/seqno, record TCP/UDP framing + replay, KEX codec, PRF, meta/host
  codec, **KAT ChaCha20 djb + Poly1305 chuẩn**, **+5 KAT interop golden từ live**: TincBase64 vs RFC 4648, SptpsEcdh
  Edwards/symmetric, SptpsPrf khớp key material tincd thật).
- **Live (2026-06-24)**: harness initiator → `tincd` (`ExperimentalProtocol`, SPTPS-only) ⇒ **`server SIG VERIFIED`** +
  client **giải mã đúng record meta đầu** server gửi (ACK request `4 655 N 0x700000c`) qua record layer mã hóa. Lab
  [`lab/tinc`](../../lab/tinc) build tinc 1.1pre18 từ source (apt chỉ có 1.0.36 không SPTPS).
- **4 bug interop self-pair offline KHÔNG bắt — phát hiện & sửa qua live** (đối chiếu source tinc, không copy GPL):
  1. **`TincBase64`** — tinc dùng base64 **little-endian per-quad** (`utils.c`), KHÁC RFC 4648. Dùng `Convert.*Base64*`
     làm `tincd` decode pubkey ra khóa khác ⇒ `Failed to verify SIG`. Sửa: codec [`TincBase64`](Hosts/TincBase64.cs#L15).
  2. **`SptpsEcdh`** — KEX KHÔNG phải X25519 thuần mà là **ECDH có khóa Ed25519** (public Edwards trên wire, shared qua
     ladder Montgomery với scalar `clamp(SHA512(seed))`; `ecdh.c`/`key_exchange.c`). X25519 thuần cho shared secret khác
     ⇒ record cipher fail (SIG vẫn pass vì không đụng shared). Sửa: [`SptpsEcdh`](Sptps/SptpsEcdh.cs#L33).
  3. **`SptpsPrf`** — key expansion là **TLS-1.0 P_hash XOR-fold** (`prf_xor`, 2 HMAC/khối), KHÔNG phải TLS-1.2 (1 HMAC,
     copy). Sửa: [`SptpsPrf`](Sptps/SptpsPrf.cs#L29).
  4. **seqno record TCP** — `send_record_priv` tăng seqno cho **MỌI** record kể cả KEX/SIG plaintext ⇒ record mã hóa đầu
     = seqno 2. Sửa: [`SptpsRecordLayer`](Sptps/SptpsRecordLayer.cs#L14) đếm seqno cả handshake record.
  - Ghi chú key: `tinc generate-ed25519-keys` ghi `ed25519_key.priv` **96B = expanded(64) ‖ public(32)** (KHÔNG có seed);
    harness/driver tự sinh **seed 32B** của mình rồi đăng ký public key (chuẩn driver-realistic) — orlp ed25519 = RFC 8032,
    nên `Ed25519Signer` (sign từ seed) tương thích `tincd` verify.
- **Phase (b) driver runtime**: XONG ở [`Drivers.Tinc`](../TqkLibrary.VpnClient.Drivers.Tinc) — TCP meta (ID→handshake→ACK→ADD_SUBNET→ADD_EDGE) +
  data-plane SPTPS riêng (REQ_KEY/ANS_KEY) + UDP data (PKT_PROBE reply + TCP fallback SPTPS_PACKET) → `IPacketChannel` (router),
  supervisor F.6, `UseTinc`, demo `--vpn <file>.tinc`. **VALIDATE LIVE** data-plane 2 chiều vs tincd 1.1pre18 (UDP probe RTT~2ms,
  client ICMP request tới server tun, wire byte-verified); full ICMP echo-reply 2 chiều residual server-side (kernel container).
  Mở rộng phase a cho phase b: `SptpsHandshake.BuildUdpLabel` + `SptpsDatagramRecordLayer.EncodeHandshake/DecodeHandshake`
  (plaintext seqno‖type‖data, đếm seqno chung với data records) + `EnableEncryption`/ctor unkeyed. Mode L2 switch
  (`IEthernetChannel`) + auto-mesh đa-node = stretch chưa làm.
- **tinc 1.0 legacy** (RSA + sơ đồ cũ) KHÔNG hiện thực — ưu tiên 1.1 SPTPS như roadmap.
