# TqkLibrary.VpnClient.Nebula

Thư viện **protocol Nebula** (mesh VPN của Slack) thuần .NET — hiện thực handshake **Noise IX**
(`Noise_IX_25519_AESGCM_SHA256`), codec **Nebula certificate** (protobuf v1 + verify chữ ký **Ed25519**), codec **gói
UDP 16-byte header** và codec **payload handshake** (`NebulaHandshake` protobuf). Đây là project protocol-level cho
driver **V.7.1** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.1). Driver runtime (UDP transport,
data-plane lifecycle, re-handshake) là phase (b) — **XONG** ở [`Drivers.Nebula`](../TqkLibrary.VpnClient.Drivers.Nebula), validate live full-tunnel ICMP 2 chiều.

> **Trạng thái:** **phase (a) protocol XONG + VALIDATE LIVE handshake ✓** (2026-06-24, nebula v1.9.5 thật, lab
> [`lab/nebula`](../../lab/nebula/README-vi.md)): nebula THẬT chấp nhận stage-1 của ta (`Handshake message received
> certName=client style:ix_psk0`) + gửi stage-2, ta giải mã + verify cert responder. **Tái dùng nguyên**
> [`NoiseSymmetricState`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs#L20) (V3.a, KHÔNG refactor — SHA-256 +
> HMAC-SHA-256 + AES-256-GCM đều pass validate 32/12/16) + [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15)
> + [`AesGcmCipher`](../TqkLibrary.VpnClient.Crypto/Aead/AesGcmCipher.cs#L18). **Mới ở Crypto cho V.7.1**:
> [`Ed25519Signer`](../TqkLibrary.VpnClient.Crypto/Noise/Ed25519Signer.cs#L15) + [`Sha256Hash`](../TqkLibrary.VpnClient.Crypto/Sha256Hash.cs#L11).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[OpenVpn](../TqkLibrary.VpnClient.OpenVpn)):
các khối giao thức thuần, **không** I/O socket. Handshake là **state machine đối xứng thuần** (driver bơm gói vào/ra;
test + harness chạy initiator↔responder/nebula). Khác WireGuard: Noise **IX** (vs IKpsk2 — không PSK, không cookie,
hash SHA-256 vs BLAKE2s, cipher AES-256-GCM mặc định) + danh tính bằng **certificate ký Ed25519** (vs static pubkey trần).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`NoiseSymmetricState`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs#L20) (symmetric IX), [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15) (X25519 DH), [`AesGcmCipher`](../TqkLibrary.VpnClient.Crypto/Aead/AesGcmCipher.cs#L18)/[`ChaCha20Poly1305Cipher`](../TqkLibrary.VpnClient.Crypto/Aead/ChaCha20Poly1305Cipher.cs#L18) (AEAD), [`HmacPrf.Sha256`](../TqkLibrary.VpnClient.Crypto/HmacPrf.cs#L29) (KDF PRF), [`Sha256Hash`](../TqkLibrary.VpnClient.Crypto/Sha256Hash.cs#L11) (transcript hash), [`Ed25519Signer`](../TqkLibrary.VpnClient.Crypto/Noise/Ed25519Signer.cs#L15) (verify chữ ký cert) |
| Được dùng bởi | [`Drivers.Nebula`](../TqkLibrary.VpnClient.Drivers.Nebula) (V.7.1 phase b) | driver lắp ráp UDP transport + data-plane lifecycle + re-handshake quanh các codec/handshake này |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Nebula/
├─ Certificate/
│  ├─ ProtobufReader.cs              codec protobuf tối thiểu (varint/length-delimited/packed) — đọc, ref struct
│  ├─ ProtobufWriter.cs              codec protobuf tối thiểu — ghi (ascending field order, packed uint32)
│  ├─ NebulaCertificateCodec.cs      Marshal/Unmarshal cert v1; MarshalDetails proto3 default-omission (khớp byte CA ký)
│  ├─ NebulaCertificateValidator.cs  VerifySignature (Ed25519 against CA pubkey) + ComputeFingerprint (SHA-256)
│  ├─ NebulaPem.cs                   decode PEM banner (NEBULA CERTIFICATE / X25519 / ED25519 PRIVATE-PUBLIC KEY)
│  ├─ Enums/NebulaCurve.cs           Curve25519=0 / P256=1
│  └─ Models/
│     ├─ NebulaCertificate.cs        Details + Signature (RawNebulaCertificate)
│     └─ NebulaCertificateDetails.cs POCO: Name/Ips/Subnets/Groups/NotBefore/NotAfter/PublicKey/IsCa/Issuer/Curve
├─ Handshake/
│  ├─ NebulaNoiseIxHandshake.cs      state machine Noise IX 1 phía (CreateInitiation/ConsumeInitiation/CreateResponse/ConsumeResponse + Split)
│  ├─ NebulaHandshakePayloadCodec.cs Marshal/Unmarshal NebulaHandshake payload (Details=1, Hmac=2)
│  └─ Models/NebulaHandshakeDetails.cs POCO: Cert/InitiatorIndex/ResponderIndex/Time
└─ Packet/
   ├─ NebulaHeaderCodec.cs           encode/decode 16-byte header BE + EncodePacket
   ├─ Enums/NebulaMessageType.cs     Handshake=0/Message=1/RecvError=2/LightHouse=3/Test=4/CloseTunnel=5/Control=6
   ├─ Enums/NebulaMessageSubType.cs  None=0/HandshakeIxPsk0=0/MessageRelay=1
   └─ Models/NebulaHeader.cs         Version/Type/SubType/Reserved/RemoteIndex/MessageCounter (Size=16)
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`NebulaNoiseIxHandshake`](Handshake/NebulaNoiseIxHandshake.cs#L21) | Chạy 1 phía Noise IX: `msg1 = e, s` (plaintext + MixHash, vì chưa có key) → `msg2 = e, ee, se, s, es` (s + payload AEAD sau khi MixKey 3 DH). `Split()` → cặp transport key crossed theo role. Tái dùng `NoiseSymmetricState` + `Curve25519DhGroup` + `AesGcmCipher`. |
| [`NebulaCertificateCodec`](Certificate/NebulaCertificateCodec.cs#L16) | Marshal/Unmarshal `RawNebulaCertificate(Details)`. **`MarshalDetails`** ghi proto3-đúng (field tăng dần, bỏ default: Curve25519/IsCa-false/bytes-rỗng) ⇒ tái-marshal cho ra **đúng byte CA đã ký**; `UnmarshalCertificate` giữ raw signed-details để verify chính xác. |
| [`NebulaCertificateValidator`](Certificate/NebulaCertificateValidator.cs#L14) | `VerifySignature` (Ed25519 of details against CA pubkey, chỉ path Curve25519) + `ComputeFingerprint` (SHA-256 of marshaled cert = giá trị `Issuer`). |
| [`NebulaPem`](Certificate/NebulaPem.cs#L11) | Decode PEM block của `nebula-cert` (cert + X25519/Ed25519 key); `DecodeEd25519Seed` lấy 32B seed từ private 64B. |
| [`ProtobufReader`](Certificate/ProtobufReader.cs#L8)/[`ProtobufWriter`](Certificate/ProtobufWriter.cs#L9) | Codec protobuf tối thiểu (varint, length-delimited, packed uint32) — đủ cho cert/handshake Nebula, không kéo package protobuf nặng. |
| [`NebulaHeaderCodec`](Packet/NebulaHeaderCodec.cs#L12) | Encode/decode 16-byte header BE (`b0=Ver<<4\|Type`, sub, reserved2, remoteIndex4, counter8) + `EncodePacket`. |
| [`NebulaHandshakePayloadCodec`](Handshake/NebulaHandshakePayloadCodec.cs#L10) | Marshal/Unmarshal `NebulaHandshake{Details, Hmac}` + `NebulaHandshakeDetails{Cert, InitiatorIndex, ResponderIndex, Time}`. |

## Bảng chuẩn / RFC

| Chuẩn | Áp dụng |
|-------|---------|
| Noise Protocol Framework (rev 34), pattern **IX** | `NebulaNoiseIxHandshake` — name `Noise_IX_25519_AESGCM_SHA256`, prologue rỗng (MixHash empty), token `e,s` / `e,ee,se,s,es`, DH ee/se/es theo §5.3 |
| RFC 8032 (Ed25519 PureEdDSA) | verify chữ ký cert (qua `Ed25519Signer` ở Crypto) |
| RFC 7748 (X25519) | DH static/ephemeral (qua `Curve25519DhGroup`) |
| FIPS 180-4 (SHA-256) | transcript hash + cert fingerprint (qua `Sha256Hash`) |
| Protocol Buffers (proto3 wire format) | cert v1 + handshake payload (codec tự viết) |
| Nebula `cert_v1.proto` / `header.go` / `handshake/payload.go` | field numbers cert/handshake + layout header (đối chiếu spec, clean-room) |

## Luồng nội bộ (handshake initiator)

1. [`CreateInitiation`](Handshake/NebulaNoiseIxHandshake.cs#L82): `InitializeSymmetric(name)` + `MixHash(empty)` (prologue) → token `e` (gen ephemeral, `MixHash`) → token `s` (`EncryptAndHash(staticPub)` = plaintext + MixHash) → payload (`EncryptAndHash` = plaintext). Trả `e.pub ‖ s.pub ‖ payload`.
2. Driver bọc header `Type=Handshake` ([`NebulaHeaderCodec.EncodePacket`](Packet/NebulaHeaderCodec.cs#L36)) + gửi UDP.
3. Nhận stage-2, [`ConsumeResponse`](Handshake/NebulaNoiseIxHandshake.cs#L152): token `e` (`MixHash`) → `ee`/`se` (`MixKey` DH) → token `s` (`DecryptAndHash` = static responder, AEAD) → `es` (`MixKey` DH) → payload (`DecryptAndHash`).
4. [`Split`](Handshake/NebulaNoiseIxHandshake.cs#L185) → `(send, receive)` crossed; recombine + verify cert responder ([`NebulaCertificateValidator.VerifySignature`](Certificate/NebulaCertificateValidator.cs#L37)).

## Trạng thái & ghi chú

- **Build xanh `netstandard2.0` + `net8.0`**; 22 test offline (`tests/TqkLibrary.VpnClient.Nebula.Tests`) — handshake self-pair (crossed keys + biến thể ChaChaPoly), codec round-trip, cert sign/verify. WireGuard 77 test không regression (không refactor shared code).
- **VALIDATE LIVE ✓**: offline interop với cert THẬT (re-marshal == signed bytes 100==100, fingerprint khớp `nebula-cert print`, sig valid against CA) + live Noise IX handshake với nebula v1.9.5 (first-run success, không bug interop). Chi tiết [`lab/nebula`](../../lab/nebula/README-vi.md).
- **Cipher**: mặc định AES-256-GCM (name `…AESGCM…`); network `chachapoly` truyền `cipher: ChaCha20Poly1305Cipher` + `protocolName: "Noise_IX_25519_ChaChaPoly_SHA256"`.
- **Phase b XONG ✓** ([`Drivers.Nebula`](../TqkLibrary.VpnClient.Drivers.Nebula)): UDP transport runtime, **tunnel lifecycle** (giữ tunnel sống bằng re-handshake make-before-break định kỳ), `SwappablePacketChannel` + supervisor F.6, `VpnClientBuilder.UseNebula`. **VALIDATE LIVE FULL-TUNNEL ICMP 2 chiều** với nebula v1.9.5 thật (tcpdump overlay echo request+reply, 0 bug data-plane). Chi tiết [`Drivers.Nebula README`](../TqkLibrary.VpnClient.Drivers.Nebula/README-vi.md) + [`lab/nebula`](../../lab/nebula/README-vi.md).
- **Chưa làm**: lighthouse query động (discovery peer→endpoint runtime — phase b dùng `static_host_map`/endpoint tĩnh), relay/punchy NAT hole-punching, multi-peer mesh. Cert v2 (ASN.1 DER) + P256/ECDSA cũng chưa (chỉ v1 + Curve25519/Ed25519).
