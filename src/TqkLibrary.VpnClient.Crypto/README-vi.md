# TqkLibrary.VpnClient.Crypto

> Managed crypto: primitive contracts (Interfaces/), MD4/DES/SHA-0/SHA-256/DH-MODP/AES-CBC/CTR/RC4/Salsa20/HMAC/RNG, AEAD (AES-GCM + ChaCha20-Poly1305: native trên net8.0, BouncyCastle trên netstandard2.0; cộng XChaCha20-Poly1305 = HChaCha20 + ChaCha20-Poly1305 cho WireGuard cookie-reply), PRF TLS 1.0 (`Tls1Prf`) + cửa sổ chống replay (`AntiReplayWindow`), MPPE/PPTP (RC4 + key schedule RFC 3078/3079), Salsa20 (rounds tham số — Salsa20/20 chuẩn + Salsa20/12 ZeroTier, KAT ECRYPT), và Noise primitives (X25519/Ed25519/BLAKE2s/HMAC-BLAKE2s/Noise-KDF/SymmetricState qua BouncyCastle trên cả 2 TFM — nền cho WireGuard `Noise_IKpsk2` + Nebula `Noise_IX`).

## Mục đích

Project này là tầng **CRYPTO** thuần — gom mọi *primitive* mật mã mà các tầng PROTOCOL (IPsec/IKE, PPP/MS-CHAPv2) cần, sau một bộ **hợp đồng (interface) ổn định** trong thư mục [Interfaces/](Interfaces). Mục tiêu:

- **Đảo ngược phụ thuộc**: tầng giao thức chỉ phụ thuộc vào interface (`IBlockCipher`, `IAeadCipher`, `IDhGroup`, `IPrf`, `IIntegrityAlgo`, `IHashAlgo`), không phụ thuộc vào lớp hiện thực cụ thể.
- **Che khác biệt runtime**: net8.0 có sẵn `AesGcm`/`ChaCha20Poly1305` trong BCL; netstandard2.0 thì không → fallback BouncyCastle nằm gọn trong từng class AEAD, người dùng không thấy.
- **Cung cấp thuật toán không có trong BCL hiện đại**: MD4 (RFC 1320) và DES không-kiểm-weak-key — cả hai **bắt buộc** cho cơ chế thử-thách/đáp MS-CHAPv2 (NT hash + DES challenge-response).
- Không tham chiếu `Abstractions` hay bất kỳ project nào khác trong solution — đây là tầng đáy, chỉ tự chứa (và BouncyCastle trên netstandard2.0).

## Vị trí trong kiến trúc

- **Tầng:** CRYPTO (primitive thuần).
- **Target frameworks:** `netstandard2.0; net8.0` (xem [src/Directory.Build.props](../Directory.Build.props)); `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`).
- **Phụ thuộc:**
  - ProjectReference: **không có** (tầng đáy, tự chứa).
  - PackageReference (đặc thù): `BouncyCastle.Cryptography 2.4.0` — ref trên **cả 2 TFM**. Hai lý do: (1) BCL `netstandard2.0` không có AES-GCM lẫn ChaCha20-Poly1305 → fallback ở [Aead/AesGcmCipher.cs](Aead/AesGcmCipher.cs) + [Aead/ChaCha20Poly1305Cipher.cs](Aead/ChaCha20Poly1305Cipher.cs) (chỉ nhánh `netstandard2.0`); (2) **cả net8.0 lẫn netstandard2.0 đều thiếu X25519 + BLAKE2s** → các primitive trong [Noise/](Noise) dùng BouncyCastle **không điều kiện** (không có nhánh native). Xem [TqkLibrary.VpnClient.Crypto.csproj:7-14](TqkLibrary.VpnClient.Crypto.csproj#L7-L14).
- **Được dùng bởi (ProjectReference trực tiếp):** `TqkLibrary.VpnClient.Ipsec`, `TqkLibrary.VpnClient.Ppp`, `TqkLibrary.VpnClient.OpenVpn`, `TqkLibrary.VpnClient.Pptp`, `TqkLibrary.VpnClient.SoftEther`, `TqkLibrary.VpnClient.WireGuard`, `TqkLibrary.VpnClient.Nebula`, `TqkLibrary.VpnClient.ZeroTier`, `TqkLibrary.VpnClient.N2n`, `TqkLibrary.VpnClient.Tinc`, `TqkLibrary.VpnClient.Vtun`, `TqkLibrary.VpnClient.Ssh`, `TqkLibrary.VpnClient.Tailscale`, `TqkLibrary.VpnClient.Drivers.SoftEther`, `TqkLibrary.VpnClient.Drivers.WireGuard`, `TqkLibrary.VpnClient.Drivers.Nebula`, `TqkLibrary.VpnClient.Drivers.N2n`, `TqkLibrary.VpnClient.Drivers.ZeroTier`, `TqkLibrary.VpnClient.Drivers.Tinc`.

> Lưu ý: namespace của các interface là `TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces` (không phải `...Crypto.Interfaces`) — đây là các hợp đồng primitive *cục bộ* của project Crypto, **không** liên quan tới project `TqkLibrary.VpnClient.Abstractions`.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Crypto/
├── Interfaces/            # Hợp đồng primitive (namespace ...Crypto.Abstractions.Interfaces)
│   ├── IHashAlgo.cs       # hash một-phát (MD4/MD5/SHA-*)
│   ├── IBlockCipher.cs    # cipher đối xứng có IV, KHÔNG xác thực (AES-CBC/CTR, DES)
│   ├── IAeadCipher.cs     # cipher AEAD Seal/Open (AES-GCM...)
│   ├── IDhGroup.cs        # nhóm Diffie-Hellman (MODP) cho IKE
│   ├── IPrf.cs            # pseudo-random function (HMAC-*) cho key derivation
│   ├── IIntegrityAlgo.cs  # MAC toàn vẹn với ICV (thường bị cắt ngắn) cho ESP/IKE
│   └── ISignatureAlgo.cs  # lược đồ chữ ký khóa-công-khai (Ed25519/ECDSA) — verify cert Nebula
├── Aead/
│   ├── AesGcmCipher.cs           # AES-GCM: native net8.0 / BouncyCastle netstandard2.0
│   ├── ChaCha20Poly1305Cipher.cs # ChaCha20-Poly1305 (RFC 8439): native net5+ / BouncyCastle netstandard2.0
│   └── XChaCha20Poly1305Cipher.cs # XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha): HChaCha20 + ChaCha20-Poly1305 (WG cookie-reply)
├── Mppe/                  # MPPE legacy (PPTP/CCP) — RFC 3078/3079, RC4 + MS-CHAPv2 keys (BROKEN, chỉ legacy)
│   ├── Enums/MppeKeyStrength.cs # cường độ session key (40/56/128-bit)
│   ├── MppeKeyDerivation.cs    # GetNewKeyFromSHA + initial/re-key + strength reduction (static codec)
│   └── MppeSession.cs          # 1 chiều MPPE: RC4 state + coherency count + stateless/stateful re-key
├── Noise/                 # Primitive cho Noise/WireGuard/Nebula — BouncyCastle trên CẢ 2 TFM (BCL không có X25519/BLAKE2s/Ed25519)
│   ├── Curve25519DhGroup.cs # X25519 (RFC 7748, IANA group 31) — IDhGroup
│   ├── Ed25519Signer.cs     # Ed25519 PureEdDSA (RFC 8032), key 32B/sig 64B — ISignatureAlgo (verify cert Nebula V.7.1)
│   ├── Blake2s.cs           # BLAKE2s-256 unkeyed (RFC 7693) — IHashAlgo
│   ├── Blake2sKeyedMac.cs   # keyed BLAKE2s output tùy chỉnh (WG mac1/mac2 16B) — static
│   ├── HmacBlake2sPrf.cs     # HMAC-BLAKE2s (RFC 2104, block 64) — IPrf
│   ├── NoiseKdf.cs          # KDF Noise/WireGuard (HKDF RFC 5869 trên HMAC-BLAKE2s) — static
│   └── NoiseSymmetricState.cs # Noise SymmetricState (spec §5.2) — WireGuard Noise_IKpsk2 + Nebula Noise_IX (generic) — class state machine
├── Sha256Hash.cs          # SHA-256 (IHashAlgo, FIPS 180-4) — transcript hash Noise IX cho Nebula (V.7.1)
├── AesCbcCipher.cs        # AES-CBC no-padding (IBlockCipher)
├── AesCtr.cs              # AES-CTR (static, dựng từ AES-ECB)
├── Rc4.cs                 # RC4 stream cipher (KSA/PRGA) — MPPE/PPTP + SoftEther use_encrypt (BROKEN, RFC 7465)
├── Salsa20.cs             # Salsa20 stream cipher (rounds tham số: /20 chuẩn + /12 ZeroTier) — KAT ECRYPT (V.7.3)
├── ChaCha20.cs            # ChaCha20 stream cipher (djb gốc: nonce 8B + counter 64-bit, KHÔNG phải RFC 8439) — nền OpenSSH chacha20-poly1305@openssh.com (V.10)
├── Blowfish.cs            # Blowfish block cipher (Schneier) ECB no-padding 8B (BouncyCastle) — vtun challenge-response (V.11, BROKEN, chỉ legacy)
├── Md4.cs                 # MD4 (IHashAlgo) — NT hash cho MS-CHAPv2
├── Sha0.cs                # SHA-0 (IHashAlgo, FIPS 180 1993) — SoftEther auth password (V.4)
├── Des.cs                 # DES 1 block ECB-encrypt, không check weak key — MS-CHAPv2
├── MsChapV2.cs            # Codec MS-CHAPv2 (RFC 2759) + dẫn xuất khoá MPPE/MSK (RFC 3079) — dùng chung Ppp + IKEv2 EAP
├── ModpDhGroup.cs         # DH MODP group 2 / 14 (IDhGroup)
├── HmacPrf.cs             # HMAC-PRF (IPrf)
├── HmacIntegrity.cs       # HMAC integrity với ICV cắt ngắn (IIntegrityAlgo)
├── HmacUtil.cs            # helper internal chọn HMAC theo HashAlgorithmName
├── PrfPlus.cs             # IKEv2 prf+ key expansion (static)
├── Tls1Prf.cs             # PRF TLS 1.0/1.1 (RFC 2246 §5) = P_MD5 XOR P_SHA1 — OpenVPN key-method-2 (static)
├── Speck.cs               # SPECK-128/128 ARX block cipher (ECB + CTR, LE-word) — n2n -H header-enc (V.7.4); KAT libn2n.a + NSA
├── PearsonHash.cs         # n2n block-Pearson 64/128 (Mix13, no-table) — n2n -H key-derive + checksum (V.7.4); KAT tests-hashing
└── AntiReplayWindow.cs    # cửa sổ chống replay trượt 64 gói trên seq 32-bit (RFC 4303 §3.4.3) — ESP + OpenVPN AEAD
```

## Thành phần chính

### Hợp đồng (Interfaces/)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `IHashAlgo` | Hash một-phát, trả `HashSizeInBytes` + `ComputeHash` | [IHashAlgo.cs:4](Interfaces/IHashAlgo.cs#L4) |
| `IBlockCipher` | Cipher đối xứng có IV, không xác thực (`Encrypt`/`Decrypt`) | [IBlockCipher.cs:4](Interfaces/IBlockCipher.cs#L4) |
| `IAeadCipher` | AEAD `Seal`/`Open`, che split netstandard2.0 vs net8.0 | [IAeadCipher.cs:4](Interfaces/IAeadCipher.cs#L4) |
| `IDhGroup` | Nhóm Diffie-Hellman cho IKE (`GeneratePrivateKey`/`DerivePublicValue`/`DeriveSharedSecret`) | [IDhGroup.cs:4](Interfaces/IDhGroup.cs#L4) |
| `IPrf` | Pseudo-random function (1 block) cho key derivation | [IPrf.cs:4](Interfaces/IPrf.cs#L4) |
| `IIntegrityAlgo` | MAC toàn vẹn với ICV (thường cắt ngắn) | [IIntegrityAlgo.cs:4](Interfaces/IIntegrityAlgo.cs#L4) |
| `ISignatureAlgo` | Lược đồ chữ ký khóa-công-khai (`DerivePublicKey`/`Sign`/`Verify`); Ed25519/ECDSA — verify cert Nebula (V.7.1) | [ISignatureAlgo.cs:4](Interfaces/ISignatureAlgo.cs#L4) |

### Hiện thực

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `Md4` | MD4 digest (16 byte) — NT hash cho MS-CHAPv2; có `static Hash(...)` tiện dụng | [Md4.cs:9](Md4.cs#L9) |
| `Sha0` | SHA-0 digest (20 byte, FIPS 180 1993 — SHA-1 **bỏ ROTL1** trong message schedule); auth password SoftEther (V.4); có `static Hash(...)` | [Sha0.cs:13](Sha0.cs#L13) |
| `Sha256Hash` | SHA-256 (32 byte, FIPS 180-4, `IHashAlgo`) qua BCL `SHA256` cả 2 TFM; transcript hash Noise IX cho Nebula (V.7.1) | [Sha256Hash.cs:11](Sha256Hash.cs#L11) |
| `Des` | DES 1 block, ECB-encrypt, **không** check weak-key; `static EncryptBlock(key8, block8)` | [Des.cs:8](Des.cs#L8) |
| `AesCbcCipher` | AES-CBC no-padding (`IBlockCipher`, block 16 byte) | [AesCbcCipher.cs:10](AesCbcCipher.cs#L10) |
| `AesCtr` | AES-CTR `static Transform(...)` dựng từ AES-ECB, counter big-endian | [AesCtr.cs:9](AesCtr.cs#L9) |
| `Rc4` | RC4 stream cipher (KSA/PRGA), `Process`/`GenerateKeystream` + `static Apply(key, data)`; key 1..256B; **broken** (RFC 7465) — chỉ MPPE/PPTP + SoftEther `use_encrypt` | [Rc4.cs:12](Rc4.cs#L12) |
| `Salsa20` | Salsa20 stream cipher (Bernstein/eSTREAM), **rounds tham số** (Salsa20/20 chuẩn + **Salsa20/12** ZeroTier), key 32B / nonce 8B; `Transform`/`GenerateKeystream` (counter=0 mỗi lần) + **`CreateStream`/`Stream`** (keystream stateful, counter giữ qua nhiều `Process` — cho memory-hard hash CBC-like ZeroTier); trên BouncyCastle `Salsa20Engine(rounds)` cả 2 TFM; **KAT ECRYPT byte-exact** (Set 1 vec 0 + all-zero, cả 12 & 20 rounds) — nền VL1 ZeroTier (V.7.3, KAT live vs zerotier-one) + memory-hard identity hash | [Salsa20.cs:24](Salsa20.cs#L24) |
| `ChaCha20` | ChaCha20 stream cipher (Bernstein, bản **djb gốc**: key 32B / nonce **8B** / counter 64-bit — **KHÔNG** phải layout IETF RFC 8439 nonce-12B); `Transform` (counter=0) + **`CreateStream`/`Stream`** (keystream stateful giữ counter qua nhiều `Process`/`Skip` — block counter-0 cho khoá Poly1305 rồi payload từ counter 1); BouncyCastle `ChaChaEngine` (20 rounds) cả 2 TFM; nền AEAD `chacha20-poly1305@openssh.com` của OpenSSH (V.10) | [ChaCha20.cs:25](ChaCha20.cs#L25) |
| `Blowfish` | Blowfish block cipher (Schneier) **ECB no-padding** 1 block 8B (`BlockSizeInBytes=8`), `EncryptEcb`/`DecryptEcb` in-place; key 1..56B (vtun dùng MD5 16B); khớp OpenSSL `BF_set_key`/`BF_ecb_encrypt` (big-endian I/O) qua BouncyCastle `BlowfishEngine` cả 2 TFM; vtun challenge-response (V.11) — ⚠️ ECB không chaining/auth, **chỉ legacy** | [Blowfish.cs:20](Blowfish.cs#L20) |
| `Speck` | **SPECK-128/128** ARX block cipher (NSA), `EncryptBlock`/`DecryptBlock` (ECB 1 block 16B) + `Ctr` (CTR, IV 16B); key 16B; **little-endian word** byte order khớp n2n; 32 rounds `R(x,y,k)=ror(x,8)+y; ^k; rol(y,3)^x`. Chỉ cho **n2n `-H` header-enc** (V.7.4) — ⚠️ KHÔNG dùng làm cipher đa dụng. **KAT golden** từ n2n v3.1.1 `libn2n.a` + NSA Speck128/128 vector | [Speck.cs:19](Speck.cs#L19) |
| `PearsonHash` | n2n **block-Pearson** hash, `Hash64`/`Hash128` — **không bảng 256-byte** mà digest qua Stafford Mix13 finalizer (`permute64`); input 8B LE-word rồi byte lẻ, đảo `~` trước remainder + length. n2n `-H` key-derive (`pearson128(community)`) + checksum (`pearson64`). **KAT golden** từ n2n `tests-hashing` (512B) + community "labnet" (V.7.4) | [PearsonHash.cs:19](PearsonHash.cs#L19) |
| `AesGcmCipher` | AES-GCM (`IAeadCipher`), nonce 12B / tag 16B; native vs BouncyCastle | [Aead/AesGcmCipher.cs:18](Aead/AesGcmCipher.cs#L18) |
| `ChaCha20Poly1305Cipher` | ChaCha20-Poly1305 (`IAeadCipher`, RFC 8439), key 32B / nonce 12B / tag 16B; native vs BouncyCastle | [Aead/ChaCha20Poly1305Cipher.cs:18](Aead/ChaCha20Poly1305Cipher.cs#L18) |
| `XChaCha20Poly1305Cipher` | XChaCha20-Poly1305 (`IAeadCipher`, draft-irtf-cfrg-xchacha), key 32B / **nonce 24B** / tag 16B; `HChaCha20` (pure, public) suy subkey rồi ủy quyền `ChaCha20Poly1305Cipher` (WireGuard cookie-reply V3.c) | [Aead/XChaCha20Poly1305Cipher.cs:14](Aead/XChaCha20Poly1305Cipher.cs#L14) |
| `ModpDhGroup` | DH MODP group 2 (1024-bit) / 14 (2048-bit), g=2 (`IDhGroup`) | [ModpDhGroup.cs:12](ModpDhGroup.cs#L12) |
| `HmacPrf` | HMAC-PRF (`IPrf`); factory `Sha256()` | [HmacPrf.cs:7](HmacPrf.cs#L7) |
| `HmacIntegrity` | HMAC integrity ICV cắt ngắn (`IIntegrityAlgo`); factory `HmacSha256_128()`, `HmacSha1_96()` | [HmacIntegrity.cs:7](HmacIntegrity.cs#L7) |
| `PrfPlus` | IKEv2 `prf+` key expansion, `static Expand(IPrf, key, seed, length)` | [PrfPlus.cs:9](PrfPlus.cs#L9) |
| `Tls1Prf` | PRF TLS 1.0/1.1 (RFC 2246 §5 / RFC 4346) = `P_MD5(S1, label‖seed) XOR P_SHA1(S2, label‖seed)`, secret cắt đôi S1/S2 (chia byte giữa khi lẻ); pure static `Compute(...)`; OpenVPN key-method-2 khi không `tls-ekm` | [Tls1Prf.cs:11](Tls1Prf.cs#L11) |
| `AntiReplayWindow` | cửa sổ chống replay trượt 64 gói trên seq/packet-id 32-bit (RFC 4303 §3.4.3); `Check` (kiểm thuần, không ghi) + `Commit` (ghi sau khi integrity pass) + `Highest`; gói đầu = seq 1; dùng cho ESP + OpenVPN AEAD | [AntiReplayWindow.cs:8](AntiReplayWindow.cs#L8) |
| `MsChapV2` | Codec MS-CHAPv2 client-side (RFC 2759): NT hash (MD4), challenge hash (SHA-1), NT-Response (3×DES), Authenticator-Response §8.7 (`GenerateAuthenticatorResponse`) + dẫn xuất HLAK/MPPE (RFC 3079) & EAP-MSK 64B (`DeriveMsk`) + **MPPE start keys** (`DeriveMppeMasterKey`/`DeriveMppeSendStartKey`/`DeriveMppeReceiveStartKey`, có cờ `isServer` chọn Magic2/Magic3); dùng chung cho PPP auth, IKEv2 EAP & MPPE/PPTP | [MsChapV2.cs:10](MsChapV2.cs#L10) |
| `MppeKeyDerivation` | MPPE key schedule (RFC 3078 §7 + RFC 3079): `GetNewKeyFromSha` + `DeriveInitialSessionKey` (SHA-only) + `DeriveNextSessionKey` (SHA→RC4(self) re-key) + `ReduceStrength` (40→0xD126 9E / 56→0xD1 / 128 nguyên); dùng SHA-1 BCL (không phải SHA-0) | [Mppe/MppeKeyDerivation.cs:19](Mppe/MppeKeyDerivation.cs#L19) |
| `MppeSession` | 1 chiều MPPE-encrypted PPP (RFC 3078): RC4 state + 12-bit coherency count + framing header A/B/C/D; `Encrypt`/`Decrypt`; **stateless** = re-key (`mppe_rekey(0)`) + FLUSHED **mỗi gói KỂ CẢ gói đầu** (khớp kernel `ppp_mppe.c`; bug live V.6 đã sửa — bỏ rekey gói-0 làm key lệch 1 bước ⇒ peer giải mã rác) vs **stateful** = re-key mỗi 256 gói khi low-octet=0xFF | [Mppe/MppeSession.cs:16](Mppe/MppeSession.cs#L16) |
| `MppeKeyStrength` | enum cường độ session key MPPE (40/56/128-bit) | [Mppe/Enums/MppeKeyStrength.cs:8](Mppe/Enums/MppeKeyStrength.cs#L8) |
| `HmacUtil` | Internal: chọn `HMACMD5/SHA1/SHA256/SHA384/SHA512` theo `HashAlgorithmName` | [HmacUtil.cs:6](HmacUtil.cs#L6) |
| `Curve25519DhGroup` | X25519 (RFC 7748, IANA group 31), key 32B (`IDhGroup`); BouncyCastle `Rfc7748.X25519` cả 2 TFM | [Noise/Curve25519DhGroup.cs:15](Noise/Curve25519DhGroup.cs#L15) |
| `Ed25519Signer` | Ed25519 PureEdDSA (RFC 8032, `ISignatureAlgo`), key 32B / sig 64B, **không** pre-hash (khớp Go `crypto/ed25519`); BouncyCastle `Rfc8032.Ed25519` cả 2 TFM; verify chữ ký Nebula cert (V.7.1) | [Noise/Ed25519Signer.cs:15](Noise/Ed25519Signer.cs#L15) |
| `Blake2s` | BLAKE2s-256 unkeyed (RFC 7693), digest 32B (`IHashAlgo`); BouncyCastle `Blake2sDigest` | [Noise/Blake2s.cs:12](Noise/Blake2s.cs#L12) |
| `Blake2sKeyedMac` | Keyed BLAKE2s output 1..32B (WG mac1/mac2 16B), `static ComputeMac(key, input, output)` | [Noise/Blake2sKeyedMac.cs:11](Noise/Blake2sKeyedMac.cs#L11) |
| `HmacBlake2sPrf` | HMAC-BLAKE2s (RFC 2104, block 64, **không** phải keyed-BLAKE2s), output 32B (`IPrf`) | [Noise/HmacBlake2sPrf.cs:14](Noise/HmacBlake2sPrf.cs#L14) |
| `NoiseKdf` | KDF Noise/WireGuard (HKDF RFC 5869 trên HMAC-BLAKE2s); `static Derive/Kdf1/Kdf2/Kdf3` | [Noise/NoiseKdf.cs:11](Noise/NoiseKdf.cs#L11) |
| `NoiseSymmetricState` | Noise SymmetricState (spec §5.2) **generic** — WireGuard `Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s` (**seed string** = `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, **đã sửa bug + validate live V.3**) **và** Nebula `Noise_IX_25519_AESGCM_SHA256` (V.7.1, **validate live** — qua `InitializeSymmetric` + HMAC-SHA-256/`Sha256Hash`/`AesGcmCipher`, đều pass validate 32/12/16, **KHÔNG refactor**): `InitializeWireGuard`/`InitializeSymmetric`/`MixHash`/`MixKey` (Kdf2)/`MixKeyAndHash` (Kdf3, PSK)/`EncryptAndHash`+`DecryptAndHash` (nonce `0^4‖counter` LE, AAD = `h`)/`Split` (Kdf2 → cặp transport key 32B); DI `IPrf`/`IHashAlgo`/`IAeadCipher` (tái dùng nguyên primitive) | [Noise/NoiseSymmetricState.cs:20](Noise/NoiseSymmetricState.cs#L20) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|------------------------|--------------------|---------|
| RFC 1320 (MD4) | `Md4` | [Md4.cs:6](Md4.cs#L6) | Ghi rõ trong comment; cần cho NT hash MS-CHAPv2 |
| FIPS 180 (SHA-0, 1993) | `Sha0` | [Sha0.cs:6](Sha0.cs#L6) | Comment; = SHA-1 bỏ `ROTL1` ở schedule `W[t]=W[t-3]^W[t-8]^W[t-14]^W[t-16]`; auth password SoftEther; KAT "abc"/rỗng/2-block + đối chiếu khác SHA-1 |
| FIPS 46-3 (DES) | `Des` | [Des.cs:4](Des.cs#L4) | Comment; ECB-encrypt 1 block, bỏ check weak-key cho MS-CHAPv2 |
| NIST SP 800-38A (CTR mode) | `AesCtr` | [AesCtr.cs:7](AesCtr.cs#L7) | Comment; counter 128-bit tăng big-endian |
| RFC 3686 (AES-CTR cho ESP) | `AesCtr` | [AesCtr.cs:7](AesCtr.cs#L7) | Comment; framing counter đặc thù ESP nằm ở tầng trên |
| RFC 3602 (AES-CBC cho IPsec ESP) | `AesCbcCipher` | [AesCbcCipher.cs:7](AesCbcCipher.cs#L7) | Comment; no-padding, caller tự pad |
| RFC 2409 group 2 / RFC 3526 group 14 (MODP DH) | `ModpDhGroup` | [ModpDhGroup.cs:9](ModpDhGroup.cs#L9), prime tại [:15](ModpDhGroup.cs#L15) & [:22](ModpDhGroup.cs#L22) | Comment; g=2, public value cố định độ dài modulus |
| RFC 7296 §2.13 (IKEv2 `prf+`) | `PrfPlus` | [PrfPlus.cs:5-7](PrfPlus.cs#L5-L7) | Comment; T1=prf(K,S\|0x01), Tn=prf(K,T(n-1)\|S\|n) |
| RFC 4868 (PRF-HMAC-SHA256, HMAC-SHA256-128) | `HmacPrf`, `HmacIntegrity` | [HmacPrf.cs:28](HmacPrf.cs#L28), [HmacIntegrity.cs:32](HmacIntegrity.cs#L32) | Comment |
| RFC 2404 (HMAC-SHA1-96) | `HmacIntegrity` | [HmacIntegrity.cs:35](HmacIntegrity.cs#L35) | Comment |
| IANA DH group registry | `IDhGroup.GroupId` | [Interfaces/IDhGroup.cs:6](Interfaces/IDhGroup.cs#L6) | Comment; số nhóm DH (2, 14, 19...) |
| FIPS 197 (AES) | `AesCbcCipher`, `AesCtr`, `AesGcmCipher` | [AesCbcCipher.cs:10](AesCbcCipher.cs#L10), [AesCtr.cs:9](AesCtr.cs#L9), [Aead/AesGcmCipher.cs:18](Aead/AesGcmCipher.cs#L18) | (suy luận) AES không ghi tên FIPS trong comment |
| NIST SP 800-38D (AES-GCM / GCM) | `AesGcmCipher` | [Aead/AesGcmCipher.cs:18](Aead/AesGcmCipher.cs#L18) | (suy luận) comment chỉ nói "AES-GCM AEAD" |
| RFC 8439 (ChaCha20-Poly1305) | `ChaCha20Poly1305Cipher` | [Aead/ChaCha20Poly1305Cipher.cs:18](Aead/ChaCha20Poly1305Cipher.cs#L18) | Comment; test vector §2.8.2 |
| draft-irtf-cfrg-xchacha (XChaCha20-Poly1305 / HChaCha20) | `XChaCha20Poly1305Cipher` | [Aead/XChaCha20Poly1305Cipher.cs:6](Aead/XChaCha20Poly1305Cipher.cs#L6) | KAT HChaCha20 §2.2.1 + AEAD §A.3.1 (test ở WireGuard.Tests) |
| RFC 7748 (X25519) + RFC 8031 (Curve25519 IKE group 31) | `Curve25519DhGroup` | [Noise/Curve25519DhGroup.cs:11](Noise/Curve25519DhGroup.cs#L11) | Comment; test vector RFC 7748 §5.2/§6.1 (KAT) |
| RFC 8032 (Ed25519 PureEdDSA) | `Ed25519Signer` | [Noise/Ed25519Signer.cs:12](Noise/Ed25519Signer.cs#L12) | Comment; KAT RFC 8032 §7.1 TEST 2/3 + cross-check BouncyCastle; verify cert Nebula |
| FIPS 180-4 (SHA-256) | `Sha256Hash` | [Sha256Hash.cs:6](Sha256Hash.cs#L6) | Comment; KAT FIPS ""/`abc`/56-byte; transcript hash Noise IX |
| RFC 7693 (BLAKE2) | `Blake2s`, `Blake2sKeyedMac` | [Noise/Blake2s.cs:8](Noise/Blake2s.cs#L8), [Noise/Blake2sKeyedMac.cs:7](Noise/Blake2sKeyedMac.cs#L7) | Comment; KAT BLAKE2s-256 + keyed-KAT (blake2s-kat) |
| RFC 5869 (HKDF) — Noise/WireGuard KDF | `NoiseKdf` | [Noise/NoiseKdf.cs:6](Noise/NoiseKdf.cs#L6) | Comment; extract t0=HMAC(key,input) rồi expand ti=HMAC(t0,t(i-1)\|i) |
| Noise Protocol Framework §5.2 (SymmetricState) + WireGuard whitepaper §5.4 (handshake) | `NoiseSymmetricState` | [Noise/NoiseSymmetricState.cs:7](Noise/NoiseSymmetricState.cs#L7) | Comment; CONSTRUCTION/IDENTIFIER WireGuard, nonce AEAD `0^4‖counter` LE + AAD = `h`; test đối chiếu hằng trung gian `ck0`/`h0` |
| RFC 2104 / FIPS 198-1 (HMAC) | `HmacUtil`, `HmacPrf`, `HmacIntegrity` | [HmacUtil.cs:6](HmacUtil.cs#L6) | (suy luận) dùng `HMAC*` của BCL |
| RFC 2246 §5 / RFC 4346 (TLS 1.0/1.1 PRF) | `Tls1Prf` | [Tls1Prf.cs:5-9](Tls1Prf.cs#L5-L9) | Comment; `P_MD5 XOR P_SHA1`, secret cắt đôi S1/S2; OpenVPN key-method-2 (không `tls-ekm`) |
| RFC 4303 §3.4.3 (anti-replay window) | `AntiReplayWindow` | [AntiReplayWindow.cs:3-7](AntiReplayWindow.cs#L3-L7) | Comment; cửa sổ trượt 64 gói trên seq 32-bit, gói đầu = seq 1; dùng cho ESP + OpenVPN AEAD |
| RFC 2759 (MS-CHAPv2) | `MsChapV2` (codec) trên `Md4`+`Des`+SHA-1 | [MsChapV2.cs:10](MsChapV2.cs#L10) | NtPasswordHash §8.3 [L12](MsChapV2.cs#L12), ChallengeHash §8.2 [L16](MsChapV2.cs#L16), ChallengeResponse §8.5 [L32](MsChapV2.cs#L32), GenerateNTResponse §8.1 [L48](MsChapV2.cs#L48), GenerateAuthenticatorResponse §8.7 [L130](MsChapV2.cs#L130) |
| RFC 3079 (dẫn xuất khoá MPPE / EAP-MSK) | `MsChapV2.DeriveHlak` / `MsChapV2.DeriveMsk` / `MsChapV2.DeriveMppe*StartKey` | [MsChapV2.cs:86](MsChapV2.cs#L86), [DeriveMsk L110](MsChapV2.cs#L110), [GetAsymmetricStartKey L193](MsChapV2.cs#L193) | HLAK 32B (SSTP crypto binding) + EAP-MSK 64B = **send\|\|recv**\|\|zeros (perspective peer = dual của server's recv\|\|send; **validate live strongSwan** — order ngược vẫn pass EAP nhưng fail IKEv2 AUTH-with-MSK của gateway) cho IKEv2 EAP AUTH + MPPE start keys (Magic2/Magic3 theo IsSend/IsServer); KAT §3.5 (MasterKey/StartKey/SessionKey 40/56/128) |
| RFC 3078 (MPPE protocol: GetNewKeyFromSHA + framing) | `MppeKeyDerivation`, `MppeSession` | [Mppe/MppeKeyDerivation.cs:19](Mppe/MppeKeyDerivation.cs#L19), [Mppe/MppeSession.cs:16](Mppe/MppeSession.cs#L16) | §7.3 GetNewKeyFromSHA (SHA-1, SHApad1=40×0x00, SHApad2=40×0xF2) + re-key RC4(InterimKey, InterimKey) + §3.1 header coherency 12-bit; KAT §3.5 "Sample Encrypted Message" |
| RFC 6229 (RC4 test vectors) / RFC 7465 (cấm RC4 trong TLS) | `Rc4` | [Rc4.cs:13](Rc4.cs#L13) | KAT keystream 40-bit/128-bit (RFC 6229) + classic vector Rivest; cảnh báo broken |

## API / cách dùng

Tất cả primitive đều public và thường được tạo qua factory tĩnh hoặc dùng trực tiếp:

```csharp
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

// 1) MD4 (NT hash cho MS-CHAPv2)
byte[] ntHash = Md4.Hash(unicodePassword);           // 16 byte

// 2) DES 1 block (MS-CHAPv2 challenge-response)
byte[] cipher = Des.EncryptBlock(key8, challenge8);

// 3) AES-CBC (ESP/IKE), caller tự pad về bội số 16
IBlockCipher cbc = new AesCbcCipher();
int n = cbc.Encrypt(key, iv16, plaintext, ciphertext);

// 4) AES-CTR (keystream XOR)
AesCtr.Transform(key, initialCounter16, input, output);

// 5) AES-GCM AEAD (nonce 12B, tag 16B)
IAeadCipher gcm = new AesGcmCipher(keySizeInBytes: 32);
gcm.Seal(key, nonce12, plaintext, aad, ciphertext, tag);
bool ok = gcm.Open(key, nonce12, ciphertext, tag, aad, plaintext);

// 5b) ChaCha20-Poly1305 AEAD (key 32B, nonce 12B, tag 16B) — cùng hợp đồng IAeadCipher
IAeadCipher chacha = new ChaCha20Poly1305Cipher();
chacha.Seal(key32, nonce12, plaintext, aad, ciphertext, tag);

// 6) Diffie-Hellman MODP (IKE)
IDhGroup dh = ModpDhGroup.Group14();                 // 2048-bit
byte[] priv = dh.GeneratePrivateKey();
byte[] pub  = dh.DerivePublicValue(priv);
byte[] shared = dh.DeriveSharedSecret(priv, peerPublicValue);

// 7) PRF + prf+ (key derivation IKEv2)
IPrf prf = HmacPrf.Sha256();
byte[] keyMaterial = PrfPlus.Expand(prf, sk_d, seed, length: 64);

// 8) HMAC integrity (ESP/IKE ICV cắt ngắn)
IIntegrityAlgo integ = HmacIntegrity.HmacSha256_128(); // key 32B, ICV 16B
integ.ComputeIcv(key, data, icv);
```

## Luồng nội bộ

- **AES-CTR** ([AesCtr.cs:12-34](AesCtr.cs#L12-L34)): tạo `Aes` ở chế độ ECB/no-padding, mỗi vòng mã hoá khối counter 16 byte để lấy keystream rồi XOR với input; sau mỗi khối, counter được tăng big-endian toàn 16 byte qua `IncrementBigEndian` ([AesCtr.cs:36-42](AesCtr.cs#L36-L42)).
- **AES-GCM split runtime** ([Aead/AesGcmCipher.cs:49-62](Aead/AesGcmCipher.cs#L49-L62) và [:74-103](Aead/AesGcmCipher.cs#L74-L103)): nhánh `#if NET7_0_OR_GREATER` dùng `System.Security.Cryptography.AesGcm` (gate net7+ vì ctor `AesGcm(key, tagSize)` + `AuthenticationTagMismatchException` có từ .NET 7; build hiện tại là net8.0); nhánh `#else` dùng `GcmBlockCipher(new AesEngine())` của BouncyCastle. `Open` trả `false` khi tag sai (`AuthenticationTagMismatchException` trên net7.0+; `InvalidCipherTextException` trên netstandard2.0) thay vì ghi plaintext. Alias type cụ thể để tránh đụng `Org.BouncyCastle...IAeadCipher` với interface cùng tên của project ([Aead/AesGcmCipher.cs:4-10](Aead/AesGcmCipher.cs#L4-L10)).
- **ChaCha20-Poly1305 split runtime** ([Aead/ChaCha20Poly1305Cipher.cs:42-55](Aead/ChaCha20Poly1305Cipher.cs#L42-L55) và [:67-95](Aead/ChaCha20Poly1305Cipher.cs#L67-L95)): cùng khuôn `AesGcmCipher` nhưng gate `#if NET5_0_OR_GREATER` vì `System.Security.Cryptography.ChaCha20Poly1305` có từ .NET 5; nhánh `#else` dùng `Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305`. Key cố định 32B, nonce 12B, tag 16B (RFC 8439). `Open` trả `false` khi tag sai thay vì ghi plaintext. Alias type cụ thể tránh đụng tên với `IAeadCipher` của project ([Aead/ChaCha20Poly1305Cipher.cs:1-8](Aead/ChaCha20Poly1305Cipher.cs#L1-L8)).
- **DES** ([Des.cs:11-32](Des.cs#L11-L32)): IP → 16 vòng Feistel với `KeySchedule` 16 subkey 48-bit ([Des.cs:34-48](Des.cs#L34-L48)) → swap → FP. Hàm Feistel dùng E-expansion, 8 S-box và P-permutation ([Des.cs:50-62](Des.cs#L50-L62)). Bỏ qua bit parity của key (đúng đặc tả DES) và **không** loại weak key — vì MS-CHAPv2 sinh key DES từ password hash có thể yếu.
- **MODP DH** ([ModpDhGroup.cs:57-83](ModpDhGroup.cs#L57-L83)): private key là số mũ ngẫu nhiên trong `[2, p-2]`; public/shared dùng `BigInteger.ModPow`. Mọi giá trị wire là big-endian cố định độ dài modulus; chuyển đổi big-endian ↔ `BigInteger` (chèn byte 0x00 để giữ dấu dương) tại [ModpDhGroup.cs:93-114](ModpDhGroup.cs#L93-L114).
- **prf+** ([PrfPlus.cs:12-44](PrfPlus.cs#L12-L44)): lặp `Tn = prf(K, T(n-1) | S | n)`, nối khối cho tới khi đủ `length`; ném lỗi nếu vượt 255 vòng (counter byte tràn về 0).
- **MD4** ([Md4.cs:15-43](Md4.cs#L15-L43)): xử lý từng khối 64 byte + tail có padding 0x80 và độ dài bit 64-bit little-endian; mỗi khối qua 3 round F/G/H ([Md4.cs:53-90](Md4.cs#L53-L90)).
- **SHA-0** ([Sha0.cs:19-47](Sha0.cs#L19-L47)): cấu trúc Merkle–Damgård big-endian giống SHA-1 (khối 64 byte + tail 0x80 + độ dài bit 64-bit **big-endian**); 80 vòng 4 hàm f/k. Khác biệt **duy nhất** so với SHA-1 nằm ở message schedule ([Sha0.cs:63-64](Sha0.cs#L63-L64)): `W[t]=W[t-3]^W[t-8]^W[t-14]^W[t-16]` **không** bọc trong `ROTL1(...)` — đây chính là lỗ hổng FIPS 180-1 vá lại. Dùng cho auth password SoftEther (hash cục bộ, không lên wire).

## Trạng thái & ghi chú

- **Đã hiện thực & dùng thật:** MD4, DES, AES-CBC, AES-CTR, AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, MODP DH (group 2/14), HMAC-PRF, HMAC-integrity, prf+, `Tls1Prf` (PRF TLS 1.0 cho OpenVPN key-method-2), `AntiReplayWindow` (cửa sổ chống replay 64 gói, RFC 4303 §3.4.3 — dùng cho ESP + OpenVPN AEAD) — tiêu thụ bởi `Ipsec` (IKE/ESP), `Ppp` (MS-CHAPv2), `OpenVpn` (NCP data channel: AES-GCM + ChaCha20-Poly1305) và `WireGuard` (XChaCha20-Poly1305 cho cookie-reply V3.c).
- **SHA-0 ([Sha0.cs](Sha0.cs)) — đã hiện thực + KAT, consumer SoftEther (V.4) còn ở roadmap:** `Sha0` (`IHashAlgo`, 20 byte, FIPS 180 1993) = SHA-1 **bỏ ROTL1** ở message schedule, mirror cách viết `Md4`/`Des`. Dùng cho auth password SoftEther SSL-VPN (hash password+username **cục bộ**, hash không lên wire). KAT FIPS-180: "abc" `0164b8a9…`, chuỗi rỗng `f96cea19…`, ví dụ 2-block `d2516ee1…` + đối chiếu **khác** SHA-1 cho mọi padding ([Sha0Tests](../../tests/TqkLibrary.VpnClient.Crypto.Tests/Sha0Tests.cs)).
- **MPPE + RC4 ([Mppe/](Mppe) + [Rc4.cs](Rc4.cs)) — đã hiện thực + KAT offline (F.5b); consumer đầu tiên = CCP negotiator PPTP (V6.a):** `Rc4` (stream cipher KSA/PRGA) + `MppeKeyDerivation` (suy khóa RFC 3078/3079: `GetNewKeyFromSHA` SHA-1, initial key SHA-only, re-key SHA→RC4-self, strength reduction 40/56/128-bit) + `MppeSession` (1 chiều: RC4 state + coherency count 12-bit + framing A/B/C/D, stateless re-key-mỗi-gói vs stateful re-key-mỗi-256-gói). MPPE start key suy từ MS-CHAPv2 qua `MsChapV2.DeriveMppe*StartKey` (tái dùng `GetMasterKey`/`GetAsymmetricStartKey` sẵn có, thêm cờ `isServer` chọn Magic2/Magic3 — client-send=server-receive). **CẢNH BÁO BẢO MẬT: MPPE + MS-CHAPv2 đã bị phá hoàn toàn** (MS-CHAPv2 brute-force DES 2¹⁶, RC4 keystream lệch RFC 7465) — chỉ dùng cho tương thích PPTP legacy, **tuyệt đối không** cho thiết kế mới. KAT byte-chính-xác: RC4 (RFC 6229 40/128-bit + classic Rivest), MPPE key derivation (RFC 3079 §3.5 MasterKey/StartKey/SessionKey 40/56/128 + "Sample Encrypted Message" rc4(SessionKey,"test message") — lưu ý byte cuối 56-bit §3.5.2 là erratum RFC, giá trị thật kết thúc `B8`), session round-trip stateless/stateful qua 600 gói ([`Rc4Tests`](../../tests/TqkLibrary.VpnClient.Crypto.Tests/Rc4Tests.cs)/[`MppeKeyDerivationTests`](../../tests/TqkLibrary.VpnClient.Crypto.Tests/MppeKeyDerivationTests.cs)/[`MppeSessionTests`](../../tests/TqkLibrary.VpnClient.Crypto.Tests/MppeSessionTests.cs)). **Nay đã có consumer**: CCP negotiator + `MppeSessionFactory` ở [`TqkLibrary.VpnClient.Pptp`](../TqkLibrary.VpnClient.Pptp) (V6.a) suy `MppeSession` từ MS-CHAPv2 + kết quả CCP; **GRE data plane** PPTP (V6.b) còn chờ F.9 raw-IP.
- **Noise primitives ([Noise/](Noise)) — đã hiện thực + KAT + dùng thật bởi WireGuard (V.3) và Nebula (V.7.1):** `Curve25519DhGroup` (X25519), `Ed25519Signer` (RFC 8032, **mới V.7.1**), `Blake2s`, `Blake2sKeyedMac`, `HmacBlake2sPrf`, `NoiseKdf`, **`NoiseSymmetricState` (V3.a)** + `Sha256Hash` (FIPS 180-4, **mới V.7.1**). KAT byte-chính-xác: X25519 (RFC 7748 §5.2/§6.1), Ed25519 (RFC 8032 §7.1 TEST 2/3 + cross-check BCL — **validate live** verify cert nebula thật), SHA-256 (FIPS 180-4), BLAKE2s-256 + keyed-KAT, HMAC-BLAKE2s đối chiếu HMAC-textbook, `NoiseKdf` extract/expand. `NoiseSymmetricState` là Noise SymmetricState (spec §5.2) **generic**: WireGuard `Noise_IKpsk2_…ChaChaPoly_BLAKE2s` (validate live V.3) **và** Nebula `Noise_IX_25519_AESGCM_SHA256` (validate live V.7.1 — qua `InitializeSymmetric` + SHA-256/HMAC-SHA-256/AES-256-GCM, đều pass validate 32/12/16, **KHÔNG refactor**). Handshake state machine Noise_IKpsk2 ở [`WireGuard`](../TqkLibrary.VpnClient.WireGuard); Noise IX ở [`Nebula`](../TqkLibrary.VpnClient.Nebula).
- **Khác biệt netstandard2.0 vs net8.0:** chỉ ở `AesGcmCipher` + `ChaCha20Poly1305Cipher` — net8.0 dùng `AesGcm`/`ChaCha20Poly1305` của BCL, netstandard2.0 fallback BouncyCastle. Các primitive `Noise/` (X25519/BLAKE2s/HMAC-BLAKE2s) dùng BouncyCastle **giống nhau trên cả 2 TFM** (BCL không có sẵn ⇒ không nhánh `#if`). `BouncyCastle.Cryptography` nay là PackageReference **không điều kiện** (cả 2 TFM). Các primitive còn lại dùng BCL chung cho cả hai TFM.
- **MODP group 2 (1024-bit)** giữ lại cho tương thích IKEv1/VPN Gate dù đã yếu theo tiêu chuẩn hiện đại; **group 14 (2048-bit)** là lựa chọn mặc định khuyến nghị.
- **MD4, DES & SHA-0** cố ý dùng thuật toán đã "vỡ" về mặt mật mã — MD4/DES vì MS-CHAPv2 bắt buộc, SHA-0 vì SoftEther auth bắt buộc; **không** dùng cho mục đích bảo mật mới.
- **SHA-1/256/384/512** vẫn được dùng gián tiếp qua HMAC của BCL ([HmacUtil.cs:24-32](HmacUtil.cs#L24-L32)) — không có file SHA-1/2 độc lập (BCL đã có); chỉ **SHA-0** mới cần file riêng ([Sha0.cs](Sha0.cs)) vì vắng mặt trong BCL.
- **`HmacPrf`/`HmacIntegrity`** hiện cấp factory cho SHA-256 (PRF, ICV-128) và SHA-1-96 (ICV); họ HMAC khác (MD5/SHA384/SHA512) đã sẵn trong `HmacUtil` nếu cần mở rộng.
- Không có khoá/khử cấp phát: nhiều API dùng `ReadOnlySpan<byte>` ở biên ngoài nhưng bên trong vẫn `ToArray()` (do BCL/BigInteger yêu cầu mảng) — chưa zeroize bộ đệm trung gian; đây là hạn chế đã biết.
- Tài liệu as-built tổng thể: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
