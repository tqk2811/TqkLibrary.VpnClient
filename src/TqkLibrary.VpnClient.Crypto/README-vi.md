# TqkLibrary.VpnClient.Crypto

> Managed crypto: primitive contracts (Interfaces/), MD4/DES/SHA-0/DH-MODP/AES-CBC/CTR/HMAC/RNG, và AEAD (AES-GCM: native trên net8.0, BouncyCastle trên netstandard2.0).

## Mục đích

Project này là tầng **CRYPTO** thuần — gom mọi *primitive* mật mã mà các tầng PROTOCOL (IPsec/IKE, PPP/MS-CHAPv2) cần, sau một bộ **hợp đồng (interface) ổn định** trong thư mục [Interfaces/](Interfaces). Mục tiêu:

- **Đảo ngược phụ thuộc**: tầng giao thức chỉ phụ thuộc vào interface (`IBlockCipher`, `IAeadCipher`, `IDhGroup`, `IPrf`, `IIntegrityAlgo`, `IHashAlgo`), không phụ thuộc vào lớp hiện thực cụ thể.
- **Che khác biệt runtime**: net8.0 có sẵn `AesGcm` trong BCL; netstandard2.0 thì không → fallback BouncyCastle nằm gọn trong một class duy nhất, người dùng không thấy.
- **Cung cấp thuật toán không có trong BCL hiện đại**: MD4 (RFC 1320) và DES không-kiểm-weak-key — cả hai **bắt buộc** cho cơ chế thử-thách/đáp MS-CHAPv2 (NT hash + DES challenge-response).
- Không tham chiếu `Abstractions` hay bất kỳ project nào khác trong solution — đây là tầng đáy, chỉ tự chứa (và BouncyCastle trên netstandard2.0).

## Vị trí trong kiến trúc

- **Tầng:** CRYPTO (primitive thuần).
- **Target frameworks:** `netstandard2.0; net8.0` (xem [src/Directory.Build.props](../Directory.Build.props)); `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`).
- **Phụ thuộc:**
  - ProjectReference: **không có** (tầng đáy, tự chứa).
  - PackageReference (đặc thù): `BouncyCastle.Cryptography 2.4.0` — **chỉ** khi `TargetFramework == netstandard2.0`, và **chỉ** được dùng bởi [Aead/AesGcmCipher.cs](Aead/AesGcmCipher.cs) (BCL netstandard2.0 không có AES-GCM). Xem [TqkLibrary.VpnClient.Crypto.csproj:7-10](TqkLibrary.VpnClient.Crypto.csproj#L7-L10).
- **Được dùng bởi:** `TqkLibrary.VpnClient.Ipsec`, `TqkLibrary.VpnClient.Ppp`, `TqkLibrary.VpnClient` (project entry-point).

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
│   └── IIntegrityAlgo.cs  # MAC toàn vẹn với ICV (thường bị cắt ngắn) cho ESP/IKE
├── Aead/
│   └── AesGcmCipher.cs    # AES-GCM: native net8.0 / BouncyCastle netstandard2.0
├── AesCbcCipher.cs        # AES-CBC no-padding (IBlockCipher)
├── AesCtr.cs              # AES-CTR (static, dựng từ AES-ECB)
├── Md4.cs                 # MD4 (IHashAlgo) — NT hash cho MS-CHAPv2
├── Des.cs                 # DES 1 block ECB-encrypt, không check weak key — MS-CHAPv2
├── MsChapV2.cs            # Codec MS-CHAPv2 (RFC 2759) + dẫn xuất khoá MPPE/MSK (RFC 3079) — dùng chung Ppp + IKEv2 EAP
├── ModpDhGroup.cs         # DH MODP group 2 / 14 (IDhGroup)
├── HmacPrf.cs             # HMAC-PRF (IPrf)
├── HmacIntegrity.cs       # HMAC integrity với ICV cắt ngắn (IIntegrityAlgo)
├── HmacUtil.cs            # helper internal chọn HMAC theo HashAlgorithmName
└── PrfPlus.cs             # IKEv2 prf+ key expansion (static)
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

### Hiện thực

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `Md4` | MD4 digest (16 byte) — NT hash cho MS-CHAPv2; có `static Hash(...)` tiện dụng | [Md4.cs:9](Md4.cs#L9) |
| `Des` | DES 1 block, ECB-encrypt, **không** check weak-key; `static EncryptBlock(key8, block8)` | [Des.cs:8](Des.cs#L8) |
| `AesCbcCipher` | AES-CBC no-padding (`IBlockCipher`, block 16 byte) | [AesCbcCipher.cs:10](AesCbcCipher.cs#L10) |
| `AesCtr` | AES-CTR `static Transform(...)` dựng từ AES-ECB, counter big-endian | [AesCtr.cs:9](AesCtr.cs#L9) |
| `AesGcmCipher` | AES-GCM (`IAeadCipher`), nonce 12B / tag 16B; native vs BouncyCastle | [Aead/AesGcmCipher.cs:18](Aead/AesGcmCipher.cs#L18) |
| `ModpDhGroup` | DH MODP group 2 (1024-bit) / 14 (2048-bit), g=2 (`IDhGroup`) | [ModpDhGroup.cs:12](ModpDhGroup.cs#L12) |
| `HmacPrf` | HMAC-PRF (`IPrf`); factory `Sha256()` | [HmacPrf.cs:7](HmacPrf.cs#L7) |
| `HmacIntegrity` | HMAC integrity ICV cắt ngắn (`IIntegrityAlgo`); factory `HmacSha256_128()`, `HmacSha1_96()` | [HmacIntegrity.cs:7](HmacIntegrity.cs#L7) |
| `PrfPlus` | IKEv2 `prf+` key expansion, `static Expand(IPrf, key, seed, length)` | [PrfPlus.cs:9](PrfPlus.cs#L9) |
| `MsChapV2` | Codec MS-CHAPv2 client-side (RFC 2759): NT hash (MD4), challenge hash (SHA-1), NT-Response (3×DES) + dẫn xuất HLAK/MPPE (RFC 3079); dùng chung cho PPP auth & IKEv2 EAP | [MsChapV2.cs:11](MsChapV2.cs#L11) |
| `HmacUtil` | Internal: chọn `HMACMD5/SHA1/SHA256/SHA384/SHA512` theo `HashAlgorithmName` | [HmacUtil.cs:6](HmacUtil.cs#L6) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|------------------------|--------------------|---------|
| RFC 1320 (MD4) | `Md4` | [Md4.cs:6](Md4.cs#L6) | Ghi rõ trong comment; cần cho NT hash MS-CHAPv2 |
| FIPS 46-3 (DES) | `Des` | [Des.cs:4](Des.cs#L4) | Comment; ECB-encrypt 1 block, bỏ check weak-key cho MS-CHAPv2 |
| NIST SP 800-38A (CTR mode) | `AesCtr` | [AesCtr.cs:7](AesCtr.cs#L7) | Comment; counter 128-bit tăng big-endian |
| RFC 3686 (AES-CTR cho ESP) | `AesCtr` | [AesCtr.cs:7](AesCtr.cs#L7) | Comment; framing counter đặc thù ESP nằm ở tầng trên |
| RFC 3602 (AES-CBC cho IPsec ESP) | `AesCbcCipher` | [AesCbcCipher.cs:7](AesCbcCipher.cs#L7) | Comment; no-padding, caller tự pad |
| RFC 2409 group 2 / RFC 3526 group 14 (MODP DH) | `ModpDhGroup` | [ModpDhGroup.cs:9](ModpDhGroup.cs#L9), prime tại [:14](ModpDhGroup.cs#L14) & [:21](ModpDhGroup.cs#L21) | Comment; g=2, public value cố định độ dài modulus |
| RFC 7296 §2.13 (IKEv2 `prf+`) | `PrfPlus` | [PrfPlus.cs:5-7](PrfPlus.cs#L5-L7) | Comment; T1=prf(K,S\|0x01), Tn=prf(K,T(n-1)\|S\|n) |
| RFC 4868 (PRF-HMAC-SHA256, HMAC-SHA256-128) | `HmacPrf`, `HmacIntegrity` | [HmacPrf.cs:28](HmacPrf.cs#L28), [HmacIntegrity.cs:32](HmacIntegrity.cs#L32) | Comment |
| RFC 2404 (HMAC-SHA1-96) | `HmacIntegrity` | [HmacIntegrity.cs:35](HmacIntegrity.cs#L35) | Comment |
| IANA DH group registry | `IDhGroup.GroupId` | [Interfaces/IDhGroup.cs:6](Interfaces/IDhGroup.cs#L6) | Comment; số nhóm DH (2, 14, 19...) |
| FIPS 197 (AES) | `AesCbcCipher`, `AesCtr`, `AesGcmCipher` | [AesCbcCipher.cs:10](AesCbcCipher.cs#L10), [AesCtr.cs:9](AesCtr.cs#L9), [Aead/AesGcmCipher.cs:18](Aead/AesGcmCipher.cs#L18) | (suy luận) AES không ghi tên FIPS trong comment |
| NIST SP 800-38D (AES-GCM / GCM) | `AesGcmCipher` | [Aead/AesGcmCipher.cs:18](Aead/AesGcmCipher.cs#L18) | (suy luận) comment chỉ nói "AES-GCM AEAD" |
| RFC 2104 / FIPS 198-1 (HMAC) | `HmacUtil`, `HmacPrf`, `HmacIntegrity` | [HmacUtil.cs:6](HmacUtil.cs#L6) | (suy luận) dùng `HMAC*` của BCL |
| RFC 2759 (MS-CHAPv2) | `MsChapV2` (codec) trên `Md4`+`Des`+SHA-1 | [MsChapV2.cs:11](MsChapV2.cs#L11) | NtPasswordHash §8.3 [L14](MsChapV2.cs#L14), ChallengeHash §8.2 [L18](MsChapV2.cs#L18), ChallengeResponse §8.5 [L34](MsChapV2.cs#L34), GenerateNTResponse §8.1 [L50](MsChapV2.cs#L50) |
| RFC 3079 (dẫn xuất khoá MPPE) | `MsChapV2.DeriveHlak` | [MsChapV2.cs:87](MsChapV2.cs#L87) | Master/Send/Receive key → HLAK 32 byte cho SSTP crypto binding |

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
- **DES** ([Des.cs:11-32](Des.cs#L11-L32)): IP → 16 vòng Feistel với `KeySchedule` 16 subkey 48-bit ([Des.cs:34-48](Des.cs#L34-L48)) → swap → FP. Hàm Feistel dùng E-expansion, 8 S-box và P-permutation ([Des.cs:50-62](Des.cs#L50-L62)). Bỏ qua bit parity của key (đúng đặc tả DES) và **không** loại weak key — vì MS-CHAPv2 sinh key DES từ password hash có thể yếu.
- **MODP DH** ([ModpDhGroup.cs:57-83](ModpDhGroup.cs#L57-L83)): private key là số mũ ngẫu nhiên trong `[2, p-2]`; public/shared dùng `BigInteger.ModPow`. Mọi giá trị wire là big-endian cố định độ dài modulus; chuyển đổi big-endian ↔ `BigInteger` (chèn byte 0x00 để giữ dấu dương) tại [ModpDhGroup.cs:93-114](ModpDhGroup.cs#L93-L114).
- **prf+** ([PrfPlus.cs:12-44](PrfPlus.cs#L12-L44)): lặp `Tn = prf(K, T(n-1) | S | n)`, nối khối cho tới khi đủ `length`; ném lỗi nếu vượt 255 vòng (counter byte tràn về 0).
- **MD4** ([Md4.cs:15-43](Md4.cs#L15-L43)): xử lý từng khối 64 byte + tail có padding 0x80 và độ dài bit 64-bit little-endian; mỗi khối qua 3 round F/G/H ([Md4.cs:53-90](Md4.cs#L53-L90)).

## Trạng thái & ghi chú

- **Đã hiện thực & dùng thật:** MD4, DES, AES-CBC, AES-CTR, AES-GCM, MODP DH (group 2/14), HMAC-PRF, HMAC-integrity, prf+ — tất cả được tiêu thụ bởi `Ipsec` (IKE/ESP) và `Ppp` (MS-CHAPv2).
- **Khác biệt netstandard2.0 vs net8.0:** chỉ ở `AesGcmCipher`. net8.0 dùng `AesGcm` của BCL; netstandard2.0 fallback BouncyCastle (PackageReference chỉ kéo vào ở TFM này). Các primitive còn lại dùng BCL chung cho cả hai TFM.
- **MODP group 2 (1024-bit)** giữ lại cho tương thích IKEv1/VPN Gate dù đã yếu theo tiêu chuẩn hiện đại; **group 14 (2048-bit)** là lựa chọn mặc định khuyến nghị.
- **MD4 & DES** cố ý dùng thuật toán đã "vỡ" về mặt mật mã — chỉ vì MS-CHAPv2 bắt buộc; **không** dùng cho mục đích bảo mật mới.
- **Ghi chú "SHA-0" trong `<Description>` csproj** mang tính liệt kê họ thuật toán; trong code, SHA-1/256/384/512 được dùng gián tiếp qua HMAC của BCL ([HmacUtil.cs:24-32](HmacUtil.cs#L24-L32)), không có file SHA độc lập trong project.
- **`HmacPrf`/`HmacIntegrity`** hiện cấp factory cho SHA-256 (PRF, ICV-128) và SHA-1-96 (ICV); họ HMAC khác (MD5/SHA384/SHA512) đã sẵn trong `HmacUtil` nếu cần mở rộng.
- Không có khoá/khử cấp phát: nhiều API dùng `ReadOnlySpan<byte>` ở biên ngoài nhưng bên trong vẫn `ToArray()` (do BCL/BigInteger yêu cầu mảng) — chưa zeroize bộ đệm trung gian; đây là hạn chế đã biết.
- Tài liệu as-built tổng thể: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
