# TqkLibrary.Vpn.Ipsec

> IPsec: ESP transform (RFC 4303) dưới `Esp/`, và IKE dưới `Ike/` — IKEv1 Main+Quick Mode (`Ike/V1`) và IKEv2 (`Ike/V2`).

## Mục đích

Project này hiện thực **IPsec ở tầng PROTOCOL** cho VPN client userspace, gồm hai mảng tách bạch:

- **IKE (Internet Key Exchange)** — control plane: thương lượng SA và sinh khóa.
  - `Ike/V1` — ISAKMP/IKEv1 (RFC 2407/2408/2409): Main Mode (PSK, 6 message) + Quick Mode (3 message), cộng các Informational (DPD keepalive, Delete teardown, Quick Mode rekey). **Đây là phần đang chạy thực tế**, được driver L2TP/IPsec dùng để dựng ESP CHILD SA cho L2TP/IPsec qua VPN Gate.
  - `Ike/V2` — IKEv2 (RFC 7296): IKE_SA_INIT + IKE_AUTH (PSK) đầy đủ, có unit test, **nhưng chưa driver nào wire vào**.
- **ESP (Encapsulating Security Payload)** — data plane (RFC 4303): `Esp/` đóng/mở gói ESP (`Protect` / `TryUnprotect`), gán sequence number, anti-replay window, hỗ trợ hai bộ suite CBC+HMAC và GCM (AEAD).

Toàn bộ là **logic giao thức thuần** (build/process từng message, encode/decode payload, dẫn xuất khóa). Project **không** sở hữu transport: driver bên ngoài lo socket UDP, chuyển port 500→4500 khi NAT-T, và điều phối handshake. Primitive crypto (AES, DH, HMAC-PRF, GCM) nằm ở project `TqkLibrary.Vpn.Crypto`.

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (giữa CRYPTO và DRIVER).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.Vpn.Abstractions](../TqkLibrary.Vpn.Abstractions) — interface + model + enum dùng chung.
  - [TqkLibrary.Vpn.Crypto](../TqkLibrary.Vpn.Crypto) — AES-CBC/GCM, DH (MODP), HMAC-PRF, các integrity algo.
  - Không có PackageReference đặc thù (xem [TqkLibrary.Vpn.Ipsec.csproj](TqkLibrary.Vpn.Ipsec.csproj)).
- **Được dùng bởi:** [TqkLibrary.Vpn.Drivers.L2tpIpsec](../TqkLibrary.Vpn.Drivers.L2tpIpsec) (driver L2TP/IPsec dùng `Ike/V1` + `Esp/`).

Xem thêm tài liệu as-built toàn cục: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Ipsec/
├─ Esp/                         ESP data plane (RFC 4303) — đóng/mở gói, anti-replay, các cipher suite
│  ├─ EspSession.cs             Cặp SA hai chiều: outbound (sequence) + inbound (anti-replay) — đơn vị data plane gửi qua
│  ├─ EspCipherSuite.cs         Lớp trừu tượng cho 1 ESP transform + 3 factory (CBC/SHA256, CBC/SHA1, GCM)
│  ├─ EspCbcHmacSuite.cs        Suite AES-CBC + HMAC (encrypt-then-MAC): SPI|Seq|IV|ct|ICV
│  ├─ EspGcmSuite.cs            Suite AES-GCM AEAD (RFC 4106): salt+explicit-IV, AAD = SPI|Seq
│  ├─ AntiReplayWindow.cs       Cửa sổ trượt 64 gói chống replay (RFC 4303 §3.4.3)
│  └─ EspConstants.cs           Hằng số/helper header ESP (SPI 4B + Sequence 4B)
└─ Ike/                         Internet Key Exchange — control plane
   ├─ V1/                       ISAKMP/IKEv1 — ĐANG CHẠY THỰC TẾ (L2TP/IPsec)
   │  ├─ IkeV1Client.cs         Client initiator: MM1–MM6, QM1–QM3, rekey, DPD, Delete (điểm vào chính)
   │  ├─ IkeV1KeyMaterial.cs    SKEYID / SKEYID_d/a/e + khóa Phase 1 + IV đầu (RFC 2409 §5)
   │  ├─ IkeV1Auth.cs           HASH_I / HASH_R (xác thực Main Mode)
   │  ├─ IkeV1QuickMode.cs      HASH(1)/HASH(2)/HASH(3) (xác thực Quick Mode)
   │  ├─ IkeV1Phase2Keys.cs     KEYMAT = prf+(SKEYID_d, …) → khóa ESP CHILD SA hai chiều
   │  ├─ IkeV1Cipher.cs         Trạng thái mã hóa CBC theo phase (chain IV) + Quick Mode IV
   │  ├─ IkeV1NatDetection.cs   NAT-T Vendor ID + NAT-D hash (RFC 3947)
   │  ├─ IkeV1Dpd.cs            DPD R-U-THERE / ACK (RFC 3706)
   │  ├─ IkeV1Delete.cs         Delete payload body cho ESP / ISAKMP teardown (RFC 2408 §3.15)
   │  ├─ IkeV1Proposals.cs      Proposal mặc định Phase 1 / Phase 2 (interop VPN Gate / RRAS)
   │  ├─ IkeV1Lifetimes.cs      Lifetime SA (Phase 1 = 8h, Phase 2 = 1h)
   │  ├─ IsakmpMessage.cs       Header 28B + chain payload (encode/decode/parse)
   │  ├─ Enums/                 Payload type, exchange type, hằng số ISAKMP, kind Informational
   │  ├─ Models/                IsakmpAttribute / IsakmpTransform / IsakmpProposal + InformationalResult
   │  └─ Payloads/              IsakmpPayload (base), IsakmpRawPayload, IsakmpSaPayload
   └─ V2/                       IKEv2 (RFC 7296) — đầy đủ + test, CHƯA driver nào dùng
      ├─ IkeClient.cs           Client initiator IKEv2: IKE_SA_INIT + IKE_AUTH (PSK)
      ├─ IkeSaInitiator.cs      Nửa initiator của IKE_SA_INIT (SPI, DH, nonce, SK_*)
      ├─ IkeKeyMaterial.cs      7 khóa SK_d/ai/ar/ei/er/pi/pr (RFC 7296 §2.14)
      ├─ ChildSaKeys.cs         KEYMAT CHILD_SA = prf+(SK_d, Ni|Nr) (RFC 7296 §2.17)
      ├─ IkeCipher.cs           Mã hóa/giải mã SK payload (RFC 7296 §3.14)
      ├─ IkePskAuth.cs          AUTH = prf(prf(PSK,"Key Pad…"), SignedOctets) (RFC 7296 §2.15)
      ├─ IkeMessage.cs / IkeBuffer.cs   Header 28B + payload chain (encode/decode)
      ├─ IkeProposals.cs / NatDetection.cs
      ├─ Enums/ Models/ Payloads/   Cấu trúc payload IKEv2 (SA, KE, Nonce, Notify, TS, ID, AUTH…)
```

## Thành phần chính

### ESP (data plane)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `EspSession` | Cặp SA hai chiều: `Protect` (gán sequence) + `TryUnprotect` (check SPI/replay/integrity rồi giải mã) | [EspSession.cs:7](Esp/EspSession.cs#L7) |
| `EspCipherSuite` | Lớp trừu tượng 1 ESP transform + factory `AesCbcHmacSha256` / `AesCbcHmacSha1` / `AesGcm` | [EspCipherSuite.cs:10](Esp/EspCipherSuite.cs#L10) |
| `EspCbcHmacSuite` | AES-CBC + HMAC, encrypt-then-MAC, layout `SPI\|Seq\|IV\|ct\|ICV` | [EspCbcHmacSuite.cs:11](Esp/EspCbcHmacSuite.cs#L11) |
| `EspGcmSuite` | AES-GCM AEAD, nonce = salt(4)‖seq-IV(8), AAD = `SPI\|Seq` | [EspGcmSuite.cs:11](Esp/EspGcmSuite.cs#L11) |
| `AntiReplayWindow` | Cửa sổ trượt 64 gói; `Check` (thuần) + `Commit` (sau khi qua integrity) | [AntiReplayWindow.cs:7](Esp/AntiReplayWindow.cs#L7) |
| `EspConstants` | Hằng số + helper header (`ReadSpi`/`ReadSequence`/`WriteHeader`) | [EspConstants.cs:4](Esp/EspConstants.cs#L4) |

### IKEv1 (đang chạy)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `IkeV1Client` | Client initiator: build/process từng MM/QM, rekey, DPD, Delete, Informational | [IkeV1Client.cs:16](Ike/V1/IkeV1Client.cs#L16) |
| `IkeV1KeyMaterial` | SKEYID + SKEYID_d/a/e + khóa Phase 1 + IV đầu; `ExpandKey` | [IkeV1KeyMaterial.cs:12](Ike/V1/IkeV1KeyMaterial.cs#L12) |
| `IkeV1Auth` | `ComputeHashI` / `ComputeHashR` (xác thực Main Mode) | [IkeV1Auth.cs:10](Ike/V1/IkeV1Auth.cs#L10) |
| `IkeV1QuickMode` | `ComputeHash1/2/3` (xác thực Quick Mode, keyed by SKEYID_a) | [IkeV1QuickMode.cs:10](Ike/V1/IkeV1QuickMode.cs#L10) |
| `IkeV1Phase2Keys` | `Derive`: KEYMAT → khóa ESP enc/integ hai chiều (no PFS) | [IkeV1Phase2Keys.cs:10](Ike/V1/IkeV1Phase2Keys.cs#L10) |
| `IkeV1Cipher` | Trạng thái CBC theo phase (chain IV) + `QuickModeIv` | [IkeV1Cipher.cs:12](Ike/V1/IkeV1Cipher.cs#L12) |
| `IkeV1NatDetection` | Vendor ID NAT-T + NAT-D hash để ép sang UDP/4500 | [IkeV1NatDetection.cs:12](Ike/V1/IkeV1NatDetection.cs#L12) |
| `IkeV1Dpd` | Build/parse Notification R-U-THERE / ACK (DPD) | [IkeV1Dpd.cs:9](Ike/V1/IkeV1Dpd.cs#L9) |
| `IkeV1Delete` | Build Delete body cho ESP / ISAKMP SA | [IkeV1Delete.cs:9](Ike/V1/IkeV1Delete.cs#L9) |
| `IkeV1Proposals` | Proposal Phase 1 / Phase 2 mặc định (AES-CBC/SHA1/PSK, MODP 2/14) | [IkeV1Proposals.cs:12](Ike/V1/IkeV1Proposals.cs#L12) |
| `IsakmpMessage` | Header 28B + chain payload: `Encode`/`Decode`/`ParsePayloadChain` | [IsakmpMessage.cs:11](Ike/V1/IsakmpMessage.cs#L11) |
| `IkeV1InformationalResult` / `IkeV1InformationalKind` | Phân loại Informational đến (DPD/Delete/Unknown) | [IkeV1InformationalResult.cs:6](Ike/V1/Models/IkeV1InformationalResult.cs#L6), [IkeV1InformationalKind.cs:4](Ike/V1/Enums/IkeV1InformationalKind.cs#L4) |
| `IkeV1Constants` | DOI, protocol/transform id, lớp attribute SA (RFC 2407/2408/2409) | [IkeV1Constants.cs:24](Ike/V1/Enums/IkeV1Constants.cs#L24) |

### IKEv2 (đầy đủ nhưng chưa wire)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `IkeClient` | Client initiator IKEv2: IKE_SA_INIT → IKE_AUTH (PSK), verify AUTH, sinh CHILD_SA | [IkeClient.cs:15](Ike/V2/IkeClient.cs#L15) |
| `IkeSaInitiator` | Nửa initiator IKE_SA_INIT: SPI, DH (MODP-2048), nonce, SK_* | [IkeSaInitiator.cs:15](Ike/V2/IkeSaInitiator.cs#L15) |
| `IkeKeyMaterial` | 7 khóa SK_d/ai/ar/ei/er/pi/pr (RFC 7296 §2.14) | [IkeKeyMaterial.cs:11](Ike/V2/IkeKeyMaterial.cs#L11) |
| `ChildSaKeys` | KEYMAT CHILD_SA = prf+(SK_d, Ni\|Nr) (no PFS) | [ChildSaKeys.cs:11](Ike/V2/ChildSaKeys.cs#L11) |
| `IkeCipher` | Mã hóa/giải mã SK payload (AES-CBC-256 + HMAC-SHA-256-128) | [IkeCipher.cs:12](Ike/V2/IkeCipher.cs#L12) |
| `IkePskAuth` | AUTH = prf(prf(PSK,"Key Pad for IKEv2"), SignedOctets) | [IkePskAuth.cs:12](Ike/V2/IkePskAuth.cs#L12) |

## Chuẩn / RFC tuân thủ

> Mục trọng tâm — ánh xạ class/namespace → chuẩn. Hầu hết RFC được chú thích sẵn trong comment code (link tới đúng dòng). Chuẩn nổi tiếng không ghi trong comment đánh dấu **(suy luận)**.

| Chuẩn (RFC/FIPS/NIST) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|------------------------|--------------------------|---------------------|---------|
| **RFC 4303** (ESP) | `EspConstants` (header §2/§2.6), `EspSession` (§3.3.3), `AntiReplayWindow` (§3.4.3), `EspCipherSuite.TryStripTrailer` (§2.4 padding) | [EspConstants.cs:3](Esp/EspConstants.cs#L3), [EspSession.cs:14](Esp/EspSession.cs#L14), [AntiReplayWindow.cs:4](Esp/AntiReplayWindow.cs#L4), [EspCipherSuite.cs:50](Esp/EspCipherSuite.cs#L50) | Có trong comment |
| **RFC 3602** (AES-CBC cho IPsec) | `EspCbcHmacSuite` (confidentiality) | [EspCbcHmacSuite.cs:7](Esp/EspCbcHmacSuite.cs#L7), [EspCipherSuite.cs:20](Esp/EspCipherSuite.cs#L20) | Có trong comment |
| **RFC 4868** (HMAC-SHA-256-128) | `EspCbcHmacSuite` (integrity mặc định, IKEv2) | [EspCbcHmacSuite.cs:8](Esp/EspCbcHmacSuite.cs#L8), [EspCipherSuite.cs:20](Esp/EspCipherSuite.cs#L20) | Có trong comment |
| **RFC 2404** (HMAC-SHA-1-96) | `EspCipherSuite.AesCbcHmacSha1` (ESP SA của IKEv1) | [EspCipherSuite.cs:24](Esp/EspCipherSuite.cs#L24) | Có trong comment |
| **RFC 4106** (AES-GCM trong ESP) | `EspGcmSuite` (AEAD, salt+explicit-IV, alignment 4B) | [EspGcmSuite.cs:7](Esp/EspGcmSuite.cs#L7), [EspGcmSuite.cs:15](Esp/EspGcmSuite.cs#L15) | Có trong comment |
| **RFC 2409** (IKEv1) | `IkeV1KeyMaterial` (§5), `IkeV1Auth` (§5), `IkeV1QuickMode` (§5.5), `IkeV1Phase2Keys` (§5.5), `IkeV1Cipher` (§5.5) | [IkeV1KeyMaterial.cs:8](Ike/V1/IkeV1KeyMaterial.cs#L8), [IkeV1Auth.cs:6](Ike/V1/IkeV1Auth.cs#L6), [IkeV1QuickMode.cs:6](Ike/V1/IkeV1QuickMode.cs#L6), [IkeV1Phase2Keys.cs:6](Ike/V1/IkeV1Phase2Keys.cs#L6), [IkeV1Cipher.cs:8](Ike/V1/IkeV1Cipher.cs#L8) | Có trong comment |
| **RFC 2408** (ISAKMP) | `IsakmpMessage` (§3.1), `IsakmpSaPayload` (§3.4), `IsakmpPayload` (base), `IsakmpProposal` (§3.5)/`IsakmpTransform` (§3.6), `IsakmpAttribute` (§3.3), `IkeV1Dpd` (Notification §3.14), `IkeV1Delete` (Delete §3.15), `IkeV1Constants` (flags §3.1) | [IsakmpMessage.cs:8](Ike/V1/IsakmpMessage.cs#L8), [IsakmpSaPayload.cs:7](Ike/V1/Payloads/IsakmpSaPayload.cs#L7), [IkeV1Dpd.cs:20](Ike/V1/IkeV1Dpd.cs#L20), [IkeV1Delete.cs:6](Ike/V1/IkeV1Delete.cs#L6), [IkeV1Constants.cs:3](Ike/V1/Enums/IkeV1Constants.cs#L3) | Có trong comment |
| **RFC 2407** (IPsec DOI) | `IkeV1Constants` (protocol/transform id, attribute class, encap mode) | [IkeV1Constants.cs:32](Ike/V1/Enums/IkeV1Constants.cs#L32), [IkeV1Constants.cs:117](Ike/V1/Enums/IkeV1Constants.cs#L117) | Có trong comment |
| **RFC 3947** (NAT-T cho IKEv1) | `IkeV1NatDetection` (Vendor ID + NAT-D hash), `IsakmpPayloadType.NatDiscovery`, encap UDP-Tunnel/Transport | [IkeV1NatDetection.cs:8](Ike/V1/IkeV1NatDetection.cs#L8), [IsakmpPayloadType.cs:48](Ike/V1/Enums/IsakmpPayloadType.cs#L48), [IkeV1Constants.cs:141](Ike/V1/Enums/IkeV1Constants.cs#L141) | Có trong comment |
| **draft-ietf-ipsec-nat-t-ike-02/03** | `IkeV1NatDetection.VendorIdDraft02/03` (fallback NAT-T cũ, payload NAT-D = 130) | [IkeV1NatDetection.cs:17](Ike/V1/IkeV1NatDetection.cs#L17) | Có trong comment |
| **RFC 3706** (DPD) | `IkeV1Dpd` (R-U-THERE / R-U-THERE-ACK), `IkeV1InformationalKind` | [IkeV1Dpd.cs:6](Ike/V1/IkeV1Dpd.cs#L6), [IkeV1InformationalKind.cs:3](Ike/V1/Enums/IkeV1InformationalKind.cs#L3) | Có trong comment |
| **RFC 7296** (IKEv2) | `IkeMessage` (§3.1), `IkeKeyMaterial` (§2.14), `ChildSaKeys` (§2.17), `IkeCipher` (§3.14), `IkePskAuth` (§2.15), `IkeSaInitiator` (§2.15), `NatDetection` (§2.23), `Ike/V2/Payloads/*`, `Ike/V2/Enums/*` | [IkeMessage.cs:7](Ike/V2/IkeMessage.cs#L7), [IkeKeyMaterial.cs:7](Ike/V2/IkeKeyMaterial.cs#L7), [ChildSaKeys.cs:7](Ike/V2/ChildSaKeys.cs#L7), [IkeCipher.cs:8](Ike/V2/IkeCipher.cs#L8), [IkePskAuth.cs:7](Ike/V2/IkePskAuth.cs#L7), [NatDetection.cs:7](Ike/V2/NatDetection.cs#L7) | Có trong comment (chưa wire) |
| **FIPS-197** (AES) | Khóa AES-128/192/256 cho mọi suite ESP + cipher IKE (qua `TqkLibrary.Vpn.Crypto`) | [EspCbcHmacSuite.cs:28](Esp/EspCbcHmacSuite.cs#L28) | **(suy luận)** — không chú thích trong comment |
| **NIST SP 800-38D** (AES-GCM) | `EspGcmSuite` (chế độ GCM của AES) | [EspGcmSuite.cs:11](Esp/EspGcmSuite.cs#L11) | **(suy luận)** — RFC 4106 mới được ghi |
| **NIST SP 800-38A** (CBC mode) | `EspCbcHmacSuite`, `IkeV1Cipher`, `IkeCipher` (V2) | [EspCbcHmacSuite.cs:11](Esp/EspCbcHmacSuite.cs#L11) | **(suy luận)** |
| **RFC 2104** (HMAC) / **FIPS-198** | HMAC-PRF + integrity (qua `TqkLibrary.Vpn.Crypto`) | [IkeV1KeyMaterial.cs:51](Ike/V1/IkeV1KeyMaterial.cs#L51) | **(suy luận)** |

## API / cách dùng

### ESP — đóng/mở gói (data plane)

```csharp
// Sau Quick Mode (IKEv1), driver dẫn xuất khóa rồi dựng EspSession:
IkeV1Phase2Keys p2 = ike.CreatePhase2Keys(); // AES-256 + HMAC-SHA1
var outbound = EspCipherSuite.AesCbcHmacSha1(p2.OutboundEncryption, p2.OutboundIntegrity);
var inbound  = EspCipherSuite.AesCbcHmacSha1(p2.InboundEncryption,  p2.InboundIntegrity);

uint outSpi = BitConverter.ToUInt32(...ike.ChildOutboundSpi...); // big-endian
uint inSpi  = BitConverter.ToUInt32(...ike.ChildInboundSpi...);
var esp = new EspSession(outSpi, outbound, inSpi, inbound);

byte[] wire = esp.Protect(innerPayload, EspConstants.NextHeaderUdp); // gửi qua UDP/4500
if (esp.TryUnprotect(received, out byte[] payload, out byte nextHeader)) { /* dùng payload */ }
```

### IKEv1 — handshake (driver điều phối UDP)

```csharp
var ike = new IkeV1Client(preSharedKey, IPAddress.Any, serverIp);
Send(ike.BuildMainMode1());          ike.ProcessMainMode2(Recv());  // MM1/MM2
Send(ike.BuildMainMode3(local, srv)); ike.ProcessMainMode4(Recv()); // MM3/MM4 → SKEYID
Send(ike.BuildMainMode5());           ike.ProcessMainMode6(Recv()); // MM5/MM6 → verify HASH_R
Send(ike.BuildQuickMode1());          ike.ProcessQuickMode2(Recv()); // QM1/QM2 → ESP SPI peer
Send(ike.BuildQuickMode3());                                         // QM3
IkeV1Phase2Keys keys = ike.CreatePhase2Keys();
// Sau handshake: ike.BuildDpdRUThere/BuildDpdAck (keepalive), BuildRekeyQuickMode1/3 (rekey),
// BuildDeleteEsp/BuildDeleteIsakmp (teardown), ProcessInformational (phân loại message đến).
```

### IKEv2 — (chưa driver nào dùng)

```csharp
var ike = new IkeClient(psk, identity, requestTransportMode: true);
IkeMessage init = ike.BuildInitRequest(localIp, 500, remoteIp, 500);
ike.ProcessInitResponse(Decode(Recv()));   // IKE_SA_INIT → SK_*
Send(ike.BuildAuthRequest());               // IKE_AUTH (encrypted)
if (ike.ProcessAuthResponse(Recv())) { ChildSaKeys child = ike.ChildKeys!; }
```

## Luồng nội bộ

### IKEv1 Main + Quick Mode (initiator)

1. **MM1/MM2** — gửi SA proposal + Vendor ID NAT-T; đọc responder cookie, transform được chọn, flavour NAT-T. [IkeV1Client.cs:85](Ike/V1/IkeV1Client.cs#L85), [IkeV1Client.cs:99](Ike/V1/IkeV1Client.cs#L99)
2. **MM3/MM4** — gửi KE + Ni + 2 NAT-D (ép NAT-T); đọc KEr + Nr → tính `g^xy` → `DeriveMainMode` sinh SKEYID & khóa Phase 1. [IkeV1Client.cs:125](Ike/V1/IkeV1Client.cs#L125), [IkeV1Client.cs:139](Ike/V1/IkeV1Client.cs#L139), [IkeV1KeyMaterial.cs:38](Ike/V1/IkeV1KeyMaterial.cs#L38)
3. **MM5/MM6** — gửi IDi + HASH_I (đã mã hóa); giải mã MM6, verify HASH_R, lưu IV cuối Phase 1. [IkeV1Client.cs:153](Ike/V1/IkeV1Client.cs#L153), [IkeV1Client.cs:168](Ike/V1/IkeV1Client.cs#L168), [IkeV1Auth.cs:13](Ike/V1/IkeV1Auth.cs#L13)
4. **QM1/QM2/QM3** — IV Quick Mode dẫn từ IV Phase 1 cuối + message id; HASH(1)/(2)/(3) keyed by SKEYID_a; bắt ESP SPI của peer. [IkeV1Client.cs:184](Ike/V1/IkeV1Client.cs#L184), [IkeV1Cipher.cs:53](Ike/V1/IkeV1Cipher.cs#L53), [IkeV1QuickMode.cs:13](Ike/V1/IkeV1QuickMode.cs#L13)
5. **Phase 2 keys** — `CreatePhase2Keys` → KEYMAT = prf+(SKEYID_d, proto\|SPI\|Ni\|Nr) → khóa ESP enc/integ hai chiều. [IkeV1Client.cs:227](Ike/V1/IkeV1Client.cs#L227), [IkeV1Phase2Keys.cs:30](Ike/V1/IkeV1Phase2Keys.cs#L30)
6. **Hậu handshake (Informational)** — mọi datagram IKE sau handshake route qua `ProcessInformational`: phân loại DPD request/ack hoặc Delete; build DPD/Delete/rekey dưới message id mới với IV dẫn xuất riêng. [IkeV1Client.cs:334](Ike/V1/IkeV1Client.cs#L334), [IkeV1Client.cs:389](Ike/V1/IkeV1Client.cs#L389)

### ESP `Protect` / `TryUnprotect`

- **Protect** — tăng sequence (checked), gọi suite encode `SPI\|Seq\|IV\|ct\|ICV` (hoặc GCM). Property [`OutboundSequence`](Esp/EspSession.cs#L36) lộ sequence hiện tại để driver rekey **trước khi** chạm 2³² (xem note ESP suite bên dưới). [EspSession.cs:39](Esp/EspSession.cs#L39), [EspCbcHmacSuite.cs:37](Esp/EspCbcHmacSuite.cs#L37)
- **TryUnprotect** — check độ dài → SPI → `AntiReplayWindow.Check` → integrity → giải mã → strip trailer → `Commit`. Replay window **chỉ advance sau khi gói qua integrity**. [EspSession.cs:50](Esp/EspSession.cs#L50), [AntiReplayWindow.cs:20](Esp/AntiReplayWindow.cs#L20)

## Trạng thái & ghi chú

- **Đang chạy thực tế:** `Ike/V1` + `Esp/` — driver `L2tpIpsec` dùng `IkeV1Client` ([L2tpIpsecConnection.cs:136](../TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecConnection.cs#L136)) và `EspSession`/`EspCipherSuite` cho data plane. Đã verify live trên VPN Gate (PSK + AES-256 + HMAC-SHA1, MODP group 2/14).
- **Đầy đủ nhưng chưa wire:** `Ike/V2` (IKEv2) — `IkeClient` có đủ IKE_SA_INIT + IKE_AUTH (PSK) và unit test, nhưng **không driver nào tham chiếu** (grep `IkeClient` trong `Drivers` không có kết quả). Đây là khung sẵn cho IKEv2 transport mode/ESP tương lai.
- **ESP suite:** ba bộ — AES-CBC+HMAC-SHA256-128 (mặc định IKEv2), AES-CBC+HMAC-SHA1-96 (ESP SA của IKEv1, đang dùng), AES-GCM (RFC 4106, AEAD). Anti-replay cố định cửa sổ 64, **không hỗ trợ Extended Sequence Number** (ESN): GCM IV để 4 byte cao = 0 ([EspGcmSuite.cs:87](Esp/EspGcmSuite.cs#L87)); sequence là 32-bit, `Protect` dùng `checked` nên sẽ ném nếu vượt `uint.MaxValue` — đây là **backstop**: driver `L2tpIpsec` theo dõi `OutboundSequence` và chủ động rekey Phase 2 ở high-watermark ~75%×2³² (RFC 4303 §3.3.3) **trước khi** chạm giới hạn này.
- **IKEv1 PFS:** Quick Mode rekey **không có PFS** (KEYMAT chỉ từ SKEYID_d + nonce mới, không trao đổi KE mới) — phù hợp interop L2TP/IPsec phổ biến.
- **netstandard2.0 vs net8.0:** cùng codebase; tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`). Primitive crypto khác biệt nằm ở `TqkLibrary.Vpn.Crypto` (BouncyCastle trên netstandard2.0), không phải project này.
- **Phạm vi:** chỉ logic giao thức (build/process/encode/decode/derive). Transport UDP, chuyển port 500→4500 khi NAT-T, retransmit, vòng đời SA do driver bên ngoài sở hữu.
