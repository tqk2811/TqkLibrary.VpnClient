# TqkLibrary.VpnClient.Ipsec

> IPsec: ESP transform (RFC 4303) dưới `Esp/`, IKE dưới `Ike/` — IKEv1 Main+Quick Mode (`Ike/V1`) và IKEv2 (`Ike/V2`) — và NAT-T UDP framing/channel (RFC 3948, cổng 500/4500) dưới `Nat/`.

## Mục đích

Project này hiện thực **IPsec ở tầng PROTOCOL** cho VPN client userspace, gồm ba mảng tách bạch:

- **IKE (Internet Key Exchange)** — control plane: thương lượng SA và sinh khóa.
  - `Ike/V1` — ISAKMP/IKEv1 (RFC 2407/2408/2409): Main Mode (PSK, 6 message) **+ Aggressive Mode (group PSK, 3 message)** + Quick Mode (3 message, transport **hoặc tunnel**), **Transaction exchange (XAUTH user/pass + Mode-Config virtual IP/DNS)**, cộng các Informational (DPD keepalive, Delete teardown, Quick Mode rekey). **Đây là phần đang chạy thực tế**: driver L2TP/IPsec dùng Main Mode + Quick Mode transport; driver [`Drivers.CiscoIpsec`](../TqkLibrary.VpnClient.Drivers.CiscoIpsec) (V.12) dùng **Aggressive Mode + XAUTH + Mode-Config + Quick Mode tunnel** (validate live vs strongSwan). Transaction exchange chain CBC IV **per Message-ID** (RFC 2409 §5.5): reply XAUTH/Mode-Config echo Message-ID của request server gửi + mã hóa từ IV đã advance (KHÔNG derive lại) — bug live strongSwan đã sửa.
  - `Ike/V2` — IKEv2 (RFC 7296): IKE_SA_INIT + IKE_AUTH (PSK / **EAP-MSCHAPv2** §2.16, verify responder PSK **hoặc chữ ký số/cert** §2.15) + Configuration Payload (virtual IP/DNS) + **CERTREQ/CERT** (§3.6/§3.7) + **multi-traffic-selector** (§3.13) + INFORMATIONAL (DPD liveness, DELETE teardown) + CREATE_CHILD_SA (rekey CHILD_SA make-before-break **và rekey IKE SA** Phase-1-equivalent: SPI mới + DH mới + dẫn xuất lại SK_*, RFC 7296 §2.18), có unit test — **đủ protocol cho driver V.1 IKEv2-native; driver [`Drivers.Ikev2`](../TqkLibrary.VpnClient.Drivers.Ikev2) consume PSK / EAP / cert + multi-TS + timer rekey CHILD_SA. Primitive rekey IKE SA (`BuildRekeyIkeSaRequest`/`ProcessRekeyIkeSaResponse`) đã có + unit test nhưng driver chưa wire timer/route (xem §Trạng thái)**.
- **ESP (Encapsulating Security Payload)** — data plane (RFC 4303): `Esp/` đóng/mở gói ESP (`Protect` / `TryUnprotect`), gán sequence number, anti-replay window, hỗ trợ hai bộ suite **AES-CBC+HMAC** và **AES-GCM** (AEAD). `EspSuiteSelection` là descriptor "suite đã negotiate" — ánh xạ thuật toán → độ dài keymat → `EspCipherSuite`, dùng chung cho cả IKEv1 lẫn IKEv2 sau khi đọc transform server chọn.
- **NAT-T (UDP encapsulation)** — `Nat/` (RFC 3948, gom từ project cũ `TqkLibrary.VpnClient.Transport.Udp`): framing **Non-ESP Marker** phân biệt IKE với ESP khi chung cổng 4500 ([NatTraversal.cs](Nat/NatTraversal.cs)) + kênh UDP một-gateway có trạng thái cổng ([NatTraversalChannel.cs](Nat/NatTraversalChannel.cs)) — bind cổng local ephemeral (≠500/4500, tránh đụng IKEEXT của OS và ép forced-NAT-T) **theo họ địa chỉ gateway (IPv4/IPv6 — outer IPv6 P1.2)**, gửi/nhận IKE+ESP, đổi cổng 500→4500 theo lệnh.

`Ike/` và `Esp/` là **logic giao thức thuần** (build/process từng message, encode/decode payload, dẫn xuất khóa) — không socket; `Nat/` là ngoại lệ duy nhất sở hữu một `UdpClient`. Driver bên ngoài vẫn điều phối handshake (retransmit, thời điểm gọi `SwitchToNatTPort`). Primitive crypto (AES, DH, HMAC-PRF, GCM) nằm ở project `TqkLibrary.VpnClient.Crypto`.

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (giữa CRYPTO và DRIVER).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface + model + enum dùng chung.
  - [TqkLibrary.VpnClient.Crypto](../TqkLibrary.VpnClient.Crypto) — AES-CBC/GCM, DH (MODP), HMAC-PRF, các integrity algo.
  - Không có PackageReference đặc thù (xem [TqkLibrary.VpnClient.Ipsec.csproj](TqkLibrary.VpnClient.Ipsec.csproj)).
- **Được dùng bởi:**
  - [TqkLibrary.VpnClient.Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) — driver L2TP/IPsec dùng `Ike/V1` + `Esp/` + `Nat/`.
  - [TqkLibrary.VpnClient.Drivers.CiscoIpsec](../TqkLibrary.VpnClient.Drivers.CiscoIpsec) — driver Cisco IPsec/EzVPN (V.12) dùng `Ike/V1` (Aggressive Mode + XAUTH + Mode-Config + Quick Mode tunnel) + `Esp/` + `Nat/`.
  - [TqkLibrary.VpnClient.Drivers.Ikev2](../TqkLibrary.VpnClient.Drivers.Ikev2) — driver IKEv2-native dùng `Ike/V2` (`IkeClient`) + `Esp/` (`EspTunnelChannel`) + `Nat/`.

Xem thêm tài liệu as-built toàn cục: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Ipsec/
├─ Nat/                         NAT-T UDP encapsulation (RFC 3948) — gom từ project cũ Transport.Udp
│  ├─ NatTraversal.cs           static helper: hằng số cổng 500/4500 + framing Non-ESP Marker (Wrap/Classify/Unwrap)
│  ├─ NatTraversalChannel.cs    kênh UDP có trạng thái: gửi/nhận IKE & ESP, đổi cổng 500->4500
│  └─ Enums/NatTPacketKind.cs   phân loại datagram trên 4500: Invalid / Ike / Esp
├─ Esp/                         ESP data plane (RFC 4303) — đóng/mở gói, anti-replay, các cipher suite
│  ├─ EspSession.cs             Cặp SA hai chiều: outbound (sequence) + inbound (anti-replay) — đơn vị data plane gửi qua
│  ├─ EspDataPlane.cs           Base dùng chung: giữ SA hiện tại + SA cũ (make-before-break), watermark rekey 2³² (transport & tunnel mode)
│  ├─ EspTunnelChannel.cs       ESP tunnel mode (RFC 4303) → IPacketChannel: bọc nguyên gói IP (NextHeader 4/41), decap demux theo NextHeader
│  ├─ EspCipherSuite.cs         Lớp trừu tượng cho 1 ESP transform + 3 factory (CBC/SHA256, CBC/SHA1, GCM)
│  ├─ EspCbcHmacSuite.cs        Suite AES-CBC + HMAC (encrypt-then-MAC): SPI|Seq|IV|ct|ICV
│  ├─ EspGcmSuite.cs            Suite AES-GCM AEAD (RFC 4106): salt+explicit-IV, AAD = SPI|Seq
│  ├─ EspSuiteSelection.cs      Descriptor suite đã negotiate → độ dài keymat + BuildSuite (dùng chung V1/V2)
│  ├─ Enums/EspEncryptionAlgorithm.cs   AesCbc / AesGcm16
│  └─ EspConstants.cs           Hằng số/helper header ESP (SPI 4B + Sequence 4B)
│  (cửa sổ chống replay `AntiReplayWindow` nay ở project Crypto, dùng chung ESP + OpenVPN AEAD)
└─ Ike/                         Internet Key Exchange — control plane
   ├─ V1/                       ISAKMP/IKEv1 — ĐANG CHẠY THỰC TẾ (L2TP/IPsec)
   │  ├─ IkeV1Client.cs         Client initiator: MM1–MM6, **AG1–AG3 (Aggressive)**, **XAUTH + Mode-Config (Transaction)**, QM1–QM3 (transport/tunnel), rekey (Phase 1+2), DPD, Delete (điểm vào chính)
   │  ├─ IkeV1KeyMaterial.cs    SKEYID / SKEYID_d/a/e + khóa Phase 1 + IV đầu (RFC 2409 §5)
   │  ├─ IkeV1Auth.cs           HASH_I / HASH_R (xác thực Main Mode)
   │  ├─ IkeV1QuickMode.cs      HASH(1)/HASH(2)/HASH(3) (xác thực Quick Mode)
   │  ├─ IkeV1Phase2Keys.cs     KEYMAT = prf+(SKEYID_d, …) → khóa ESP CHILD SA hai chiều
   │  ├─ IkeV1Cipher.cs         Trạng thái mã hóa CBC theo phase (chain IV) + Quick Mode IV
   │  ├─ IkeV1NatDetection.cs   NAT-T Vendor ID + NAT-D hash + so khớp membership (RFC 3947)
   │  ├─ IkeV1Dpd.cs            DPD R-U-THERE / ACK (RFC 3706)
   │  ├─ IkeV1Delete.cs         Delete payload body cho ESP / ISAKMP teardown (RFC 2408 §3.15)
   │  ├─ IkeV1Proposals.cs      Proposal mặc định Phase 1 / Phase 2 (interop VPN Gate / RRAS)
   │  ├─ IkeV1Lifetimes.cs      Lifetime SA (Phase 1 = 8h, Phase 2 = 1h)
   │  ├─ IsakmpMessage.cs       Header 28B + chain payload (encode/decode/parse)
   │  ├─ Enums/                 Payload type, exchange type, hằng số ISAKMP, kind Informational, CFG type (XAUTH/Mode-Config)
   │  ├─ Models/                IsakmpAttribute / IsakmpTransform + IsakmpProposal (cùng file) + InformationalResult + NatDetectionResult
   │  └─ Payloads/              IsakmpPayload (base) + IsakmpRawPayload (cùng file), IsakmpSaPayload, IsakmpConfigPayload (XAUTH/Mode-Config)
   └─ V2/                       IKEv2 (RFC 7296) — protocol đủ cho V.1 (IKE_SA_INIT/AUTH PSK/EAP/**cert** + CP + multi-TS + INFORMATIONAL + CREATE_CHILD_SA rekey CHILD_SA **và IKE SA**), wire ở Drivers.Ikev2
      ├─ IkeClient.cs           Client initiator: IKE_SA_INIT + IKE_AUTH (PSK/EAP + verify responder PSK **hoặc cert**, opt-in CP/CERTREQ/multi-TS) + DPD/DELETE + rekey CHILD_SA + rekey IKE SA (Phase-1-equivalent)
      ├─ IkeSaInitiator.cs      Nửa initiator của IKE_SA_INIT (SPI, DH, nonce, SK_*)
      ├─ IkeKeyMaterial.cs      7 khóa SK_d/ai/ar/ei/er/pi/pr (RFC 7296 §2.14) + `DeriveRekey` cho IKE SA rekey (§2.18)
      ├─ ChildSaKeys.cs         KEYMAT CHILD_SA = prf+(SK_d, Ni|Nr) (RFC 7296 §2.17)
      ├─ IkeCipher.cs           Mã hóa/giải mã SK payload (RFC 7296 §3.14)
      ├─ IkePskAuth.cs          AUTH = prf(prf(PSK,"Key Pad…"), SignedOctets) (RFC 7296 §2.15); `ComputeSignedOctets` dùng chung cho cả PSK lẫn chữ ký số
      ├─ IkeSignatureAuth.cs    Verify chữ ký số responder (RFC 7296 §2.15 method 1 RSA / 9-11 ECDSA) trên SignedOctets bằng public key của X509Certificate2
      ├─ IkeMessage.cs / IkeBuffer.cs   Header 28B + payload chain (encode/decode)
      ├─ IkeProposals.cs / NatDetection.cs
      ├─ Models/ChildSaParameters.cs   Tham số CHILD_SA (SPI in/out + keys + suite) trả về cho driver sau rekey
      ├─ Models/IkeCertificateTrust.cs   Trust anchor verify responder cert: pin leaf hoặc chain tới CA (offline, không dùng OS store)
      ├─ Payloads/ConfigurationPayload.cs   CP (RFC 7296 §3.15): kéo virtual IP/netmask/DNS
      ├─ Payloads/CertificatePayload.cs / CertificateRequestPayload.cs   CERT (§3.6) / CERTREQ (§3.7) — X.509 DER
      ├─ Payloads/DeletePayload.cs   DELETE (RFC 7296 §3.11): teardown CHILD_SA (ESP SPI) / IKE SA (no-SPI)
      ├─ Payloads/EapPayload.cs   EAP (RFC 7296 §3.16): bọc gói EAP (RFC 3748 §4) verbatim cho EAP-MSCHAPv2
      ├─ Eap/EapCode.cs           Mã Code của gói EAP (Request/Response/Success/Failure, RFC 3748 §4)
      ├─ Eap/EapResult.cs         Kết quả 1 vòng EAP (Continue/Success/Failed)
      ├─ Eap/EapPacket.cs         Codec gói EAP dùng chung 2 chiều (Build Code|Id|Length|[Type|Type-Data])
      ├─ Eap/EapMsChapV2Client.cs State machine EAP-MSCHAPv2 phía peer (Identity/Challenge/Success + MSK)
      ├─ Enums/ Models/ Payloads/   Cấu trúc payload IKEv2 (SA, KE, Nonce, Notify, Delete, CP, EAP, TS, ID, AUTH…)
```

## Thành phần chính

### ESP (data plane)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `EspSession` | Cặp SA hai chiều: `Protect` (gán sequence) + `TryUnprotect` (check SPI/replay/integrity rồi giải mã); cửa sổ replay là `AntiReplayWindow` của project Crypto | [EspSession.cs:13](Esp/EspSession.cs#L13) |
| `EspDataPlane` | Base scaffolding ESP dùng chung 2 mode: `ProtectOutbound`/`TryUnprotectInbound` + `SwapSession`/`DropPreviousInbound` (make-before-break) + watermark `RekeyNeeded` quanh 2³² | [EspDataPlane.cs:9](Esp/EspDataPlane.cs#L9) |
| `EspTunnelChannel` | ESP **tunnel mode** → `IPacketChannel`: gói IP nguyên gói với NextHeader 4 (IPv4)/41 (IPv6), inbound demux theo NextHeader → `InboundIpPacket` (không PPP/L2TP) — data plane của IKEv2 | [EspTunnelChannel.cs:12](Esp/EspTunnelChannel.cs#L12) |
| `EspCipherSuite` | Lớp trừu tượng 1 ESP transform + factory `AesCbcHmacSha256` / `AesCbcHmacSha1` / `AesGcm` | [EspCipherSuite.cs:10](Esp/EspCipherSuite.cs#L10) |
| `EspCbcHmacSuite` | AES-CBC + HMAC, encrypt-then-MAC, layout `SPI\|Seq\|IV\|ct\|ICV` | [EspCbcHmacSuite.cs:11](Esp/EspCbcHmacSuite.cs#L11) |
| `EspGcmSuite` | AES-GCM AEAD, nonce = salt(4)‖seq-IV(8), AAD = `SPI\|Seq` | [EspGcmSuite.cs:11](Esp/EspGcmSuite.cs#L11) |
| `EspSuiteSelection` | Suite đã negotiate: `EncryptionKeyLengthBytes`/`SecondSliceLengthBytes` + `BuildSuite(enc, second)` → `EspCipherSuite` (CBC: second=integ key; GCM: second=salt 4B) | [EspSuiteSelection.cs:15](Esp/EspSuiteSelection.cs#L15) |
| `EspEncryptionAlgorithm` | `AesCbc` / `AesGcm16` (thuật toán confidentiality đã negotiate) | [EspEncryptionAlgorithm.cs:4](Esp/Enums/EspEncryptionAlgorithm.cs#L4) |
| `EspConstants` | Hằng số + helper header (`ReadSpi`/`ReadSequence`/`WriteHeader`) | [EspConstants.cs:4](Esp/EspConstants.cs#L4) |

> Cửa sổ chống replay `AntiReplayWindow` (trượt 64 gói; `Check` thuần + `Commit` sau khi qua integrity) đã **chuyển sang project Crypto** ([AntiReplayWindow.cs:8](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L8)) để dùng chung cho ESP và OpenVPN AEAD; `EspSession` tham chiếu nó qua `using TqkLibrary.VpnClient.Crypto`.

### NAT-T (Nat/)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `NatTraversal` (static) | Hằng số cổng (`IkePort`=500, `NatTPort`=4500, `MarkerLength`=4) + framing Non-ESP Marker: `WrapIke`/`Classify`/`UnwrapIke` | [NatTraversal.cs:9](Nat/NatTraversal.cs#L9) |
| `NatTPacketKind` (enum) | Phân loại datagram nhận trên 4500: `Invalid` / `Ike` / `Esp` | [NatTPacketKind.cs:4](Nat/Enums/NatTPacketKind.cs#L4) |
| `NatTraversalChannel` (sealed, `IAsyncDisposable`) | Kênh UDP một-gateway: bind cổng ephemeral **theo họ địa chỉ gateway** (`new UdpClient(localPort, remoteAddress.AddressFamily)` — IPv4/IPv6, P1.2), `SendIkeAsync`/`SendEspAsync`/`ReceiveAsync` (tự thêm/bóc marker theo cổng đích), `SwitchToNatTPort` đổi 500→4500 | [NatTraversalChannel.cs:13](Nat/NatTraversalChannel.cs#L13) |

### IKEv1 (đang chạy)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `IkeV1Client` | Client initiator: build/process từng MM/QM, rekey, DPD, Delete, Informational; QM2 **xác thực HASH(2)** responder (RFC 2409 §5.5, sai ⇒ `VpnServerRejectedException`); `NegotiatedEsp`/`RekeyNegotiatedEsp` lộ suite ESP server chọn ở QM2; `static TryReadRejectNotify` nhận diện Informational clear-text mang **NOTIFY lỗi** (type 1–16383) để driver fail-fast khi handshake bị từ chối (**P0.8a**); `DetectNat` đọc verdict NAT-D của responder (MM4) cho honest-first NAT-T (**P0.8b**); `IsForThisSa` so cookie initiator (8 byte cleartext) để driver định tuyến reply rekey **Phase 1 in-place** (ISAKMP SA mới = `IkeV1Client` mới) tách khỏi DPD của SA cũ trên cùng socket (**P1.3**). **V.12 (Cisco IPsec/EzVPN):** `PreferTunnelMode` + `SetAggressiveIdentity(idType, idData)` → `BuildAggressive1/ProcessAggressive2/BuildAggressive3` (group PSK, HASH_R/HASH_I); `BuildXAuthReply/BuildXAuthAck` (XAUTH user/pass) + `BuildModeConfigRequest/ProcessModeConfigReply` (virtual IP/DNS) qua **Transaction exchange chain CBC IV per Message-ID** (`TransactionCipher(messageId)` cache 1 cipher/M-ID; reply echo Message-ID của request — fix bug live strongSwan); `CreatePhase2Keys`/`ChildOutboundSpi` cho ESP tunnel | [IkeV1Client.cs:72](Ike/V1/IkeV1Client.cs#L72) |
| `IkeV1KeyMaterial` | SKEYID + SKEYID_d/a/e + khóa Phase 1 + IV đầu; `ExpandKey` | [IkeV1KeyMaterial.cs:12](Ike/V1/IkeV1KeyMaterial.cs#L12) |
| `IkeV1Auth` | `ComputeHashI` / `ComputeHashR` (xác thực Main Mode) | [IkeV1Auth.cs:10](Ike/V1/IkeV1Auth.cs#L10) |
| `IkeV1QuickMode` | `ComputeHash1/2/3` (xác thực Quick Mode, keyed by SKEYID_a) | [IkeV1QuickMode.cs:10](Ike/V1/IkeV1QuickMode.cs#L10) |
| `IkeV1Phase2Keys` | `Derive`: KEYMAT → keymat ESP hai chiều (no PFS); độ dài lát thứ 2 = integ key (CBC) hoặc salt (GCM) theo `NegotiatedEsp` | [IkeV1Phase2Keys.cs:10](Ike/V1/IkeV1Phase2Keys.cs#L10) |
| `IkeV1Cipher` | Trạng thái CBC theo phase (chain IV) + `QuickModeIv` | [IkeV1Cipher.cs:12](Ike/V1/IkeV1Cipher.cs#L12) |
| `IkeV1NatDetection` | Vendor ID NAT-T + NAT-D hash (ép sang UDP/4500) + `MatchesAny` so khớp NAT-D (đọc verdict honest-first) | [IkeV1NatDetection.cs:13](Ike/V1/IkeV1NatDetection.cs#L13) |
| `IkeV1Dpd` | Build/parse Notification R-U-THERE / ACK (DPD); `TryReadNotifyType` đọc Notify-Type tổng quát từ mọi Notification body (tái dùng cho P0.8a) | [IkeV1Dpd.cs:9](Ike/V1/IkeV1Dpd.cs#L9) |
| `IkeV1Delete` | Build Delete body cho ESP / ISAKMP SA | [IkeV1Delete.cs:9](Ike/V1/IkeV1Delete.cs#L9) |
| `IkeV1Proposals` | Proposal Phase 1 (AES-CBC/SHA1/PSK, MODP 2/14) + Phase 2 (AES-CBC-256+SHA1 **rồi** AES-GCM-16-256) | [IkeV1Proposals.cs:13](Ike/V1/IkeV1Proposals.cs#L13) |
| `IkeV1Lifetimes` | Hằng số lifetime SA (Phase 1 = 8h, Phase 2 = 1h) cho proposal | [IkeV1Lifetimes.cs:4](Ike/V1/IkeV1Lifetimes.cs#L4) |
| `IsakmpMessage` | Header 28B + chain payload: `Encode`/`Decode`/`ParsePayloadChain` | [IsakmpMessage.cs:11](Ike/V1/IsakmpMessage.cs#L11) |
| `IkeV1InformationalResult` / `IkeV1InformationalKind` | Phân loại Informational đến (DPD/Delete/Unknown) | [IkeV1InformationalResult.cs:6](Ike/V1/Models/IkeV1InformationalResult.cs#L6), [IkeV1InformationalKind.cs:4](Ike/V1/Enums/IkeV1InformationalKind.cs#L4) |
| `IkeV1NatDetectionResult` | Verdict NAT-D đọc từ MM4: `ServerSentNatD`/`LocalBehindNat`/`RemoteBehindNat` + `ShouldFloatToNatT` (honest-first **P0.8b**) | [IkeV1NatDetectionResult.cs:7](Ike/V1/Models/IkeV1NatDetectionResult.cs#L7) |
| `IkeV1Constants` | DOI, protocol/transform id, lớp attribute SA (RFC 2407/2408/2409) | [IkeV1Constants.cs:24](Ike/V1/Enums/IkeV1Constants.cs#L24) |

### IKEv2 (protocol đủ cho V.1, wire ở Drivers.Ikev2)

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `IkeClient` | Client initiator IKEv2: IKE_SA_INIT → IKE_AUTH (PSK, opt-in CFG_REQUEST/CERTREQ/multi-TS), verify AUTH responder (PSK **hoặc chữ ký số/cert** qua `VerifyResponderAuth` → `IkeCertificateTrust` + `IkeSignatureAuth`; cert/CA không tin / chữ ký sai / downgrade-PSK ⇒ `VpnServerRejectedException`; expose `ResponderCertificate`), sinh CHILD_SA; chào AES-CBC + AES-GCM rồi build suite server chọn (`NegotiatedEsp`/`ChildKeys`). Hậu-AUTH: `BuildDeadPeerDetection`/`BuildDeleteChildSa()`/`BuildDeleteChildSa(spi)` (xóa CHILD_SA cũ theo SPI cụ thể sau rekey, RFC 7296 §2.8)/`BuildDeleteIkeSa` + `BuildInformationalResponse` (INFORMATIONAL), `BuildRekeyChildSaRequest`/`ProcessRekeyChildSaResponse` (rekey CHILD_SA → `ChildSaParameters`), `BuildRekeyIkeSaRequest`/`ProcessRekeyIkeSaResponse` (**rekey IKE SA** §2.18 — SPI/DH mới, swing toàn bộ SK channel + reset message-id về 0; trước khi swing **chuẩn bị sẵn** INFORMATIONAL+DELETE cho IKE SA cũ mã hóa bằng SK_* cũ — `TakePendingOldIkeSaDelete` cho driver gửi trên SA cũ); "current IKE SA" (SPI/cipher/SK_d) tách khỏi init-state để DPD/DELETE/child-rekey sau rekey ride SA mới. **EAP-MSCHAPv2** (RFC 7296 §2.16): `BuildAuthRequestEap` (IKE_AUTH bỏ AUTH → báo EAP) + `ProcessAuthResponseEap` pump (verify PSK AUTH responder ở msg4, bơm EAP qua các vòng IKE_AUTH, AUTH cuối bằng MSK 2 chiều, sinh CHILD_SA ở exchange cuối) → `EapEstablished`/`EapFailed` | [IkeClient.cs:19](Ike/V2/IkeClient.cs#L19) |
| `IkeCertificateTrust` | Trust anchor verify responder cert: `PinLeaf(...)` (so khớp leaf chính xác) hoặc `TrustCa(...)` (leaf chain tới CA); chain build offline (no AIA/OCSP/CRL, không dùng OS store), gốc phải là 1 CA đã cấu hình | [IkeCertificateTrust.cs:11](Ike/V2/Models/IkeCertificateTrust.cs#L11) |
| `IkeSignatureAuth` | Verify chữ ký số responder (RFC 7296 §2.15 method 1 RSA PKCS#1 cả 2 TFM; method 9/10/11 ECDSA r‖s chỉ net5+) trên SignedOctets bằng public key của X509Certificate2 | [IkeSignatureAuth.cs:15](Ike/V2/IkeSignatureAuth.cs#L15) |
| `CertificatePayload` / `CertificateRequestPayload` | CERT (RFC 7296 §3.6) / CERTREQ (§3.7) — X.509 DER (`X509CertificateSignature`); CERTREQ.AnyX509() gửi CA rỗng (chấp mọi CA, verify ở client) | [CertificatePayload.cs:10](Ike/V2/Payloads/CertificatePayload.cs#L10), [CertificateRequestPayload.cs:11](Ike/V2/Payloads/CertificateRequestPayload.cs#L11) |
| `TrafficSelectorPayload` | TSi/TSr (RFC 7296 §3.13): `AnyIpv4` (1 selector match-all), `Multiple(selectors)` (nhiều subnet, rỗng→match-all), `Subnet(network, prefix)` build TS_IPV4_ADDR_RANGE từ subnet/prefix | [TrafficSelectorPayload.cs:66](Ike/V2/Payloads/TrafficSelectorPayload.cs#L66) |
| `ConfigurationPayload` | CP (RFC 7296 §3.15): `Request()` CFG_REQUEST rỗng ↔ CFG_REPLY; accessor `AssignedIp4Address`/`AssignedIp6Address`/`DnsServers` | [ConfigurationPayload.cs:13](Ike/V2/Payloads/ConfigurationPayload.cs#L13) |
| `DeletePayload` | DELETE (RFC 7296 §3.11): `Esp(spi)` cho CHILD_SA, `Ike()` cho IKE SA (no-SPI) | [DeletePayload.cs:10](Ike/V2/Payloads/DeletePayload.cs#L10) |
| `EapPayload` | EAP (RFC 7296 §3.16): bọc gói EAP (RFC 3748 §4) verbatim trong `Message`; accessor `Code`/`Identifier` | [EapPayload.cs:11](Ike/V2/Payloads/EapPayload.cs#L11) |
| `EapMsChapV2Client` | State machine EAP-MSCHAPv2 phía peer (draft-kamath): Identity → Challenge/Response (tái dùng `MsChapV2.GenerateNTResponse`) → verify Success "S=" (`GenerateAuthenticatorResponse`) → MSK 64B (`DeriveMsk`); trả `EapResult` + gói EAP response | [Eap/EapMsChapV2Client.cs:14](Ike/V2/Eap/EapMsChapV2Client.cs#L14) |
| `EapPacket` | Codec gói EAP dùng chung 2 chiều: `Build(code, id, type?, typeData)` (RFC 3748 §4) | [Eap/EapPacket.cs:7](Ike/V2/Eap/EapPacket.cs#L7) |
| `ChildSaParameters` | Kết quả rekey: SPI in/out + `ChildSaKeys` + `EspSuiteSelection` cho driver dựng `EspSession` mới | [ChildSaParameters.cs:10](Ike/V2/Models/ChildSaParameters.cs#L10) |
| `IkeSaInitiator` | Nửa initiator IKE_SA_INIT: SPI, DH (MODP-2048), nonce, SK_* | [IkeSaInitiator.cs:15](Ike/V2/IkeSaInitiator.cs#L15) |
| `IkeKeyMaterial` | 7 khóa SK_d/ai/ar/ei/er/pi/pr: `Derive`=`prf(Ni\|Nr, g^ir)` (§2.14), `DeriveRekey`=`prf(SK_d_old, g^ir\|Ni\|Nr)` cho IKE SA rekey (§2.18); cùng prf+ expand | [IkeKeyMaterial.cs:11](Ike/V2/IkeKeyMaterial.cs#L11) |
| `ChildSaKeys` | KEYMAT CHILD_SA = prf+(SK_d, Ni\|Nr) (no PFS) | [ChildSaKeys.cs:11](Ike/V2/ChildSaKeys.cs#L11) |
| `IkeCipher` | Mã hóa/giải mã SK payload (AES-CBC-256 + HMAC-SHA-256-128) | [IkeCipher.cs:12](Ike/V2/IkeCipher.cs#L12) |
| `IkePskAuth` | AUTH = prf(prf(PSK,"Key Pad for IKEv2"), SignedOctets) | [IkePskAuth.cs:12](Ike/V2/IkePskAuth.cs#L12) |

## Chuẩn / RFC tuân thủ

> Mục trọng tâm — ánh xạ class/namespace → chuẩn. Hầu hết RFC được chú thích sẵn trong comment code (link tới đúng dòng). Chuẩn nổi tiếng không ghi trong comment đánh dấu **(suy luận)**.

| Chuẩn (RFC/FIPS/NIST) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|------------------------|--------------------------|---------------------|---------|
| **RFC 4303** (ESP) | `EspConstants` (header §2/§2.6 + NextHeader 4/41 tunnel mode §3.1.1), `EspSession` (§3.3.3), `EspTunnelChannel` (tunnel mode §3.1.1), `AntiReplayWindow` (§3.4.3, ở project Crypto), `EspCipherSuite.TryStripTrailer` (§2.4 padding) | [EspConstants.cs:3](Esp/EspConstants.cs#L3), [EspSession.cs:16](Esp/EspSession.cs#L16), [EspTunnelChannel.cs:7](Esp/EspTunnelChannel.cs#L7), [AntiReplayWindow.cs:4](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L4), [EspCipherSuite.cs:53](Esp/EspCipherSuite.cs#L53) | Có trong comment |
| **RFC 3602** (AES-CBC cho IPsec) | `EspCbcHmacSuite` (confidentiality) | [EspCbcHmacSuite.cs:7](Esp/EspCbcHmacSuite.cs#L7), [EspCipherSuite.cs:20](Esp/EspCipherSuite.cs#L20) | Có trong comment |
| **RFC 4868** (HMAC-SHA-256-128) | `EspCbcHmacSuite` (integrity mặc định, IKEv2) | [EspCbcHmacSuite.cs:8](Esp/EspCbcHmacSuite.cs#L8), [EspCipherSuite.cs:20](Esp/EspCipherSuite.cs#L20) | Có trong comment |
| **RFC 2404** (HMAC-SHA-1-96) | `EspCipherSuite.AesCbcHmacSha1` (ESP SA của IKEv1) | [EspCipherSuite.cs:24](Esp/EspCipherSuite.cs#L24) | Có trong comment |
| **RFC 4106** (AES-GCM trong ESP) | `EspGcmSuite` (AEAD, salt+explicit-IV, alignment 4B) | [EspGcmSuite.cs:7](Esp/EspGcmSuite.cs#L7), [EspGcmSuite.cs:15](Esp/EspGcmSuite.cs#L15) | Có trong comment |
| **RFC 2409** (IKEv1) | `IkeV1KeyMaterial` (§5), `IkeV1Auth` (§5), `IkeV1QuickMode` (§5.5), `IkeV1Phase2Keys` (§5.5), `IkeV1Cipher` (§5.5) | [IkeV1KeyMaterial.cs:8](Ike/V1/IkeV1KeyMaterial.cs#L8), [IkeV1Auth.cs:6](Ike/V1/IkeV1Auth.cs#L6), [IkeV1QuickMode.cs:6](Ike/V1/IkeV1QuickMode.cs#L6), [IkeV1Phase2Keys.cs:6](Ike/V1/IkeV1Phase2Keys.cs#L6), [IkeV1Cipher.cs:8](Ike/V1/IkeV1Cipher.cs#L8) | Có trong comment |
| **RFC 2408** (ISAKMP) | `IsakmpMessage` (§3.1), `IsakmpSaPayload` (§3.4), `IsakmpPayload` (base), `IsakmpProposal` (§3.5)/`IsakmpTransform` (§3.6), `IsakmpAttribute` (§3.3), `IkeV1Dpd` (Notification §3.14 — gồm `TryReadNotifyType` + phân loại error-notify type 1–16383 ở `IkeV1Client.TryReadRejectNotify`), `IkeV1Delete` (Delete §3.15), `IkeV1Constants` (flags §3.1) | [IsakmpMessage.cs:8](Ike/V1/IsakmpMessage.cs#L8), [IsakmpSaPayload.cs:7](Ike/V1/Payloads/IsakmpSaPayload.cs#L7), [IkeV1Dpd.cs:20](Ike/V1/IkeV1Dpd.cs#L20), [IkeV1Delete.cs:6](Ike/V1/IkeV1Delete.cs#L6), [IkeV1Constants.cs:3](Ike/V1/Enums/IkeV1Constants.cs#L3) | Có trong comment |
| **RFC 2407** (IPsec DOI) | `IkeV1Constants` (protocol/transform id, attribute class, encap mode) | [IkeV1Constants.cs:32](Ike/V1/Enums/IkeV1Constants.cs#L32), [IkeV1Constants.cs:138](Ike/V1/Enums/IkeV1Constants.cs#L138) | Có trong comment |
| **RFC 3947** (NAT-T cho IKEv1) | `IkeV1NatDetection` (Vendor ID + NAT-D hash), `IsakmpPayloadType.NatDiscovery`, encap UDP-Tunnel/Transport; trigger `NatTraversalChannel.SwitchToNatTPort` (kênh chỉ thực thi đổi cổng, quyết định NAT do tầng IKE) | [IkeV1NatDetection.cs:8](Ike/V1/IkeV1NatDetection.cs#L8), [IsakmpPayloadType.cs:49](Ike/V1/Enums/IsakmpPayloadType.cs#L49), [IkeV1Constants.cs:144](Ike/V1/Enums/IkeV1Constants.cs#L144), [NatTraversalChannel.cs:53](Nat/NatTraversalChannel.cs#L53) | Có trong comment (RFC 3947 không ghi trong comment `Nat/`) |
| **RFC 3948** (UDP Encapsulation of ESP — Non-ESP Marker §2.2, ghép kênh IKE/ESP trên 4500) | `NatTraversal` (framing/Classify), `NatTPacketKind`, `NatTraversalChannel` | [NatTraversal.cs:6](Nat/NatTraversal.cs#L6), [NatTPacketKind.cs:3](Nat/Enums/NatTPacketKind.cs#L3), [NatTraversalChannel.cs:8](Nat/NatTraversalChannel.cs#L8) | RFC ghi rõ trong comment |
| **draft-ietf-ipsec-nat-t-ike-02/03** | `IkeV1NatDetection.VendorIdDraft02/03` (fallback NAT-T cũ, payload NAT-D = 130) | [IkeV1NatDetection.cs:19](Ike/V1/IkeV1NatDetection.cs#L19) | Có trong comment |
| **RFC 3706** (DPD) | `IkeV1Dpd` (R-U-THERE / R-U-THERE-ACK), `IkeV1InformationalKind` | [IkeV1Dpd.cs:6](Ike/V1/IkeV1Dpd.cs#L6), [IkeV1InformationalKind.cs:3](Ike/V1/Enums/IkeV1InformationalKind.cs#L3) | Có trong comment |
| **RFC 7296** (IKEv2) | `IkeMessage` (§3.1), `IkeKeyMaterial` (§2.14), `ChildSaKeys` (§2.17), `IkeCipher` (§3.14), `IkePskAuth` (§2.15), `IkeSignatureAuth` (§2.15 chữ ký số method 1/9/10/11), `IkeCertificateTrust` + `CertificatePayload`/`CertificateRequestPayload` (CERT §3.6 / CERTREQ §3.7), `TrafficSelectorPayload` multi-TS (§3.13), `IkeSaInitiator` (§2.15), `NatDetection` (§2.23), `ConfigurationPayload` (§3.15), `DeletePayload` (§3.11), `EapPayload` (§3.16, gói EAP RFC 3748 §4), `IkeClient` INFORMATIONAL/DPD (§1.4) + CREATE_CHILD_SA rekey CHILD_SA (§1.3.3) + rekey IKE SA (§1.3.2/§2.18) + **EAP-MSCHAPv2** (§2.16, AUTH bằng MSK) + verify responder cert (§2.15), `Ike/V2/Payloads/*`, `Ike/V2/Enums/*` | [IkeMessage.cs:7](Ike/V2/IkeMessage.cs#L7), [IkeKeyMaterial.cs:7](Ike/V2/IkeKeyMaterial.cs#L7), [ChildSaKeys.cs:7](Ike/V2/ChildSaKeys.cs#L7), [IkeCipher.cs:8](Ike/V2/IkeCipher.cs#L8), [IkePskAuth.cs:7](Ike/V2/IkePskAuth.cs#L7), [IkeSignatureAuth.cs:15](Ike/V2/IkeSignatureAuth.cs#L15), [IkeCertificateTrust.cs:11](Ike/V2/Models/IkeCertificateTrust.cs#L11), [ConfigurationPayload.cs:11](Ike/V2/Payloads/ConfigurationPayload.cs#L11), [DeletePayload.cs:7](Ike/V2/Payloads/DeletePayload.cs#L7), [IkeClient.cs:19](Ike/V2/IkeClient.cs#L19), [NatDetection.cs:7](Ike/V2/NatDetection.cs#L7) | Có trong comment (driver consume PSK/EAP/cert) |
| **RFC 3748** (EAP) + **draft-kamath-pppext-eap-mschapv2** | `EapPayload`, `EapPacket`, `EapMsChapV2Client` (codec MS-CHAPv2 ở Crypto `MsChapV2`) | [EapPayload.cs:11](Ike/V2/Payloads/EapPayload.cs#L11), [Eap/EapPacket.cs:7](Ike/V2/Eap/EapPacket.cs#L7), [Eap/EapMsChapV2Client.cs:14](Ike/V2/Eap/EapMsChapV2Client.cs#L14) | Gói EAP §4; EAP-MSCHAPv2 Identity/Challenge/Response/Success; MSK feed AUTH §2.16 |
| **FIPS-197** (AES) | Khóa AES-128/192/256 cho mọi suite ESP + cipher IKE (qua `TqkLibrary.VpnClient.Crypto`) | [EspCbcHmacSuite.cs:28](Esp/EspCbcHmacSuite.cs#L28) | **(suy luận)** — không chú thích trong comment |
| **NIST SP 800-38D** (AES-GCM) | `EspGcmSuite` (chế độ GCM của AES) | [EspGcmSuite.cs:11](Esp/EspGcmSuite.cs#L11) | **(suy luận)** — RFC 4106 mới được ghi |
| **NIST SP 800-38A** (CBC mode) | `EspCbcHmacSuite`, `IkeV1Cipher`, `IkeCipher` (V2) | [EspCbcHmacSuite.cs:11](Esp/EspCbcHmacSuite.cs#L11) | **(suy luận)** |
| **RFC 2104** (HMAC) / **FIPS-198** | HMAC-PRF + integrity (qua `TqkLibrary.VpnClient.Crypto`) | [IkeV1KeyMaterial.cs:51](Ike/V1/IkeV1KeyMaterial.cs#L51) | **(suy luận)** |

## API / cách dùng

### ESP — đóng/mở gói (data plane)

```csharp
// Sau Quick Mode (IKEv1), driver dựng EspSession theo suite server chọn (AES-CBC hoặc AES-GCM):
EspSuiteSelection sel = ike.NegotiatedEsp;           // QM2 đã set: AesCbc hoặc AesGcm16
IkeV1Phase2Keys p2 = ike.CreatePhase2Keys();          // keymat sized theo sel (enc ‖ integ-key/salt)
var outbound = sel.BuildSuite(p2.OutboundEncryption, p2.OutboundIntegrity); // lát 2 = integ key (CBC) / salt (GCM)
var inbound  = sel.BuildSuite(p2.InboundEncryption,  p2.InboundIntegrity);

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
Send(ike.BuildQuickMode1());          ike.ProcessQuickMode2(Recv()); // QM1/QM2 → verify HASH(2) + ESP SPI peer + NegotiatedEsp
Send(ike.BuildQuickMode3());                                         // QM3
EspSuiteSelection esp = ike.NegotiatedEsp;   // suite server chọn (CBC/GCM)
IkeV1Phase2Keys keys = ike.CreatePhase2Keys();
// Sau handshake: ike.BuildDpdRUThere/BuildDpdAck (keepalive), BuildRekeyQuickMode1/3 (rekey),
// BuildDeleteEsp/BuildDeleteIsakmp (teardown), ProcessInformational (phân loại message đến).
```

### NAT-T — kênh UDP cho IKE/ESP (Nat/)

```csharp
await using var natt = new NatTraversalChannel(serverIp, NatTraversal.IkePort);

// Main Mode 1-4 trên UDP/500 (chưa marker)
await natt.SendIkeAsync(ike.BuildMainMode1());
var (kind, reply) = await natt.ReceiveAsync(ct);   // kind == NatTPacketKind.Ike

// IKE phát hiện NAT (NAT-D) → chuyển sang UDP/4500 (từ đây IKE có Non-ESP Marker)
natt.SwitchToNatTPort();
await natt.SendIkeAsync(ike.BuildMainMode5());

// Sau Quick Mode: data plane ESP (không marker; SPI là 4 byte đầu)
await natt.SendEspAsync(espDatagram);

// Vòng nhận chung cho cả IKE và ESP
var (k, payload) = await natt.ReceiveAsync(ct);
if (k == NatTPacketKind.Ike) { /* DPD / Delete / rekey reply */ }
else if (k == NatTPacketKind.Esp) { /* đẩy vào EspSession */ }
```

Cách dùng thật trong driver: [L2tpIpsecConnection.cs:194-202](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecConnection.cs#L194-L202) (handshake Phase 1/2) — vòng nhận demux IKE/ESP ở [L2tpIpsecConnection.cs:442-468](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecConnection.cs#L442-L468).

### IKEv2 — (driver `Drivers.Ikev2` điều phối UDP/socket)

```csharp
var ike = new IkeClient(psk, identity, requestTransportMode: true);
IkeMessage init = ike.BuildInitRequest(localIp, 500, remoteIp, 500);
ike.ProcessInitResponse(Decode(Recv()));   // IKE_SA_INIT → SK_*
Send(ike.BuildAuthRequest());               // IKE_AUTH (encrypted) — chào AES-CBC + AES-GCM
if (ike.ProcessAuthResponse(Recv())) { ChildSaKeys child = ike.ChildKeys!; EspSuiteSelection esp = ike.NegotiatedEsp!; }
```

## Luồng nội bộ

### IKEv1 Main + Quick Mode (initiator)

1. **MM1/MM2** — gửi SA proposal + Vendor ID NAT-T; đọc responder cookie, transform được chọn, flavour NAT-T. [IkeV1Client.cs:230](Ike/V1/IkeV1Client.cs#L230), [IkeV1Client.cs:244](Ike/V1/IkeV1Client.cs#L244)
2. **MM3/MM4** — gửi KE + Ni + 2 NAT-D; đọc KEr + Nr → tính `g^xy` → `DeriveMainMode` sinh SKEYID & khóa Phase 1. NAT-D 2 cách: `BuildMainMode3(local, srv)` **khai man** cổng 500 (ép NAT-T) hoặc overload `BuildMainMode3(localIp, localPort, remoteIp, remotePort)` **trung thực**; `ProcessMainMode4` giữ NAT-D của responder để `DetectNat` đọc verdict (honest-first **P0.8b**). [IkeV1Client.cs:278](Ike/V1/IkeV1Client.cs#L278), [IkeV1Client.cs:286](Ike/V1/IkeV1Client.cs#L286), [IkeV1Client.cs:300](Ike/V1/IkeV1Client.cs#L300), [IkeV1Client.cs:325](Ike/V1/IkeV1Client.cs#L325), [IkeV1KeyMaterial.cs:38](Ike/V1/IkeV1KeyMaterial.cs#L38)
3. **MM5/MM6** — gửi IDi + HASH_I (đã mã hóa); giải mã MM6, verify HASH_R, lưu IV cuối Phase 1. [IkeV1Client.cs:340](Ike/V1/IkeV1Client.cs#L340), [IkeV1Client.cs:355](Ike/V1/IkeV1Client.cs#L355), [IkeV1Auth.cs:13](Ike/V1/IkeV1Auth.cs#L13)
4. **QM1/QM2/QM3** — IV Quick Mode dẫn từ IV Phase 1 cuối + message id; HASH(1)/(2)/(3) keyed by SKEYID_a; QM2 **xác thực HASH(2)** responder (`prf(SKEYID_a, M-ID‖Ni_b‖payload-sau-HASH)`, hash trên byte gốc nhận — mismatch ⇒ `VpnServerRejectedException`) rồi bắt ESP SPI của peer **và transform server chọn** → set `NegotiatedEsp` (AES-CBC hoặc AES-GCM-16; mặc định khoan dung về CBC+SHA1+256). [IkeV1Client.cs:401](Ike/V1/IkeV1Client.cs#L401), [IkeV1Cipher.cs:53](Ike/V1/IkeV1Cipher.cs#L53), [IkeV1QuickMode.cs:13](Ike/V1/IkeV1QuickMode.cs#L13)
5. **Phase 2 keys** — `CreatePhase2Keys` → KEYMAT = prf+(SKEYID_d, proto\|SPI\|Ni\|Nr) → keymat ESP hai chiều, độ dài theo `NegotiatedEsp` (CBC: enc ‖ integ-key; GCM: enc ‖ salt 4B); driver gọi `NegotiatedEsp.BuildSuite(...)` để ra `EspCipherSuite`. [IkeV1Client.cs:453](Ike/V1/IkeV1Client.cs#L453), [IkeV1Phase2Keys.cs:30](Ike/V1/IkeV1Phase2Keys.cs#L30), [EspSuiteSelection.cs:15](Esp/EspSuiteSelection.cs#L15)
6. **Hậu handshake (Informational)** — mọi datagram IKE sau handshake route qua `ProcessInformational`: phân loại DPD request/ack hoặc Delete; build DPD/Delete/rekey dưới message id mới với IV dẫn xuất riêng. [IkeV1Client.cs:790](Ike/V1/IkeV1Client.cs#L790), [IkeV1Client.cs:773](Ike/V1/IkeV1Client.cs#L773)
   - **Trong handshake (P0.8a)** — driver lọc mỗi reply qua `static TryReadRejectNotify`: Informational clear-text mang NOTIFY lỗi (type 1–16383, vd NO-PROPOSAL-CHOSEN) ⇒ báo từ chối thay vì parse nhầm thành MM/QM reply. [IkeV1Client.cs:844](Ike/V1/IkeV1Client.cs#L844)

### ESP `Protect` / `TryUnprotect`

- **Protect** — tăng sequence (checked), gọi suite encode `SPI\|Seq\|IV\|ct\|ICV` (hoặc GCM). Property [`OutboundSequence`](Esp/EspSession.cs#L53) lộ sequence hiện tại để driver rekey **trước khi** chạm 2³² (xem note ESP suite bên dưới). [EspSession.cs:56](Esp/EspSession.cs#L56), [EspCbcHmacSuite.cs:37](Esp/EspCbcHmacSuite.cs#L37)
- **TryUnprotect** — check độ dài → SPI → `AntiReplayWindow.Check` → integrity → giải mã → strip trailer → `Commit`. Replay window **chỉ advance sau khi gói qua integrity**. [EspSession.cs:67](Esp/EspSession.cs#L67), [AntiReplayWindow.cs:21](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L21)

## Trạng thái & ghi chú

- **Đang chạy thực tế:** `Ike/V1` + `Esp/` + `Nat/` — driver `L2tpIpsec` dựng `IkeV1Client` + `NatTraversalChannel` trong `BringUpPhase1Async` ([L2tpIpsecConnection.cs:194](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecConnection.cs#L194)) và demux IKE/ESP ở `ReceiveLoopAsync` ([L2tpIpsecConnection.cs:442](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecConnection.cs#L442)), dùng `EspSession`/`EspCipherSuite` cho data plane. Đã verify live trên VPN Gate (PSK + AES-256 + HMAC-SHA1, MODP group 2/14).
- **`Nat/` gom từ project cũ `TqkLibrary.VpnClient.Transport.Udp`** (đã xóa; namespace mới `TqkLibrary.VpnClient.Ipsec.Nat`): kênh một-gateway (không multiplex nhiều peer); chỉ phục vụ IKE/ESP trên 500/4500 — logic phát hiện NAT (NAT-D, RFC 3947) vẫn ở `Ike/V1`, kênh chỉ đổi cổng theo lệnh. Khác biệt `netstandard2.0` vs `net8.0` duy nhất: `ReceiveAsync` trên netstandard2.0 không truyền được `CancellationToken` vào `UdpClient.ReceiveAsync` (chỉ `ThrowIfCancellationRequested` trước khi chờ; nhánh `#if NET6_0_OR_GREATER`) — [NatTraversalChannel.cs:77-82](Nat/NatTraversalChannel.cs#L77-L82). Cấp phát đơn giản (`ToArray` mỗi gói), chấp nhận được với nhịp datagram IKE/ESP.
- **Protocol đủ, driver consume một phần:** `Ike/V2` (IKEv2) — driver `Drivers.Ikev2` (V.1) tham chiếu `IkeClient` để dựng IKE_SA_INIT + IKE_AUTH (PSK) + CP + ESP tunnel + DPD/DELETE + rekey CHILD_SA. Hai primitive `BuildRekeyIkeSaRequest`/`ProcessRekeyIkeSaResponse` (**rekey IKE SA**, RFC 7296 §2.18) đã có + unit test nhưng **driver chưa wire timer/route** (V.1c — cần supervisor F.6 + lab Q.1). ESP CHILD_SA chào **2 proposal**: AES-CBC-256+SHA256 (#1) rồi AES-GCM-16-256 (#2) — `ProcessAuthResponse` đọc proposal server chọn → `NegotiatedEsp` + `ChildKeys` đúng độ dài.
- **ESP suite (negotiate được):** ba bộ — AES-CBC+HMAC-SHA256-128 (mặc định IKEv2), AES-CBC+HMAC-SHA1-96 (ESP SA của IKEv1), AES-GCM-16 (RFC 4106, AEAD). Cả IKEv1 (QM2) lẫn IKEv2 (SAr2) **đọc transform server chọn** rồi dựng đúng suite qua `EspSuiteSelection` — IKEv1 chào CBC **trước** GCM nên VPN Gate/SoftEther (không hỗ trợ GCM) vẫn chọn CBC (đường live không đổi); gateway hỗ trợ GCM (strongSwan…) chọn được GCM. Anti-replay cố định cửa sổ 64, **không hỗ trợ Extended Sequence Number** (ESN): GCM IV để 4 byte cao = 0 ([EspGcmSuite.cs:87](Esp/EspGcmSuite.cs#L87)); sequence là 32-bit, `Protect` dùng `checked` nên sẽ ném nếu vượt `uint.MaxValue` — đây là **backstop**: driver `L2tpIpsec` theo dõi `OutboundSequence` và chủ động rekey Phase 2 ở high-watermark ~75%×2³² (RFC 4303 §3.3.3) **trước khi** chạm giới hạn này.
- **IKEv1 PFS:** Quick Mode rekey **không có PFS** (KEYMAT chỉ từ SKEYID_d + nonce mới, không trao đổi KE mới) — phù hợp interop L2TP/IPsec phổ biến.
- **netstandard2.0 vs net8.0:** cùng codebase; `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`). Primitive crypto khác biệt nằm ở `TqkLibrary.VpnClient.Crypto` (BouncyCastle trên netstandard2.0), không phải project này.
- **Phạm vi:** `Ike/`+`Esp/` chỉ logic giao thức (build/process/encode/decode/derive); socket UDP NAT-T nay thuộc `Nat/` của chính project này. Điều phối handshake (retransmit, thời điểm `SwitchToNatTPort`) và vòng đời SA vẫn do driver bên ngoài sở hữu.
- **Logging tầng protocol sâu (Q.2):** [`IkeV1Client`](Ike/V1/IkeV1Client.cs#L21) và [`EspSession`](Esp/EspSession.cs#L13) nhận tham số ctor cuối `ILogger? logger = null` (mặc định `NullLogger` ⇒ **no-op, không đổi hành vi**). IkeV1Client log per-step Main/Quick Mode/NAT-D/rekey/informational; EspSession log SA-install + drop phân loại trong `TryUnprotect` (Malformed/Replay/DecryptFailed qua `VpnDropReason`; SPI-mismatch không log — là demux). Tất cả ở `LogLevel.Trace`/`Debug` qua seam `VpnEventIds.ProtocolStep`/`VpnLogExtensions.LogProtocolStep` (`Abstractions/Diagnostics`); hot-path guard `IsEnabled`. Driver `Drivers.L2tpIpsec`/`Drivers.Ikev2` truyền `Logger` (base supervisor) xuống.
