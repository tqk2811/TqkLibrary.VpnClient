# 10 — Kiến trúc & luồng hoạt động (as-built)

> Tài liệu **bám sát code thực tế** (khác với `00`–`09` là design-intent). Mọi mô tả ở đây đối chiếu
> với mã nguồn hiện hành, link tới `file:line` thật. Nếu code đổi, cập nhật lại file này.
>
> **Lưu ý lệch so với design docs:** một số điểm trong `00`/`04` đã không còn khớp hiện thực — xem mục
> [Khác biệt so với design docs](#khác-biệt-so-với-design-docs) ở cuối.

## 1. Bản chất

VPN client **thuần userspace**: tự cài đặt toàn bộ ngăn xếp (IKE, ESP, L2TP, PPP, SSTP, TCP/IP) ở tầng
ứng dụng, **không cần TUN/TAP adapter của OS, không ghi bảng route hệ thống**. Ứng dụng nhận một IP ảo
trong đường hầm rồi mở TCP/UDP socket chạy *bên trong* đường hầm.

Hai triết lý:
- **Plugin theo driver** — mỗi giao thức là một `IVpnProtocolDriver`, đăng ký theo tên (`"sstp"`, `"l2tp-ipsec"`).
- **Đảo ngược phụ thuộc** — mọi tầng chỉ phụ thuộc project `Abstractions`, không phụ thuộc ngang.

## 2. Phân lớp (10 project trong `src/`)

```
APP       TqkLibrary.Vpn            VpnClient / VpnClientBuilder   (entry point)
          TqkLibrary.Vpn.Sockets   VpnTcpClient / VpnUdpClient / VpnNetworkStream
─────────────────────────────────────────────────────────────────────────────
DRIVER    TqkLibrary.Vpn.Drivers   L2tpIpsec/ , Sstp/   (lắp ráp toàn bộ stack)
─────────────────────────────────────────────────────────────────────────────
PROTOCOL  TqkLibrary.Vpn.Ipsec     Ike/V1 , Ike/V2 , Esp
          TqkLibrary.Vpn.L2tp      L2TPv2 control + data
          TqkLibrary.Vpn.Ppp       LCP / IPCP / MS-CHAPv2 / HDLC
          TqkLibrary.Vpn.IpStack   IPv4 / TCP / UDP userspace
─────────────────────────────────────────────────────────────────────────────
TRANSPORT TqkLibrary.Vpn.Transport.Udp   NAT-T (UDP 500↔4500, ghép kênh IKE/ESP)
─────────────────────────────────────────────────────────────────────────────
CRYPTO    TqkLibrary.Vpn.Crypto    AES-CBC/CTR/GCM, DH(MODP), HMAC-PRF, MD4, DES
─────────────────────────────────────────────────────────────────────────────
CORE      TqkLibrary.Vpn.Abstractions   interface + model + enum (không phụ thuộc gì)
```

## 3. Hợp đồng cốt lõi (Abstractions)

Chuỗi 3 interface phân cấp là xương sống của toàn bộ thư viện:

| Interface | Vai trò |
|---|---|
| [IVpnProtocolDriver.cs:9](../src/TqkLibrary.Vpn.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs#L9) | Điểm vào plugin: `Name`, `Capabilities`, `ConnectAsync(endpoint, credentials, ct)` |
| [IVpnConnection.cs:7](../src/TqkLibrary.Vpn.Abstractions/Drivers/Interfaces/IVpnConnection.cs#L7) | Một kết nối sống (1 IKE-SA / 1 TLS), sở hữu nhiều `IVpnSession`; `OpenSessionAsync()` |
| [IVpnSession.cs:10](../src/TqkLibrary.Vpn.Abstractions/Drivers/Interfaces/IVpnSession.cs#L10) | Một endpoint IP logic: `Config` (IP/DNS/route/MTU) + `PacketChannel` |
| [IPacketChannel.cs:6](../src/TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) | Kênh L3: `WriteIpPacketAsync()` + event `InboundIpPacket` — "card mạng ảo" mà IP stack bám vào |
| [ILinkChannel.cs:9](../src/TqkLibrary.Vpn.Abstractions/Channels/Interfaces/ILinkChannel.cs#L9) | Base chung: `Mtu`, `MaxHeaderLength`, `Medium` (Ip/Ethernet), `RequiresLinkAddressResolution` |
| [IEthernetChannel.cs:7](../src/TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IEthernetChannel.cs#L7) | Kênh **L2** (kế thừa `ILinkChannel`): `LinkAddress` (MAC 6 byte), `WriteFrameAsync()` + event `InboundFrame` — **hợp đồng đã định nghĩa, chưa có implementation** (đường L2 tương lai) |

Hợp đồng phụ trợ (định nghĩa sẵn, dùng một phần): [IByteStreamTransport.cs:4](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs#L4) /
[IDatagramTransport.cs:7](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L7) (đáy TCP/UDP),
[ISecuritySession.cs:7](../src/TqkLibrary.Vpn.Abstractions/Security/Interfaces/ISecuritySession.cs#L7) (mã hóa từng gói),
[IPacketEncapsulator.cs:9](../src/TqkLibrary.Vpn.Abstractions/Encapsulation/Interfaces/IPacketEncapsulator.cs#L9) (đóng khung). *(`ISecuritySession`/`IPacketEncapsulator` hiện **mồ côi** — không class nào implement; ESP dùng `EspSession` riêng — xem roadmap §11.)*

[VpnDriverCapabilities.cs:9](../src/TqkLibrary.Vpn.Abstractions/Drivers/Models/VpnDriverCapabilities.cs#L9) cho façade
"hỏi năng lực" driver trước khi kết nối — thuộc tính chính: `LinkLayer`, `MultiHostModel`, `TransportKinds`, `SecurityKinds`,
`AuthMethods`, `AddressAssignment`, `UsesPpp`, `RequiresRawIpSocket`, `RequiresElevation`. Các enum năng lực —
[VpnLinkLayer.cs:4](../src/TqkLibrary.Vpn.Abstractions/Drivers/Enums/VpnLinkLayer.cs#L4) (L3Ip/L2Ethernet/Both) ·
[MultiHostModel.cs:4](../src/TqkLibrary.Vpn.Abstractions/Drivers/Enums/MultiHostModel.cs#L4) (None/RoutedPrefixes/L2BroadcastDomain) ·
[VpnTransportKind.cs:5](../src/TqkLibrary.Vpn.Abstractions/Drivers/Enums/VpnTransportKind.cs#L5) `[Flags]` (Tcp/Udp/Tls/Dtls/RawIp) ·
[VpnSecurityKind.cs:5](../src/TqkLibrary.Vpn.Abstractions/Drivers/Enums/VpnSecurityKind.cs#L5) `[Flags]` (Tls/Dtls/Esp/Noise/Mppe) ·
[VpnAuthMethod.cs:5](../src/TqkLibrary.Vpn.Abstractions/Drivers/Enums/VpnAuthMethod.cs#L5) `[Flags]` (PreSharedKey/Certificate/UserPassword/Eap/Saml/Otp) ·
[AddressAssignment.cs:4](../src/TqkLibrary.Vpn.Abstractions/Drivers/Enums/AddressAssignment.cs#L4) (Ipcp/ConfigPush/OutOfBand/Dhcp) —
phần lớn là **khung mở rộng tương lai** (WireGuard/OpenVPN/DTLS/L2 Ethernet…); 2 driver hiện tại đều khai **L3Ip + UsesPpp +
AddressAssignment=Ipcp** (xem §6/§7). Khi driver cần quyền (RawIp) mà process thiếu → ném [VpnElevationRequiredException.cs:7](../src/TqkLibrary.Vpn.Abstractions/Drivers/VpnElevationRequiredException.cs#L7).
Model đi kèm: [VpnEndpoint.cs:4](../src/TqkLibrary.Vpn.Abstractions/Drivers/Models/VpnEndpoint.cs#L4) (Host/Port),
[VpnCredentials.cs:4](../src/TqkLibrary.Vpn.Abstractions/Drivers/Models/VpnCredentials.cs#L4) (Username/Password + PreSharedKey),
[TunnelConfig.cs:9](../src/TqkLibrary.Vpn.Abstractions/Drivers/Models/TunnelConfig.cs#L9) (AssignedAddress, PrefixLength=32, DnsServers, Routes, Mtu=1400 — chính là `Config` ở bảng trên).

## 4. Điểm vào

[VpnClientBuilder.cs:8](../src/TqkLibrary.Vpn/VpnClientBuilder.cs#L8) đăng ký driver kiểu fluent;
[VpnClient.cs:18](../src/TqkLibrary.Vpn/VpnClient.cs#L18) tra driver theo tên rồi ủy thác `ConnectAsync`.
`UseSstp()` / `UseL2tpIpsec()` / [`UseL2tpIpsec(L2tpIpsecReconnectOptions)` @ :26](../src/TqkLibrary.Vpn/VpnClientBuilder.cs#L26) đều là wrapper gọi
[`AddDriver(IVpnProtocolDriver)` @ :13](../src/TqkLibrary.Vpn/VpnClientBuilder.cs#L13) (keyed theo `driver.Name`) — nên driver tự định nghĩa cũng nạp được.
`VpnClient` còn có [`GetCapabilities(protocol)` @ :27](../src/TqkLibrary.Vpn/VpnClient.cs#L27) trả `VpnDriverCapabilities` (indexer, ném `KeyNotFoundException` nếu chưa đăng ký — khác `ConnectAsync` ném `NotSupportedException`).

```csharp
var vpn  = new VpnClientBuilder().UseSstp().UseL2tpIpsec().Build();
IVpnConnection conn = await vpn.ConnectAsync("l2tp-ipsec", endpoint, creds);
IVpnSession    sess = conn.Sessions[0];

// mở socket chạy TRONG tunnel:
var stack = sess.CreateTcpStack();                       // VpnSessionSocketsExtensions
var tcp   = await VpnTcpClient.ConnectAsync(stack, ip, 80);
Stream s  = tcp.GetStream();                             // cắm thẳng vào HttpClient
```

## 5. Vai trò từng module

| Module | Type chính | Trách nhiệm |
|---|---|---|
| **Crypto** | 6 hợp đồng [Crypto/Interfaces/](../src/TqkLibrary.Vpn.Crypto/Interfaces/) (`IHashAlgo`/`IBlockCipher`/`IAeadCipher`/`IDhGroup`/`IPrf`/`IIntegrityAlgo`); hiện thực [AesCbcCipher.cs:10](../src/TqkLibrary.Vpn.Crypto/AesCbcCipher.cs#L10), [AesCtr.cs:9](../src/TqkLibrary.Vpn.Crypto/AesCtr.cs#L9), [AesGcmCipher.cs:18](../src/TqkLibrary.Vpn.Crypto/Aead/AesGcmCipher.cs#L18), [ModpDhGroup.cs:12](../src/TqkLibrary.Vpn.Crypto/ModpDhGroup.cs#L12), [HmacPrf.cs:7](../src/TqkLibrary.Vpn.Crypto/HmacPrf.cs#L7)/[HmacIntegrity.cs:7](../src/TqkLibrary.Vpn.Crypto/HmacIntegrity.cs#L7), [PrfPlus.cs:9](../src/TqkLibrary.Vpn.Crypto/PrfPlus.cs#L9), [Md4.cs:9](../src/TqkLibrary.Vpn.Crypto/Md4.cs#L9), [Des.cs:8](../src/TqkLibrary.Vpn.Crypto/Des.cs#L8) | Primitive theo hợp đồng (đảo ngược phụ thuộc §1). DH MODP group 2 (1024-bit) + 14 (2048-bit); factory integrity `HmacSha1_96` (key20/ICV12 — IKEv1) & `HmacSha256_128` (key32/ICV16 — IKEv2). MD4/DES bắt buộc cho MS-CHAPv2 dù lỗi thời. `AesGcmCipher` là nơi duy nhất `#if`: BCL `AesGcm` (net8.0) vs BouncyCastle (netstandard2.0), nonce 12B/tag 16B. |
| **Ipsec.Esp** | [EspSession.cs:7](../src/TqkLibrary.Vpn.Ipsec/Esp/EspSession.cs#L7), [EspCipherSuite.cs:10](../src/TqkLibrary.Vpn.Ipsec/Esp/EspCipherSuite.cs#L10) (+ [EspCbcHmacSuite.cs:11](../src/TqkLibrary.Vpn.Ipsec/Esp/EspCbcHmacSuite.cs#L11) / [EspGcmSuite.cs:11](../src/TqkLibrary.Vpn.Ipsec/Esp/EspGcmSuite.cs#L11)), [AntiReplayWindow.cs:7](../src/TqkLibrary.Vpn.Ipsec/Esp/AntiReplayWindow.cs#L7) | Data-plane IPsec: `Protect`/`TryUnprotect`, sequence dùng [`checked(+1)` @ EspSession:34](../src/TqkLibrary.Vpn.Ipsec/Esp/EspSession.cs#L34) → **OverflowException ở gói thứ 2³²** (chưa rekey-by-sequence), chống replay (cửa sổ 64 gói). `EspCipherSuite` là base + 3 factory: `AesCbcHmacSha1` (đường **live** IKEv1), `AesCbcHmacSha256` (mặc định IKEv2), `AesGcm` (RFC 4106 — **chưa được negotiate**); wire `SPI‖Seq‖IV‖ct‖ICV`, encrypt-then-MAC. |
| **Ipsec.Ike.V1** | [IkeV1Client.cs:16](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs#L16) + codec [IsakmpMessage.cs:11](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IsakmpMessage.cs#L11), khóa [IkeV1KeyMaterial.cs:12](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1KeyMaterial.cs#L12)/[IkeV1Phase2Keys.cs:10](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Phase2Keys.cs#L10), [IkeV1Cipher.cs:12](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Cipher.cs#L12), [IkeV1Auth.cs:10](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Auth.cs#L10), [IkeV1QuickMode.cs:10](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1QuickMode.cs#L10), [IkeV1NatDetection.cs:12](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1NatDetection.cs#L12), [IkeV1Proposals.cs:12](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Proposals.cs#L12), [IkeV1Lifetimes.cs:4](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Lifetimes.cs#L4) | Bắt tay ISAKMP/IKEv1 cho L2TP: Main Mode (MM1–MM6) + Quick Mode (QM1–QM3) → KEYMAT cho ESP. **Đây là IKE đang chạy thực tế.** Chỉ đề xuất **AES-CBC + SHA1 + PSK + MODP 2/14** (không GCM/3DES dù enum có). `IkeV1Cipher` giữ **CBC IV-chaining** (RFC 2409 §5.5: IV Quick Mode/Informational = hash(IV-Phase1-cuối ‖ M-ID)) — lý do mỗi DPD/Delete/rekey có IV riêng. Thêm qua **Informational**: DPD keepalive ([IkeV1Dpd.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Dpd.cs)), Quick Mode rekey (`BuildRekeyQuickMode1/2/3`), Delete teardown ([IkeV1Delete.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Delete.cs)). |
| **Ipsec.Ike.V2** | [IkeClient.cs:15](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeClient.cs#L15) + [IkeSaInitiator.cs:15](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeSaInitiator.cs#L15), khóa [IkeKeyMaterial.cs:11](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeKeyMaterial.cs#L11)/[ChildSaKeys.cs:11](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/ChildSaKeys.cs#L11), [IkeCipher.cs:12](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeCipher.cs#L12), [IkePskAuth.cs:12](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkePskAuth.cs#L12), [NatDetection.cs:12](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/NatDetection.cs#L12), [IkeProposals.cs:7](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeProposals.cs#L7), codec [IkeMessage.cs:10](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeMessage.cs#L10) + 7 payload concrete [V2/Payloads/](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/Payloads/) | IKEv2 PSK: **chỉ IKE_SA_INIT + IKE_AUTH** (sinh CHILD_SA/ESP keys), suite AES-CBC-256 + HMAC-SHA-256-128 + PRF-SHA-256 + MODP-2048, transport-mode + NAT-D. **Đã build & có test nhưng CHƯA driver nào dùng**; **chưa** có CreateChildSA/Informational ⇒ chưa rekey/DPD/teardown như V1. Payload chưa model (CP/Delete/EAP/Cert/VendorId) rơi về [RawPayload.cs:9](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/Payloads/RawPayload.cs#L9). |
| **L2tp** | [L2tpClient.cs:12](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs#L12) trên [IL2tpTransport.cs:7](../src/TqkLibrary.Vpn.L2tp/IL2tpTransport.cs#L7), [L2tpControlChannel.cs:10](../src/TqkLibrary.Vpn.L2tp/L2tpControlChannel.cs#L10), codec [L2tpCodec.cs:11](../src/TqkLibrary.Vpn.L2tp/L2tpCodec.cs#L11) | L2TPv2 (RFC 2661): tunnel SCCRQ→SCCRP→SCCCN, session ICRQ→ICRP→ICCN (SCCCN/ICCN tự gửi trong `OnControl`); truyền tin cậy Ns/Nr + ZLB ack + retransmit 1s (chỉ head-of-line, **không giới hạn retry**). `L2tpCodec` serialize header+AVP, phân biệt control (T=1) vs data (T=0). Keepalive `SendHelloAsync` (HELLO); teardown `SendCallDisconnectAsync` (CDN) + `SendStopControlConnectionAsync` (StopCCN). Event [`Disconnected` @ :48](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs#L48) (server StopCCN/CDN) chính là tín hiệu "L2TP teardown" ở §6.1; [`DataReceived` @ :45](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs#L45) là PPP inbound. |
| **Ppp** | [PppEngine.cs:14](../src/TqkLibrary.Vpn.Ppp/PppEngine.cs#L14) trên [IPppFrameChannel.cs:7](../src/TqkLibrary.Vpn.Ppp/Interfaces/IPppFrameChannel.cs#L7); negotiate [PppNegotiator.cs:11](../src/TqkLibrary.Vpn.Ppp/PppNegotiator.cs#L11) (base) → [LcpNegotiator.cs:10](../src/TqkLibrary.Vpn.Ppp/LcpNegotiator.cs#L10)/[IpcpNegotiator.cs:12](../src/TqkLibrary.Vpn.Ppp/IpcpNegotiator.cs#L12); auth [IPppAuthenticator.cs:9](../src/TqkLibrary.Vpn.Ppp/Interfaces/IPppAuthenticator.cs#L9) → [MsChapV2Authenticator.cs:12](../src/TqkLibrary.Vpn.Ppp/Auth/MsChapV2Authenticator.cs#L12) ([MsChapV2.cs:11](../src/TqkLibrary.Vpn.Ppp/Auth/MsChapV2.cs#L11)); framing [HdlcFramer.cs:7](../src/TqkLibrary.Vpn.Ppp/Framing/HdlcFramer.cs#L7)/[HdlcDecoder.cs:7](../src/TqkLibrary.Vpn.Ppp/Framing/HdlcDecoder.cs#L7) | Engine chạy **LCP → MS-CHAPv2 → IPCP** (demux theo protocol field dưới 1 lock), event `LinkUp`/`AuthSucceeded`/`AuthFailed`. LCP chỉ chấp nhận MS-CHAPv2 (0xC223+0x81), reject auth khác; IPCP xin IP 0.0.0.0+DNS, nhận qua Configure-Nak; `MsChapV2Authenticator` là nơi `DeriveHlak()` (cho crypto binding SSTP). Có sẵn **chế độ server** (assignPeer*) — chưa driver nào dùng. [PppPacketChannel.cs:10](../src/TqkLibrary.Vpn.Ppp/PppPacketChannel.cs#L10) là `IPacketChannel` L3 trả ra; HDLC chỉ dùng cho đường SSTP. |
| **IpStack** | [TcpIpStack.cs:11](../src/TqkLibrary.Vpn.IpStack/Tcp/TcpIpStack.cs#L11), [TcpConnection.cs:13](../src/TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs#L13), [UdpConnection.cs:10](../src/TqkLibrary.Vpn.IpStack/Tcp/UdpConnection.cs#L10); codec [Ipv4.cs:6](../src/TqkLibrary.Vpn.IpStack/Ipv4.cs#L6)/[TcpSegment.cs:7](../src/TqkLibrary.Vpn.IpStack/Tcp/TcpSegment.cs#L7)/[UdpDatagram.cs:6](../src/TqkLibrary.Vpn.IpStack/UdpDatagram.cs#L6), [TcpState.cs:4](../src/TqkLibrary.Vpn.IpStack/Tcp/Enums/TcpState.cs#L4) | TCP/IP userspace: demux IPv4 inbound theo port (cấp ephemeral port từ **49152**, chung TCP+UDP). TCP active-open **6 state** (Closed/SynSent/Established/FinWait1/CloseWait/LastAck — không TIME_WAIT, không buffer reorder): MSS=**1360**, cửa sổ quảng bá cố định **65535**, ACK tích lũy, RST→IOException; **không retransmit/SACK** (dựa tunnel in-order). Tự tính checksum ([InternetChecksum.cs:4](../src/TqkLibrary.Vpn.IpStack/InternetChecksum.cs#L4)); `Ipv4` đã khai `ProtocolIcmp` nhưng **chưa xử lý ICMP**. |
| **Transport.Udp** | [NatTraversalChannel.cs:12](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversalChannel.cs#L12), [NatTraversal.cs:20](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversal.cs#L20) (enum [NatTPacketKind](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversal.cs#L4), hằng `IkePort=500`/`NatTPort=4500`/`MarkerLength=4`) | NAT-T (RFC 3948): 1 UDP socket. **Bind local port ephemeral (≠500/4500)** để gateway coi client là NATed → **forced-NAT-T** (xem §8). [`SwitchToNatTPort()` @ :33](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversalChannel.cs#L33) (driver gọi sau khi IKE NAT-D phát hiện, không tự phát hiện) chuyển sang 4500; **ghép kênh IKE/ESP** trên 4500 (4 byte 0 ⇒ IKE; SPI≠0 ⇒ ESP). Trên port 500 phân loại bằng độ dài ≥28 (ISAKMP header), không marker. |
| **Sockets** | [VpnTcpClient.cs:8](../src/TqkLibrary.Vpn.Sockets/VpnTcpClient.cs#L8), [VpnUdpClient.cs:10](../src/TqkLibrary.Vpn.Sockets/VpnUdpClient.cs#L10), [VpnNetworkStream.cs:7](../src/TqkLibrary.Vpn.Sockets/VpnNetworkStream.cs#L7) | API socket trên tunnel: TCP trả `Stream` (cắm `HttpClient`) — `VpnNetworkStream` no-seek, `WriteAsync` fire-and-forget, `Dispose` phát **half-close** (FIN). UDP là "connected UDP" (lọc đúng remote endpoint), hỗ trợ DNS-over-tunnel. |
| **Abstractions.Channels** | [SwappablePacketChannel.cs:14](../src/TqkLibrary.Vpn.Abstractions/Channels/SwappablePacketChannel.cs#L14) | Facade `IPacketChannel` **ổn định**: hot-swap kênh PPP bên trong khi reconnect, ghim metadata link, drop write khi chưa có inner. Để IP stack **không phải re-bind** qua reconnect (xem §6.1). |

## 6. Luồng kết nối — L2TP/IPsec (control plane)

Plugin entry: [L2tpIpsecDriver.cs:9](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecDriver.cs#L9) (`Name="l2tp-ipsec"`, [Capabilities @ :26](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecDriver.cs#L26): L3Ip + UsesPpp + Esp + UserPassword\|PreSharedKey + Ipcp) ánh xạ `VpnEndpoint`/`VpnCredentials` — PSK mặc định [`"vpn"` @ :12](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecDriver.cs#L12) (VPN Gate) khi credential không kèm PSK — rồi tạo `L2tpIpsecConnection`, bọc trong [L2tpIpsecVpnConnection.cs:6](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecVpnConnection.cs#L6) (single-session, `OpenSessionAsync` ném `NotSupported`).

Điều phối: [`ConnectAsync` @ L2tpIpsecConnection.cs:100](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L100) lưu credential rồi ủy thác cho [`EstablishAsync` @ :114](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L114) — **factory clean-slate** dùng chung cho lần connect đầu **và mọi lần reconnect** (xem §6.1).

1. **Resolve + mở UDP** tới gateway:500; chạy `ReceiveLoopAsync` nền (gắn theo NAT-T channel của từng attempt) phân loại datagram IKE/ESP — [L2tpIpsecConnection.cs:124-130](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L124-L130).
2. **IKEv1 Phase 1 – Main Mode** MM1/MM3 trên port 500 (đề xuất SA + Vendor ID NAT-T, trao đổi DH + nonce + NAT-D), sinh `SKEYID` + khóa Phase 1 — [L2tpIpsecConnection.cs:133-136](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L133-L136).
3. **Phát hiện NAT → `SwitchToNatTPort()`** sang 4500; MM5/MM6 (đã mã hóa) xác thực PSK qua `HASH_R` — [L2tpIpsecConnection.cs:137-141](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L137-L141).
4. **IKEv1 Phase 2 – Quick Mode** QM1/QM2/QM3 → sinh `KEYMAT` cho ESP — [L2tpIpsecConnection.cs:142-145](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L142-L145).
5. **Dựng ESP**: `BuildEspSession` lấy khóa Phase 2 → `EspSession` AES-CBC + HMAC-SHA1 (2 chiều); bật `_espActive` — [L2tpIpsecConnection.cs:147-152, 197](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L147-L152).
6. **L2TP**: `L2tpClient` chạy trên [IpsecL2tpTransport.cs:11](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/IpsecL2tpTransport.cs#L11) → dựng tunnel + session — [L2tpIpsecConnection.cs:154-157](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L154-L157).
7. **PPP**: [L2tpPppFrameChannel.cs:7](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpPppFrameChannel.cs#L7) cầu nối L2TP data ↔ `PppEngine`; LCP → MS-CHAPv2 → IPCP (nhận IP) → `LinkUp` — [L2tpIpsecConnection.cs:159-172](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L159-L172).
8. **Cắm vào facade ổn định**: kênh PPP mới được nạp vào `_facade.SetInner(...)` ([L2tpIpsecConnection.cs:171](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L171)) rồi `StartKeepalive()`. Driver bọc thành [L2tpIpsecVpnSession.cs:10](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecVpnSession.cs#L10) trả về với `PacketChannel` = [`_facade`](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L39) (**bền qua reconnect**), IP/DNS từ IPCP.

### 6.1 Vòng đời sau khi connect (keepalive · rekey · reconnect · teardown)

Sau `LinkUp`, [`StartKeepalive` @ :252](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L252) bật 4 timer; IKE inbound hậu-handshake đi vào [`HandleInboundIke` @ :300](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L300).

- **Keepalive**: **L2TP HELLO** (60s) + **IKE DPD R-U-THERE** (20s); 3 lần không ACK ⇒ peer chết. Cũng trả ACK cho probe của server, và phát hiện **Delete** inbound ⇒ rớt.
- **Rekey Phase 2** (make-before-break): ~90% lifetime (3600s) → [`RekeyPhase2Async` @ :333](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L333) chạy Quick Mode mới trên IKE-SA hiện có → `EspSession` mới; [`IpsecL2tpTransport.SwapSession` @ :32](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/IpsecL2tpTransport.cs#L32) chuyển outbound ngay, giữ SA cũ cho inbound thêm 10s ([`ScheduleDropPreviousInbound` @ :365](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L365)).
- **Auto-reconnect**: mọi tín hiệu rớt (DPD chết / server Delete / L2TP teardown / **Phase 1 hết hạn 8h** = rekey-by-reconnect) → [`OnLinkLost` @ :376](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L376) (lock chống double-supervisor + drop-window race) → [`ReconnectLoopAsync` @ :404](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L404) retry **backoff 1s→30s ×2 ±20%** (bật mặc định, [L2tpIpsecReconnectOptions.cs](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecReconnectOptions.cs)). Tunnel mới chui sau `_facade` ⇒ IP stack + flow **same-IP sống sót không re-bind**; đổi IP ⇒ cập nhật `Config` + [`L2tpIpsecVpnSession.Reconfigured` @ :29](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecVpnSession.cs#L29).
- **Teardown sạch**: [`DisconnectAsync` @ :491](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L491) (`IAsyncDisposable`) hủy reconnect đang chờ, gửi **CDN + StopCCN** (L2TP) + **Delete ESP/ISAKMP** (IKE) rồi mới đóng socket (best-effort, timeout 2s).
- **Trạng thái**: event [`StateChanged` @ :91](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L91) + enum [L2tpIpsecConnectionState.cs](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/Enums/L2tpIpsecConnectionState.cs) (Connecting/Connected/Reconnecting/Disconnected); event [`Reconnected` @ :94](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L94).

## 7. Luồng kết nối — SSTP (control plane)

Plugin entry: [SstpDriver.cs:8](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpDriver.cs#L8) (`Name="sstp"`, Capabilities: L3Ip + UsesPpp + Tls + UserPassword + Ipcp) → [SstpConnection.cs:16](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpConnection.cs#L16), bọc trong [SstpVpnConnection.cs:6](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpVpnConnection.cs#L6) (single-session — MS-SSTP chỉ 1 PPP session/HTTPS).

1. **TCP:443 → TLS** (`SslStream` **chấp nhận mọi cert** — không PKI, danh tính xác thực bằng crypto binding ở bước 5; *bắt giữ chứng chỉ server*) — [SstpTransport.cs:14](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpTransport.cs#L14).
2. **HTTP `SSTP_DUPLEX_POST`** tới URI `/sra_{GUID}/` (Content-Length = `ulong.MaxValue`, luồng duplex vô hạn) → 200 OK; từ đó TLS stream là luồng gói SSTP 2 chiều.
3. **`CallConnectRequest`** (EncapsulatedProtocolId = PPP) → nhận **`CallConnectAck`** kèm nonce 32 byte.
4. **PPP qua SSTP**: [SstpPppChannel.cs:11](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpPppChannel.cs#L11) đẩy frame vào `PppEngine` → LCP → MS-CHAPv2 → khi `AuthSucceeded` thì **derive HLAK**.
5. **Crypto binding**: [SstpCryptoBinding.cs:13](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpCryptoBinding.cs#L13) tính `CMK = HMAC-SHA256(HLAK,…)`, MAC kép trên gói Call-Connected + SHA-256 chứng chỉ → gửi **`CallConnected`** (ràng buộc kênh TLS với danh tính, chống MITM).
6. **IPCP** cấp IP → `LinkUp` → trả [SstpVpnSession.cs:8](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpVpnSession.cs#L8).
7. **Keepalive (thụ động)**: vòng nhận trả lời **Echo-Request → Echo-Response** để giữ tunnel sống — [SstpConnection.cs:87-89](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpConnection.cs#L87-L89). SSTP **chưa** chủ động gửi Echo-Request/timeout để phát hiện peer chết, **chưa teardown sạch** (Call-Disconnect) và **chưa auto-reconnect** — xem [roadmap §11](11-todo-roadmap.md).

## 8. Data plane — ngăn xếp đóng gói

**L2TP/IPsec** (outbound, ngoài→trong):

```
IP ứng dụng
 └─ PPP        [FF 03 | 00 21 | IP]
     └─ L2TP    [header | tunnelId | sessionId | PPP]
         └─ UDP/1701  (checksum 0)
             └─ ESP    [SPI | Seq | IV | AES-CBC(...) | HMAC-SHA1]
                 └─ UDP/4500  (SPI≠0 ⇒ ESP, KHÔNG Non-ESP Marker)
                     └─ IP thật (client → gateway)
```

Đường mã hóa: `WriteIpPacketAsync` (qua `_facade`) → `PppEngine` → `L2tpPppFrameChannel` → `L2tpClient.SendDataAsync` →
`UdpEncapsulation` → `EspSession.Protect` → `NatTraversalChannel.SendEspAsync`. Inbound đảo ngược qua
`ReceiveLoopAsync` → `OnEspPacket` → `TryUnprotect` → tách UDP/1701 → L2TP → PPP → `InboundIpPacket`.

**Ghi chú as-built**: ESP đường live dùng AES-CBC-256 + **HMAC-SHA1-96** ([EspCbcHmacSuite](../src/TqkLibrary.Vpn.Ipsec/Esp/EspCbcHmacSuite.cs#L11)); đường IKEv2 mặc định HMAC-SHA256-128. **Forced-NAT-T**: client cố tình dùng local port ephemeral nên gateway luôn thấy NATed ⇒ luôn lên UDP/4500 với ESP-in-UDP, **không thử ESP thuần** (gốc của rủi ro forced-NAT-T — roadmap §11). MTU cố định **1400** (`PppPacketChannel`/`TunnelConfig`), TCP MSS **1360**.

**Rekey Phase 2 (make-before-break)**: khi rekey, [`IpsecL2tpTransport.SwapSession` @ :32](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/IpsecL2tpTransport.cs#L32) chuyển **outbound** sang SPI mới ngay; **inbound** nhận cả SA cũ lẫn mới (SPI khác nhau) cho tới khi [`DropPreviousInbound` @ :42](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/IpsecL2tpTransport.cs#L42) (sau 10s grace) bỏ SA cũ → không mất gói đang bay dưới SA cũ.

**SSTP** (outbound):

```
IP ứng dụng
 └─ PPP [FF 03 | 00 21 | IP]   (RAW — KHÔNG HDLC stuffing/FCS)
     └─ SSTP data [10 | 00 | length]
         └─ TLS record
             └─ TCP/443 (kernel OS)
```

SSTP data mang **đúng 1 frame PPP RAW** (không HDLC byte-stuffing/FCS — khác L2TP/IPsec dùng HDLC); trường `length` của SSTP delineate gói — [SstpPppChannel.cs:11](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpPppChannel.cs#L11).

## 9. Trạng thái hiện thực

- ✅ Driver **L2TP/IPsec** (IKEv1 PSK + ESP + L2TP + PPP/MS-CHAPv2) **+ keepalive (IKE DPD RFC 3706 + L2TP HELLO) + Phase 2 rekey (make-before-break) + teardown sạch (CDN/StopCCN + IKE Delete) + auto-reconnect (backoff)** — chạy live (đã kiểm trên VPN Gate).
- ✅ **Auto-reconnect L2TP/IPsec** sau facade ổn định [SwappablePacketChannel](../src/TqkLibrary.Vpn.Abstractions/Channels/SwappablePacketChannel.cs): [L2tpIpsecReconnectOptions](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecReconnectOptions.cs) (bật mặc định) + event `StateChanged`/`Reconnected`; flow trong tunnel sống sót khi reconnect same-IP.
- ✅ Driver **SSTP** (TLS + PPP/MS-CHAPv2 + crypto binding).
- ✅ **Demo tích hợp proxy** [`demo/Vpn2ProxyDemo`](../demo/Vpn2ProxyDemo): adapter `VpnProxySource`/`VpnConnectSource` (**inline trong demo**, không phải project `src/`) đưa tunnel thành `IProxySource` của `TqkLibrary.Proxy` 1.0.35 → dựng HTTP/SOCKS proxy local định tuyến qua VPN (CONNECT/HTTP); chạy MS-SSTP **và** L2TP/IPsec → `HttpClient` qua proxy → `checkip.amazonaws.com`. Chưa: BIND, UDP-ASSOCIATE, DNS-over-tunnel, IPv6.
- ✅ **IKEv2** (`Ike/V2/`) — **IKE_SA_INIT + IKE_AUTH** hoàn chỉnh + có test, **nhưng chưa nối vào driver nào**; chưa có CreateChildSA/Informational ⇒ chưa rekey/DPD/teardown (khác V1).
- ⏳ Nhiều enum năng lực (WireGuard/OpenVPN/SoftEther/L2 Ethernet/DTLS) là **khung mở rộng**, chưa hiện thực. Hợp đồng L2 [IEthernetChannel](../src/TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IEthernetChannel.cs#L7) **đã khai báo** nhưng chưa có implementation/driver.
- 11 project test trong `tests/` (~93 test method `[Fact]`/`[Theory]`) phủ từng tầng độc lập + tích hợp live driver L2tpIpsec/SSTP (7 test `[Trait("Category","Integration")]`).

## Khác biệt so với design docs

Các file `00`–`09` mô tả **ý định thiết kế**; vài điểm đã lệch khỏi code hiện hành:

| Design doc nói | Code thực tế |
|---|---|
| `04`: L2TP/IPsec dùng **IKEv2** | Dùng **IKEv1** ([IkeV1Client.cs:16](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs#L16)); IKEv2 tồn tại nhưng chưa wire |
| `00`: decorator **`EspIkeDemuxTransport`** | Không tồn tại; demux IKE/ESP nằm trong [NatTraversalChannel](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversalChannel.cs#L12) + vòng lặp nhận |
| `00`/`04`: tên `IVpnTransport`, `VpnConnection`, `VpnSession`, tham số `options` | Thực tế: `IVpnConnection`/`IVpnSession`, `ConnectAsync` không có `options`; transport tách `IByteStreamTransport`/`IDatagramTransport` |
| `00`: `EthernetAdapter`, `VirtualHost`, L2 multi-host | `EthernetAdapter`/`VirtualHost` chưa hiện thực; **hợp đồng** L2 [IEthernetChannel](../src/TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IEthernetChannel.cs#L7) đã khai báo (chưa có impl), mới chạy đường L3 (`IPacketChannel`) |
| `00`: data plane qua `ISecuritySession` / `IPacketEncapsulator` | 2 hợp đồng này **mồ côi** — không class nào implement; ESP dùng `EspSession` riêng (giống `IByteStreamTransport`) |
| `00`–`04`: **không** đề cập keepalive / rekey / teardown / reconnect | **Đã bổ sung as-built** (live): IKE DPD + L2TP HELLO, Phase 2 rekey make-before-break, teardown CDN/StopCCN + IKE Delete, auto-reconnect backoff sau `SwappablePacketChannel` — xem §6.1 |

---
*Tạo bằng cách đọc song song toàn bộ subsystem + truy vết 2 luồng connect, đối chiếu trực tiếp mã nguồn.*
