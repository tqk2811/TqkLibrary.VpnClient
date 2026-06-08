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

Hợp đồng phụ trợ (định nghĩa sẵn, dùng một phần): [IByteStreamTransport.cs:4](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs#L4) /
[IDatagramTransport.cs:7](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L7) (đáy TCP/UDP),
[ISecuritySession.cs:7](../src/TqkLibrary.Vpn.Abstractions/Security/Interfaces/ISecuritySession.cs#L7) (mã hóa từng gói),
[IPacketEncapsulator.cs:9](../src/TqkLibrary.Vpn.Abstractions/Encapsulation/Interfaces/IPacketEncapsulator.cs#L9) (đóng khung).

[VpnDriverCapabilities.cs:9](../src/TqkLibrary.Vpn.Abstractions/Drivers/Models/VpnDriverCapabilities.cs#L9) cho façade
"hỏi năng lực" driver trước khi kết nối. **Nhiều enum năng lực là khung mở rộng tương lai** (WireGuard/OpenVPN/
DTLS/L2 Ethernet…); hiện chỉ 2 driver L3 được hiện thực.

## 4. Điểm vào

[VpnClientBuilder.cs:8](../src/TqkLibrary.Vpn/VpnClientBuilder.cs#L8) đăng ký driver kiểu fluent;
[VpnClient.cs:18](../src/TqkLibrary.Vpn/VpnClient.cs#L18) tra driver theo tên rồi ủy thác `ConnectAsync`.

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
| **Crypto** | [AesCbcCipher.cs:10](../src/TqkLibrary.Vpn.Crypto/AesCbcCipher.cs#L10), [ModpDhGroup.cs:12](../src/TqkLibrary.Vpn.Crypto/ModpDhGroup.cs#L12), [PrfPlus.cs:9](../src/TqkLibrary.Vpn.Crypto/PrfPlus.cs#L9), [Md4.cs:9](../src/TqkLibrary.Vpn.Crypto/Md4.cs#L9), [Des.cs:8](../src/TqkLibrary.Vpn.Crypto/Des.cs#L8) | Primitive thuần. MD4/DES bắt buộc cho MS-CHAPv2 dù đã lỗi thời. Nhánh `net8.0` (BCL) vs `netstandard2.0` (BouncyCastle cho AES-GCM). |
| **Ipsec.Esp** | [EspSession.cs:7](../src/TqkLibrary.Vpn.Ipsec/Esp/EspSession.cs#L7), [AntiReplayWindow.cs:7](../src/TqkLibrary.Vpn.Ipsec/Esp/AntiReplayWindow.cs#L7) | Data-plane IPsec: `Protect`/`TryUnprotect` gói ESP, sequence, chống replay (cửa sổ 64 gói). Suite CBC+HMAC và GCM. |
| **Ipsec.Ike.V1** | [IkeV1Client.cs:16](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs#L16) | Bắt tay ISAKMP/IKEv1 cho L2TP: Main Mode (MM1–MM6) + Quick Mode (QM1–QM3) → sinh khóa ESP. **Đây là IKE đang chạy thực tế.** |
| **Ipsec.Ike.V2** | [IkeClient.cs:15](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeClient.cs#L15) | IKEv2 đầy đủ (IKE_SA_INIT + IKE_AUTH + CHILD_SA). **Đã build & có test nhưng CHƯA driver nào dùng** — hạ tầng sẵn cho driver IKEv2/IPsec tương lai. |
| **L2tp** | [L2tpClient.cs:12](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs#L12), [L2tpControlChannel.cs:10](../src/TqkLibrary.Vpn.L2tp/L2tpControlChannel.cs#L10) | L2TPv2 (RFC 2661): tunnel SCCRQ→SCCRP→SCCCN, session ICRQ→ICRP→ICCN; truyền tin cậy Ns/Nr + ZLB ack + retransmit 1s. PPP frame chui trong L2TP data. |
| **Ppp** | [PppEngine.cs:14](../src/TqkLibrary.Vpn.Ppp/PppEngine.cs#L14), [MsChapV2.cs:11](../src/TqkLibrary.Vpn.Ppp/Auth/MsChapV2.cs#L11), [HdlcFramer.cs:7](../src/TqkLibrary.Vpn.Ppp/Framing/HdlcFramer.cs#L7) | Engine PPP chạy tuần tự **LCP → MS-CHAPv2 → IPCP**, kết thúc bằng event `LinkUp` khi có IP. [PppPacketChannel.cs:10](../src/TqkLibrary.Vpn.Ppp/PppPacketChannel.cs#L10) chính là `IPacketChannel` L3 trả ra. |
| **IpStack** | [TcpIpStack.cs:11](../src/TqkLibrary.Vpn.IpStack/Tcp/TcpIpStack.cs#L11), [TcpConnection.cs:13](../src/TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs#L13), [UdpConnection.cs:10](../src/TqkLibrary.Vpn.IpStack/Tcp/UdpConnection.cs#L10) | TCP/IP userspace: demux gói IPv4 inbound theo port; TCP state machine SYN-SENT→ESTABLISHED→FIN; tự tính checksum ([InternetChecksum.cs:4](../src/TqkLibrary.Vpn.IpStack/InternetChecksum.cs#L4)). |
| **Transport.Udp** | [NatTraversalChannel.cs:12](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversalChannel.cs#L12), [NatTraversal.cs:20](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversal.cs#L20) | NAT-T (RFC 3948): 1 UDP socket, chuyển 500→4500 khi phát hiện NAT, **ghép kênh IKE/ESP** trên port 4500 (4 byte 0 ⇒ IKE; SPI≠0 ⇒ ESP). |
| **Sockets** | [VpnTcpClient.cs:8](../src/TqkLibrary.Vpn.Sockets/VpnTcpClient.cs#L8), [VpnUdpClient.cs:10](../src/TqkLibrary.Vpn.Sockets/VpnUdpClient.cs#L10) | API socket trên tunnel: TCP trả `Stream` (cắm `HttpClient`), UDP hỗ trợ DNS-over-tunnel. |

## 6. Luồng kết nối — L2TP/IPsec (control plane)

Toàn bộ điều phối: [L2tpIpsecConnection.ConnectAsync @ L2tpIpsecConnection.cs:50](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L50)

1. **Resolve + mở UDP** tới gateway:500; chạy `ReceiveLoopAsync` nền phân loại datagram IKE/ESP — [L2tpIpsecConnection.cs:52-55](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L52-L55).
2. **IKEv1 Phase 1 – Main Mode** MM1/MM3 trên port 500 (đề xuất SA + Vendor ID NAT-T, trao đổi DH + nonce + NAT-D), sinh `SKEYID` + khóa Phase 1 — [L2tpIpsecConnection.cs:60-61](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L60-L61).
3. **Phát hiện NAT → `SwitchToNatTPort()`** sang 4500; MM5/MM6 (đã mã hóa) xác thực PSK qua `HASH_R` — [L2tpIpsecConnection.cs:64-66](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L64-L66).
4. **IKEv1 Phase 2 – Quick Mode** QM1/QM2/QM3 → sinh `KEYMAT` cho ESP — [L2tpIpsecConnection.cs:69-71](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L69-L71).
5. **Dựng ESP**: `BuildEspSession` lấy khóa Phase 2 → `EspSession` AES-CBC + HMAC-SHA1 (2 chiều); bật `_espActive` — [L2tpIpsecConnection.cs:74-76, 93-99](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L74-L99).
6. **L2TP**: `L2tpClient` chạy trên [IpsecL2tpTransport.cs:11](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/IpsecL2tpTransport.cs#L11) → dựng tunnel + session — [L2tpIpsecConnection.cs:78-79](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L78-L79).
7. **PPP**: [L2tpPppFrameChannel.cs:7](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpPppFrameChannel.cs#L7) cầu nối L2TP data ↔ `PppEngine`; LCP → MS-CHAPv2 → IPCP (nhận IP) → `LinkUp` — [L2tpIpsecConnection.cs:81-90](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs#L81-L90).
8. Driver bọc kết quả thành [L2tpIpsecVpnSession.cs:8](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecVpnSession.cs#L8) (IP/DNS từ IPCP) trả về.

## 7. Luồng kết nối — SSTP (control plane)

Điều phối: [SstpConnection.cs:16](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpConnection.cs#L16)

1. **TCP:443 → TLS** (`SslStream`, *bắt giữ chứng chỉ server* để crypto-binding) — [SstpTransport.cs:14](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpTransport.cs#L14).
2. **HTTP `SSTP_DUPLEX_POST`** tới URI `/sra_{GUID}/` → 200 OK; từ đó TLS stream là luồng gói SSTP 2 chiều.
3. **`CallConnectRequest`** (EncapsulatedProtocolId = PPP) → nhận **`CallConnectAck`** kèm nonce 32 byte.
4. **PPP qua SSTP**: [SstpPppChannel.cs:11](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpPppChannel.cs#L11) đẩy frame vào `PppEngine` → LCP → MS-CHAPv2 → khi `AuthSucceeded` thì **derive HLAK**.
5. **Crypto binding**: [SstpCryptoBinding.cs:13](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpCryptoBinding.cs#L13) tính `CMK = HMAC-SHA256(HLAK,…)`, MAC kép trên gói Call-Connected + SHA-256 chứng chỉ → gửi **`CallConnected`** (ràng buộc kênh TLS với danh tính, chống MITM).
6. **IPCP** cấp IP → `LinkUp` → trả [SstpVpnSession.cs:8](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpVpnSession.cs#L8).

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

Đường mã hóa: `WriteIpPacketAsync` → `PppEngine` → `L2tpPppFrameChannel` → `L2tpClient.SendDataAsync` →
`UdpEncapsulation` → `EspSession.Protect` → `NatTraversalChannel.SendEspAsync`. Inbound đảo ngược qua
`ReceiveLoopAsync` → `OnEspPacket` → `TryUnprotect` → tách UDP/1701 → L2TP → PPP → `InboundIpPacket`.

**SSTP** (outbound):

```
IP ứng dụng
 └─ PPP [FF 03 | 00 21 | IP]
     └─ SSTP data [10 | 00 | length]
         └─ TLS record
             └─ TCP/443 (kernel OS)
```

## 9. Trạng thái hiện thực

- ✅ Driver **L2TP/IPsec** (IKEv1 PSK + ESP + L2TP + PPP/MS-CHAPv2) — chạy live (đã kiểm trên VPN Gate).
- ✅ Driver **SSTP** (TLS + PPP/MS-CHAPv2 + crypto binding).
- ✅ **IKEv2** (`Ike/V2/`) — hoàn chỉnh + có test, **nhưng chưa nối vào driver nào**.
- ⏳ Nhiều enum năng lực (WireGuard/OpenVPN/SoftEther/L2 Ethernet/DTLS) là **khung mở rộng**, chưa hiện thực.
- 12 project test trong `tests/` phủ từng tầng độc lập + tích hợp driver L2tpIpsec.

## Khác biệt so với design docs

Các file `00`–`09` mô tả **ý định thiết kế**; vài điểm đã lệch khỏi code hiện hành:

| Design doc nói | Code thực tế |
|---|---|
| `04`: L2TP/IPsec dùng **IKEv2** | Dùng **IKEv1** ([IkeV1Client.cs:16](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs#L16)); IKEv2 tồn tại nhưng chưa wire |
| `00`: decorator **`EspIkeDemuxTransport`** | Không tồn tại; demux IKE/ESP nằm trong [NatTraversalChannel](../src/TqkLibrary.Vpn.Transport.Udp/NatTraversalChannel.cs#L12) + vòng lặp nhận |
| `00`/`04`: tên `IVpnTransport`, `VpnConnection`, `VpnSession`, tham số `options` | Thực tế: `IVpnConnection`/`IVpnSession`, `ConnectAsync` không có `options`; transport tách `IByteStreamTransport`/`IDatagramTransport` |
| `00`: `EthernetAdapter`, `VirtualHost`, L2 multi-host | Chưa hiện thực; mới chỉ có đường L3 (`IPacketChannel`) |

---
*Tạo bằng cách đọc song song toàn bộ subsystem + truy vết 2 luồng connect, đối chiếu trực tiếp mã nguồn.*
