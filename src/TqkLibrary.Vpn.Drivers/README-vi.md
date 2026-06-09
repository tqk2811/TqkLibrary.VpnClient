# TqkLibrary.Vpn.Drivers

> VPN protocol drivers: MS-SSTP (`Sstp/`) và L2TP/IPsec (`L2tpIpsec/`). Đây là nơi lắp ráp toàn bộ stack giao thức thành một `IVpnConnection` hoàn chỉnh.

## Mục đích

Project này là **tầng DRIVER** — điểm điều phối control plane của toàn thư viện. Mỗi driver lấy các khối giao thức rời rạc (IKE, ESP, L2TP, PPP, NAT-T transport, TLS) và **lắp ráp chúng thành một đường hầm hoàn chỉnh**, rồi bọc lại sau interface trung lập `IVpnConnection` để tầng `TqkLibrary.Vpn` ở trên tiêu thụ mà không cần biết giao thức cụ thể.

Hai driver được hiện thực:

- **L2TP/IPsec** ([L2tpIpsecDriver.cs:9](L2tpIpsec/L2tpIpsecDriver.cs#L9)) — IKEv1 PSK (Main Mode + Quick Mode) qua NAT-T (UDP 500→4500), ESP transport mode làm data plane, L2TPv2 trên UDP/1701, và PPP/MS-CHAPv2 để nhận IP. Kèm vòng đời đầy đủ: keepalive (L2TP HELLO + IKE DPD), rekey ESP CHILD SA (make-before-break), teardown sạch (IKE Delete + L2TP CDN/StopCCN), và auto-reconnect (exponential backoff) sau một facade kênh ổn định.
- **MS-SSTP** ([SstpDriver.cs:8](Sstp/SstpDriver.cs#L8)) — TLS trên 443, handshake `SSTP_DUPLEX_POST`, control message theo `[MS-SSTP]`, PPP/MS-CHAPv2, và **crypto binding** (gắn HLAK của PPP vào cert TLS để chống MITM).

Vấn đề được giải quyết: tách phần "biết cách nói chuyện với từng loại gateway VPN" ra khỏi phần "biết cách dùng đường hầm" (sockets/IP stack ở trên), nhờ đảo ngược phụ thuộc qua `IVpnProtocolDriver`/`IVpnConnection` trong `Abstractions`.

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.Vpn` ở trên và các project PROTOCOL/TRANSPORT/CRYPTO ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.Vpn.Abstractions](../TqkLibrary.Vpn.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`...).
  - [TqkLibrary.Vpn.Ppp](../TqkLibrary.Vpn.Ppp) — `PppEngine`, `MsChapV2Authenticator`, `IPppFrameChannel`.
  - [TqkLibrary.Vpn.Transport.Udp](../TqkLibrary.Vpn.Transport.Udp) — `NatTraversalChannel` (NAT-T, ghép kênh IKE/ESP).
  - [TqkLibrary.Vpn.Ipsec](../TqkLibrary.Vpn.Ipsec) — `IkeV1Client`, `EspSession`, `EspCipherSuite`.
  - [TqkLibrary.Vpn.L2tp](../TqkLibrary.Vpn.L2tp) — `L2tpClient`, `IL2tpTransport`.
  - Không có PackageReference đặc thù — chỉ dùng BCL (`SslStream`, `HMACSHA256`, `SHA256`).
- **Được dùng bởi:** [TqkLibrary.Vpn](../TqkLibrary.Vpn) (entry point — `VpnClient`/`VpnClientBuilder` đăng ký các driver này).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Drivers/
├── L2tpIpsec/                       Driver L2TP/IPsec (IKEv1 + ESP + L2TP + PPP)
│   ├── L2tpIpsecDriver.cs           IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
│   ├── L2tpIpsecConnection.cs       Bộ điều phối: handshake + keepalive + rekey + teardown + reconnect
│   ├── IpsecL2tpTransport.cs        ESP data plane (IL2tpTransport): bọc/giải UDP-1701 trong ESP, swap SA khi rekey
│   ├── UdpEncapsulation.cs          Build/parse UDP header (port 1701, checksum 0) cho ESP transport mode
│   ├── L2tpPppFrameChannel.cs       Cầu nối L2TP data ↔ PPP engine (IPppFrameChannel)
│   ├── L2tpIpsecReconnectOptions.cs Chính sách auto-reconnect (backoff/jitter/max attempts)
│   ├── L2tpIpsecVpnConnection.cs    Adapter sang IVpnConnection (một session)
│   ├── L2tpIpsecVpnSession.cs       IVpnSession: facade ổn định + áp dụng reconnect vào TunnelConfig
│   ├── Enums/                       L2tpIpsecConnectionState (Disconnected/Connecting/Connected/Reconnecting)
│   └── Models/                      L2tpIpsecReconnectInfo (địa chỉ mới + cờ AddressChanged)
└── Sstp/                            Driver MS-SSTP (TLS + PPP + crypto binding)
    ├── SstpDriver.cs                IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
    ├── SstpConnection.cs            Bộ điều phối: TLS + control + PPP + crypto binding + Echo keepalive
    ├── SstpTransport.cs             TLS + SSTP_DUPLEX_POST handshake + framing gói SSTP
    ├── SstpControlCodec.cs          Encode/decode body control message ([MS-SSTP] §2.2.2–2.2.3)
    ├── SstpCryptoBinding.cs         CMK/Compound-MAC (HMAC-SHA256) cho Call Connected
    ├── SstpPppChannel.cs            Cầu nối SSTP data ↔ PPP (RAW PPP, không HDLC) + dispatch control
    ├── SstpConstants.cs             Hằng số [MS-SSTP] (version 0x10, DuplexUri, hash protocol...)
    ├── SstpVpnConnection.cs         Adapter sang IVpnConnection (một session)
    ├── SstpVpnSession.cs            IVpnSession
    ├── Enums/                       SstpMessageType, SstpAttributeId
    └── Models/                      SstpAttribute, SstpControlMessage
```

## Thành phần chính

### L2TP/IPsec

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `L2tpIpsecDriver` | `IVpnProtocolDriver`: khai báo capabilities, `ConnectAsync` dựng `L2tpIpsecConnection` → trả `IVpnConnection` | [L2tpIpsecDriver.cs:9](L2tpIpsec/L2tpIpsecDriver.cs#L9) |
| `L2tpIpsecConnection` | Bộ điều phối control plane: chạy handshake IKE/L2TP/PPP, keepalive, rekey, teardown, supervisor reconnect | [L2tpIpsecConnection.cs:24](L2tpIpsec/L2tpIpsecConnection.cs#L24) |
| `IpsecL2tpTransport` | `IL2tpTransport`: ESP data plane — bọc L2TP-trong-UDP/1701-trong-ESP; giữ SA cũ tạm thời khi rekey | [IpsecL2tpTransport.cs:11](L2tpIpsec/IpsecL2tpTransport.cs#L11) |
| `UdpEncapsulation` | Build/parse UDP header (1701, checksum 0) mà ESP transport mode bảo vệ | [UdpEncapsulation.cs:8](L2tpIpsec/UdpEncapsulation.cs#L8) |
| `L2tpPppFrameChannel` | `IPppFrameChannel`: PPP frame đi trong L2TP data message | [L2tpPppFrameChannel.cs:7](L2tpIpsec/L2tpPppFrameChannel.cs#L7) |
| `L2tpIpsecReconnectOptions` | Chính sách auto-reconnect: backoff/jitter/max attempts | [L2tpIpsecReconnectOptions.cs:8](L2tpIpsec/L2tpIpsecReconnectOptions.cs#L8) |
| `L2tpIpsecVpnConnection` | Adapter `IVpnConnection` (một PPP session/tunnel) | [L2tpIpsecVpnConnection.cs:6](L2tpIpsec/L2tpIpsecVpnConnection.cs#L6) |
| `L2tpIpsecVpnSession` | `IVpnSession`: facade ổn định + `ApplyReconnect` cập nhật `TunnelConfig` | [L2tpIpsecVpnSession.cs:10](L2tpIpsec/L2tpIpsecVpnSession.cs#L10) |
| `L2tpIpsecConnectionState` | Enum trạng thái vòng đời | [L2tpIpsecConnectionState.cs:4](L2tpIpsec/Enums/L2tpIpsecConnectionState.cs#L4) |
| `L2tpIpsecReconnectInfo` | Kết quả reconnect: địa chỉ mới + `AddressChanged` | [L2tpIpsecReconnectInfo.cs:6](L2tpIpsec/Models/L2tpIpsecReconnectInfo.cs#L6) |

### MS-SSTP

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `SstpDriver` | `IVpnProtocolDriver`: capabilities + `ConnectAsync` → `IVpnConnection` | [SstpDriver.cs:8](Sstp/SstpDriver.cs#L8) |
| `SstpConnection` | Bộ điều phối: TLS + control + PPP + crypto binding + Echo keepalive | [SstpConnection.cs:16](Sstp/SstpConnection.cs#L16) |
| `SstpTransport` | TLS + `SSTP_DUPLEX_POST` handshake + framing gói SSTP 4-byte header | [SstpTransport.cs:14](Sstp/SstpTransport.cs#L14) |
| `SstpControlCodec` | Build/parse body control message (type + attributes) | [SstpControlCodec.cs:7](Sstp/SstpControlCodec.cs#L7) |
| `SstpCryptoBinding` | Dựng attribute Crypto Binding (CMK + Compound-MAC) cho Call Connected | [SstpCryptoBinding.cs:13](Sstp/SstpCryptoBinding.cs#L13) |
| `SstpPppChannel` | `IPppFrameChannel`: RAW PPP frame trong SSTP data packet + dispatch control | [SstpPppChannel.cs:11](Sstp/SstpPppChannel.cs#L11) |
| `SstpConstants` | Hằng số `[MS-SSTP]` (Version 0x10, DuplexUri, hash protocol) | [SstpConstants.cs:4](Sstp/SstpConstants.cs#L4) |
| `SstpVpnConnection` / `SstpVpnSession` | Adapter `IVpnConnection` / `IVpnSession` | [SstpVpnConnection.cs:6](Sstp/SstpVpnConnection.cs#L6) · [SstpVpnSession.cs:8](Sstp/SstpVpnSession.cs#L8) |
| `SstpMessageType` / `SstpAttributeId` | Enum control type / attribute id | [SstpMessageType.cs:4](Sstp/Enums/SstpMessageType.cs#L4) · [SstpAttributeId.cs:4](Sstp/Enums/SstpAttributeId.cs#L4) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|-------------------------|--------------------|---------|
| `[MS-SSTP]` §2.2.1, §3 (transport + framing) | `SstpTransport` | [SstpTransport.cs:12](Sstp/SstpTransport.cs#L12) | Comment dẫn rõ tiết diện |
| `[MS-SSTP]` §2.2.2–2.2.3 (control message + attributes) | `SstpControlCodec` | [SstpControlCodec.cs:6](Sstp/SstpControlCodec.cs#L6) | Comment dẫn rõ |
| `[MS-SSTP]` §2.2.2 (message types) | `SstpMessageType` | [SstpMessageType.cs:3](Sstp/Enums/SstpMessageType.cs#L3) | Comment dẫn rõ |
| `[MS-SSTP]` §2.2.3 (attribute ids) | `SstpAttributeId` | [SstpAttributeId.cs:3](Sstp/Enums/SstpAttributeId.cs#L3) | Comment dẫn rõ |
| `[MS-SSTP]` §2.2.7, §3.2.5.2 (Crypto Binding) | `SstpCryptoBinding` | [SstpCryptoBinding.cs:9](Sstp/SstpCryptoBinding.cs#L9) | Comment dẫn rõ; CMK = HMAC-SHA256(HLAK, seed) |
| `[MS-SSTP]` (hằng số chung) | `SstpConstants` | [SstpConstants.cs:3](Sstp/SstpConstants.cs#L3) | Version 0x10, DuplexUri |
| `[MS-SSTP]` (RAW PPP per packet, không HDLC) | `SstpPppChannel` | [SstpPppChannel.cs:7](Sstp/SstpPppChannel.cs#L7) | Comment dẫn rõ |
| RFC 3706 (IKE DPD — Dead Peer Detection) | `L2tpIpsecConnection` (keepalive: L2TP HELLO + IKE DPD) | [L2tpIpsecConnection.cs:250](L2tpIpsec/L2tpIpsecConnection.cs#L250) | Comment dẫn rõ `RFC 3706` |
| FIPS PUB 198-1 / RFC 6234 (HMAC-SHA-256) | `SstpCryptoBinding` (`HMACSHA256` BCL) | [SstpCryptoBinding.cs:44](Sstp/SstpCryptoBinding.cs#L44) | (suy luận) — dùng `System.Security.Cryptography.HMACSHA256` |
| FIPS PUB 180-4 (SHA-256, hash cert TLS) | `SstpConnection` (`SHA256.Create()`) | [SstpConnection.cs:67](Sstp/SstpConnection.cs#L67) | (suy luận) |
| RFC 8446 / 5246 (TLS, qua `SslStream`) | `SstpTransport` | [SstpTransport.cs:44](Sstp/SstpTransport.cs#L44) | (suy luận) — BCL `SslStream.AuthenticateAsClientAsync` |
| RFC 2759 (MS-CHAPv2) | `MsChapV2Authenticator` (dùng từ `Ppp`) | [SstpConnection.cs:60](Sstp/SstpConnection.cs#L60), [L2tpIpsecConnection.cs:158](L2tpIpsec/L2tpIpsecConnection.cs#L158) | (suy luận) — hiện thực nằm ở project `Ppp` |
| RFC 3079 (MPPE/HLAK key derivation) + `[MS-SSTP]` crypto binding | `MsChapV2Authenticator.DeriveHlak` (từ `Ppp`) | [SstpConnection.cs:65](Sstp/SstpConnection.cs#L65) | (suy luận) — derive ở `Ppp` (code chú thích `RFC 3079`), dùng tại đây |
| RFC 2409 (IKEv1 Main/Quick Mode, PSK) | `IkeV1Client` (từ `Ipsec`), điều phối tại đây | [L2tpIpsecConnection.cs:133](L2tpIpsec/L2tpIpsecConnection.cs#L133) | (suy luận) — hiện thực nằm ở `Ipsec/Ike/V1` |
| RFC 3947 / 3948 (IPsec NAT-T, UDP 500↔4500) | `NatTraversalChannel` (từ `Transport.Udp`), `natt.SwitchToNatTPort()` | [L2tpIpsecConnection.cs:138](L2tpIpsec/L2tpIpsecConnection.cs#L138) | (suy luận) — hiện thực ở `Transport.Udp` |
| RFC 4303 (ESP), AES-CBC + HMAC-SHA1 | `IpsecL2tpTransport`, `EspSession`/`EspCipherSuite.AesCbcHmacSha1` (từ `Ipsec`) | [L2tpIpsecConnection.cs:197-201](L2tpIpsec/L2tpIpsecConnection.cs#L197-L201) | (suy luận) — cipher suite hiện thực ở `Ipsec/Esp` |
| RFC 2661 (L2TPv2 control/data) | `L2tpClient` (từ `L2tp`), điều phối qua `IpsecL2tpTransport` | [L2tpIpsecConnection.cs:152](L2tpIpsec/L2tpIpsecConnection.cs#L152) | (suy luận) — hiện thực ở `L2tp` |
| RFC 1661 / 1332 (PPP LCP + IPCP) | `PppEngine` (từ `Ppp`) | [L2tpIpsecConnection.cs:159](L2tpIpsec/L2tpIpsecConnection.cs#L159), [SstpConnection.cs:61](Sstp/SstpConnection.cs#L61) | (suy luận) — hiện thực ở `Ppp` |

> Lưu ý: project này là tầng **điều phối** — phần lớn chuẩn crypto/protocol được **hiện thực** ở các project dưới (`Ipsec`, `L2tp`, `Ppp`, `Transport.Udp`, `Crypto`); ở đây chỉ **lắp ráp và gọi**. Hai chuẩn được hiện thực trực tiếp trong project này là `[MS-SSTP]` (toàn bộ thư mục `Sstp/`) và phần keepalive DPD (RFC 3706) trong `L2tpIpsecConnection`.

## API / cách dùng

Điểm vào công khai là hai driver `IVpnProtocolDriver`. Thông thường tầng `TqkLibrary.Vpn` (`VpnClientBuilder`) đăng ký driver và gọi `ConnectAsync`; có thể dùng trực tiếp:

```csharp
// L2TP/IPsec — auto-reconnect bật mặc định
var driver = new L2tpIpsecDriver(); // hoặc new L2tpIpsecDriver(new L2tpIpsecReconnectOptions { Enabled = false })
IVpnConnection conn = await driver.ConnectAsync(
    new VpnEndpoint("vpn.example.com", 0),
    new VpnCredentials { Username = "user", Password = "pass" /*, PreSharedKey = ... */ });

IVpnSession session = conn.Sessions[0];
IPacketChannel channel = session.PacketChannel;   // kênh L3 ổn định, sống qua reconnect
IPAddress myIp = session.Config.AssignedAddress;
await conn.DisposeAsync();                          // teardown sạch: IKE Delete + L2TP CDN/StopCCN

// MS-SSTP
var sstp = new SstpDriver();
IVpnConnection sstpConn = await sstp.ConnectAsync(
    new VpnEndpoint("sstp.example.com", 443),
    new VpnCredentials { Username = "user", Password = "pass" });
```

Class hạ tầng (`L2tpIpsecConnection`, `SstpConnection`) cũng public nếu cần điều khiển chi tiết (sự kiện `StateChanged`/`Reconnected`, `DisconnectAsync`...).

## Luồng nội bộ

### L2TP/IPsec — handshake (trong `EstablishAsync`)

1. Resolve host → tạo `NatTraversalChannel` (UDP/500), chạy `ReceiveLoopAsync` ghép kênh IKE/ESP — [L2tpIpsecConnection.cs:123-128](L2tpIpsec/L2tpIpsecConnection.cs#L123-L128).
2. **IKEv1 Phase 1 (Main Mode)** MM1–MM4 trên UDP/500 — [L2tpIpsecConnection.cs:134-135](L2tpIpsec/L2tpIpsecConnection.cs#L134-L135).
3. Phát hiện NAT-T → `SwitchToNatTPort()` (sang UDP/4500), MM5/MM6 đã mã hoá — [L2tpIpsecConnection.cs:138-140](L2tpIpsec/L2tpIpsecConnection.cs#L138-L140).
4. **Phase 2 (Quick Mode)** QM1–QM3 → khoá ESP CHILD SA — [L2tpIpsecConnection.cs:143-145](L2tpIpsec/L2tpIpsecConnection.cs#L143-L145).
5. Dựng `EspSession` + `IpsecL2tpTransport` (data plane); `L2tpClient.ConnectAsync` (L2TP tunnel/session); `PppEngine` + `MsChapV2Authenticator` chạy LCP/Auth/IPCP — [L2tpIpsecConnection.cs:148-167](L2tpIpsec/L2tpIpsecConnection.cs#L148-L167).
6. Khi `LinkUp`: cắm kênh PPP vào facade `SwappablePacketChannel` và bật keepalive — [L2tpIpsecConnection.cs:170-172](L2tpIpsec/L2tpIpsecConnection.cs#L170-L172).

### L2TP/IPsec — keepalive · rekey · teardown · reconnect

- **Keepalive:** L2TP HELLO (60s) + IKE DPD R-U-THERE (20s, miss ≥3 ⇒ link lost) — [L2tpIpsecConnection.cs:252-329](L2tpIpsec/L2tpIpsecConnection.cs#L252-L329).
- **Rekey (make-before-break):** Quick Mode mới → `SwapSession` (gửi trên SA mới ngay, giữ SA cũ để nhận trong grace 10s rồi `DropPreviousInbound`) — [L2tpIpsecConnection.cs:333-371](L2tpIpsec/L2tpIpsecConnection.cs#L333-L371) · [IpsecL2tpTransport.cs:32-45](L2tpIpsec/IpsecL2tpTransport.cs#L32-L45).
- **Link-loss + supervisor:** mọi nguồn (DPD chết, server Delete, L2TP teardown, Phase 1 hết hạn) gọi `OnLinkLost` → khởi động `ReconnectLoopAsync` với exponential backoff + jitter; thành công thì raise `Reconnected` (cập nhật `TunnelConfig` qua `L2tpIpsecVpnSession.ApplyReconnect`) — [L2tpIpsecConnection.cs:376-450](L2tpIpsec/L2tpIpsecConnection.cs#L376-L450).
- **Teardown:** `DisconnectAsync` hủy reconnect, gửi L2TP CDN + StopCCN và IKE Delete (ESP + ISAKMP), rồi đóng transport — [L2tpIpsecConnection.cs:491-539](L2tpIpsec/L2tpIpsecConnection.cs#L491-L539).
- **Facade ổn định:** `SwappablePacketChannel` ([SwappablePacketChannel](../TqkLibrary.Vpn.Abstractions)) cho phép tráo kênh PPP bên dưới khi reconnect mà socket trong tunnel ở tầng trên không bị đứt (nếu địa chỉ giữ nguyên).

### MS-SSTP — handshake (trong `SstpConnection.ConnectAsync`)

1. `SstpTransport.ConnectAsync`: TCP+TLS, nhận cert, `SSTP_DUPLEX_POST` HTTP handshake — [SstpTransport.cs:33-47](Sstp/SstpTransport.cs#L33-L47).
2. Gửi `CallConnectRequest` (Encapsulated Protocol = PPP) → nhận `CallConnectAck`, lấy 32-byte nonce trong Crypto Binding Req — [SstpConnection.cs:45-56](Sstp/SstpConnection.cs#L45-L56).
3. `PppEngine` chạy trên `SstpPppChannel`; khi `AuthSucceeded`: lấy HLAK + SHA-256(cert) → dựng Crypto Binding → gửi `CallConnected` — [SstpConnection.cs:58-71](Sstp/SstpConnection.cs#L58-L71).
4. `LinkUp` (IPCP đã cấp IP) ⇒ kết nối sẵn sàng; vòng lặp đọc trả lời `EchoRequest` bằng `EchoResponse` để giữ tunnel — [SstpConnection.cs:73-90](Sstp/SstpConnection.cs#L73-L90).

## Trạng thái & ghi chú

- **Đã hiện thực đầy đủ và chạy live (VPN Gate):** driver L2TP/IPsec dùng **IKEv1** (`Ipsec/Ike/V1`) với vòng đời keepalive/rekey/teardown/auto-reconnect.
- **SSTP:** handshake + crypto binding + Echo keepalive đã có; SSTP **chưa có auto-reconnect/rekey supervisor** như L2TP/IPsec (đường hầm đơn lẻ, dispose khi đứt).
- **IKEv2 (`Ipsec/Ike/V2`) đủ nhưng chưa wire:** `L2tpIpsecConnection` hiện chỉ dùng `IkeV1Client`; lớp `IpsecL2tpTransport` viết trung lập IKEv1/IKEv2 (comment "identical for IKEv1 or IKEv2" — [IpsecL2tpTransport.cs:9](L2tpIpsec/IpsecL2tpTransport.cs#L9)) nên có thể tái dùng khi wire IKEv2.
- **Phụ thuộc hành vi vào project dưới:** crypto/protocol thực sự nằm ở `Ipsec`/`L2tp`/`Ppp`/`Transport.Udp`; project này chỉ điều phối — đọc README các project đó để biết chi tiết chuẩn.
- **netstandard2.0 vs net8.0:** code tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`); dùng API BCL chung (`SslStream`, `HMACSHA256`, `Timer`) khả dụng trên cả hai target.
- **Hạn chế đã biết:**
  - UDP checksum của gói L2TP-trong-ESP gửi 0 (hợp lệ IPv4 sau NAT vì client không biết địa chỉ thật cho pseudo-header) — [UdpEncapsulation.cs:3-7](L2tpIpsec/UdpEncapsulation.cs#L3-L7).
  - SSTP chấp nhận mọi cert TLS (xác thực bằng crypto binding, không qua PKI) — [SstpTransport.cs:38-43](Sstp/SstpTransport.cs#L38-L43).
  - Mỗi connection chỉ một PPP session; `OpenSessionAsync` ném `NotSupportedException` — [L2tpIpsecVpnConnection.cs:22-23](L2tpIpsec/L2tpIpsecVpnConnection.cs#L22-L23), [SstpVpnConnection.cs:22-23](Sstp/SstpVpnConnection.cs#L22-L23).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md).
