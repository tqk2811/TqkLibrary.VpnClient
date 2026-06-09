# TqkLibrary.Vpn.Drivers.L2tpIpsec

> Driver VPN **L2TP/IPsec**: IKEv1 PSK (Main + Quick Mode) qua NAT-T, ESP transport mode, L2TPv2, PPP/MS-CHAPv2. Đây là nơi lắp ráp toàn bộ stack giao thức thành một `IVpnConnection` hoàn chỉnh.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối control plane cho giao thức L2TP/IPsec. Nó lấy các khối giao thức rời rạc (IKE, ESP, L2TP, PPP, NAT-T transport) và **lắp ráp chúng thành một đường hầm hoàn chỉnh**, rồi bọc lại sau interface trung lập `IVpnConnection` để tầng `TqkLibrary.Vpn` ở trên tiêu thụ mà không cần biết giao thức cụ thể.

Driver L2TP/IPsec ([L2tpIpsecDriver.cs:9](L2tpIpsecDriver.cs#L9)) gồm: IKEv1 PSK (Main Mode + Quick Mode) qua NAT-T (UDP 500→4500), ESP transport mode làm data plane, L2TPv2 trên UDP/1701, và PPP/MS-CHAPv2 để nhận IP. Kèm **vòng đời đầy đủ**: keepalive (L2TP HELLO + IKE DPD), rekey ESP CHILD SA (make-before-break), teardown sạch (IKE Delete + L2TP CDN/StopCCN), và auto-reconnect (exponential backoff) sau một facade kênh ổn định.

Vấn đề được giải quyết: tách phần "biết cách nói chuyện với gateway L2TP/IPsec" ra khỏi phần "biết cách dùng đường hầm" (sockets/IP stack ở trên), nhờ đảo ngược phụ thuộc qua `IVpnProtocolDriver`/`IVpnConnection` trong `Abstractions`.

> Driver MS-SSTP nằm ở project anh em [TqkLibrary.Vpn.Drivers.Sstp](../TqkLibrary.Vpn.Drivers.Sstp). Trước đây hai driver chung một project `TqkLibrary.Vpn.Drivers` (subfolder `L2tpIpsec/`+`Sstp/`); đã tách thành 2 project, file phẳng ở gốc, namespace giữ nguyên.

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.Vpn` ở trên và các project PROTOCOL/TRANSPORT/CRYPTO ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.Vpn.Abstractions](../TqkLibrary.Vpn.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, typed exception...).
  - [TqkLibrary.Vpn.Ppp](../TqkLibrary.Vpn.Ppp) — `PppEngine`, `MsChapV2Authenticator`, `IPppFrameChannel`.
  - [TqkLibrary.Vpn.Transport.Udp](../TqkLibrary.Vpn.Transport.Udp) — `NatTraversalChannel` (NAT-T, ghép kênh IKE/ESP).
  - [TqkLibrary.Vpn.Ipsec](../TqkLibrary.Vpn.Ipsec) — `IkeV1Client`, `EspSession`, `EspCipherSuite`.
  - [TqkLibrary.Vpn.L2tp](../TqkLibrary.Vpn.L2tp) — `L2tpClient`, `IL2tpTransport`.
  - Không có PackageReference đặc thù — chỉ dùng BCL.
- **Được dùng bởi:** [TqkLibrary.Vpn](../TqkLibrary.Vpn) (entry point — `VpnClientBuilder.UseL2tpIpsec()` đăng ký driver này).

## Cấu trúc thư mục

> File **phẳng ở gốc project** (không còn subfolder `L2tpIpsec/`); chỉ giữ `Enums/`+`Models/`.

```
TqkLibrary.Vpn.Drivers.L2tpIpsec/
├── L2tpIpsecDriver.cs           IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
├── L2tpIpsecConnection.cs       Bộ điều phối: handshake + keepalive + rekey + teardown + reconnect
├── IpsecL2tpTransport.cs        ESP data plane (IL2tpTransport): bọc/giải UDP-1701 trong ESP, swap SA khi rekey
├── UdpEncapsulation.cs          Build/parse UDP header (port 1701, checksum 0) cho ESP transport mode
├── L2tpPppFrameChannel.cs       Cầu nối L2TP data ↔ PPP engine (IPppFrameChannel)
├── L2tpIpsecReconnectOptions.cs Chính sách auto-reconnect (backoff/jitter/max attempts)
├── L2tpIpsecTimeoutOptions.cs   Timeout/retransmit cap cho IKE + L2TP control channel
├── L2tpIpsecVpnConnection.cs    Adapter sang IVpnConnection (một session)
├── L2tpIpsecVpnSession.cs       IVpnSession: facade ổn định + áp dụng reconnect vào TunnelConfig
├── Enums/                       L2tpIpsecConnectionState (Disconnected/Connecting/Connected/Reconnecting)
└── Models/                      L2tpIpsecReconnectInfo (địa chỉ mới + cờ AddressChanged)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `L2tpIpsecDriver` | `IVpnProtocolDriver`: khai báo capabilities, `ConnectAsync` dựng `L2tpIpsecConnection` → trả `IVpnConnection`; wire `Reconnected`→`ApplyReconnect` | [L2tpIpsecDriver.cs:9](L2tpIpsecDriver.cs#L9) |
| `L2tpIpsecConnection` | Bộ điều phối control plane: chạy handshake IKE/L2TP/PPP, keepalive, rekey, teardown, supervisor reconnect | [L2tpIpsecConnection.cs:25](L2tpIpsecConnection.cs#L25) |
| `IpsecL2tpTransport` | `IL2tpTransport`: ESP data plane — bọc L2TP-trong-UDP/1701-trong-ESP; giữ SA cũ tạm thời khi rekey | [IpsecL2tpTransport.cs:11](IpsecL2tpTransport.cs#L11) |
| `UdpEncapsulation` | Build/parse UDP header (1701, checksum 0) mà ESP transport mode bảo vệ | [UdpEncapsulation.cs:8](UdpEncapsulation.cs#L8) |
| `L2tpPppFrameChannel` | `IPppFrameChannel`: PPP frame đi trong L2TP data message | [L2tpPppFrameChannel.cs:7](L2tpPppFrameChannel.cs#L7) |
| `L2tpIpsecReconnectOptions` | Chính sách auto-reconnect: backoff/jitter/max attempts | [L2tpIpsecReconnectOptions.cs:8](L2tpIpsecReconnectOptions.cs#L8) |
| `L2tpIpsecTimeoutOptions` | Timeout cấu hình được: IKE retransmit interval/số lần (`ExchangeIkeAsync`/`ExchangeRekeyAsync`) + L2TP control-channel retransmit interval/cap | [L2tpIpsecTimeoutOptions.cs:8](L2tpIpsecTimeoutOptions.cs#L8) |
| `L2tpIpsecVpnConnection` | Adapter `IVpnConnection` (một PPP session/tunnel) | [L2tpIpsecVpnConnection.cs:6](L2tpIpsecVpnConnection.cs#L6) |
| `L2tpIpsecVpnSession` | `IVpnSession`: facade ổn định + `ApplyReconnect` cập nhật `TunnelConfig` | [L2tpIpsecVpnSession.cs:10](L2tpIpsecVpnSession.cs#L10) |
| `L2tpIpsecConnectionState` | Enum trạng thái vòng đời | [Enums/L2tpIpsecConnectionState.cs:4](Enums/L2tpIpsecConnectionState.cs#L4) |
| `L2tpIpsecReconnectInfo` | Kết quả reconnect: địa chỉ mới + `AddressChanged` | [Models/L2tpIpsecReconnectInfo.cs:6](Models/L2tpIpsecReconnectInfo.cs#L6) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|-------------------------|--------------------|---------|
| RFC 3706 (IKE DPD — Dead Peer Detection) | `L2tpIpsecConnection` (keepalive: L2TP HELLO + IKE DPD) | [L2tpIpsecConnection.cs:258](L2tpIpsecConnection.cs#L258) | Comment dẫn rõ `RFC 3706` |
| RFC 2759 (MS-CHAPv2) | `MsChapV2Authenticator` (dùng từ `Ppp`) | [L2tpIpsecConnection.cs:166](L2tpIpsecConnection.cs#L166) | (suy luận) — hiện thực nằm ở project `Ppp` |
| RFC 2409 (IKEv1 Main/Quick Mode, PSK) | `IkeV1Client` (từ `Ipsec`), điều phối tại đây | [L2tpIpsecConnection.cs:136](L2tpIpsecConnection.cs#L136) | (suy luận) — hiện thực nằm ở `Ipsec/Ike/V1` |
| RFC 3947 / 3948 (IPsec NAT-T, UDP 500↔4500) | `NatTraversalChannel` (từ `Transport.Udp`), `natt.SwitchToNatTPort()` | [L2tpIpsecConnection.cs:144](L2tpIpsecConnection.cs#L144) | (suy luận) — hiện thực ở `Transport.Udp` |
| RFC 4303 (ESP), AES-CBC + HMAC-SHA1 | `IpsecL2tpTransport`, `EspSession`/`EspCipherSuite.AesCbcHmacSha1` (từ `Ipsec`) | [L2tpIpsecConnection.cs:207-208](L2tpIpsecConnection.cs#L207-L208) | (suy luận) — cipher suite hiện thực ở `Ipsec/Esp` |
| RFC 2661 (L2TPv2 control/data) | `L2tpClient` (từ `L2tp`), điều phối qua `IpsecL2tpTransport` | [L2tpIpsecConnection.cs:159](L2tpIpsecConnection.cs#L159) | (suy luận) — hiện thực ở `L2tp` |
| RFC 1661 / 1332 (PPP LCP + IPCP) | `PppEngine` (từ `Ppp`) | [L2tpIpsecConnection.cs:167](L2tpIpsecConnection.cs#L167) | (suy luận) — hiện thực ở `Ppp` |

> Lưu ý: project này là tầng **điều phối** — phần lớn chuẩn crypto/protocol được **hiện thực** ở các project dưới (`Ipsec`, `L2tp`, `Ppp`, `Transport.Udp`, `Crypto`); ở đây chỉ **lắp ráp và gọi**. Chuẩn được hiện thực trực tiếp trong project này là phần keepalive DPD (RFC 3706), rekey/teardown điều phối, và ESP-in-UDP encapsulation.

## API / cách dùng

Điểm vào công khai là driver `L2tpIpsecDriver` (`IVpnProtocolDriver`). Thông thường tầng `TqkLibrary.Vpn` (`VpnClientBuilder.UseL2tpIpsec()`) đăng ký driver và gọi `ConnectAsync`; có thể dùng trực tiếp:

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
```

Class hạ tầng `L2tpIpsecConnection` cũng public nếu cần điều khiển chi tiết (sự kiện `StateChanged`/`Reconnected`, `DisconnectAsync`...). Lỗi kết nối ném typed exception (`VpnAuthenticationException` / `VpnServerRejectedException` / `VpnNetworkTimeoutException` — đều kế thừa `VpnConnectionException`).

**Timeout cấu hình được:** truyền `L2tpIpsecTimeoutOptions` (ctor driver/connection hoặc `VpnClientBuilder.UseL2tpIpsec(reconnect, timeout)`) để chỉnh số lần/khoảng retransmit IKE (`IkeMaxAttempts`/`IkeRetransmitInterval`, mặc định 5×2.5s) và L2TP control channel (`L2tpMaxRetransmits`/`L2tpRetransmitInterval`, mặc định 8×1s). IKE hết số lần ⇒ `VpnNetworkTimeoutException`; L2TP hết cap ⇒ link-loss → reconnect.

## Luồng nội bộ

### Handshake (trong `EstablishAsync` — clean-slate, dùng chung cho connect đầu và mọi reconnect)

1. Resolve host → tạo `NatTraversalChannel` (UDP/500), chạy `ReceiveLoopAsync` ghép kênh IKE/ESP — [L2tpIpsecConnection.cs:129-134](L2tpIpsecConnection.cs#L129-L134).
2. **IKEv1 Phase 1 (Main Mode)** MM1–MM4 trên UDP/500 — [L2tpIpsecConnection.cs:140-141](L2tpIpsecConnection.cs#L140-L141).
3. Phát hiện NAT-T → `SwitchToNatTPort()` (sang UDP/4500), MM5/MM6 đã mã hoá; sai PSK ⇒ `VpnAuthenticationException` — [L2tpIpsecConnection.cs:144-146](L2tpIpsecConnection.cs#L144-L146).
4. **Phase 2 (Quick Mode)** QM1–QM3 → khoá ESP CHILD SA; không có SA ⇒ `VpnServerRejectedException`; IKE no-response ⇒ `VpnNetworkTimeoutException` — [L2tpIpsecConnection.cs:149-151](L2tpIpsecConnection.cs#L149-L151).
5. Dựng `EspSession` + `IpsecL2tpTransport` (data plane); `L2tpClient.ConnectAsync` (L2TP tunnel/session); `PppEngine` + `MsChapV2Authenticator` chạy LCP/Auth/IPCP (auth fail ⇒ `VpnAuthenticationException`) — [L2tpIpsecConnection.cs:154-175](L2tpIpsecConnection.cs#L154-L175).
6. Khi `LinkUp`: cắm kênh PPP vào facade `SwappablePacketChannel` và bật keepalive — [L2tpIpsecConnection.cs:179-180](L2tpIpsecConnection.cs#L179-L180).

### Keepalive · rekey · teardown · reconnect

- **Keepalive:** L2TP HELLO (60s) + IKE DPD R-U-THERE (20s, miss ≥3 ⇒ link lost) — [L2tpIpsecConnection.cs:260-337](L2tpIpsecConnection.cs#L260-L337).
- **Rekey (make-before-break) — 2 trigger:** (a) timer ~90% lifetime (3600s); (b) **sequence-exhaustion** — sequence ESP outbound chạm high-watermark ~75%×2³² thì `RekeyNeeded` kích rekey **trước khi** wrap (RFC 4303 §3.3.3, tránh `OverflowException`). Cả hai vào `RekeyPhase2Async` (guard `_rekeyInProgress`) → Quick Mode mới → `SwapSession` (gửi trên SA mới ngay + re-arm watermark, giữ SA cũ để nhận trong grace 10s rồi `DropPreviousInbound`) — [L2tpIpsecConnection.cs:342-386](L2tpIpsecConnection.cs#L342-L386) · [IpsecL2tpTransport.cs:54-91](IpsecL2tpTransport.cs#L54-L91).
- **Link-loss + supervisor:** mọi nguồn (DPD chết, server Delete, L2TP teardown, Phase 1 hết hạn) gọi `OnLinkLost` → khởi động `ReconnectLoopAsync` với exponential backoff + jitter; thành công thì raise `Reconnected` (cập nhật `TunnelConfig` qua `L2tpIpsecVpnSession.ApplyReconnect`) — [L2tpIpsecConnection.cs:391-457](L2tpIpsecConnection.cs#L391-L457).
- **Teardown:** `DisconnectAsync` hủy reconnect, gửi L2TP CDN + StopCCN và IKE Delete (ESP + ISAKMP), rồi đóng transport — [L2tpIpsecConnection.cs:506-554](L2tpIpsecConnection.cs#L506-L554).
- **Facade ổn định:** `SwappablePacketChannel` ([từ Abstractions](../TqkLibrary.Vpn.Abstractions)) cho phép tráo kênh PPP bên dưới khi reconnect mà socket trong tunnel ở tầng trên không bị đứt (nếu địa chỉ giữ nguyên).

## Trạng thái & ghi chú

- **Đã hiện thực đầy đủ và chạy live (VPN Gate):** driver L2TP/IPsec dùng **IKEv1** (`Ipsec/Ike/V1`) với vòng đời keepalive/rekey/teardown/auto-reconnect.
- **IKEv2 (`Ipsec/Ike/V2`) đủ nhưng chưa wire:** `L2tpIpsecConnection` hiện chỉ dùng `IkeV1Client`; lớp `IpsecL2tpTransport` viết trung lập IKEv1/IKEv2 (comment "identical for IKEv1 or IKEv2" — [IpsecL2tpTransport.cs:9](IpsecL2tpTransport.cs#L9)) nên có thể tái dùng khi wire IKEv2.
- **Phụ thuộc hành vi vào project dưới:** crypto/protocol thực sự nằm ở `Ipsec`/`L2tp`/`Ppp`/`Transport.Udp`; project này chỉ điều phối — đọc README các project đó để biết chi tiết chuẩn.
- **netstandard2.0 vs net8.0:** code tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`); dùng API BCL chung khả dụng trên cả hai target.
- **Hạn chế đã biết:**
  - UDP checksum của gói L2TP-trong-ESP gửi 0 (hợp lệ IPv4 sau NAT vì client không biết địa chỉ thật cho pseudo-header) — [UdpEncapsulation.cs:4-6](UdpEncapsulation.cs#L4-L6).
  - Mỗi connection chỉ một PPP session; `OpenSessionAsync` ném `NotSupportedException` — [L2tpIpsecVpnConnection.cs:22-23](L2tpIpsecVpnConnection.cs#L22-L23).
  - `IkeV1Client.ProcessQuickMode2` **không** xác thực HASH(2) của responder (cố ý để interop rộng — xem roadmap).

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §6/§6.1 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md).
