# TqkLibrary.VpnClient.Drivers.L2tpIpsec

> Driver VPN **L2TP/IPsec**: IKEv1 PSK (Main + Quick Mode) qua NAT-T, ESP transport mode, L2TPv2, PPP/MS-CHAPv2. Đây là nơi lắp ráp toàn bộ stack giao thức thành một `IVpnConnection` hoàn chỉnh.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối control plane cho giao thức L2TP/IPsec. Nó lấy các khối giao thức rời rạc (IKE, ESP, L2TP, PPP, NAT-T transport) và **lắp ráp chúng thành một đường hầm hoàn chỉnh**, rồi bọc lại sau interface trung lập `IVpnConnection` để tầng `TqkLibrary.VpnClient` ở trên tiêu thụ mà không cần biết giao thức cụ thể.

Driver L2TP/IPsec ([L2tpIpsecDriver.cs:8](L2tpIpsecDriver.cs#L8)) gồm: IKEv1 PSK (Main Mode + Quick Mode) qua NAT-T (UDP 500→4500), ESP transport mode làm data plane, L2TPv2 trên UDP/1701, và PPP/MS-CHAPv2 để nhận IP. Kèm **vòng đời đầy đủ**: keepalive (L2TP HELLO + IKE DPD), rekey ESP CHILD SA **và ISAKMP SA in-place** (make-before-break), teardown sạch (IKE Delete + L2TP CDN/StopCCN), và auto-reconnect (exponential backoff) sau một facade kênh ổn định.

Vấn đề được giải quyết: tách phần "biết cách nói chuyện với gateway L2TP/IPsec" ra khỏi phần "biết cách dùng đường hầm" (sockets/IP stack ở trên), nhờ đảo ngược phụ thuộc qua `IVpnProtocolDriver`/`IVpnConnection` trong `Abstractions`.

> Driver MS-SSTP nằm ở project anh em [TqkLibrary.VpnClient.Drivers.Sstp](../TqkLibrary.VpnClient.Drivers.Sstp). Trước đây hai driver chung một project `TqkLibrary.VpnClient.Drivers` (subfolder `L2tpIpsec/`+`Sstp/`); đã tách thành 2 project, file phẳng ở gốc, namespace giữ nguyên.

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL/TRANSPORT/CRYPTO ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, typed exception...) + **`Diagnostics`** (`VpnEventIds`/`VpnLogExtensions` — log handshake/keepalive/rekey/reconnect, Q.2).
  - [TqkLibrary.VpnClient.Ppp](../TqkLibrary.VpnClient.Ppp) — `PppEngine`, `MsChapV2Authenticator`, `IPppFrameChannel`.
  - [TqkLibrary.VpnClient.Ipsec](../TqkLibrary.VpnClient.Ipsec) — `IkeV1Client`, `EspSession`, `EspCipherSuite`, và `NatTraversalChannel` (NAT-T, ghép kênh IKE/ESP — `Ipsec/Nat`, gom từ project cũ `Transport.Udp`).
  - [TqkLibrary.VpnClient.L2tp](../TqkLibrary.VpnClient.L2tp) — `L2tpClient`, `IL2tpTransport`.
  - Không có PackageReference đặc thù — chỉ dùng BCL.
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — `VpnClientBuilder.UseL2tpIpsec()` đăng ký driver này).

## Cấu trúc thư mục

> File **phẳng ở gốc project** (không còn subfolder `L2tpIpsec/`); chỉ giữ `Enums/`+`Models/`.

```
TqkLibrary.VpnClient.Drivers.L2tpIpsec/
├── L2tpIpsecDriver.cs           IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
├── L2tpIpsecConnection.cs       Bộ điều phối: handshake + keepalive + rekey + teardown + reconnect
├── IpsecL2tpTransport.cs        ESP data plane (IL2tpTransport): bọc/giải UDP-1701 trong ESP, swap SA khi rekey
├── UdpEncapsulation.cs          Build/parse UDP header (port 1701, checksum 0) cho ESP transport mode
├── L2tpPppFrameChannel.cs       Cầu nối một L2tpSession ↔ PPP engine (IPppFrameChannel)
├── L2tpIpsecReconnectOptions.cs Chính sách auto-reconnect (backoff/jitter/max attempts)
├── L2tpIpsecTimeoutOptions.cs   Timeout + retransmit (exponential backoff/jitter/cap) cho IKE + L2TP control channel
├── L2tpIpsecVpnConnection.cs    Adapter sang IVpnConnection (một hoặc nhiều session — OpenSessionAsync)
├── L2tpIpsecVpnSession.cs       IVpnSession: facade ổn định + áp dụng reconnect vào TunnelConfig
├── Enums/                       L2tpIpsecConnectionState · L2tpIpsecNatTraversalMode (ForcedNatT/HonestFirst)
└── Models/                      L2tpIpsecReconnectInfo (địa chỉ mới + cờ AddressChanged) · L2tpIpsecAdditionalSession (kênh/địa chỉ session phụ)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `L2tpIpsecDriver` | `IVpnProtocolDriver`: khai báo capabilities, `ConnectAsync` dựng `L2tpIpsecConnection` → trả `IVpnConnection`; wire `Reconnected`→`ApplyReconnect` | [L2tpIpsecDriver.cs:8](L2tpIpsecDriver.cs#L8) |
| `L2tpIpsecConnection` | Bộ điều phối control plane: chạy handshake IKE/L2TP/PPP, keepalive, rekey, teardown, supervisor reconnect; `OpenAdditionalSessionAsync` mở session L2TP phụ + PPP riêng (P1.7); ctor nhận `AddressFamilyPreference` + `IHostResolver` (outer IPv6, P1.2 — `ResolveAsync` chọn họ IP server) + `ILoggerFactory?` (Diagnostics Q.2, null ⇒ no-op) | [L2tpIpsecConnection.cs:29](L2tpIpsecConnection.cs#L29) |
| `IpsecL2tpTransport` | `IL2tpTransport`: ESP **transport mode** data plane — bọc L2TP-trong-UDP/1701-trong-ESP; kế thừa scaffolding swap/watermark từ `EspDataPlane` (dùng chung với `EspTunnelChannel` của IKEv2) | [IpsecL2tpTransport.cs:11](IpsecL2tpTransport.cs#L11) · [EspDataPlane.cs:12](../TqkLibrary.VpnClient.Ipsec/Esp/EspDataPlane.cs#L12) |
| `UdpEncapsulation` | Build/parse UDP header (1701, checksum 0) mà ESP transport mode bảo vệ | [UdpEncapsulation.cs:8](UdpEncapsulation.cs#L8) |
| `L2tpPppFrameChannel` | `IPppFrameChannel`: PPP frame của **một** `L2tpSession` đi trong L2TP data message | [L2tpPppFrameChannel.cs:7](L2tpPppFrameChannel.cs#L7) |
| `L2tpIpsecReconnectOptions` | Chính sách auto-reconnect: backoff/jitter/max attempts | [L2tpIpsecReconnectOptions.cs:8](L2tpIpsecReconnectOptions.cs#L8) |
| `L2tpIpsecTimeoutOptions` | Timeout cấu hình được: IKE retransmit interval/số lần + **exponential backoff** (`IkeBackoffMultiplier`/`IkeMaxRetransmitInterval`, `IkeIntervalFor`) cho `ExchangeIkeAsync`/`ExchangeRekeyAsync`; L2TP control-channel retransmit interval/cap + backoff (`BuildL2tpRetransmitOptions`); jitter chung `RetransmitJitterFraction` | [L2tpIpsecTimeoutOptions.cs:8](L2tpIpsecTimeoutOptions.cs#L8) |
| `L2tpIpsecVpnConnection` | Adapter `IVpnConnection`: session chính + `OpenSessionAsync` mở session phụ (P1.7, best-effort) qua `OpenAdditionalSessionAsync` | [L2tpIpsecVpnConnection.cs:7](L2tpIpsecVpnConnection.cs#L7) |
| `L2tpIpsecVpnSession` | `IVpnSession`: facade ổn định + `ApplyReconnect` cập nhật `TunnelConfig` | [L2tpIpsecVpnSession.cs:10](L2tpIpsecVpnSession.cs#L10) |
| `L2tpIpsecAdditionalSession` | Kết quả `OpenAdditionalSessionAsync`: `PacketChannel` + địa chỉ/DNS của session phụ | [Models/L2tpIpsecAdditionalSession.cs:11](Models/L2tpIpsecAdditionalSession.cs#L11) |
| `L2tpIpsecConnectionState` | Enum trạng thái vòng đời | [Enums/L2tpIpsecConnectionState.cs:4](Enums/L2tpIpsecConnectionState.cs#L4) |
| `L2tpIpsecNatTraversalMode` | Enum chọn cách thương lượng NAT-T: `ForcedNatT` (mặc định, ép float 4500) / `HonestFirst` (P0.8b — bind cổng 500 thật + NAT-D trung thực) | [Enums/L2tpIpsecNatTraversalMode.cs:6](Enums/L2tpIpsecNatTraversalMode.cs#L6) |
| `L2tpIpsecReconnectInfo` | Kết quả reconnect: địa chỉ mới + `AddressChanged` | [Models/L2tpIpsecReconnectInfo.cs:6](Models/L2tpIpsecReconnectInfo.cs#L6) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|-------------------------|--------------------|---------|
| RFC 3706 (IKE DPD — Dead Peer Detection) | `L2tpIpsecConnection` (keepalive: L2TP HELLO + IKE DPD) | [L2tpIpsecConnection.cs:484](L2tpIpsecConnection.cs#L484) | Comment dẫn rõ `RFC 3706` |
| RFC 2759 (MS-CHAPv2) | `MsChapV2Authenticator` (dùng từ `Ppp`) | [L2tpIpsecConnection.cs:231](L2tpIpsecConnection.cs#L231) | (suy luận) — hiện thực nằm ở project `Ppp` |
| RFC 2409 (IKEv1 Main/Quick Mode, PSK) | `IkeV1Client` (từ `Ipsec`), điều phối tại đây; rekey Phase 1 in-place qua `RekeyPhase1Async` (P1.3) | [L2tpIpsecConnection.cs:273](L2tpIpsecConnection.cs#L273) | (suy luận) — hiện thực nằm ở `Ipsec/Ike/V1` |
| RFC 3947 / 3948 (IPsec NAT-T, UDP 500↔4500) | `NatTraversalChannel` (`Ipsec/Nat`); `BringUpPhase1Async` chọn forced (khai man) / honest-first (`IkeV1Client.DetectNat`) rồi `SwitchToNatTPort()` | [L2tpIpsecConnection.cs:273-321](L2tpIpsecConnection.cs#L273-L321) | (suy luận) — hiện thực ở [`Ipsec/Nat`](../TqkLibrary.VpnClient.Ipsec/Nat) |
| RFC 4303 (ESP), AES-CBC + HMAC-SHA1 / AES-GCM | `IpsecL2tpTransport`, `EspSession`; `BuildEspSession` dựng suite theo `ike.NegotiatedEsp` (CBC hoặc GCM) qua `EspSuiteSelection.BuildSuite` | [L2tpIpsecConnection.cs:218](L2tpIpsecConnection.cs#L218) | (suy luận) — cipher suite hiện thực ở `Ipsec/Esp` |
| RFC 4106 (AES-GCM trong ESP) | `EspGcmSuite` (từ `Ipsec`), chọn khi gateway negotiate AES-GCM ở Quick Mode | [L2tpIpsecConnection.cs:218](L2tpIpsecConnection.cs#L218) | (suy luận) — VPN Gate/SoftEther vẫn chọn CBC |
| RFC 2661 (L2TPv2 control/data, multi-session) | `L2tpClient` (từ `L2tp`), điều phối qua `IpsecL2tpTransport`; `OpenAdditionalSessionAsync` mở session phụ | [L2tpIpsecConnection.cs:223](L2tpIpsecConnection.cs#L223) | (suy luận) — hiện thực ở `L2tp` |
| RFC 1661 / 1332 (PPP LCP + IPCP) | `PppEngine` (từ `Ppp`) | [L2tpIpsecConnection.cs:232](L2tpIpsecConnection.cs#L232) | (suy luận) — hiện thực ở `Ppp` |

> Lưu ý: project này là tầng **điều phối** — phần lớn chuẩn crypto/protocol được **hiện thực** ở các project dưới (`Ipsec` — gồm cả NAT-T `Nat/`, `L2tp`, `Ppp`, `Crypto`); ở đây chỉ **lắp ráp và gọi**. Chuẩn được hiện thực trực tiếp trong project này là phần keepalive DPD (RFC 3706), rekey/teardown điều phối, và ESP-in-UDP encapsulation.

## API / cách dùng

Điểm vào công khai là driver `L2tpIpsecDriver` (`IVpnProtocolDriver`). Thông thường tầng `TqkLibrary.VpnClient` (`VpnClientBuilder.UseL2tpIpsec()`) đăng ký driver và gọi `ConnectAsync`; có thể dùng trực tiếp:

```csharp
// L2TP/IPsec — auto-reconnect bật mặc định
var driver = new L2tpIpsecDriver(); // hoặc new L2tpIpsecDriver(new L2tpIpsecReconnectOptions { Enabled = false })
IVpnConnection conn = await driver.ConnectAsync(
    new VpnEndpoint("vpn.example.com", 0),
    new VpnCredentials { Username = "user", Password = "pass", PreSharedKey = Encoding.ASCII.GetBytes("vpn") }); // PSK bắt buộc (P0.4)

IVpnSession session = conn.Sessions[0];
IPacketChannel channel = session.PacketChannel;   // kênh L3 ổn định, sống qua reconnect
IPAddress myIp = session.Config.AssignedAddress;
await conn.DisposeAsync();                          // teardown sạch: IKE Delete + L2TP CDN/StopCCN
```

**PSK bắt buộc (P0.4):** driver **không** nhét PSK mặc định — `VpnCredentials.PreSharedKey` null/rỗng ⇒ ném `ArgumentException` ngay trước khi mở mạng ([L2tpIpsecDriver.cs:41-45](L2tpIpsecDriver.cs#L41-L45)). Default credential đặc thù VPN Gate (group PSK `"vpn"`) **không** thuộc lib chung; caller (vd demo) tự cấp.

Class hạ tầng `L2tpIpsecConnection` cũng public nếu cần điều khiển chi tiết (sự kiện `StateChanged`/`Reconnected`, `DisconnectAsync`...). Lỗi kết nối ném typed exception (`VpnAuthenticationException` / `VpnServerRejectedException` / `VpnNetworkTimeoutException` — đều kế thừa `VpnConnectionException`).

**Timeout cấu hình được:** truyền `L2tpIpsecTimeoutOptions` (ctor driver/connection hoặc `VpnClientBuilder.UseL2tpIpsec(reconnect, timeout)`) để chỉnh số lần/khoảng retransmit IKE (`IkeMaxAttempts`/`IkeRetransmitInterval`, mặc định 5×2.5s) và L2TP control channel (`L2tpMaxRetransmits`/`L2tpRetransmitInterval`, mặc định 8×1s). IKE hết số lần ⇒ `VpnNetworkTimeoutException` (**phân loại theo cổng — P0.8a**: im lặng sau float UDP/4500 ⇒ thông điệp nghi forced-NAT-T); gateway trả NOTIFY lỗi handshake ⇒ `VpnServerRejectedException`; L2TP hết cap ⇒ link-loss → reconnect. **Chế độ NAT-T:** `natTraversalMode` (ctor driver/connection) — `ForcedNatT` (mặc định, ép float 4500) hoặc `HonestFirst` (**P0.8b** — bind cổng 500 thật + NAT-D trung thực, tự fallback forced khi không bind được/no-NAT).

## Luồng nội bộ

### Handshake (trong `EstablishAsync` — clean-slate, dùng chung cho connect đầu và mọi reconnect)

1. Resolve host qua `IHostResolver` theo `AddressFamilyPreference` (P1.2 — ưu tiên họ IP config, fallback họ còn lại; thay filter cứng IPv4 cũ) → `StartAttemptChannel` tạo `NatTraversalChannel` (UDP/500, **bind đúng họ địa chỉ server**) + chạy `ReceiveLoopAsync` ghép kênh IKE/ESP — [L2tpIpsecConnection.cs:326](L2tpIpsecConnection.cs#L326). Trước đó `CleanupAttemptResourcesAsync` dọn attempt cũ: cancel vòng đọc, null `_natt` rồi **await** `DisposeAsync` (socket cũ đóng hẳn trước khi mở socket mới) — [L2tpIpsecConnection.cs:350-387](L2tpIpsecConnection.cs#L350-L387); vòng đọc còn **guard sau mỗi `ReceiveAsync`** (re-check token + identity channel) để gói stale đang in-flight không lọt vào waiter của attempt mới — [L2tpIpsecConnection.cs:454](L2tpIpsecConnection.cs#L454).
2. **IKEv1 Phase 1 (MM1–MM4) + quyết định cổng NAT-T** trong `BringUpPhase1Async` theo `L2tpIpsecNatTraversalMode` (mặc định `ForcedNatT`) — [L2tpIpsecConnection.cs:273-321](L2tpIpsecConnection.cs#L273-L321):
   - **ForcedNatT** (đường live đang chạy): cổng nguồn ephemeral, NAT-D **khai man** nguồn = `(Any, 500)` ⇒ ép gateway thấy NAT ⇒ **luôn** `SwitchToNatTPort()` sang 4500.
   - **HonestFirst** (opt-in **P0.8b**): thử-bind cổng nguồn **500 thật** (bind fail, vd Windows IKEEXT ⇒ fallback forced), NAT-D **trung thực**, rồi `IkeV1Client.DetectNat` đọc verdict gateway — `ShouldFloatToNatT` ⇒ float 4500; no-NAT (gateway muốn native ESP, **chưa làm** — P0.8c) ⇒ teardown rồi **fallback forced**.
3. **MM5/MM6** (đã mã hoá) trên cổng Phase 1 đã chốt, xác thực PSK qua `HASH_R`; sai PSK ⇒ `VpnAuthenticationException` — [L2tpIpsecConnection.cs:202-206](L2tpIpsecConnection.cs#L202-L206).
4. **Phase 2 (Quick Mode)** QM1–QM3 → khoá ESP CHILD SA + `NegotiatedEsp` (suite server chọn: AES-CBC mặc định, hoặc AES-GCM nếu gateway hỗ trợ); HASH(2) sai/không có SA ⇒ `VpnServerRejectedException` — [L2tpIpsecConnection.cs:210-216](L2tpIpsecConnection.cs#L210-L216). **Phân loại lỗi handshake (P0.8a)** ở [`ExchangeIkeAsync` :390](L2tpIpsecConnection.cs#L390): reply là NOTIFY lỗi (`IkeV1Client.TryReadRejectNotify`) ⇒ `VpnServerRejectedException` nêu mã; **no-response theo cổng** — im lặng sau float UDP/4500 ⇒ `VpnNetworkTimeoutException` chỉ rõ **nghi forced-NAT-T**, trên cổng 500 ⇒ "host unreachable/UDP blocked".
5. Dựng `EspSession` + `IpsecL2tpTransport` (data plane) — `BuildEspSession(ike.NegotiatedEsp, …)` chọn đúng cipher suite; `L2tpClient.ConnectAsync` (L2TP tunnel + session chính `PrimarySession`); `L2tpPppFrameChannel(l2tp.PrimarySession)` + `PppEngine` + `MsChapV2Authenticator` chạy LCP/Auth/IPCP (auth fail ⇒ `VpnAuthenticationException`) — [L2tpIpsecConnection.cs:218-238](L2tpIpsecConnection.cs#L218-L238).
6. Khi `LinkUp`: (nếu bật IPv6) `AwaitIpv6GraceAsync` chờ ngắn 2s cho IPV6CP mở để lộ link-local `fe80::/64` vào `TunnelConfig.AssignedAddressV6` (best-effort, không fail nếu server không có IPV6CP) → cắm kênh PPP vào facade `SwappablePacketChannel` và bật keepalive — [L2tpIpsecConnection.cs:252-253](L2tpIpsecConnection.cs#L252-L253), [AwaitIpv6GraceAsync @ :259](L2tpIpsecConnection.cs#L259).

### Keepalive · rekey · teardown · reconnect

- **Keepalive:** L2TP HELLO (60s) + IKE DPD R-U-THERE (20s, miss ≥3 ⇒ link lost) — [L2tpIpsecConnection.cs:484-575](L2tpIpsecConnection.cs#L484-L575).
- **Rekey Phase 2 (make-before-break) — 2 trigger:** (a) timer ~90% lifetime (3600s); (b) **sequence-exhaustion** — sequence ESP outbound chạm high-watermark ~75%×2³² thì `RekeyNeeded` kích rekey **trước khi** wrap (RFC 4303 §3.3.3, tránh `OverflowException`). Cả hai vào `RekeyPhase2Async` (guard `_rekeyInProgress`) → Quick Mode mới → `SwapSession` (gửi trên SA mới ngay + re-arm watermark, giữ SA cũ để nhận trong grace 10s rồi `DropPreviousInbound`) — [L2tpIpsecConnection.cs:581-602](L2tpIpsecConnection.cs#L581-L602) · [EspDataPlane.cs:41-101](../TqkLibrary.VpnClient.Ipsec/Esp/EspDataPlane.cs#L41-L101) (scaffolding swap/watermark dùng chung, tách khỏi `IpsecL2tpTransport`).
- **Rekey Phase 1 in-place (make-before-break, P1.3):** timer ~90% Phase 1 (8h) vào `RekeyPhase1Async` — dựng **ISAKMP SA mới hoàn toàn** (Main Mode đầy đủ, cookie/DH/SKEYID\* mới) trên cùng kênh UDP/4500 đã float, Quick Mode dưới SA mới → ESP CHILD SA mới, `SwapSession` (tái dùng y hệt rekey Phase 2), Delete ISAKMP SA cũ, rồi swing `_ike` sang SA mới. Reply rekey tách khỏi DPD SA cũ trên cùng socket nhờ cookie SA mới (`IkeV1Client.IsForThisSa` → `_phase1RekeyWaiter`); chung guard `_rekeyInProgress` với rekey Phase 2; rekey lỗi ⇒ giữ SA cũ + retry 2 phút trong biên trước hạn cứng. Không rớt tunnel suốt rekey — [L2tpIpsecConnection.cs:640-718](L2tpIpsecConnection.cs#L640-L718).
- **Multi-session (P1.7, best-effort):** `OpenAdditionalSessionAsync` mở thêm session L2TP (`L2tpClient.OpenSessionAsync`) trên cùng IKE/IPsec SA + control channel rồi chạy một `PppEngine` riêng → địa chỉ/kênh thứ hai; teardown gửi CDN cho mọi session phụ trước CDN/StopCCN session chính. Đa số server từ chối ICRQ thứ hai bằng CDN (⇒ exception); session phụ **không** được tái lập khi auto-reconnect (cleanup xóa `_extraSessions`) — [L2tpIpsecConnection.cs:154-174](L2tpIpsecConnection.cs#L154-L174).
- **Link-loss + supervisor:** mọi nguồn (DPD chết, server Delete, L2TP teardown) gọi `OnLinkLost` → khởi động `ReconnectLoopAsync` với exponential backoff + jitter; thành công thì raise `Reconnected` (cập nhật `TunnelConfig` qua `L2tpIpsecVpnSession.ApplyReconnect`) — [L2tpIpsecConnection.cs:728-804](L2tpIpsecConnection.cs#L728-L804).
- **Teardown:** `DisconnectAsync` hủy reconnect, gửi L2TP CDN + StopCCN và IKE Delete (ESP + ISAKMP), rồi đóng transport — [L2tpIpsecConnection.cs:847-899](L2tpIpsecConnection.cs#L847-L899).
- **Logging/diagnostics (Q.2):** ctor `L2tpIpsecConnection`/`L2tpIpsecDriver` nhận `ILoggerFactory?` (mặc định [`NullLogger`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs) ⇒ no-op, **ADDITIVE không đổi hành vi**). Log qua [`VpnLogExtensions`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs): Phase 1 (MM/auth) + Quick Mode + L2TP + PPP auth-success → Handshake (auth/QM fail → HandshakeFailed); bind facade → HandshakeCompleted; L2TP HELLO + IKE DPD → Keepalive; rekey Phase 2/Phase 1 → Rekey; `SetState` → StateChanged; `OnLinkLost` → LinkLost; reconnect attempt/success → ReconnectAttempt/Reconnected.
- **Facade ổn định:** `SwappablePacketChannel` ([từ Abstractions](../TqkLibrary.VpnClient.Abstractions)) cho phép tráo kênh PPP bên dưới khi reconnect mà socket trong tunnel ở tầng trên không bị đứt (nếu địa chỉ giữ nguyên).

## Trạng thái & ghi chú

- **Đã hiện thực đầy đủ và chạy live (VPN Gate):** driver L2TP/IPsec dùng **IKEv1** (`Ipsec/Ike/V1`) với vòng đời keepalive/rekey/teardown/auto-reconnect.
- **Logging/diagnostics (Q.2) đã có:** luồng `ILoggerFactory?` qua driver/connection → trace handshake (Phase 1/Quick Mode/L2TP/PPP)/HandshakeCompleted/keepalive/rekey/state/link-lost/reconnect (xem mục Keepalive·rekey·teardown·reconnect); mặc định no-op, không đổi hành vi runtime.
- **IKEv2 (`Ipsec/Ike/V2`) đủ nhưng chưa wire:** `L2tpIpsecConnection` hiện chỉ dùng `IkeV1Client`; lớp `IpsecL2tpTransport` viết trung lập IKEv1/IKEv2 (comment "identical for IKEv1 or IKEv2" — [IpsecL2tpTransport.cs:9](IpsecL2tpTransport.cs#L9)) nên có thể tái dùng khi wire IKEv2.
- **Phụ thuộc hành vi vào project dưới:** crypto/protocol thực sự nằm ở `Ipsec` (gồm NAT-T `Nat/`)/`L2tp`/`Ppp`; project này chỉ điều phối — đọc README các project đó để biết chi tiết chuẩn.
- **netstandard2.0 vs net8.0:** `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`); dùng API BCL chung khả dụng trên cả hai target.
- **Hạn chế đã biết:**
  - UDP checksum của gói L2TP-trong-ESP gửi 0 (hợp lệ IPv4 sau NAT vì client không biết địa chỉ thật cho pseudo-header) — [UdpEncapsulation.cs:4-6](UdpEncapsulation.cs#L4-L6).
  - `OpenSessionAsync` mở session PPP phụ trên cùng tunnel (P1.7) — **best-effort**: đa số server remote-access chỉ cho một session và từ chối bằng CDN; session phụ không sống qua auto-reconnect — [L2tpIpsecVpnConnection.cs:32](L2tpIpsecVpnConnection.cs#L32).
  - **NAT-T:** mặc định **ForcedNatT** (client luôn float UDP/4500, ESP-in-UDP — đường live). Opt-in **HonestFirst** (**P0.8b** đã làm): bind cổng 500 thật + NAT-D trung thực + `IkeV1Client.DetectNat` → sau-NAT thì float như cũ, no-NAT thì hiện **fallback forced** (native ESP proto-50 — (c)/`Transport.RawIp`/F.9 — **chưa làm**). Gateway từ chối forced-NAT-T **được phân loại** (P0.8a, flow bước 4). Cả 2 mode cần **lab Docker** kiểm chứng từng gateway ⇒ mặc định live chưa đổi (roadmap P0.8c).
  - **IPv6-in-tunnel (P1.1, opt-in `L2tpIpsecDriver(enableIpv6: true)` / `L2tpIpsecConnection(enableIpv6: true)`):** chạy IPV6CP song song IPCP → link-local `fe80::/64` đẩy lên `TunnelConfig.AssignedAddressV6`; PPP multiplex cả hai họ trên một `IPacketChannel` (xem [README Ppp](../TqkLibrary.VpnClient.Ppp/README-vi.md)) và `CreateTcpStack` dựng stack dual-stack khi có v6. **Mặc định tắt** (không đổi hành vi IPv4). **Chưa**: địa chỉ IPv6 **global** (cần SLAAC/RA — L2.4) nên link-local chưa định tuyến ra ngoài; **chưa test live** (đa số server VPN Gate chỉ cấp IPv4 — cần lab Q.1).

> Quick Mode QM2 nay **xác thực HASH(2)** của responder (`IkeV1Client.ProcessQuickMode2`/`ProcessRekeyQuickMode2`, RFC 2409 §5.5) — sai ⇒ `VpnServerRejectedException` (handshake chính) / giữ SA cũ (rekey). Chi tiết ở README project `Ipsec`.

> Tài liệu as-built tổng thể: [.docs/10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md) §6/§6.1 · roadmap: [.docs/11-todo-roadmap.md](../../.docs/11-todo-roadmap.md).
