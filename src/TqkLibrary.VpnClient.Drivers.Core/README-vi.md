# TqkLibrary.VpnClient.Drivers.Core

**Scaffolding dùng chung cho driver** (roadmap **F.6**) — gom phần lặp lại giữa các protocol driver thành **một base class + một model policy**, để driver mới không chép lần thứ N cùng một bộ supervisor/reconnect/keepalive. Trước F.6 mỗi driver (WireGuard, OpenConnect, OpenVPN, IKEv2, SoftEther, SSTP, L2TP/IPsec) tự bê nguyên `EstablishAsync`/`ReconnectLoopAsync`/backoff-jitter/`StateChanged`/`OnLinkLost`/guard `_running`-`_userTeardown`-`_supervisorActive`/clock đơn điệu + một `XxxReconnectOptions` gần như giống hệt. Project này rút phần đó ra:

- [`ReconnectingVpnConnection`](ReconnectingVpnConnection.cs#L24) — base **abstract** (non-generic) mang toàn bộ máy supervisor; driver kế thừa và chỉ viết phần protocol riêng.
- [`VpnConnectionState`](Enums/VpnConnectionState.cs) — enum lifecycle 4 trạng thái (Disconnected/Connecting/Connected/Reconnecting) **dùng chung** mọi driver.
- [`VpnReconnectOptions`](Models/VpnReconnectOptions.cs#L14) — model policy reconnect/backoff/jitter chung; mỗi driver giữ type tên riêng (`WireGuardReconnectOptions`, …) **kế thừa** base này để không vỡ public API.

> **Tái sử dụng tối đa, không viết lại**: base **không** phát minh hành vi mới — chính là vòng lặp các driver đang chạy live, factor lại một lần. Refactor **không đổi hành vi** (toàn bộ test driver hiện có vẫn xanh).

## Vị trí kiến trúc

`DRIVER-CORE`-layer — đứng giữa [`Abstractions`](../TqkLibrary.VpnClient.Abstractions) (interface/channel/diagnostics) và các project `Drivers.*` cụ thể. **Không** chứa logic protocol nào; chỉ là khung lifecycle + policy. Driver `sealed class XxxConnection : ReconnectingVpnConnection` override 3 hook protocol (state dùng chung enum [`VpnConnectionState`](Enums/VpnConnectionState.cs) — driver không còn tự khai enum riêng).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `SwappablePacketChannel`/`IPacketChannel` (facade ổn định), **`Diagnostics`** (`VpnLogExtensions` — log state/link-lost/reconnect), `Microsoft.Extensions.Logging.Abstractions` (transitive) |
| Được dùng bởi | [Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard) | `WireGuardConnection : ReconnectingVpnConnection` (consumer F.6 #1) |
| Được dùng bởi | [Drivers.OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) | `OpenConnectConnection : ReconnectingVpnConnection` (consumer F.6 #2) |
| Được dùng bởi | [Drivers.OpenVpn](../TqkLibrary.VpnClient.Drivers.OpenVpn) | `OpenVpnConnection : ReconnectingVpnConnection` (consumer F.6 #3) |
| Được dùng bởi | [Drivers.SoftEther](../TqkLibrary.VpnClient.Drivers.SoftEther) | `SoftEtherConnection : ReconnectingVpnConnection` (consumer F.6 #4) |
| Được dùng bởi | [Drivers.Sstp](../TqkLibrary.VpnClient.Drivers.Sstp) | `SstpConnection : ReconnectingVpnConnection` (consumer F.6 #5; `SstpReconnectOptions : VpnReconnectOptions` thêm knob `ReadTimeout`) |
| Được dùng bởi | [Drivers.Ikev2](../TqkLibrary.VpnClient.Drivers.Ikev2) | `Ikev2Connection : ReconnectingVpnConnection` (consumer F.6 #6; `Ikev2ReconnectOptions : VpnReconnectOptions` không thêm knob — rekey IKE/CHILD SA + DPD + DELETE giữ ngoài supervisor) |
| Được dùng bởi | [Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) | `L2tpIpsecConnection : ReconnectingVpnConnection` (consumer F.6 #7; `L2tpIpsecReconnectOptions : VpnReconnectOptions` không thêm knob — rekey Phase1/Phase2 in-place + multi-session + DPD/HELLO giữ ngoài supervisor) |
| Được dùng bởi | [Drivers.CiscoIpsec](../TqkLibrary.VpnClient.Drivers.CiscoIpsec) | `CiscoIpsecConnection : ReconnectingVpnConnection` (`CiscoIpsecReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.Pptp](../TqkLibrary.VpnClient.Drivers.Pptp) | `PptpConnection : ReconnectingVpnConnection` (`PptpReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.Ssh](../TqkLibrary.VpnClient.Drivers.Ssh) | `SshConnection : ReconnectingVpnConnection` (`SshReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.Vtun](../TqkLibrary.VpnClient.Drivers.Vtun) | `VtunConnection : ReconnectingVpnConnection` (`VtunReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.Tinc](../TqkLibrary.VpnClient.Drivers.Tinc) | `TincConnection : ReconnectingVpnConnection` (`TincReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.N2n](../TqkLibrary.VpnClient.Drivers.N2n) | `N2nConnection : ReconnectingVpnConnection` (`N2nReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.Nebula](../TqkLibrary.VpnClient.Drivers.Nebula) | `NebulaConnection : ReconnectingVpnConnection` (`NebulaReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.Tailscale](../TqkLibrary.VpnClient.Drivers.Tailscale) | `TailscaleConnection : ReconnectingVpnConnection` (`TailscaleReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.ZeroTier](../TqkLibrary.VpnClient.Drivers.ZeroTier) | `ZeroTierConnection : ReconnectingVpnConnection` (`ZeroTierReconnectOptions : VpnReconnectOptions` không thêm knob) |
| Được dùng bởi | [Drivers.IpEncap](../TqkLibrary.VpnClient.Drivers.IpEncap) | `IpEncapConnection : ReconnectingVpnConnection` (`IpEncapReconnectOptions : VpnReconnectOptions` không thêm knob; IP-in-IP/GRE connectionless — supervisor kế thừa cho đối xứng, reconnect chỉ chạy khi caller báo link-loss) |
| Được dùng bởi | [Drivers.GreInUdp](../TqkLibrary.VpnClient.Drivers.GreInUdp) | `GreInUdpConnection : ReconnectingVpnConnection` (`GreInUdpReconnectOptions : VpnReconnectOptions` không thêm knob; GRE-in-UDP connectionless — supervisor kế thừa cho đối xứng, reconnect chỉ chạy khi caller báo link-loss) |
| Được dùng bởi | [Drivers.Vxlan](../TqkLibrary.VpnClient.Drivers.Vxlan) | `VxlanConnection : ReconnectingVpnConnection` (`VxlanReconnectOptions : VpnReconnectOptions` không thêm knob) |

> **Mọi protocol driver** (19 driver) nay đã migrate sang base (F.6 hoàn tất); chỉ `SstpReconnectOptions` thêm knob riêng (`ReadTimeout`), các driver còn lại giữ named-type rỗng để không vỡ public API.

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Core/
├─ ReconnectingVpnConnection.cs     Base abstract (non-generic): facade + lifetime CTS + state lock + supervisor (OnLinkLost/ReconnectLoopAsync/WithJitter) + SetState/StateChanged<VpnConnectionState> + clock đơn điệu + teardown; hook abstract: EstablishAsync/CleanupAttemptResourcesAsync/StopAttemptLoop + OnReconnected
├─ TunnelConfigIpv6.cs              Helper static (P1.1): ApplyGlobalIpv6(target, v6) merge fragment IPv6 global (prefix length + DNS v6 + route ::/0) vào TunnelConfig — dùng chung SSTP + L2TP/IPsec
├─ Enums/
│  └─ VpnConnectionState.cs         Enum lifecycle 4 trạng thái (Disconnected/Connecting/Connected/Reconnecting) dùng chung mọi driver
└─ Models/
   └─ VpnReconnectOptions.cs        Policy chung: Enabled/MaxAttempts/InitialBackoff/MaxBackoff/BackoffMultiplier/JitterFraction + NextBackoff(); driver kế thừa thêm knob riêng (vd SSTP ReadTimeout)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `ReconnectingVpnConnection` | Base abstract (**non-generic** — dùng chung enum `VpnConnectionState`). Sở hữu: `SwappablePacketChannel Facade`, `LifetimeToken`, lock + cờ `IsRunning`/`IsUserTeardown` + `_supervisorActive`, máy **link-loss → supervisor → reconnect-loop** (backoff mũ + ±jitter), `SetState`/`StateChanged` + log có cấu trúc, clock đơn điệu (`Now()`), teardown (`DisconnectCoreAsync`/`DisposeCoreAsync`). Hook protocol: abstract `EstablishAsync`/`CleanupAttemptResourcesAsync`/`StopAttemptLoop` + virtual `OnReconnected`. Lifecycle cho subclass gọi: `ConnectCoreAsync`/`MarkRunning`/`MarkConnected`/`OnLinkLost`. Helper khác: `WithJitter`/`NextRandomBytes`. | [ReconnectingVpnConnection.cs:24](ReconnectingVpnConnection.cs#L24) |
| `VpnConnectionState` | Enum lifecycle **dùng chung** mọi driver: `Disconnected`/`Connecting`/`Connected`/`Reconnecting`. `State` + event `StateChanged` của base dùng type này (driver không còn tự khai enum riêng). | [Enums/VpnConnectionState.cs:4](Enums/VpnConnectionState.cs#L4) |
| `VpnReconnectOptions` | Policy reconnect/backoff/jitter chung (class **không** sealed — driver kế thừa). `NextBackoff(current)` = `min(MaxBackoff, current × BackoffMultiplier)`. | [Models/VpnReconnectOptions.cs:14](Models/VpnReconnectOptions.cs#L14) |
| `TunnelConfigIpv6` | Helper static (**P1.1**): `ApplyGlobalIpv6(target, v6)` merge fragment IPv6 **global** (prefix length + DNS v6 + route `::/0`) mà driver PPP lấy được (SLAAC/DHCPv6) vào `TunnelConfig`; địa chỉ global do caller set, no-op khi chưa có global (chỉ link-local). Dùng chung SSTP + L2TP/IPsec (cả hai chạy PPP + lấy global cùng cách). | [TunnelConfigIpv6.cs:12](TunnelConfigIpv6.cs#L12) |

## Hợp đồng base ↔ subclass

Driver cụ thể chỉ cần:

1. **Kế thừa** `ReconnectingVpnConnection` (non-generic; state dùng chung enum `VpnConnectionState` — driver không còn tự khai/ánh xạ enum state), gọi `base(driverName, options, clock, loggerFactory)` ở ctor.
2. **`EstablishAsync(ct)`** — một lần thử tunnel đầy đủ: resolve/transport → handshake → bind channel sống vào `Facade.SetInner(...)` → bật timer/receive-loop → gọi `MarkConnected()`. Ném khi lỗi (supervisor backoff + retry). Mở đầu nên gọi `CleanupAttemptResourcesAsync()` để bỏ attempt dở.
3. **`CleanupAttemptResourcesAsync()`** — gỡ mọi thứ `EstablishAsync` dựng (timer, receive loop, transport, channel). Best-effort + idempotent.
4. **`StopAttemptLoop()`** — dispose timer/loop per-attempt (base đã set `IsRunning=false` quanh nó).
5. (tuỳ) **`MarkRunning()`** sớm nếu establish có cửa sổ giữa "bind xong + bật receive-loop" và "MarkConnected" mà drop có thể xảy ra (vd OpenConnect: peer-close giữa lúc handshake DTLS) — để `OnLinkLost` honour được drop đó.
6. (tuỳ) **`OnReconnected()`** raise event `Reconnected` riêng; override `DisconnectAsync` để gửi protocol-close best-effort rồi gọi `DisconnectCoreAsync()`.

## Luồng supervisor (as-built)

1. **Connect đầu** (`ConnectCoreAsync`): `SetState(Connecting)` → `EstablishAsync`. Lỗi attempt đầu **ném thẳng** ra caller (reconnect chỉ arm sau một lần thành công — `IsRunning` chỉ true sau `MarkConnected`/`MarkRunning`).
2. **Link-loss** (`OnLinkLost(reason)`) từ receive-loop/timer/fault: dưới lock — no-op nếu `!IsRunning`; nếu không thì `StopAttemptLoop` + `IsRunning=false`, rồi **hoặc** `Disconnected` (user teardown / reconnect tắt) **hoặc** arm supervisor **đúng một lần** (`_supervisorActive`).
3. **Reconnect loop** (`ReconnectLoopAsync`): `EstablishAsync` lặp; thành công → `OnReconnected()` + về; thất bại → backoff `WithJitter(NextBackoff(...))`, dừng khi `MaxAttempts` (≠0) chạm hạn hoặc `cancellationToken`.
4. **Teardown** (`DisconnectCoreAsync`): `IsUserTeardown=true`, stop loop, cancel `LifetimeToken`, await supervisor, `CleanupAttemptResourcesAsync`, `Disconnected`.

## Trạng thái & ghi chú

- **Đã có (F.6)**: base `ReconnectingVpnConnection` (non-generic) + enum dùng chung `VpnConnectionState` + `VpnReconnectOptions`; **mọi protocol driver (19) đã migrate sang base** — chứng minh hợp đồng đủ cho cả transport datagram lẫn byte-stream, cả make-before-break lẫn re-establish, cả keepalive trong timer riêng lẫn rekey ngoài supervisor. Vài pattern tiêu biểu: WireGuard (UDP/Noise, make-before-break, timer-loop riêng `_timerRunning`) + OpenConnect (TLS+DTLS/CSTP, DTLS-fallback window dùng `MarkRunning` sớm) + OpenVPN (UDP/TCP, keepalive ping/ping-restart trong timer riêng, `StopAttemptLoop` dispose timer + tắt `_dataActive`, rekey re-establish gọi `OnLinkLost`) + SoftEther (TLS byte-stream + L2 bridge, `MarkRunning` sớm trước DHCP, `OnReconnected` raise `Reconnected`) + SSTP (TLS + PPP + crypto-binding, active Echo keepalive, override `DisconnectAsync` gửi Call-Disconnect, `OnReconnected` raise `Reconnected(SstpReconnectInfo)`). Test offline [`ReconnectingVpnConnectionTests`](../../tests/TqkLibrary.VpnClient.Drivers.Core.Tests/ReconnectingVpnConnectionTests.cs) (fake driver: connect/connect-fail/reconnect/reconnect-disabled/max-attempts/teardown-mid-loop + default policy) + toàn bộ test driver cũ **vẫn xanh** (không đổi hành vi).
- **Subclass options**: chỉ `SstpReconnectOptions : VpnReconnectOptions` **thêm knob riêng (`ReadTimeout`)** — minh chứng pattern "subclass thêm knob ngoài policy chung". 18 driver còn lại (`WireGuard`/`OpenConnect`/`OpenVpn`/`SoftEther`/`Ikev2`/`L2tpIpsec`/`CiscoIpsec`/`Pptp`/`Ssh`/`Vtun`/`Tinc`/`N2n`/`Nebula`/`Tailscale`/`ZeroTier`/`IpEncap`/`GreInUdp`/`Vxlan`) giữ named-type **rỗng** (không thêm knob) chỉ để không vỡ public API.
- **Rekey/keepalive ngoài supervisor**: các driver giữ logic rekey/DPD **ngoài** vòng supervisor trên timer riêng (rekey làm tươi SA, không re-establish): **IKEv2** rekey IKE/CHILD SA in-place trên kênh SK + DPD + DELETE, `DisconnectAsync` gửi DELETE IKE SA trước teardown base; **L2TP/IPsec** (phức tạp nhất) rekey **Phase 2** (ESP CHILD SA) + **Phase 1** (ISAKMP SA) in-place make-before-break + **multi-session** L2TP + keepalive L2TP HELLO + IKE DPD trên 4 timer riêng, `StopAttemptLoop` dispose 4 timer + tắt `_espActive`, `CleanupAttemptResourcesAsync` còn xóa `_extraSessions`, `DisconnectAsync` gửi CDN/StopCCN + IKE Delete; jitter retransmit IKE giữ helper riêng (`L2tpIpsecTimeoutOptions.RetransmitJitterFraction`) — khác jitter reconnect của base.
- **Helper IPv6 (P1.1)**: `TunnelConfigIpv6.ApplyGlobalIpv6` dùng chung bởi SSTP ([`SstpDriver.cs:62`](../TqkLibrary.VpnClient.Drivers.Sstp/SstpDriver.cs#L62)) + L2TP/IPsec ([`L2tpIpsecDriver.cs:77`](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L77)) — hai driver chạy PPP và lấy global IPv6 cùng cách.
- **Tham chiếu**: roadmap [`11`](../../.docs/11-todo-roadmap.md) (F.6 đã hoàn tất, xóa khỏi roadmap); mẫu consumer [Drivers.WireGuard README](../TqkLibrary.VpnClient.Drivers.WireGuard/README-vi.md) + [Drivers.OpenConnect README](../TqkLibrary.VpnClient.Drivers.OpenConnect/README-vi.md) + [Drivers.Ikev2 README](../TqkLibrary.VpnClient.Drivers.Ikev2/README-vi.md) + [Drivers.L2tpIpsec README](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/README-vi.md) (driver có rekey ngoài supervisor).

> Build xanh cả `netstandard2.0` + `net8.0`. Clock đơn điệu rào theo TFM thấp nhất (`Environment.TickCount64` từ net5+, else `Stopwatch`). `record`/`init`/`required` không dùng ở đây.
