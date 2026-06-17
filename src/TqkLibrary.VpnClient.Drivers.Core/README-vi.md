# TqkLibrary.VpnClient.Drivers.Core

**Scaffolding dùng chung cho driver** (roadmap **F.6**) — gom phần lặp lại giữa các protocol driver thành **một base class + một model policy**, để driver mới không chép lần thứ N cùng một bộ supervisor/reconnect/keepalive. Trước F.6 mỗi driver (WireGuard, OpenConnect, OpenVPN, IKEv2, SoftEther, SSTP, L2TP/IPsec) tự bê nguyên `EstablishAsync`/`ReconnectLoopAsync`/backoff-jitter/`StateChanged`/`OnLinkLost`/guard `_running`-`_userTeardown`-`_supervisorActive`/clock đơn điệu + một `XxxReconnectOptions` gần như giống hệt. Project này rút phần đó ra:

- [`ReconnectingVpnConnection<TState>`](ReconnectingVpnConnection.cs#L25) — base **abstract** mang toàn bộ máy supervisor; driver kế thừa và chỉ viết phần protocol riêng.
- [`VpnReconnectOptions`](Models/VpnReconnectOptions.cs#L17) — model policy reconnect/backoff/jitter chung; mỗi driver giữ type tên riêng (`WireGuardReconnectOptions`, …) **kế thừa** base này để không vỡ public API.

> **Tái sử dụng tối đa, không viết lại**: base **không** phát minh hành vi mới — chính là vòng lặp các driver đang chạy live, factor lại một lần. Refactor **không đổi hành vi** (toàn bộ test driver hiện có vẫn xanh).

## Vị trí kiến trúc

`DRIVER-CORE`-layer — đứng giữa [`Abstractions`](../TqkLibrary.VpnClient.Abstractions) (interface/channel/diagnostics) và các project `Drivers.*` cụ thể. **Không** chứa logic protocol nào; chỉ là khung lifecycle + policy. Driver `sealed class XxxConnection : ReconnectingVpnConnection<XxxConnectionState>` override 4 ánh xạ state + 3 hook protocol.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `SwappablePacketChannel`/`IPacketChannel` (facade ổn định), **`Diagnostics`** (`VpnLogExtensions` — log state/link-lost/reconnect), `Microsoft.Extensions.Logging.Abstractions` (transitive) |
| Được dùng bởi | [Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard) | `WireGuardConnection : ReconnectingVpnConnection<WireGuardConnectionState>` (consumer F.6 #1) |
| Được dùng bởi | [Drivers.OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) | `OpenConnectConnection : ReconnectingVpnConnection<OpenConnectConnectionState>` (consumer F.6 #2) |
| Được dùng bởi | [Drivers.OpenVpn](../TqkLibrary.VpnClient.Drivers.OpenVpn) | `OpenVpnConnection : ReconnectingVpnConnection<OpenVpnConnectionState>` (consumer F.6 #3) |
| Được dùng bởi | [Drivers.SoftEther](../TqkLibrary.VpnClient.Drivers.SoftEther) | `SoftEtherConnection : ReconnectingVpnConnection<SoftEtherConnectionState>` (consumer F.6 #4) |

> Các driver còn lại (IKEv2/SSTP/L2TP-IPsec) **chưa** migrate — ghi follow-up ở [Trạng thái](#trạng-thái--ghi-chú). `XxxReconnectOptions` của 3 driver đó vẫn là class độc lập (chưa kế thừa `VpnReconnectOptions`).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Core/
├─ ReconnectingVpnConnection.cs     Base abstract: facade + lifetime CTS + state lock + supervisor (OnLinkLost/ReconnectLoopAsync/WithJitter) + SetState/StateChanged + clock đơn điệu + teardown; hook abstract: EstablishAsync/CleanupAttemptResourcesAsync/StopAttemptLoop + 4 state-value + OnReconnected
└─ Models/
   └─ VpnReconnectOptions.cs        Policy chung: Enabled/MaxAttempts/InitialBackoff/MaxBackoff/BackoffMultiplier/JitterFraction + NextBackoff(); driver kế thừa thêm knob riêng (vd SSTP ReadTimeout)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `ReconnectingVpnConnection<TState>` | Base abstract (generic theo enum state của driver). Sở hữu: `SwappablePacketChannel Facade`, `LifetimeToken`, lock + cờ `IsRunning`/`IsUserTeardown` + `_supervisorActive`, máy **link-loss → supervisor → reconnect-loop** (backoff mũ + ±jitter), `SetState`/`StateChanged` + log có cấu trúc, clock đơn điệu (`Now()`), teardown (`DisconnectCoreAsync`/`DisposeCoreAsync`). Hook protocol: abstract `EstablishAsync`/`CleanupAttemptResourcesAsync`/`StopAttemptLoop` + 4 thuộc tính state-value + virtual `OnReconnected`. Lifecycle cho subclass gọi: `ConnectCoreAsync`/`MarkRunning`/`MarkConnected`/`OnLinkLost`. | [ReconnectingVpnConnection.cs:25](ReconnectingVpnConnection.cs#L25) |
| `VpnReconnectOptions` | Policy reconnect/backoff/jitter chung (class **không** sealed — driver kế thừa). `NextBackoff(current)` = `min(MaxBackoff, current × BackoffMultiplier)`. | [Models/VpnReconnectOptions.cs:17](Models/VpnReconnectOptions.cs#L17) |

## Hợp đồng base ↔ subclass

Driver cụ thể chỉ cần:

1. **Kế thừa** `ReconnectingVpnConnection<XxxConnectionState>`, gọi `base(driverName, options, clock, loggerFactory)` ở ctor.
2. **Ánh xạ state**: override 4 thuộc tính `DisconnectedState`/`ConnectingState`/`ConnectedState`/`ReconnectingState` → enum riêng.
3. **`EstablishAsync(ct)`** — một lần thử tunnel đầy đủ: resolve/transport → handshake → bind channel sống vào `Facade.SetInner(...)` → bật timer/receive-loop → gọi `MarkConnected()`. Ném khi lỗi (supervisor backoff + retry). Mở đầu nên gọi `CleanupAttemptResourcesAsync()` để bỏ attempt dở.
4. **`CleanupAttemptResourcesAsync()`** — gỡ mọi thứ `EstablishAsync` dựng (timer, receive loop, transport, channel). Best-effort + idempotent.
5. **`StopAttemptLoop()`** — dispose timer/loop per-attempt (base đã set `IsRunning=false` quanh nó).
6. (tuỳ) **`MarkRunning()`** sớm nếu establish có cửa sổ giữa "bind xong + bật receive-loop" và "MarkConnected" mà drop có thể xảy ra (vd OpenConnect: peer-close giữa lúc handshake DTLS) — để `OnLinkLost` honour được drop đó.
7. (tuỳ) **`OnReconnected()`** raise event `Reconnected` riêng; override `DisconnectAsync` để gửi protocol-close best-effort rồi gọi `DisconnectCoreAsync()`.

## Luồng supervisor (as-built)

1. **Connect đầu** (`ConnectCoreAsync`): `SetState(Connecting)` → `EstablishAsync`. Lỗi attempt đầu **ném thẳng** ra caller (reconnect chỉ arm sau một lần thành công — `IsRunning` chỉ true sau `MarkConnected`/`MarkRunning`).
2. **Link-loss** (`OnLinkLost(reason)`) từ receive-loop/timer/fault: dưới lock — no-op nếu `!IsRunning`; nếu không thì `StopAttemptLoop` + `IsRunning=false`, rồi **hoặc** `Disconnected` (user teardown / reconnect tắt) **hoặc** arm supervisor **đúng một lần** (`_supervisorActive`).
3. **Reconnect loop** (`ReconnectLoopAsync`): `EstablishAsync` lặp; thành công → `OnReconnected()` + về; thất bại → backoff `WithJitter(NextBackoff(...))`, dừng khi `MaxAttempts` (≠0) chạm hạn hoặc `cancellationToken`.
4. **Teardown** (`DisconnectCoreAsync`): `IsUserTeardown=true`, stop loop, cancel `LifetimeToken`, await supervisor, `CleanupAttemptResourcesAsync`, `Disconnected`.

## Trạng thái & ghi chú

- **Đã có (F.6)**: base `ReconnectingVpnConnection<TState>` + `VpnReconnectOptions`; **migrate 4 driver** WireGuard (UDP/Noise) + OpenConnect (TLS+DTLS/CSTP) + OpenVPN (UDP/TCP, rekey = re-establish) + SoftEther (TLS byte-stream + L2 bridge) sang base — chứng minh hợp đồng đủ cho cả transport datagram lẫn byte-stream, cả make-before-break (WG: timer-loop riêng `_timerRunning`) lẫn DTLS-fallback window (OC: `MarkRunning` sớm) lẫn keepalive ping/ping-restart trong timer riêng (OpenVPN: `StopAttemptLoop` dispose timer + tắt `_dataActive`, rekey re-establish gọi `OnLinkLost`) lẫn L2-bridge keep-alive timer (SoftEther: `MarkRunning` sớm trước DHCP, `StopAttemptLoop` dispose keep-alive timer, `OnReconnected` raise `Reconnected`). Test offline [`ReconnectingVpnConnectionTests`](../../tests/TqkLibrary.VpnClient.Drivers.Core.Tests/ReconnectingVpnConnectionTests.cs) (fake driver: connect/connect-fail/reconnect/reconnect-disabled/max-attempts/teardown-mid-loop + default policy) + toàn bộ test WireGuard/OpenConnect/OpenVPN/SoftEther cũ **vẫn xanh** (không đổi hành vi).
- **Chưa (follow-up)**: migrate 3 driver còn lại sang base —
  - **IKEv2** (`Ikev2Connection`): rekey IKE/CHILD SA in-place trên kênh SK — `EstablishAsync`/`CleanupAttemptResourcesAsync` map được, nhưng rekey không phải re-establish nên cần giữ logic riêng ngoài supervisor.
  - **SSTP** (`SstpConnection`): `SstpReconnectOptions` có thêm `ReadTimeout` → khi migrate cho kế thừa `VpnReconnectOptions` + thêm knob; supervisor map được.
  - **L2TP/IPsec** (`L2tpIpsecConnection`): rekey Phase 1/2 in-place + multi-session — phức tạp nhất; supervisor map được nhưng cần thận trọng với swap SA.
- **Tham chiếu**: roadmap [`11`](../../.docs/11-todo-roadmap.md) §F.6; mẫu consumer [Drivers.WireGuard README](../TqkLibrary.VpnClient.Drivers.WireGuard/README-vi.md) + [Drivers.OpenConnect README](../TqkLibrary.VpnClient.Drivers.OpenConnect/README-vi.md).

> Build xanh cả `netstandard2.0` + `net8.0`. Clock đơn điệu rào theo TFM thấp nhất (`Environment.TickCount64` từ net5+, else `Stopwatch`). `record`/`init`/`required` không dùng ở đây.
