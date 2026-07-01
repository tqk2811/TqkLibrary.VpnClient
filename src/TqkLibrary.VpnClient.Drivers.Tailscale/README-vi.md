# TqkLibrary.VpnClient.Drivers.Tailscale

**Driver runtime Tailscale** (V.7.5): chạy control plane **ts2021** ([`Tailscale`](../TqkLibrary.VpnClient.Tailscale))
— đăng nhập Headscale bằng preauth key + register node + lấy netmap — rồi **ánh xạ netmap → WireGuardConfig đa-peer**
và **tái dùng nguyên data plane WireGuard** ([`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard):
Noise_IKpsk2 + transport type-4 + crypto-routing). Driver này chỉ thêm control plane sinh peer; **KHÔNG viết lại
WireGuard**.

> **Trạng thái:** **FULL-TUNNEL VALIDATE LIVE ICMP 2 chiều ✓** vs Headscale v0.29.1 (2026-06-25, lab
> [`lab/tailscale`](../../lab/tailscale/README-vi.md)) giữa **2 node .NET**: login ts2021 → register (preauth) →
> netmap → build WireGuardConfig → WireGuard data plane lên qua **responder role** (driver dựng `WireGuardConnection`
> với `acceptInbound: true` — tie-break theo static pubkey: 1 node initiate type-1, node kia đáp type-2). tcpdump:
> type-1 **148B** → type-2 **92B (responder)** → type-4 data **92B 2 chiều**; ICMP `100.64.0.1↔100.64.0.2` reply
> RTT 0-8ms (89/89). **Còn future:** disco (interop node `tailscale` THẬT bọc magicsock) + DERP + netmap streaming
> động. Xem [lab](../../lab/tailscale/README-vi.md).

## Vị trí kiến trúc

`DRIVER`-layer (ngang hàng [Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard)/[Drivers.Nebula](../TqkLibrary.VpnClient.Drivers.Nebula)):
kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs) (supervisor F.6
dùng chung). Khác mọi driver mesh khác: data plane **tái dùng cả 1 driver khác** ([`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L53))
làm con bên trong — control plane Tailscale chỉ sinh `WireGuardConfig` đa-peer từ netmap rồi giao cho WireGuard.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`TunnelConfig`/capabilities |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs) (supervisor + facade + reconnect) |
| Dùng | [Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard) | [`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L53) (data plane), [`WireGuardSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/WireGuardSocketTransportFactory.cs) (UDP, fixed localPort) |
| Dùng | [Tailscale](../TqkLibrary.VpnClient.Tailscale) | [`TailscaleControlClient`](../TqkLibrary.VpnClient.Tailscale/Control/TailscaleControlClient.cs)/[`NetmapToWireGuardConfig`](../TqkLibrary.VpnClient.Tailscale/Netmap/NetmapToWireGuardConfig.cs#L24) (control + mapping) |
| Được dùng bởi | [`VpnClientBuilder.UseTailscale`](../TqkLibrary.VpnClient/VpnClientBuilder.cs) + demo `.tailscale` | đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Tailscale/
├─ Config/
│  └─ TailscaleConfig.cs            # ServerUrl + PreauthKey + Machine/Node X25519 keys + Mtu + WireGuardLocalPort + AdvertisedEndpoints; Generate()
├─ TailscaleConnection.cs           # ReconnectingVpnConnection: control -> netmap -> WireGuardConfig -> WireGuardConnection con
├─ TailscaleControlClientAdapter.cs # build TailscaleControlClient thật (net5+; ns2.0 ném PlatformNotSupported)
├─ TailscaleDriver.cs               # IVpnProtocolDriver Name="tailscale"
├─ TailscaleReconnectOptions.cs     # : VpnReconnectOptions
├─ TailscaleVpnConnection.cs        # IVpnConnection (1 session)
└─ TailscaleVpnSession.cs           # IVpnSession (facade L3 + TunnelConfig từ netmap)
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`TailscaleConfig`](Config/TailscaleConfig.cs#L18) | static profile; `Generate()` sinh 2 key X25519; `WireGuardLocalPort`/`AdvertisedEndpoints` cho disco-stand-in |
| [`TailscaleConnection`](TailscaleConnection.cs#L34) | `EstablishAsync`: `LoginAsync`→netmap→[`NetmapToWireGuardConfig.Build`](../TqkLibrary.VpnClient.Tailscale/Netmap/NetmapToWireGuardConfig.cs#L41)→[`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L53) con→`Facade.SetInner(wg.PacketChannel)` |
| [`TailscaleControlClientAdapter`](TailscaleControlClientAdapter.cs) | `ITailscaleControlClient` → `TailscaleControlClient` thật (net5+); seam `controlClientFactory` cho fake netmap offline |
| [`TailscaleDriver`](TailscaleDriver.cs#L19) | `Name="tailscale"`, caps L3Ip/Udp/Noise/PreSharedKey/RoutedPrefixes/OutOfBand |

## Luồng nội bộ (establish)

1. [`TailscaleConnection.EstablishAsync`](TailscaleConnection.cs#L83): tạo [`ITailscaleControlClient`](../TqkLibrary.VpnClient.Tailscale/Control/ITailscaleControlClient.cs) (mặc định [adapter](TailscaleControlClientAdapter.cs) → `TailscaleControlClient` thật).
2. `control.LoginAsync(preauthKey)` → [`MapResponse`](../TqkLibrary.VpnClient.Tailscale/Control/Messages/MapResponse.cs) (netmap: self + peers).
3. [`NetmapToWireGuardConfig.Build`](../TqkLibrary.VpnClient.Tailscale/Netmap/NetmapToWireGuardConfig.cs#L41) → `WireGuardConfig` đa-peer; peer không có endpoint trực tiếp bị skip (DERP = future).
4. tạo [`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L53) (fixed `localPort` khớp endpoint quảng bá, **`acceptInbound: true`** — mesh peer-to-peer) + `ConnectAsync` → WG handshake với peer (initiate hoặc respond theo tie-break static pubkey).
5. `Facade.SetInner(wg.PacketChannel)` → `MarkConnected`. WireGuard con giữ auto-reconnect data-plane (đã proven).

## Trạng thái & ghi chú

- **Data plane tái dùng nguyên + responder role**: KHÔNG viết lại WireGuard; control plane chỉ sinh `WireGuardConfig`
  và dựng WireGuard con với `acceptInbound: true`. WireGuard con giữ rekey/keepalive/auto-reconnect riêng (đã
  live-validated V.3) + nửa **responder** (đã có sẵn trong `WireGuardHandshake`, nay bật ở driver) để 2 node .NET tự
  handshake nhau (xem [README Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard/README-vi.md) — responder role).
- **FULL-TUNNEL VALIDATE LIVE ✓**: 2 node .NET qua Headscale v0.29.1 — control register+netmap (cả 2 `online=true`,
  overlay `100.64.0.1`/`.2`) → WireGuard responder role (type-1 148B → type-2 92B → data 92B 2 chiều, tcpdump) → ICMP
  89/89 reply RTT 0-8ms (chiều ngược do `TcpIpStack` peer tự đáp echo). **Vận hành (rút từ live)**: `LoginAsync` đọc
  netmap MỘT lần → lab pre-register mỗi node 1 lần (keys X25519 cố định) rồi chạy 2 node đồng thời.
- **Endpoint advertisement (disco stand-in tối giản)**: `WireGuardLocalPort` (fixed) + `AdvertisedEndpoints` (ip:port)
  quảng bá vào MapRequest để peer thấy endpoint client — đủ cho path trực tiếp trên bridge (lab), nhưng với node
  `tailscale` THẬT vẫn cần **disco** (= future, cùng DERP relay + netmap streaming động).
- **net5+ runtime**: control client cần HTTP/2 h2c. ns2.0 → adapter ném `PlatformNotSupported` (inject factory khác để
  test). Build cả 2 TFM (chỉ phần control runtime gated).
- Test offline: [`Drivers.Tailscale.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Tailscale.Tests) (5) — capabilities,
  `Generate` 2 key, netmap no-usable-peer ném + login preauth + dispose, control error propagate (fake netmap), và
  [`TailscaleTwoNodeTunnelTests`](../../tests/TqkLibrary.VpnClient.Drivers.Tailscale.Tests/TailscaleTwoNodeTunnelTests.cs)
  **end-to-end 2 node** (mỗi node fake netmap có node kia → WireGuardConfig → responder role → IP round-trip 2 chiều).
