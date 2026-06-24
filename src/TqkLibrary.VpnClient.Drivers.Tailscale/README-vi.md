# TqkLibrary.VpnClient.Drivers.Tailscale

**Driver runtime Tailscale** (V.7.5): chạy control plane **ts2021** ([`Tailscale`](../TqkLibrary.VpnClient.Tailscale))
— đăng nhập Headscale bằng preauth key + register node + lấy netmap — rồi **ánh xạ netmap → WireGuardConfig đa-peer**
và **tái dùng nguyên data plane WireGuard** ([`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard):
Noise_IKpsk2 + transport type-4 + crypto-routing). Driver này chỉ thêm control plane sinh peer; **KHÔNG viết lại
WireGuard**.

> **Trạng thái:** **control plane VALIDATE LIVE FULL ✓** vs Headscale v0.29.1 (2026-06-24, lab
> [`lab/tailscale`](../../lab/tailscale/README-vi.md)): login ts2021 → register (preauth) → netmap → build
> WireGuardConfig → WireGuard data plane khởi động + gửi **handshake initiation 2 chiều** tới endpoint từ netmap.
> **Data plane chưa hoàn tất handshake** (biên giới đã biết): [`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L45)
> **initiator-only** (không đáp type-1) + node tailscale thật cần **disco** (= future). Xem [lab](../../lab/tailscale/README-vi.md).

## Vị trí kiến trúc

`DRIVER`-layer (ngang hàng [Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard)/[Drivers.Nebula](../TqkLibrary.VpnClient.Drivers.Nebula)):
kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs) (supervisor F.6
dùng chung). Khác mọi driver mesh khác: data plane **tái dùng cả 1 driver khác** ([`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L45))
làm con bên trong — control plane Tailscale chỉ sinh `WireGuardConfig` đa-peer từ netmap rồi giao cho WireGuard.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`TunnelConfig`/capabilities |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs) (supervisor + facade + reconnect) |
| Dùng | [Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard) | [`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L45) (data plane), [`WireGuardSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/WireGuardSocketTransportFactory.cs) (UDP, fixed localPort) |
| Dùng | [Tailscale](../TqkLibrary.VpnClient.Tailscale) | [`TailscaleControlClient`](../TqkLibrary.VpnClient.Tailscale/Control/TailscaleControlClient.cs)/[`NetmapToWireGuardConfig`](../TqkLibrary.VpnClient.Tailscale/Netmap/NetmapToWireGuardConfig.cs#L33) (control + mapping) |
| Được dùng bởi | [`VpnClientBuilder.UseTailscale`](../TqkLibrary.VpnClient/VpnClientBuilder.cs) + demo `.tailscale` | đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Tailscale/
├─ Config/
│  └─ TailscaleConfig.cs            # ServerUrl + PreauthKey + Machine/Node X25519 keys + Mtu + WireGuardLocalPort + AdvertisedEndpoints; Generate()
├─ Enums/
│  └─ TailscaleConnectionState.cs   # Disconnected/Connecting/Connected/Reconnecting
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
| [`TailscaleConfig`](Config/TailscaleConfig.cs#L20) | static profile; `Generate()` sinh 2 key X25519; `WireGuardLocalPort`/`AdvertisedEndpoints` cho disco-stand-in |
| [`TailscaleConnection`](TailscaleConnection.cs#L33) | `EstablishAsync`: `LoginAsync`→netmap→[`NetmapToWireGuardConfig.Build`](../TqkLibrary.VpnClient.Tailscale/Netmap/NetmapToWireGuardConfig.cs#L42)→[`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L45) con→`Facade.SetInner(wg.PacketChannel)` |
| [`TailscaleControlClientAdapter`](TailscaleControlClientAdapter.cs) | `ITailscaleControlClient` → `TailscaleControlClient` thật (net5+); seam `controlClientFactory` cho fake netmap offline |
| [`TailscaleDriver`](TailscaleDriver.cs#L20) | `Name="tailscale"`, caps L3Ip/Udp/Noise/PreSharedKey/RoutedPrefixes/OutOfBand |

## Luồng nội bộ (establish)

1. [`TailscaleConnection.EstablishAsync`](TailscaleConnection.cs#L84): tạo [`ITailscaleControlClient`](../TqkLibrary.VpnClient.Tailscale/Control/ITailscaleControlClient.cs) (mặc định [adapter](TailscaleControlClientAdapter.cs) → `TailscaleControlClient` thật).
2. `control.LoginAsync(preauthKey)` → [`MapResponse`](../TqkLibrary.VpnClient.Tailscale/Control/Messages/MapResponse.cs) (netmap: self + peers).
3. [`NetmapToWireGuardConfig.Build`](../TqkLibrary.VpnClient.Tailscale/Netmap/NetmapToWireGuardConfig.cs#L42) → `WireGuardConfig` đa-peer; peer không có endpoint trực tiếp bị skip (DERP = future).
4. tạo [`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L45) (fixed `localPort` khớp endpoint quảng bá) + `ConnectAsync` → WG handshake tới peer.
5. `Facade.SetInner(wg.PacketChannel)` → `MarkConnected`. WireGuard con giữ auto-reconnect data-plane (đã proven).

## Trạng thái & ghi chú

- **Data plane tái dùng nguyên**: KHÔNG viết lại WireGuard; control plane chỉ sinh `WireGuardConfig`. WireGuard con
  giữ rekey/keepalive/auto-reconnect riêng (đã live-validated V.3).
- **Biên giới data plane (live)**: WG handshake initiation **2 chiều OK** tới endpoint từ netmap, nhưng KHÔNG hoàn tất:
  [`WireGuardConnection`](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L45) initiator-only (không đáp
  type-1 của peer) + node tailscale thật bọc WireGuard trong **disco** (cần disco ping/pong validate path). **disco +
  DERP = future.**
- **Endpoint advertisement (disco stand-in tối giản)**: `WireGuardLocalPort` (fixed) + `AdvertisedEndpoints` (ip:port)
  quảng bá vào MapRequest để peer thấy endpoint client — đủ để peer-thật thấy ta trong netmap, nhưng vẫn cần disco.
- **net5+ runtime**: control client cần HTTP/2 h2c. ns2.0 → adapter ném `PlatformNotSupported` (inject factory khác để
  test). Build cả 2 TFM (chỉ phần control runtime gated).
- Test offline: [`Drivers.Tailscale.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Tailscale.Tests) — capabilities,
  `Generate` 2 key, netmap no-usable-peer ném + login preauth + dispose, control error propagate (fake netmap).
