# TqkLibrary.VpnClient.Drivers.Ikev2

Driver **IKEv2-native** (RFC 7296) — kết nối trực tiếp tới gateway IKEv2/IPsec (strongSwan, libreswan, Windows RRAS…) **không qua L2TP/PPP**. Khác với [Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) (IKEv1 + L2TP + PPP), driver này dùng **IKEv2** + **Configuration Payload** lấy IP ảo + **ESP tunnel mode** đẩy thẳng gói IP vào userspace stack.

## Vị trí kiến trúc

`PROTOCOL`-layer driver, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`Ipsec`](../TqkLibrary.VpnClient.Ipsec) thành 1 tunnel sống:

- **Control plane**: [`IkeClient`](../TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeClient.cs#L16) (IKE_SA_INIT + IKE_AUTH PSK + CFG_REQUEST + DPD + DELETE + rekey CHILD_SA).
- **NAT-T**: [`NatTraversalChannel`](../TqkLibrary.VpnClient.Ipsec/Nat/NatTraversalChannel.cs#L13) (UDP/500→4500, non-ESP marker) — dùng chung với driver L2TP/IPsec.
- **Data plane**: [`EspTunnelChannel`](../TqkLibrary.VpnClient.Ipsec/Esp/EspTunnelChannel.cs#L14) — ESP tunnel mode (NextHeader 4/41) → `IPacketChannel` (không PPP/L2TP).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, exceptions, `IHostResolver` |
| Dùng | [Ipsec](../TqkLibrary.VpnClient.Ipsec) | `Ike/V2` (IkeClient + payloads), `Esp` (EspSession/EspTunnelChannel), `Nat` (NAT-T) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseIkev2()` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Ikev2/
├─ Ikev2Driver.cs              IVpnProtocolDriver: capabilities + ConnectAsync → Ikev2Connection
├─ Ikev2Connection.cs          Điều phối control plane: handshake, DPD keepalive, rekey CHILD_SA, teardown, reconnect
├─ Ikev2VpnConnection.cs       IVpnConnection: 1 session; OpenSessionAsync ném NotSupportedException (1 CHILD_SA)
├─ Ikev2VpnSession.cs          IVpnSession: PacketChannel ổn định + TunnelConfig; ApplyReconnect khi reconnect
├─ Ikev2ReconnectOptions.cs    Chính sách auto-reconnect (backoff + jitter, mirror L2TP/IPsec)
├─ Enums/Ikev2ConnectionState.cs   Disconnected/Connecting/Connected/Reconnecting
└─ Models/Ikev2ReconnectInfo.cs    Địa chỉ mới + cờ AddressChanged sau reconnect
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `Ikev2Driver` | `IVpnProtocolDriver`: capabilities (L3Ip, **không PPP**, ESP, PSK, ConfigPush), `ConnectAsync` dựng `Ikev2Connection` | [Ikev2Driver.cs:9](Ikev2Driver.cs#L9) |
| `Ikev2Connection` | Bộ điều phối: forced NAT-T (500→4500) → IKE_SA_INIT → IKE_AUTH+CP → `EspTunnelChannel`; keepalive DPD, rekey CHILD_SA make-before-break, DELETE teardown, supervisor reconnect sau `SwappablePacketChannel` ổn định | [Ikev2Connection.cs:26](Ikev2Connection.cs#L26) |
| `Ikev2VpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (IKEv2 strictly 1 CHILD_SA ở driver này) | [Ikev2VpnConnection.cs:7](Ikev2VpnConnection.cs#L7) |
| `Ikev2VpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config`; `ApplyReconnect` cập nhật IP/DNS sau reconnect | [Ikev2VpnSession.cs:10](Ikev2VpnSession.cs#L10) |
| `Ikev2ReconnectOptions` | `Enabled`/`MaxAttempts`/backoff/jitter | [Ikev2ReconnectOptions.cs:8](Ikev2ReconnectOptions.cs#L8) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`.
2. **NAT-T channel** mở cổng nguồn ephemeral (`localPort=0`) → receive loop demux IKE/ESP.
3. **IKE_SA_INIT** (UDP/500): `IkeClient.BuildInitRequest` → `ProcessInitResponse` (DH MODP-2048, SK_*).
4. **Float 4500** (`SwitchToNatTPort`) — forced NAT-T: cổng nguồn ephemeral ⇒ gateway luôn thấy NATed.
5. **IKE_AUTH** (UDP/4500, SK-encrypted): IDi + AUTH(PSK) + **CFG_REQUEST** + SAi2 (chào AES-CBC-256 + AES-GCM) + TSi/TSr. `ProcessAuthResponse` verify AUTH responder → CHILD_SA keys + đọc **CFG_REPLY** (virtual IP/DNS). Không có IP ảo ⇒ `VpnServerRejectedException`.
6. **Data plane**: dựng `EspSession` (suite gateway chọn) → `EspTunnelChannel(esp, natt.SendEspAsync, mtu=1400)`; `_facade.SetInner(dataPlane)`; bật keepalive.

## Vòng đời

- **DPD keepalive** (RFC 7296 §2.4): mỗi 20s gửi INFORMATIONAL rỗng (`BuildDeadPeerDetection`) qua exchange-gate; quá 3 lần không hồi đáp ⇒ link lost. Probe đến từ gateway (INFORMATIONAL rỗng) ⇒ ack bằng `BuildInformationalResponse`.
- **Rekey CHILD_SA** (make-before-break): timer ~90% lifetime (1h) **hoặc** watermark sequence ESP ~2³² (`EspTunnelChannel.RekeyNeeded`) → `BuildRekeyChildSaRequest`/`ProcessRekeyChildSaResponse` → `EspTunnelChannel.SwapSession` (gửi SA mới ngay, giữ SA cũ nhận thêm 10s rồi `DropPreviousInbound`).
- **Teardown** (`DisconnectAsync`): gửi `BuildDeleteIkeSa` (best-effort), hủy receive loop, đóng socket.
- **Auto-reconnect**: gateway DELETE / DPD chết ⇒ supervisor dựng lại tunnel sau `SwappablePacketChannel`; backoff mũ + jitter.

## Trạng thái & ghi chú

- **Validate live cần lab Q.1** (strongSwan Docker) — môi trường Termux/PRoot không có Docker. Toán protocol (handshake, CP, DPD/DELETE, rekey) đã test offline ở [`Ipsec.Ike.Tests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests) + data plane ở [`Ipsec.Esp.Tests`](../../tests/TqkLibrary.VpnClient.Ipsec.Esp.Tests); test client của driver (capabilities + guard) ở [`Drivers.Ikev2.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Ikev2.Tests).
- **Chỉ PSK** + **forced NAT-T** + **1 CHILD_SA / 1 IP ảo**. **Chưa**: EAP-MSCHAPv2 (username/password), rekey IKE SA (Phase-1 equivalent), honest-first NAT-T, multi-traffic-selector — xem roadmap F.7/[`11`](../../.docs/11-todo-roadmap.md).
- **Thuần client**: không có code server; "responder" trong test chỉ là harness in-process.
