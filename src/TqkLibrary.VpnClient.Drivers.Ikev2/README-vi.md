# TqkLibrary.VpnClient.Drivers.Ikev2

Driver **IKEv2-native** (RFC 7296) — kết nối trực tiếp tới gateway IKEv2/IPsec (strongSwan, libreswan, Windows RRAS…) **không qua L2TP/PPP**. Khác với [Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) (IKEv1 + L2TP + PPP), driver này dùng **IKEv2** + **Configuration Payload** lấy IP ảo + **ESP tunnel mode** đẩy thẳng gói IP vào userspace stack. Auth: **PSK** (mặc định) hoặc **EAP-MSCHAPv2** (username/password, RFC 7296 §2.16) — tự chọn theo `VpnCredentials`.

## Vị trí kiến trúc

`PROTOCOL`-layer driver, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`Ipsec`](../TqkLibrary.VpnClient.Ipsec) thành 1 tunnel sống:

- **Control plane**: [`IkeClient`](../TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeClient.cs#L16) (IKE_SA_INIT + IKE_AUTH PSK **hoặc** EAP-MSCHAPv2 + CFG_REQUEST + DPD + DELETE + rekey CHILD_SA); EAP tái dùng codec [`MsChapV2`](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs) ở Crypto.
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
| `Ikev2Driver` | `IVpnProtocolDriver`: capabilities (L3Ip, **không PPP**, ESP, **PSK\|EAP**, ConfigPush), `ConnectAsync` dựng `Ikev2Connection`; có username+password ⇒ EAP, không ⇒ PSK (lệch một nửa ⇒ `ArgumentException`) | [Ikev2Driver.cs:8](Ikev2Driver.cs#L8) |
| `Ikev2Connection` | Bộ điều phối: forced NAT-T (500→4500) → IKE_SA_INIT → IKE_AUTH (PSK **hoặc** EAP-MSCHAPv2 loop `RunEapAuthAsync`) +CP → `EspTunnelChannel`; keepalive DPD, rekey CHILD_SA make-before-break **+ rekey IKE SA** (`RekeyIkeSaAsync`, ~90% lifetime 8h), DELETE teardown, supervisor reconnect sau `SwappablePacketChannel` ổn định | [Ikev2Connection.cs:25](Ikev2Connection.cs#L25) |
| `Ikev2VpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (IKEv2 strictly 1 CHILD_SA ở driver này) | [Ikev2VpnConnection.cs:7](Ikev2VpnConnection.cs#L7) |
| `Ikev2VpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config`; `ApplyReconnect` cập nhật IP/DNS sau reconnect | [Ikev2VpnSession.cs:10](Ikev2VpnSession.cs#L10) |
| `Ikev2ReconnectOptions` | `Enabled`/`MaxAttempts`/backoff/jitter | [Ikev2ReconnectOptions.cs:8](Ikev2ReconnectOptions.cs#L8) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`.
2. **NAT-T channel** mở cổng nguồn ephemeral (`localPort=0`) → receive loop demux IKE/ESP.
3. **IKE_SA_INIT** (UDP/500): `IkeClient.BuildInitRequest` → `ProcessInitResponse` (DH MODP-2048, SK_*).
4. **Float 4500** (`SwitchToNatTPort`) — forced NAT-T: cổng nguồn ephemeral ⇒ gateway luôn thấy NATed.
5. **IKE_AUTH** (UDP/4500, SK-encrypted):
   - **PSK**: IDi(IPv4 0.0.0.0) + AUTH(PSK) + **CFG_REQUEST** + SAi2 (chào AES-CBC-256 + AES-GCM) + TSi/TSr. `ProcessAuthResponse` verify AUTH responder → CHILD_SA keys + đọc **CFG_REPLY** (virtual IP/DNS).
   - **EAP-MSCHAPv2** (`RunEapAuthAsync`): IDi = username (Rfc822/FQDN), IKE_AUTH đầu **không** AUTH (báo dùng EAP); loop `BuildAuthRequestEap`→`ProcessAuthResponseEap` chạy EAP-Identity → MSCHAPv2 Challenge/Response/Success qua các message-id liên tiếp; cả 2 bên tính AUTH cuối từ **EAP MSK**. Responder vẫn xác thực bằng PSK (lab Q.1 sẽ kiểm cert). Không có IP ảo ⇒ `VpnServerRejectedException`.
6. **Data plane**: dựng `EspSession` (suite gateway chọn) → `EspTunnelChannel(esp, natt.SendEspAsync, mtu=1400)`; `_facade.SetInner(dataPlane)`; bật keepalive.

## Vòng đời

- **DPD keepalive** (RFC 7296 §2.4): mỗi 20s gửi INFORMATIONAL rỗng (`BuildDeadPeerDetection`) qua exchange-gate; quá 3 lần không hồi đáp ⇒ link lost. Probe đến từ gateway (INFORMATIONAL rỗng) ⇒ ack bằng `BuildInformationalResponse`.
- **Rekey CHILD_SA** (make-before-break): timer ~90% lifetime (1h) **hoặc** watermark sequence ESP ~2³² (`EspTunnelChannel.RekeyNeeded`) → `BuildRekeyChildSaRequest`/`ProcessRekeyChildSaResponse` → `EspTunnelChannel.SwapSession` (gửi SA mới ngay, giữ SA cũ nhận thêm 10s rồi `DropPreviousInbound`).
- **Rekey IKE SA** (Phase-1-equivalent, RFC 7296 §1.3.2/§2.18): timer ~90% lifetime (8h) → `RekeyIkeSaAsync` gửi `BuildRekeyIkeSaRequest` (CREATE_CHILD_SA: SPI/DH/Nonce mới) trên SK channel **cũ** → `ProcessRekeyIkeSaResponse` swing SK_* mới + reset message-id về 0. **Chỉ refresh khóa control-channel** — ESP CHILD_SA/data plane không đổi nên không cần make-before-break trên traffic. Chung guard `_rekeyInProgress` với rekey CHILD_SA (không chạy chồng).
- **Teardown** (`DisconnectAsync`): gửi `BuildDeleteIkeSa` (best-effort), hủy receive loop, đóng socket.
- **Auto-reconnect**: gateway DELETE / DPD chết ⇒ supervisor dựng lại tunnel sau `SwappablePacketChannel`; backoff mũ + jitter.

## Trạng thái & ghi chú

- **Validate live cần lab Q.1** (strongSwan Docker) — môi trường Termux/PRoot không có Docker. Toán protocol (handshake, CP, DPD/DELETE, rekey) đã test offline ở [`Ipsec.Ike.Tests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests) + data plane ở [`Ipsec.Esp.Tests`](../../tests/TqkLibrary.VpnClient.Ipsec.Esp.Tests); test client của driver (capabilities + guard) ở [`Drivers.Ikev2.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Ikev2.Tests).
- **PSK hoặc EAP-MSCHAPv2** + **forced NAT-T** + **1 CHILD_SA / 1 IP ảo** + rekey **CHILD_SA và IKE SA** đều gắn timer trong driver. **Chưa**: honest-first NAT-T, multi-traffic-selector, responder AUTH bằng cert (EAP hiện verify responder bằng PSK), DELETE SA cũ sau rekey IKE SA (hiện bỏ SA cũ cho gateway tự timeout) — xem roadmap V.1/[`11`](../../.docs/11-todo-roadmap.md).
- **Thuần client**: không có code server; "responder" trong test chỉ là harness in-process.
