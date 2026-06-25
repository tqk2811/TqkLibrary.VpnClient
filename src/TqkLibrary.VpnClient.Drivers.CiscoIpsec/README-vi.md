# TqkLibrary.VpnClient.Drivers.CiscoIpsec

Driver **Cisco IPsec / EzVPN** remote-access — kết nối trực tiếp tới gateway Cisco-compatible (strongSwan
`aggressive=yes`/`xauth`, vpnc, Cisco ASA/IOS EzVPN…) **không qua L2TP/PPP**. Dùng **IKEv1 Aggressive Mode**
với **group PSK** (gateway chọn PSK theo group name gửi rõ ở message 1), rồi **XAUTH** (user name/password)
+ **Mode-Config** (kéo virtual IP/DNS), kết thúc bằng **Quick Mode** cài ESP **tunnel-mode** CHILD SA đẩy
thẳng gói IP vào userspace stack. Khác [Drivers.Ikev2](../TqkLibrary.VpnClient.Drivers.Ikev2) (IKEv2 PSK/EAP +
CP) ở chỗ dùng **IKEv1 Aggressive + XAUTH + Mode-Config**; tái dùng cùng [`IkeV1Client`](../TqkLibrary.VpnClient.Ipsec/Ike/V1/IkeV1Client.cs#L21)
với driver [L2TP/IPsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) (L2TP dùng IKEv1 Main Mode; Aggressive/XAUTH
là **nhánh thêm**, không vỡ Main Mode).

> ⚠️ **Bảo mật:** IKEv1 Aggressive Mode + group PSK là Phase 1 **yếu** — HASH_R của responder gửi cleartext
> cho phép dictionary attack offline lên group PSK. Driver này chỉ để **interop gateway Cisco-compatible
> legacy**; production nên dùng [IKEv2](../TqkLibrary.VpnClient.Drivers.Ikev2) hoặc
> [L2TP/IPsec Main Mode](../TqkLibrary.VpnClient.Drivers.L2tpIpsec).

## Vị trí kiến trúc

`PROTOCOL`-layer driver, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`Ipsec`](../TqkLibrary.VpnClient.Ipsec) thành 1 tunnel sống:

- **Control plane**: [`IkeV1Client`](../TqkLibrary.VpnClient.Ipsec/Ike/V1/IkeV1Client.cs#L21) (Aggressive Mode group PSK + XAUTH + Mode-Config + tunnel-mode Quick Mode + DPD + Delete + Phase 2 rekey).
- **NAT-T**: [`NatTraversalChannel`](../TqkLibrary.VpnClient.Ipsec/Nat/NatTraversalChannel.cs#L13) (UDP/500→4500, non-ESP marker) — dùng chung với driver L2TP/IPsec + IKEv2.
- **Data plane**: [`EspTunnelChannel`](../TqkLibrary.VpnClient.Ipsec/Esp/EspTunnelChannel.cs#L12) — ESP tunnel mode (NextHeader 4/41) → `IPacketChannel` (không PPP/L2TP).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, exceptions, `IHostResolver`, **`Diagnostics`** (log handshake/XAUTH/DPD/rekey/reconnect) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | base [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor/reconnect/backoff-jitter/facade/state, F.6) + [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14) |
| Dùng | [Ipsec](../TqkLibrary.VpnClient.Ipsec) | `Ike/V1` (IkeV1Client + Aggressive/XAUTH/Mode-Config payloads), `Esp` (EspSession/EspTunnelChannel), `Nat` (NAT-T) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseCiscoIpsec(groupName)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.CiscoIpsec/
├─ CiscoIpsecDriver.cs            IVpnProtocolDriver: capabilities + ConnectAsync → CiscoIpsecConnection; group name qua ctor, group PSK+XAUTH qua VpnCredentials
├─ CiscoIpsecConnection.cs        : ReconnectingVpnConnection<…> (F.6). Override Establish/Cleanup/StopAttemptLoop + ánh xạ state; giữ DPD/rekey ESP CHILD SA/Delete trên timer riêng (ngoài supervisor)
├─ CiscoIpsecVpnConnection.cs     IVpnConnection: 1 session; OpenSessionAsync ném NotSupportedException (1 ESP CHILD SA)
├─ CiscoIpsecVpnSession.cs        IVpnSession: PacketChannel ổn định + TunnelConfig; ApplyReconnect khi reconnect
├─ CiscoIpsecReconnectOptions.cs  : VpnReconnectOptions (F.6) — không thêm knob, giữ cho public API
├─ Enums/CiscoIpsecConnectionState.cs   Disconnected/Connecting/Connected/Reconnecting
└─ Models/CiscoIpsecReconnectInfo.cs    Địa chỉ mới + cờ AddressChanged sau reconnect
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `CiscoIpsecDriver` | `IVpnProtocolDriver`: capabilities (L3Ip, **không PPP**, ESP, **PSK\|UserPassword**, ConfigPush), `ConnectAsync` dựng `CiscoIpsecConnection`; **group name qua ctor** (`UseCiscoIpsec(groupName)`), group PSK = `VpnCredentials.PreSharedKey`, XAUTH user/pass = `Username`/`Password` (thiếu PSK hoặc thiếu một nửa XAUTH ⇒ `ArgumentException`) | [CiscoIpsecDriver.cs:18](CiscoIpsecDriver.cs#L18) |
| `CiscoIpsecConnection` | Bộ điều phối, **kế thừa** [`ReconnectingVpnConnection<CiscoIpsecConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6): override `EstablishAsync` (forced NAT-T 500→4500 → Aggressive AG1/AG2/AG3 group PSK → XAUTH `RunXAuthAsync` → Mode-Config virtual IP → Quick Mode ESP tunnel → `EspTunnelChannel` bind sau `Facade`) + `CleanupAttemptResourcesAsync`/`StopAttemptLoop` + ánh xạ 4 state + `OnReconnected`. **Phần IKEv1-riêng giữ ngoài supervisor trên timer riêng**: keepalive DPD (IKE R-U-THERE), rekey Phase 2 ESP CHILD SA make-before-break, **Delete SA khi teardown**; `DisconnectAsync` gửi Delete ESP + ISAKMP trước teardown base | [CiscoIpsecConnection.cs:37](CiscoIpsecConnection.cs#L37) |
| `CiscoIpsecVpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (1 ESP CHILD SA / 1 IP ảo ở driver này) | [CiscoIpsecVpnConnection.cs:6](CiscoIpsecVpnConnection.cs#L6) |
| `CiscoIpsecVpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config`; `ApplyReconnect` cập nhật IP/DNS sau reconnect | [CiscoIpsecVpnSession.cs:10](CiscoIpsecVpnSession.cs#L10) |
| `CiscoIpsecReconnectOptions` | **kế thừa** [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14) (F.6): `Enabled`/`MaxAttempts`/backoff/jitter — Cisco IPsec không thêm knob, giữ named type cho public API | [CiscoIpsecReconnectOptions.cs:12](CiscoIpsecReconnectOptions.cs#L12) |

## Bảng chuẩn / RFC

| Chuẩn | Phần dùng |
|-------|-----------|
| RFC 2407/2408/2409 (ISAKMP/IKEv1) | Aggressive Mode (AG1 cleartext + KE/Nonce/ID, AG2 reply HASH_R, AG3 HASH_I) ; Quick Mode tunnel-mode ; Transaction exchange (XAUTH/Mode-Config) chain CBC IV per Message-ID (§5.5) |
| draft-ietf-ipsec-isakmp-xauth (XAUTH) | CFG_REQUEST (gateway pull) → CFG_REPLY (X_USER/X_PWD) → CFG_SET (status) → CFG_ACK |
| draft-ietf-ipsec-isakmp-mode-cfg (Mode-Config) | CFG_REQUEST pull INTERNAL_IP4_ADDRESS/NETMASK/DNS/NBNS → CFG_REPLY (hoặc server-initiated CFG_SET) |
| RFC 3706 (DPD) | IKE R-U-THERE / R-U-THERE-ACK keepalive |
| RFC 3947/3948 (NAT-T) | forced NAT-T float UDP/500→4500, ESP-in-UDP |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`.
2. **NAT-T channel** mở cổng nguồn ephemeral (`localPort=0`) → receive loop demux IKE/ESP.
3. **Aggressive Mode** (UDP/500): `SetAggressiveIdentity(KEY_ID, groupName)` → `BuildAggressive1` (SA+KE+Nonce+ID group name cleartext) → `ProcessAggressive2` (verify HASH_R = group PSK đúng + derive keys) → **float 4500** (`SwitchToNatTPort` — forced NAT-T) → `BuildAggressive3` (HASH_I, encrypted, no reply).
4. **XAUTH** (`RunXAuthAsync`, UDP/4500 encrypted Transaction): chờ gateway gửi CFG_REQUEST → `BuildXAuthReply(request, user, pass)` (X_USER/X_PWD, **echo Message-ID + chain IV của request**) → gateway gửi CFG_SET status → `BuildXAuthAck(set, out ok)` (echo M-ID của set); status FAIL ⇒ `VpnAuthenticationException`.
5. **Mode-Config** (client-initiated Transaction): `BuildModeConfigRequest` (pull INTERNAL_IP4_*, M-ID mới) → `ProcessModeConfigReply` đọc virtual IP/netmask/DNS; không có IP ⇒ `VpnServerRejectedException`.
6. **Quick Mode** (tunnel mode): `BuildQuickMode1` (IDci = virtual IP, IDcr = 0.0.0.0/0, ESP AES-CBC/HMAC-SHA1 hoặc GCM tunnel) → `ProcessQuickMode2` → `BuildQuickMode3` (no reply).
7. **Data plane**: dựng `EspSession` (suite gateway chọn) → `EspTunnelChannel(esp, natt.SendEspAsync, mtu=1400)`; `Facade.SetInner(dataPlane)` → `MarkConnected()`; bật keepalive/rekey timer.

## Vòng đời

- **DPD keepalive** (RFC 3706): mỗi 20s gửi IKE R-U-THERE (`BuildDpdRUThere`); quá 3 lần không hồi đáp ⇒ link lost. Probe từ gateway (R-U-THERE) ⇒ ack bằng `BuildDpdAck`.
- **Rekey Phase 2 ESP CHILD SA** (make-before-break): timer ~90% lifetime Phase2 (1h) **hoặc** watermark sequence ESP ~2³² (`EspTunnelChannel.RekeyNeeded`) → `BuildRekeyQuickMode1`/`ProcessRekeyQuickMode2`/`BuildRekeyQuickMode3` → `EspTunnelChannel.SwapSession` (giữ SA cũ nhận thêm 10s rồi `DropPreviousInbound`). Cố ý **ngoài supervisor** — rekey làm tươi SA in-place, tunnel không rớt.
- **Teardown** (`DisconnectAsync` override): gửi `BuildDeleteEsp` + `BuildDeleteIsakmp` (best-effort) **trước**, rồi gọi `DisconnectCoreAsync` của base.
- **Auto-reconnect** (ở base, F.6): gateway Delete / DPD chết ⇒ `OnLinkLost` → `ReconnectLoopAsync` dựng lại tunnel sau `Facade`; backoff mũ + jitter; `OnReconnected` raise `Reconnected(CiscoIpsecReconnectInfo)`.
- **Logging/diagnostics**: ctor nhận `ILoggerFactory?` (mặc định no-op, ADDITIVE); log handshake (Aggressive/XAUTH/Mode-Config/Quick Mode)→Handshake, bind ESP plane→HandshakeCompleted, DPD→Keepalive, rekey→Rekey, state/link-lost/reconnect.

## Trạng thái & ghi chú

- **VALIDATE LIVE ✓ (2026-06-24, lab [`cisco-ipsec`](../../lab/cisco-ipsec) — strongSwan Cisco-compatible remote-access IKEv1 Aggressive + XAUTH + Mode-Config + ESP tunnel, 2 container bridge Docker):** demo scheme `cisco://user:pass@host?psk=&group=`. Client forced NAT-T (Aggressive AG1/AG2 group PSK UDP/500 → float UDP/4500 AG3) → XAUTH user/pass → Mode-Config virtual IP `10.41.0.1` + DNS → ESP tunnel mode; server quan sát **`XAuth authentication of 'testuser' successful` + `IKE_SA … ESTABLISHED` + `assigning virtual IP 10.41.0.1` + CHILD_SA `INSTALLED` `TS 0.0.0.0/0 === 10.41.0.1/32` (tunnel)**; ICMP gateway RTT 2ms + UDP DNS google.com qua tunnel OK (ESP decrypt 2 chiều). Teardown xác nhận (Delete ESP + ISAKMP). **Lần validate này phát hiện + sửa 2 BUG client** (self-pair offline bỏ sót): (1) XAUTH/Mode-Config reply **không echo Message-ID** server gửi ⇒ strongSwan "queueing/ignoring TRANSACTION request, queue full"; (2) reply **derive lại IV** thay vì **chain CBC IV** per Message-ID (RFC 2409 §5.5) ⇒ "invalid HASH_V1 payload length, decryption failed?". Sửa ở [`IkeV1Client.BuildTransaction(config, messageId)` + `TransactionCipher`](../TqkLibrary.VpnClient.Ipsec/Ike/V1/IkeV1Client.cs#L713). Test offline (Aggressive/XAUTH/Mode-Config/QM tunnel + ESP 2 chiều) ở [`IkeV1CiscoIpsecTests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests/IkeV1CiscoIpsecTests.cs); test client của driver (capabilities + guard + single-session) ở [`Drivers.CiscoIpsec.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.CiscoIpsec.Tests).
- **Còn lại (residual, không chặn client):** live-rekey Phase 2 ESP CHILD SA cần timer ~54 phút (~90% lifetime Phase2) hoặc đẩy >2³² gói — không khả thi trong một phiên lab ngắn; client-initiated rekey đã test offline. DPD live cần phiên >20s.
- **Group PSK + XAUTH** (auth) + **forced NAT-T** + **1 ESP CHILD SA / 1 IP ảo** + rekey Phase 2 gắn timer trong driver. **Group name truyền qua DRIVER ctor** (không có field GroupName trong `VpnCredentials`) — bám pattern Ikev2 (cấu hình trong ctor).
- **Thuần client**: không có code server; "responder" trong test chỉ là harness in-process (`SimulatedCiscoResponder`).
