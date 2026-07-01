# TqkLibrary.VpnClient.Drivers.Ikev2

Driver **IKEv2-native** (RFC 7296) — kết nối trực tiếp tới gateway IKEv2/IPsec (strongSwan, libreswan, Windows RRAS…) **không qua L2TP/PPP**. Khác với [Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) (IKEv1 + L2TP + PPP), driver này dùng **IKEv2** + **Configuration Payload** lấy IP ảo + **ESP tunnel mode** đẩy thẳng gói IP vào userspace stack. Auth client: **PSK** (mặc định) hoặc **EAP-MSCHAPv2** (username/password, RFC 7296 §2.16) — tự chọn theo `VpnCredentials`. Auth responder (gateway): **PSK** mặc định, hoặc **chữ ký số / certificate** (RFC 7296 §2.15 method 1 RSA, 9/10/11 ECDSA) khi cấu hình `IkeCertificateTrust` (pin leaf hoặc trust CA) qua driver — verify CERT + chữ ký AUTH, fail ⇒ `VpnServerRejectedException`. Hỗ trợ **multi-traffic-selector** (nhiều subnet TSi/TSr, RFC 7296 §3.13).

## Vị trí kiến trúc

`PROTOCOL`-layer driver, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`Ipsec`](../TqkLibrary.VpnClient.Ipsec) thành 1 tunnel sống:

- **Control plane**: [`IkeClient`](../TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeClient.cs#L19) (IKE_SA_INIT + IKE_AUTH PSK **hoặc** EAP-MSCHAPv2 + CFG_REQUEST + DPD + DELETE + rekey CHILD_SA); EAP tái dùng codec [`MsChapV2`](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs) ở Crypto.
- **NAT-T**: [`NatTraversalChannel`](../TqkLibrary.VpnClient.Ipsec/Nat/NatTraversalChannel.cs#L13) (UDP/500→4500, non-ESP marker) — dùng chung với driver L2TP/IPsec.
- **Data plane**: [`EspTunnelChannel`](../TqkLibrary.VpnClient.Ipsec/Esp/EspTunnelChannel.cs#L12) — ESP tunnel mode (NextHeader 4/41) → `IPacketChannel` (không PPP/L2TP).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, exceptions, `IHostResolver`, **`Diagnostics`** (`VpnEventIds`/`VpnLogExtensions` — log handshake/DPD/rekey/reconnect, Q.2) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | base [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor/reconnect/backoff-jitter/facade/state, F.6) + [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14) |
| Dùng | [Ipsec](../TqkLibrary.VpnClient.Ipsec) | `Ike/V2` (IkeClient + payloads), `Esp` (EspSession/EspTunnelChannel), `Nat` (NAT-T) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseIkev2()` / `UseIkev2(IkeCertificateTrust)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Ikev2/
├─ Ikev2Driver.cs              IVpnProtocolDriver: capabilities + ConnectAsync → Ikev2Connection
├─ Ikev2Connection.cs          : ReconnectingVpnConnection<…> (F.6). Override Establish/Cleanup/StopAttemptLoop + ánh xạ state; giữ DPD/rekey IKE+CHILD SA/DELETE trên timer riêng (ngoài supervisor)
├─ Ikev2VpnConnection.cs       IVpnConnection: 1 session; OpenSessionAsync ném NotSupportedException (1 CHILD_SA)
├─ Ikev2VpnSession.cs          IVpnSession: PacketChannel ổn định + TunnelConfig; ApplyReconnect khi reconnect
├─ Ikev2ReconnectOptions.cs    : VpnReconnectOptions (F.6) — không thêm knob, giữ cho public API
├─ Enums/Ikev2ConnectionState.cs   Disconnected/Connecting/Connected/Reconnecting
└─ Models/Ikev2ReconnectInfo.cs    Địa chỉ mới + cờ AddressChanged sau reconnect
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `Ikev2Driver` | `IVpnProtocolDriver`: capabilities (L3Ip, **không PPP**, ESP, **PSK\|EAP** (+**Certificate** khi cấu hình `responderTrust`), ConfigPush), `ConnectAsync` dựng `Ikev2Connection`; có username+password ⇒ EAP, không ⇒ PSK (lệch một nửa ⇒ `ArgumentException`); ctor nhận `IkeCertificateTrust?` + danh sách `TrafficSelector` initiator/responder | [Ikev2Driver.cs:11](Ikev2Driver.cs#L11) |
| `Ikev2Connection` | Bộ điều phối, **kế thừa** [`ReconnectingVpnConnection<Ikev2ConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6): override `EstablishAsync` (forced NAT-T 500→4500 → IKE_SA_INIT → IKE_AUTH PSK **hoặc** EAP-MSCHAPv2 loop `RunEapAuthAsync` +CP → `EspTunnelChannel` bind sau `Facade`) + `CleanupAttemptResourcesAsync`/`StopAttemptLoop` + ánh xạ 4 state + `OnReconnected`. **Phần IKEv2-riêng giữ ngoài supervisor trên timer riêng**: keepalive DPD, rekey CHILD_SA make-before-break **+ rekey IKE SA** (`RekeyIkeSaAsync`, ~90% lifetime 8h), **DELETE SA cũ sau cả 2 loại rekey** (`SendDeleteAsync`); `DisconnectAsync` gửi DELETE IKE SA trước teardown base. Supervisor/reconnect/backoff-jitter/facade/lifetime/state ở base | [Ikev2Connection.cs:35](Ikev2Connection.cs#L35) |
| `Ikev2VpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (IKEv2 strictly 1 CHILD_SA ở driver này) | [Ikev2VpnConnection.cs:6](Ikev2VpnConnection.cs#L6) |
| `Ikev2VpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config`; `ApplyReconnect` cập nhật IP/DNS sau reconnect | [Ikev2VpnSession.cs:10](Ikev2VpnSession.cs#L10) |
| `Ikev2ReconnectOptions` | **kế thừa** [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14) (F.6): `Enabled`/`MaxAttempts`/backoff/jitter — IKEv2 không thêm knob, giữ named type cho public API | [Ikev2ReconnectOptions.cs:12](Ikev2ReconnectOptions.cs#L12) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`.
2. **NAT-T channel** mở cổng nguồn ephemeral (`localPort=0`) → receive loop demux IKE/ESP.
3. **IKE_SA_INIT** (UDP/500): `IkeClient.BuildInitRequest` → `ProcessInitResponse` (DH MODP-2048, SK_*).
4. **Float 4500** (`SwitchToNatTPort`) — forced NAT-T: cổng nguồn ephemeral ⇒ gateway luôn thấy NATed.
5. **IKE_AUTH** (UDP/4500, SK-encrypted):
   - **PSK**: IDi(IPv4 0.0.0.0) + AUTH(PSK) + **CFG_REQUEST** + SAi2 (chào AES-CBC-256 + AES-GCM) + TSi/TSr (1 selector match-all hoặc **nhiều subnet** khi cấu hình). Khi cấu hình `IkeCertificateTrust` còn gửi **CERTREQ** (RFC 7296 §3.7). `ProcessAuthResponse` verify AUTH responder → CHILD_SA keys + đọc **CFG_REPLY** (virtual IP/DNS).
     - **Verify responder bằng cert** (RFC 7296 §2.15 method 1/9/10/11): nếu AUTH responder là **chữ ký số**, [`IkeClient.VerifyResponderAuth`](../TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeClient.cs) parse CERT payload → [`IkeCertificateTrust.IsTrusted`](../TqkLibrary.VpnClient.Ipsec/Ike/V2/Models/IkeCertificateTrust.cs#L11) (pin leaf hoặc chain tới CA) → [`IkeSignatureAuth.VerifyResponderSignature`](../TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeSignatureAuth.cs#L22) verify chữ ký trên `ResponderSignedOctets` bằng public key của cert (RSA PKCS#1 cả 2 TFM; ECDSA chỉ net5+); cert không tin / chữ ký sai / responder rớt xuống PSK (downgrade) ⇒ `VpnServerRejectedException`. Khi **không** cấu hình trust: giữ nguyên hành vi PSK cũ (mismatch ⇒ auth fail).
   - **EAP-MSCHAPv2** (`RunEapAuthAsync`): IDi = username (Rfc822/FQDN), IKE_AUTH đầu **không** AUTH (báo dùng EAP); loop `BuildAuthRequestEap`→`ProcessAuthResponseEap` chạy EAP-Identity → MSCHAPv2 Challenge/Response/Success qua các message-id liên tiếp; cả 2 bên tính AUTH cuối từ **EAP MSK**. Responder vẫn xác thực bằng PSK (lab Q.1 sẽ kiểm cert). Không có IP ảo ⇒ `VpnServerRejectedException`.
6. **Data plane**: dựng `EspSession` (suite gateway chọn) → `EspTunnelChannel(esp, natt.SendEspAsync, mtu=1400)`; `Facade.SetInner(dataPlane)` (facade ổn định của base) → `MarkConnected()`; bật keepalive/rekey timer.

## Vòng đời

- **DPD keepalive** (RFC 7296 §2.4): mỗi 20s gửi INFORMATIONAL rỗng (`BuildDeadPeerDetection`) qua exchange-gate; quá 3 lần không hồi đáp ⇒ link lost. Probe đến từ gateway (INFORMATIONAL rỗng) ⇒ ack bằng `BuildInformationalResponse`.
- **Rekey CHILD_SA** (make-before-break): timer ~90% lifetime (1h) **hoặc** watermark sequence ESP ~2³² (`EspTunnelChannel.RekeyNeeded`) → `BuildRekeyChildSaRequest`/`ProcessRekeyChildSaResponse` → `EspTunnelChannel.SwapSession` (gửi SA mới ngay, giữ SA cũ nhận thêm 10s rồi `DropPreviousInbound`); sau swap, **DELETE CHILD_SA cũ** trên IKE SA đang sống — `BuildDeleteChildSa(oldInboundSpi)` (SPI cũ capture trước khi `ProcessRekeyChildSaResponse` ghi đè) gửi best-effort qua `SendDeleteAsync` (RFC 7296 §2.8).
- **Rekey IKE SA** (Phase-1-equivalent, RFC 7296 §1.3.2/§2.18): timer ~90% lifetime (8h) → `RekeyIkeSaAsync` gửi `BuildRekeyIkeSaRequest` (CREATE_CHILD_SA: SPI/DH/Nonce mới) trên SK channel **cũ** → `ProcessRekeyIkeSaResponse` swing SK_* mới + reset message-id về 0. **Chỉ refresh khóa control-channel** — ESP CHILD_SA/data plane không đổi nên không cần make-before-break trên traffic. Sau swing, **DELETE IKE SA cũ**: wire đã được `IkeClient` mã hóa bằng SK_* **cũ** + SPI cũ ngay trước swing (`TakePendingOldIkeSaDelete`) → gửi best-effort trên SA cũ qua `SendDeleteAsync` (không chờ ACK trên SA sắp chết). Chung guard `_rekeyInProgress` với rekey CHILD_SA (không chạy chồng).
- **Teardown** (`DisconnectAsync` override): gửi `BuildDeleteIkeSa` (best-effort) **trước**, rồi gọi `DisconnectCoreAsync` của base (hủy reconnect đang chờ, dừng timer qua `StopAttemptLoop`, hủy receive loop, đóng socket).
- **Auto-reconnect** (ở base, F.6): gateway DELETE / DPD chết ⇒ gọi `OnLinkLost` của base → `ReconnectLoopAsync` dựng lại tunnel (`EstablishAsync`) sau `Facade` (`SwappablePacketChannel`); backoff mũ + jitter; `OnReconnected` raise `Reconnected(Ikev2ReconnectInfo)`. **Rekey IKE/CHILD SA cố ý KHÔNG đi qua supervisor** — làm tươi SA in-place, tunnel không rớt.
- **Logging/diagnostics (Q.2)**: ctor `Ikev2Connection`/`Ikev2Driver` nhận `ILoggerFactory?` (mặc định [`NullLogger`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs) ⇒ no-op, **ADDITIVE không đổi hành vi**). Log qua [`VpnLogExtensions`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs): IKE_SA_INIT + IKE_AUTH (PSK/EAP)→Handshake (auth fail→HandshakeFailed); bind ESP plane→HandshakeCompleted; DPD probe→Keepalive; rekey CHILD_SA/IKE SA→Rekey; `SetState`→StateChanged; `OnLinkLost`→LinkLost; reconnect attempt/success→ReconnectAttempt/Reconnected.

## Trạng thái & ghi chú

- **VALIDATE LIVE ✓ (2026-06-24, lab [`ikev2-native`](../../lab/ikev2-native) — strongSwan 5.9.5 IKEv2 PSK/EAP + ESP tunnel + CP, 2 container bridge Docker):** demo scheme `ikev2://…?psk=` (+ `--ikev2-eap`). **Đường PSK:** client forced NAT-T (IKE_SA_INIT UDP/500 → IKE_AUTH PSK float UDP/4500) → CP cấp virtual IP `10.40.0.1` + DNS → ESP tunnel mode; server quan sát **`ESTABLISHED` + IKE proposal khớp đúng `AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048` + CHILD_SA `INSTALLED, TUNNEL, ESP in UDP` + `bytes_i > 0`** (giải mã 2 chiều); ICMP gateway RTT 2ms + UDP DNS qua tunnel OK. **DPD** xác nhận (server thấy INFORMATIONAL request 2/3 mỗi ~20s). **Teardown** xác nhận (`DisconnectAsync` → server `received DELETE for IKE_SA … ESTABLISHED ⇒ DELETING ⇒ DESTROYING`). **Đường EAP-MSCHAPv2** (`--ikev2-eap`): server `ikev2-eap[N]: ESTABLISHED … [testuser]` + CHILD_SA `INSTALLED, TUNNEL` + bytes_i>0. **Lần validate này phát hiện + sửa BUG MSK** (xem [`10`](../../.docs/10-codebase-architecture-and-flow.md) §"Khác biệt"): [`MsChapV2.DeriveMsk`](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs#L110) **đảo thứ tự** send/recv key trong MSK 64-byte ⇒ EAP "succeeds" nhưng IKEv2 AUTH-with-MSK (RFC 7296 §2.16) **fail trên gateway** (`verification of AUTH payload with EAP MSK failed`); test offline KHÔNG bắt được vì harness responder dùng **chung** `DeriveMsk` (đối xứng tự-khớp); sửa = layout `send||recv` (dual của server's `recv||send`). Toán protocol (handshake, CP, DPD/DELETE, rekey) test offline ở [`Ipsec.Ike.Tests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests) + data plane ở [`Ipsec.Esp.Tests`](../../tests/TqkLibrary.VpnClient.Ipsec.Esp.Tests); test client của driver (capabilities + guard) ở [`Drivers.Ikev2.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Ikev2.Tests).
- **Còn lại (residual, không chặn client):** live-rekey CHILD_SA / IKE SA cần timer ~54 phút / ~7.2h (timer cứng ~90% lifetime) hoặc đẩy >2³² gói — không khả thi trong một phiên lab ngắn; client-initiated rekey + DELETE-SA-cũ đã test offline ([`Ipsec.Ike.Tests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests)). Honest-first NAT-T; responder AUTH bằng cert trên **đường EAP**.
- **PSK hoặc EAP-MSCHAPv2** (auth client) + **PSK hoặc cert** (auth responder) + **forced NAT-T** + **1 CHILD_SA / 1 IP ảo** + **multi-traffic-selector** (offer nhiều subnet) + rekey **CHILD_SA và IKE SA** đều gắn timer trong driver, **mỗi loại rekey phát DELETE cho SA cũ** (không để gateway tự timeout). Responder-cert + multi-TS test offline self-interop ở [`IkeCertAuthHandshakeTests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests/IkeCertAuthHandshakeTests.cs) (responder ký AUTH bằng RSA test-cert; cert sai/CA không tin/chữ ký hỏng ⇒ từ chối). **Chưa**: honest-first NAT-T; responder AUTH bằng cert trên **đường EAP** (EAP hiện verify responder bằng PSK) — xem roadmap V.1/[`11`](../../.docs/11-todo-roadmap.md).
- **Logging/diagnostics (Q.2) đã có**: luồng `ILoggerFactory?` qua driver/connection → trace handshake (IKE_SA_INIT/IKE_AUTH)/HandshakeCompleted/DPD/rekey/state/link-lost/reconnect (xem Vòng đời); mặc định no-op, không đổi hành vi runtime.
- **Thuần client**: không có code server; "responder" trong test chỉ là harness in-process.
