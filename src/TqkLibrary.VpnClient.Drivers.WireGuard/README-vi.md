# TqkLibrary.VpnClient.Drivers.WireGuard

Driver **WireGuard** — ráp các khối protocol thuần ở [`WireGuard`](../TqkLibrary.VpnClient.WireGuard) (V3.a–V3.e) thành một tunnel **L3** chạy thật sau facade, trên **một transport UDP** (WireGuard chỉ UDP; 1 datagram = 1 message type-1/2/3/4, **không framing**). Chạy handshake `Noise_IKpsk2` vai **initiator** (type-1 + mac1 → type-2 → transport keys), bind data channel **type-4** vào [`WireGuardChannel`](../TqkLibrary.VpnClient.WireGuard/Transport/WireGuardChannel.cs) phơi qua [`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs), rồi bơm [`WireGuardPeerState`](../TqkLibrary.VpnClient.WireGuard/WireGuardPeerState.cs) trong timer loop cho **keepalive** + **rekey make-before-break** (handshake mới trên index mới chạy nền, swap channel khi response về). Config tĩnh [`WireGuardConfig`](../TqkLibrary.VpnClient.WireGuard/Config/WireGuardConfig.cs) point-to-point → `TunnelConfig` **tĩnh** (địa chỉ out-of-band, **không IPCP/DHCP**); full-tunnel allowed-ips `0.0.0.0/0, ::/0` (multi-peer routing để sau).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`WireGuard`](../TqkLibrary.VpnClient.WireGuard) thành 1 tunnel sống (mirror cấu trúc [`Drivers.OpenVpn`](../TqkLibrary.VpnClient.Drivers.OpenVpn)):

- **Transport**: UDP qua seam [`IWireGuardTransportFactory`](Transport/IWireGuardTransportFactory.cs) — production socket thật [`WireGuardSocketTransportFactory`](Transport/WireGuardSocketTransportFactory.cs) (bọc `IDatagramTransport` + receive loop), test inject loopback.
- **Control plane**: [`WireGuardHandshake`](../TqkLibrary.VpnClient.WireGuard/Handshake/WireGuardHandshake.cs) vai initiator (`CreateInitiation`+`StampOutgoingMacs` → `ConsumeResponse`/`ConsumeCookieReply` → `DeriveTransportKeys`); demux gói vào theo message type.
- **Data plane**: [`WireGuardTransport`](../TqkLibrary.VpnClient.WireGuard/DataChannel/WireGuardTransport.cs) (type-4, ChaCha20-Poly1305, counter u64 + anti-replay) bind vào [`WireGuardChannel`](../TqkLibrary.VpnClient.WireGuard/Transport/WireGuardChannel.cs) → `IPacketChannel`.
- **Timer/lifecycle**: [`WireGuardPeerState`](../TqkLibrary.VpnClient.WireGuard/WireGuardPeerState.cs) (`Evaluate(nowMs)` → keepalive/rekey/resend/abandon) + supervisor/auto-reconnect.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, exceptions, `IHostResolver` |
| Dùng | [WireGuard](../TqkLibrary.VpnClient.WireGuard) | `WireGuardHandshake`/`WireGuardMessageCodec` (handshake + codec), `WireGuardTransport`/`WireGuardChannel` (data channel), `WireGuardPeerState`/`WireGuardTimers` (timer state machine), `WireGuardConfig` (config tĩnh) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | `Curve25519DhGroup` (derive public key từ private key trong config) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseWireGuard(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.WireGuard/
├─ WireGuardDriver.cs                    IVpnProtocolDriver: capabilities (L3Ip/Noise/OutOfBand/Udp) + ConnectAsync(config+endpoint) → WireGuardConnection
├─ WireGuardConnection.cs                Điều phối: UDP transport → handshake initiator → bind data channel → timer loop (keepalive + rekey) + demux + reconnect
├─ WireGuardVpnConnection.cs             IVpnConnection: 1 session; OpenSessionAsync ném NotSupportedException (point-to-point = 1 IP)
├─ WireGuardVpnSession.cs                IVpnSession: PacketChannel ổn định + TunnelConfig tĩnh (không đổi khi rekey/reconnect)
├─ WireGuardReconnectOptions.cs          Chính sách auto-reconnect (backoff + jitter, mirror OpenVPN/IKEv2/L2TP)
├─ Transport/
│  ├─ IWireGuardTransportFactory.cs      Seam dựng UDP transport tới endpoint (production socket / test loopback)
│  ├─ WireGuardTransportHandle.cs        IDatagramTransport + SetReceiver + receive-pump trả về từ factory
│  └─ WireGuardSocketTransportFactory.cs Socket thật: UDP (UdpClient) + receive loop dispatch — live-only, cross-TFM
├─ Enums/WireGuardConnectionState.cs     Disconnected/Connecting/Connected/Reconnecting
└─ Models/WireGuardReconnectInfo.cs      Cờ AddressChanged (luôn false: WireGuard địa chỉ tĩnh)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `WireGuardDriver` | `IVpnProtocolDriver`: capabilities (`L3Ip`, **không PPP**, `Noise`, **PreSharedKey** (static keys + PSK), `Udp`, `OutOfBand`); `ConnectAsync` dựng `WireGuardConnection` từ `WireGuardConfig` + endpoint (host/port) | [WireGuardDriver.cs:17](WireGuardDriver.cs#L17) |
| `WireGuardConnection` | Bộ điều phối: resolve → `IWireGuardTransportFactory.ConnectAsync` (UDP) → handshake **initiator** (type-1 + mac1, đợi type-2) → bind `WireGuardTransport` vào `WireGuardChannel` qua `SwappablePacketChannel` → timer loop bơm `WireGuardPeerState` (keepalive + **rekey make-before-break**: handshake mới trên index mới, swap channel khi response về) + **demux** gói vào (type-2 hoàn tất, type-3 cookie-reply, type-4 data); phiên chết (handshake quá `REKEY_ATTEMPT_TIME` / fault) → supervisor reconnect | [WireGuardConnection.cs:31](WireGuardConnection.cs#L31) |
| `WireGuardVpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (1 IP point-to-point; multi-peer routing để sau) | [WireGuardVpnConnection.cs:6](WireGuardVpnConnection.cs#L6) |
| `WireGuardVpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config` tĩnh — cả hai không đổi khi rekey/reconnect (địa chỉ là config, không đàm phán) | [WireGuardVpnSession.cs:13](WireGuardVpnSession.cs#L13) |
| `WireGuardReconnectOptions` | `Enabled`/`MaxAttempts`/backoff/jitter (mirror OpenVPN) | [WireGuardReconnectOptions.cs:14](WireGuardReconnectOptions.cs#L14) |
| `IWireGuardTransportFactory` / `WireGuardTransportHandle` | Seam dựng UDP transport: trả `IDatagramTransport` + `SetReceiver` (đăng ký handler demux) + receive-pump (null nếu self-pump loopback) | [Transport/IWireGuardTransportFactory.cs:11](Transport/IWireGuardTransportFactory.cs#L11) |
| `WireGuardSocketTransportFactory` | Production: UDP qua `UdpClient` connected (1 datagram = 1 message, **không framing**) + receive loop raise handler; cross-TFM (net5+ overload ct, ns2.0 cancel-by-dispose) — **live-only** | [Transport/WireGuardSocketTransportFactory.cs:18](Transport/WireGuardSocketTransportFactory.cs#L18) |
| `WireGuardConnectionState` | `Disconnected`/`Connecting`/`Connected`/`Reconnecting` | [Enums/WireGuardConnectionState.cs:5](Enums/WireGuardConnectionState.cs#L5) |
| `WireGuardReconnectInfo` | Cờ `AddressChanged` (luôn false — địa chỉ tĩnh) sau reconnect | [Models/WireGuardReconnectInfo.cs:8](Models/WireGuardReconnectInfo.cs#L8) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`; IP-literal verbatim không-DNS.
2. **Transport**: `IWireGuardTransportFactory.ConnectAsync(IPEndPoint, ct)` dựng UDP socket → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)` gắn handler demux; chạy receive-pump nền (socket transport) — loopback tự pump.
3. **Handshake initiator** ([`StartHandshake`](WireGuardConnection.cs#L31)): cấp **local index** random → `WireGuardHandshake.CreateInitiation(localIndex)` → `WireGuardMessageCodec.EncodeInitiation` → `StampOutgoingMacs` (mac1 key-peer, mac2 nếu đã có cookie) → gửi gói type-1. Bật **timer loop trước khi đợi** (để initiation chưa được trả lời — vd responder trả cookie-reply — được resend kèm mac2 hợp lệ qua `ResendHandshake`).
4. **Đợi type-2** (`WaitForHandshakeAsync`, cap `REKEY_ATTEMPT_TIME`): demux gói vào — `OnResponse` decode type-2 + `VerifyIncomingMac1` (key-self) + `ConsumeResponse` (sai tag/PSK ⇒ drop); `OnCookieReply` decode type-3 + `ConsumeCookieReply` (cache cookie → mac2 lần resend). Hết cap ⇒ `VpnConnectionException`.
5. **Bind session** ([`BindSession`](WireGuardConnection.cs#L31)): `DeriveTransportKeys` → `WireGuardTransport(keys, peerIndex, localIndex)` → `WireGuardChannel(transport, send=transport.SendAsync, mtu, onSealed/onReceived → WireGuardPeerState)` → `_facade.SetInner(channel)`. `OnHandshakeCompleted` mở `_hasSession`.
6. **TunnelConfig**: `WireGuardConfig.ToTunnelConfig()` (address out-of-band, allowed-ips thành routes, MTU 1420) — tĩnh, không đàm phán.

## Vòng đời

- **Demux** (`OnInboundDatagram`): theo byte type — type-2 = response (hoàn tất handshake đang đợi theo `ReceiverIndex` echo lại local-index), type-3 = cookie-reply, type-4 = transport-data (`WireGuardChannel.Deliver`: `TryOpen` → kiểm receiver-index của mình → anti-replay → AEAD → raise `InboundIpPacket`, **drop payload rỗng = keepalive**). type-1 (initiation) là việc của server — drop.
- **Gửi data** (`WireGuardChannel.WriteIpPacketAsync`): `WireGuardTransport.Seal` (counter u64 đơn điệu, overflow ⇒ ném — rekey trước) → `transport.SendAsync`; callback đếm `OnDataSent` cho timer.
- **Timer loop** (250ms tick, `WireGuardPeerState.Evaluate(nowMs)`): `SendKeepalive` ⇒ `WireGuardChannel.SendKeepaliveAsync` (type-4 rỗng); `InitiateHandshake` ⇒ **rekey make-before-break** (`StartRekey`: handshake mới trên index mới chạy nền `_pending`, session cũ vẫn tải data tới khi response về thì `BindSession` swap channel); `ResendHandshake` ⇒ resend initiation (kèm mac2 nếu có cookie); `AbandonHandshake`/`SessionDead` ⇒ link lost.
- **Rekey make-before-break**: khác OpenVPN (re-establish) — WireGuard chạy handshake thứ 2 song song, `_active` cũ vẫn nhận/gửi tới khi `_pending` hoàn tất, rồi swap `_facade` sang channel mới (không gián đoạn). Make-before-break đúng tinh thần whitepaper §6.2.
- **Teardown** (`DisconnectAsync`): hủy reconnect đang chờ, hủy receive loop + timer, dispose transport.
- **Reconnect** (supervisor): mirror OpenVPN/IKEv2 — `EstablishAsync`/`ReconnectLoopAsync` backoff+jitter sau `SwappablePacketChannel` ổn định; địa chỉ tĩnh nên `Reconnected` cờ `AddressChanged=false`.

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Handshake | WireGuard whitepaper §5.4 (`Noise_IKpsk2`) | initiation/response/transport keys + mac1/mac2/cookie (xem [WireGuard README](../TqkLibrary.VpnClient.WireGuard/README-vi.md)) |
| Data channel | type-4 + ChaCha20-Poly1305 (RFC 8439) | nonce `0^4‖counter LE`, AAD rỗng, anti-replay 64-gói trên counter u64 |
| Timers | WireGuard whitepaper §6.2 | Rekey/Reject-After-Time 120s/180s, Rekey-Attempt 90s, Rekey-Timeout 5s, Keepalive-Timeout 10s, persistent-keepalive |
| Transport | UDP (WireGuard không TCP) | 1 datagram = 1 message, không framing |
| Address | out-of-band (config tĩnh) | không IPCP/DHCP — `WireGuardConfig` → `TunnelConfig` |

## Trạng thái & ghi chú

- **Đã có (V3.f)**: end-to-end **offline** — handshake Noise_IKpsk2 (initiator + mac1/mac2/cookie), data channel type-4 2 chiều, keepalive (persistent + passive), **rekey make-before-break** (swap channel), supervisor reconnect; config tĩnh point-to-point `0.0.0.0/0,::/0`; `UseWireGuard(config)`. Test offline qua **responder giả lập** (dùng chính `WireGuardHandshake` responder + `WireGuardTransport`) trên loopback UDP: handshake → IP round-trip 2 chiều → PSK → sai peer-key ⇒ fail → cookie/mac2 resend → rekey → persistent-keepalive → driver facade.
- **Chưa**:
  - **multi-peer routing** — hiện 1 peer full-tunnel allowed-ips `0.0.0.0/0,::/0`; nhiều `[Peer]` allowed-ips → bảng route trên channel là việc sau.
  - **roaming endpoint** (peer đổi địa chỉ UDP) — hiện endpoint cố định từ config/endpoint.
  - **validate live** (lab **Q.1** — WireGuard Docker): interop với `wg`/`wireguard-go` thật, cookie dưới tải thật, MTU/PMTU.
- **Tham chiếu**: WireGuard whitepaper "WireGuard: Next Generation Kernel Network Tunnel" (zx2c4) — **chỉ đọc spec/behavior, không copy GPL/kernel source**; thiết kế Noise [`08`](../../.docs/08-crypto-primitives.md) + taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.3.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`OpenVpnSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.OpenVpn/Transport/OpenVpnSocketTransportFactory.cs) (net5+ overload ct; ns2.0 cancel-by-dispose). `WireGuardConnection` giữ Span ngoài await (`Seal` tính đồng bộ trước await — an toàn C# 12).
