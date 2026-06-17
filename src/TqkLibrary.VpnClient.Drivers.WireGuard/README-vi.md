# TqkLibrary.VpnClient.Drivers.WireGuard

Driver **WireGuard** — ráp các khối protocol thuần ở [`WireGuard`](../TqkLibrary.VpnClient.WireGuard) (V3.a–V3.f) thành một tunnel **L3** chạy thật sau facade, trên **một transport UDP** (WireGuard chỉ UDP; 1 datagram = 1 message type-1/2/3/4, **không framing**). Chạy handshake `Noise_IKpsk2` vai **initiator** với **mỗi peer cấu hình** (type-1 + mac1 → type-2 → transport keys), bind data channel **type-4** của từng peer vào [`WireGuardChannel`](../TqkLibrary.VpnClient.WireGuard/Transport/WireGuardChannel.cs) sau một [`WireGuardMultiPeerChannel`](../TqkLibrary.VpnClient.WireGuard/Transport/WireGuardMultiPeerChannel.cs) ổn định (phơi qua [`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs)), rồi bơm một [`WireGuardPeerState`](../TqkLibrary.VpnClient.WireGuard/WireGuardPeerState.cs) **mỗi peer** trong timer loop cho **keepalive** + **rekey make-before-break per-peer** (handshake mới trên index mới chạy nền, swap channel của peer đó khi response về). **Crypto-routing**: mỗi gói outbound route tới peer có allowed-ips phủ địa chỉ đích bằng longest-prefix match ([`WireGuardCryptoRouter`](../TqkLibrary.VpnClient.WireGuard/Routing/WireGuardCryptoRouter.cs)); không peer nào phủ ⇒ drop. Config tĩnh [`WireGuardConfig`](../TqkLibrary.VpnClient.WireGuard/Config/WireGuardConfig.cs) (single-peer hoặc multi-peer qua [`WireGuardPeer`](../TqkLibrary.VpnClient.WireGuard/Config/WireGuardPeer.cs)) → `TunnelConfig` **tĩnh** (địa chỉ out-of-band, **không IPCP/DHCP**); single-peer full-tunnel allowed-ips `0.0.0.0/0, ::/0`.

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`WireGuard`](../TqkLibrary.VpnClient.WireGuard) thành 1 tunnel sống (mirror cấu trúc [`Drivers.OpenVpn`](../TqkLibrary.VpnClient.Drivers.OpenVpn)):

- **Transport**: UDP qua seam [`IWireGuardTransportFactory`](Transport/IWireGuardTransportFactory.cs) — production socket thật [`WireGuardSocketTransportFactory`](Transport/WireGuardSocketTransportFactory.cs) (bọc `IDatagramTransport` + receive loop), test inject loopback.
- **Control plane**: [`WireGuardHandshake`](../TqkLibrary.VpnClient.WireGuard/Handshake/WireGuardHandshake.cs) vai initiator **mỗi peer** (`CreateInitiation`+`StampOutgoingMacs` → `ConsumeResponse`/`ConsumeCookieReply` → `DeriveTransportKeys`); demux gói vào theo message type (type-2/type-3 khớp peer theo receiver-index qua mọi peer).
- **Data plane**: [`WireGuardTransport`](../TqkLibrary.VpnClient.WireGuard/DataChannel/WireGuardTransport.cs) (type-4, ChaCha20-Poly1305, counter u64 + anti-replay) mỗi peer bind vào một [`WireGuardChannel`](../TqkLibrary.VpnClient.WireGuard/Transport/WireGuardChannel.cs) sau [`WireGuardMultiPeerChannel`](../TqkLibrary.VpnClient.WireGuard/Transport/WireGuardMultiPeerChannel.cs) → `IPacketChannel`; outbound crypto-route theo dest ([`WireGuardCryptoRouter`](../TqkLibrary.VpnClient.WireGuard/Routing/WireGuardCryptoRouter.cs) longest-prefix).
- **Timer/lifecycle**: một [`WireGuardPeerState`](../TqkLibrary.VpnClient.WireGuard/WireGuardPeerState.cs) **mỗi peer** (`Evaluate(nowMs)` → keepalive/rekey/resend/abandon) + supervisor/auto-reconnect.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, exceptions, `IHostResolver`, **`Diagnostics`** (`VpnEventIds`/`VpnDropReason`/`VpnLogExtensions` — log handshake/rekey/drop, Q.2) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection<TState>`** (base supervisor F.6: facade/lifetime/`OnLinkLost`/`ReconnectLoopAsync`/backoff-jitter/`SetState`/clock) + **`VpnReconnectOptions`** (`WireGuardReconnectOptions` kế thừa) |
| Dùng | [WireGuard](../TqkLibrary.VpnClient.WireGuard) | `WireGuardHandshake`/`WireGuardMessageCodec` (handshake + codec), `WireGuardTransport`/`WireGuardChannel`/`WireGuardMultiPeerChannel` (data channel + route), `WireGuardCryptoRouter` (longest-prefix), `WireGuardPeerState`/`WireGuardTimers` (timer state machine), `WireGuardConfig`/`WireGuardPeer` (config tĩnh đa-peer) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | `Curve25519DhGroup` (derive public key từ private key trong config) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseWireGuard(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.WireGuard/
├─ WireGuardDriver.cs                    IVpnProtocolDriver: capabilities (L3Ip/Noise/OutOfBand/Udp) + ConnectAsync(config+endpoint) → WireGuardConnection
├─ WireGuardConnection.cs                Điều phối (kế thừa ReconnectingVpnConnection<…> F.6): UDP transport → handshake initiator mỗi peer → bind data channel vào WireGuardMultiPeerChannel → timer loop per-peer (keepalive + rekey) + demux; supervisor/reconnect ở base
├─ WireGuardVpnConnection.cs             IVpnConnection: 1 session (toàn bộ peer dùng chung 1 IP stack/kênh route); OpenSessionAsync ném NotSupportedException
├─ WireGuardVpnSession.cs                IVpnSession: PacketChannel ổn định + TunnelConfig tĩnh (không đổi khi rekey/reconnect)
├─ WireGuardReconnectOptions.cs          Kế thừa VpnReconnectOptions (Drivers.Core, F.6) — giữ type tên riêng cho public API
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
| `WireGuardConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection<WireGuardConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L25) (supervisor F.6): override `EstablishAsync` (resolve → `IWireGuardTransportFactory.ConnectAsync` (UDP) → dựng `WireGuardMultiPeerChannel` + N `Peer` (mỗi peer 1 `WireGuardPeerState`); handshake **initiator** type-1 + mac1 **tới mọi peer**, đợi tất cả type-2 → bind mỗi `WireGuardTransport` vào `WireGuardChannel` qua `SetPeerChannel` → `Facade.SetInner(channel)` → `MarkConnected`) + `CleanupAttemptResourcesAsync`/`StopAttemptLoop`; timer loop riêng (`_timerRunning`) bơm `WireGuardPeerState` **từng peer** (keepalive + **rekey make-before-break per-peer**: handshake mới trên index mới, swap channel của peer đó khi response về) + **demux** gói vào (type-2/type-3 khớp peer theo receiver-index, type-4 deliver qua channel route); một peer chết (handshake quá `REKEY_ATTEMPT_TIME` / fault) → `OnLinkLost` của base arm reconnect | [WireGuardConnection.cs:42](WireGuardConnection.cs#L42) |
| `WireGuardVpnConnection` | `IVpnConnection`: 1 session (toàn bộ peer chia sẻ 1 kênh route/IP stack); `OpenSessionAsync` ⇒ `NotSupportedException` | [WireGuardVpnConnection.cs:6](WireGuardVpnConnection.cs#L6) |
| `WireGuardVpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config` tĩnh — cả hai không đổi khi rekey/reconnect (địa chỉ là config, không đàm phán) | [WireGuardVpnSession.cs:13](WireGuardVpnSession.cs#L13) |
| `WireGuardReconnectOptions` | Kế thừa [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L17) (F.6) — `Enabled`/`MaxAttempts`/backoff/jitter ở base; giữ tên riêng cho public API | [WireGuardReconnectOptions.cs:12](WireGuardReconnectOptions.cs#L12) |
| `IWireGuardTransportFactory` / `WireGuardTransportHandle` | Seam dựng UDP transport: trả `IDatagramTransport` + `SetReceiver` (đăng ký handler demux) + receive-pump (null nếu self-pump loopback) | [Transport/IWireGuardTransportFactory.cs:11](Transport/IWireGuardTransportFactory.cs#L11) |
| `WireGuardSocketTransportFactory` | Production: UDP qua `UdpClient` connected (1 datagram = 1 message, **không framing**) + receive loop raise handler; cross-TFM (net5+ overload ct, ns2.0 cancel-by-dispose) — **live-only** | [Transport/WireGuardSocketTransportFactory.cs:18](Transport/WireGuardSocketTransportFactory.cs#L18) |
| `WireGuardConnectionState` | `Disconnected`/`Connecting`/`Connected`/`Reconnecting` | [Enums/WireGuardConnectionState.cs:5](Enums/WireGuardConnectionState.cs#L5) |
| `WireGuardReconnectInfo` | Cờ `AddressChanged` (luôn false — địa chỉ tĩnh) sau reconnect | [Models/WireGuardReconnectInfo.cs:8](Models/WireGuardReconnectInfo.cs#L8) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`; IP-literal verbatim không-DNS.
2. **Transport**: `IWireGuardTransportFactory.ConnectAsync(IPEndPoint, ct)` dựng UDP socket → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)` gắn handler demux; chạy receive-pump nền (socket transport) — loopback tự pump.
3. **Dựng peer + kênh route**: `WireGuardConfig.EnumeratePeers()` ra danh sách peer; dựng `WireGuardMultiPeerChannel` (router longest-prefix `WireGuardCryptoRouter.Build` từ allowed-ips mọi peer) + N `Peer` (mỗi peer 1 `WireGuardPeerState`, timer kèm persistent-keepalive riêng của peer).
4. **Handshake initiator mỗi peer** ([`StartHandshake`](WireGuardConnection.cs#L184)): cho từng peer cấp **local index** random → `WireGuardHandshake.CreateInitiation(localIndex)` → `EncodeInitiation` → `StampOutgoingMacs` (mac1 key-peer, mac2 nếu có cookie) → gửi type-1. Bật **timer loop trước khi đợi** (initiation chưa trả lời — vd cookie-reply — được resend kèm mac2 qua `ResendHandshake`).
5. **Đợi type-2 mọi peer** (`WaitForHandshakeAsync`, cap `REKEY_ATTEMPT_TIME`): demux gói vào — `OnResponse` khớp peer theo `ReceiverIndex` (echo local-index) qua mọi peer + `VerifyIncomingMac1` + `ConsumeResponse`; `OnCookieReply` cache cookie. Một peer hết cap ⇒ `VpnConnectionException`.
6. **Bind session mỗi peer** ([`BindSession`](WireGuardConnection.cs#L207)): `DeriveTransportKeys` → `WireGuardTransport(keys, peerIndex, localIndex)` → `WireGuardChannel(...)` → `WireGuardMultiPeerChannel.SetPeerChannel(peerIndex, channel)`. Sau khi mọi peer bind: `Facade.SetInner(multiPeerChannel)` → `MarkConnected`.
7. **TunnelConfig**: `WireGuardConfig.ToTunnelConfig()` (address out-of-band, routes = hợp allowed-ips mọi peer, MTU 1420) — tĩnh, không đàm phán.

## Vòng đời

- **Demux** (`OnInboundDatagram`): theo byte type — type-2 = response (`MatchPendingHandshake` quét mọi peer tìm session có local-index khớp `ReceiverIndex`), type-3 = cookie-reply (cũng khớp theo receiver-index), type-4 = transport-data (`WireGuardMultiPeerChannel.Deliver`: thử từng peer channel → peer mở được nhận gói; raise `InboundIpPacket`, **drop payload rỗng = keepalive**). type-1 (initiation) là việc của server — drop.
- **Gửi data** (`WireGuardMultiPeerChannel.WriteIpPacketAsync`): đọc dest → `WireGuardCryptoRouter.TryRoute` longest-prefix → peer → `WireGuardChannel.WriteIpPacketAsync` (`WireGuardTransport.Seal` counter u64, overflow ⇒ ném) → `transport.SendAsync`; callback `OnDataSent` cho timer của peer. **Không route** ⇒ drop (`VpnDropReason.NoRoute`); single-peer ⇒ peer 0 không cần parse.
- **Timer loop** (250ms tick) duyệt **từng peer** gọi `WireGuardPeerState.Evaluate(nowMs)`: `SendKeepalive` ⇒ `WireGuardChannel.SendKeepaliveAsync` của peer (type-4 rỗng); `InitiateHandshake` ⇒ **rekey make-before-break per-peer** (`StartRekey`: handshake mới trên index mới chạy nền `peer.Pending`, session cũ vẫn tải data tới khi response về thì `BindSession` swap channel của peer đó); `ResendHandshake` ⇒ resend initiation; `AbandonHandshake`/`SessionDead` ⇒ link lost (một peer chết hạ toàn bộ attempt).
- **Rekey make-before-break per-peer**: khác OpenVPN (re-establish) — WireGuard chạy handshake thứ 2 song song cho một peer, `peer.Active` cũ vẫn nhận/gửi tới khi `peer.Pending` hoàn tất, rồi `SetPeerChannel` swap channel peer đó (các peer khác không động). Make-before-break đúng tinh thần whitepaper §6.2.
- **Teardown** (`DisconnectAsync`): hủy reconnect đang chờ, hủy receive loop + timer, dispose transport.
- **Reconnect** (supervisor): nay nằm ở base [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L25) (F.6) — `OnLinkLost` arm `ReconnectLoopAsync` (backoff+jitter) gọi `EstablishAsync` của driver sau `SwappablePacketChannel` ổn định; địa chỉ tĩnh nên `OnReconnected` raise `Reconnected` cờ `AddressChanged=false`.
- **Logging/diagnostics (Q.2)**: ctor `WireGuardConnection`/`WireGuardDriver` nhận `ILoggerFactory?` (mặc định [`NullLogger`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs) ⇒ no-op, **ADDITIVE không đổi hành vi**). Log qua [`VpnLogExtensions`](../TqkLibrary.VpnClient.Abstractions/Diagnostics/Extensions/VpnLogExtensions.cs): `SetState`→StateChanged; gửi/nhận type-1/type-2 + bind→Handshake/HandshakeCompleted; quá `REKEY_ATTEMPT_TIME`→HandshakeFailed; rekey start/swap→Rekey; keepalive type-4→Keepalive; demux drop type-2 (mac1/AEAD/no-match)/type-4 không-deliver→PacketDropped (`VpnDropReason`); `OnLinkLost`→LinkLost; reconnect attempt/success→ReconnectAttempt/Reconnected.

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
- **Đã có (V.3 multi-peer)**: nhiều `[Peer]` (`WireGuardConfig.Peers`/`WireGuardPeer`), mỗi peer handshake/timer/transport-keys độc lập; outbound **crypto-routing** longest-prefix (`WireGuardCryptoRouter` qua `WireGuardMultiPeerChannel`) chọn peer theo địa chỉ đích (v4+v6), inbound type-4 gán về peer mở được; không peer nào phủ ⇒ drop. Test offline `WireGuardMultiPeerTests.cs` (2 peer: 10.0.0.0/24 vs 0.0.0.0/0 — LAN→peer1, internet→peer0, v6→peer0; no-route drop nhưng kênh vẫn sống) + `WireGuardCryptoRoutingTests.cs` (ở project [WireGuard](../TqkLibrary.VpnClient.WireGuard): IpPrefix v4/v6/mask, longest-prefix thắng /8, tie = peer trước, no-match, skip CIDR sai).
- **Đã có (Q.2)**: luồng `ILoggerFactory?` qua driver/connection → trace state/handshake/rekey/keepalive/link-lost/reconnect/drop (xem Vòng đời). Test offline `WireGuardLoggingTests.cs`: logger giả lập bắt Handshake/HandshakeCompleted/StateChanged khi connect (+round-trip vẫn xanh), gói type-2 ngoại lai ⇒ PacketDropped, sai peer-key ⇒ HandshakeFailed, NullLogger no-op.
- **Chưa**:
  - **per-peer endpoint riêng tới địa chỉ khác nhau** — `WireGuardPeer.Endpoint` đã có trong model nhưng data plane hiện gửi mọi peer qua **một** UDP socket connected tới endpoint của connection (mô hình 1 listen-socket); gửi tới N endpoint khác nhau cần unconnected socket + SendTo (validate live Q.1).
  - **roaming endpoint** (peer đổi địa chỉ UDP) — hiện endpoint cố định từ config/endpoint.
  - **validate live** (lab **Q.1** — WireGuard Docker): interop với `wg`/`wireguard-go` thật, cookie dưới tải thật, MTU/PMTU, multi-peer thật.
- **Tham chiếu**: WireGuard whitepaper "WireGuard: Next Generation Kernel Network Tunnel" (zx2c4) — **chỉ đọc spec/behavior, không copy GPL/kernel source**; thiết kế Noise [`08`](../../.docs/08-crypto-primitives.md) + taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.3.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`OpenVpnSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.OpenVpn/Transport/OpenVpnSocketTransportFactory.cs) (net5+ overload ct; ns2.0 cancel-by-dispose). `WireGuardConnection` giữ Span ngoài await (`Seal` tính đồng bộ trước await — an toàn C# 12).
