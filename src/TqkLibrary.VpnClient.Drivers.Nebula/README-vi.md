# TqkLibrary.VpnClient.Drivers.Nebula

Driver **Nebula** (Slack mesh VPN) — ráp các khối protocol thuần ở [`Nebula`](../TqkLibrary.VpnClient.Nebula) (V.7.1 phase a: Noise IX handshake + cert codec + packet header codec) thành một tunnel **L3** chạy thật sau facade, trên **transport UDP** (Nebula chỉ UDP; 1 datagram = 1 gói Nebula — handshake/message/recv-error, **không framing**). Chạy handshake `Noise_IX_25519_AESGCM_SHA256` vai **initiator** với peer cấu hình (stage-1 `e,s` plaintext → stage-2 `e,ee,se,s,es` AEAD → transport keys AES-256-GCM), **verify cert responder** với CA mạng (Ed25519), bind data plane **type-1 (Message)** vào [`NebulaChannel`](DataChannel/NebulaChannel.cs) sau một [`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs) ổn định, rồi bơm timer loop giữ tunnel sống (**re-handshake make-before-break định kỳ** + resend stage-1 chưa trả lời). Config tĩnh [`NebulaConfig`](Config/NebulaConfig.cs) (CA cert, host cert + X25519 key, peer endpoint `static_host_map`, overlay IP/CIDR, MTU 1300) → `TunnelConfig` **tĩnh** (overlay nướng sẵn trong cert, **không IPCP/DHCP**). Point-to-point với endpoint tĩnh (bỏ qua lighthouse discovery động — đủ cho 2-node).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`Nebula`](../TqkLibrary.VpnClient.Nebula) thành 1 tunnel sống (mirror cấu trúc [`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard)):

- **Transport**: UDP qua seam [`INebulaTransportFactory`](Transport/INebulaTransportFactory.cs) — production socket thật [`NebulaSocketTransportFactory`](Transport/NebulaSocketTransportFactory.cs) (`UdpClient` connected + receive loop), test inject loopback. 1 transport tới peer endpoint; receive loop bơm chung `OnInboundDatagram` demux theo message type.
- **Control plane**: [`NebulaNoiseIxHandshake`](../TqkLibrary.VpnClient.Nebula/Handshake/NebulaNoiseIxHandshake.cs) vai initiator (`CreateInitiation` payload protobuf `NebulaHandshake` → `ConsumeResponse` → `Split`); verify cert responder qua [`NebulaCertificateValidator`](../TqkLibrary.VpnClient.Nebula/Certificate/NebulaCertificateValidator.cs) (recombine static pubkey từ Noise `s` token → Ed25519 verify against CA).
- **Data plane**: [`NebulaTransport`](DataChannel/NebulaTransport.cs) (type-1 Message, AES-256-GCM, counter u64 + anti-replay) bind vào [`NebulaChannel`](DataChannel/NebulaChannel.cs) → `IPacketChannel`. Header 16-byte = **AAD** (`RemoteIndex`=responderIndex routing, `MessageCounter`=nonce), nonce `0^4‖counter(8 BE)`.
- **Timer/lifecycle**: timer loop (250ms) resend stage-1 chưa trả lời + **re-handshake make-before-break** định kỳ (handshake mới trên index mới chạy nền, swap channel khi response về) + supervisor/auto-reconnect (F.6).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, exceptions, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions` — log handshake/rekey/drop, Q.2) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection<TState>`** (base supervisor F.6: facade/lifetime/`OnLinkLost`/`ReconnectLoopAsync`/backoff-jitter/`SetState`/clock) + **`VpnReconnectOptions`** (`NebulaReconnectOptions` kế thừa) |
| Dùng | [Nebula](../TqkLibrary.VpnClient.Nebula) | `NebulaNoiseIxHandshake` (handshake IX), `NebulaCertificateCodec`/`NebulaCertificateValidator` (cert protobuf + Ed25519 verify), `NebulaHandshakePayloadCodec` (payload `NebulaHandshake`), `NebulaHeaderCodec`/`NebulaHeader` (header 16B = AAD) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | `AntiReplayWindow` (tái dùng trong `NebulaReplayProtector` 64-bit), `AesGcmCipher` (data-plane AEAD mặc định) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseNebula(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Nebula/
├─ NebulaDriver.cs                    IVpnProtocolDriver: capabilities (L3Ip/Noise/Certificate/OutOfBand/Udp) + ConnectAsync(config+endpoint) → NebulaConnection
├─ NebulaConnection.cs                Điều phối (kế thừa ReconnectingVpnConnection<…> F.6): UDP transport → handshake IX initiator + verify cert → bind NebulaChannel → timer loop (re-handshake make-before-break) + demux; supervisor/reconnect ở base
├─ NebulaVpnConnection.cs             IVpnConnection: 1 session point-to-point; OpenSessionAsync ném NotSupportedException
├─ NebulaVpnSession.cs               IVpnSession: PacketChannel ổn định + TunnelConfig tĩnh (không đổi khi re-handshake/reconnect)
├─ NebulaReconnectOptions.cs         Kế thừa VpnReconnectOptions (Drivers.Core, F.6) — giữ type tên riêng cho public API
├─ NebulaDriverConstants.cs          MTU 1300, tag 16B, nonce 12B
├─ Config/NebulaConfig.cs            CA/host cert + X25519 key + peer endpoint + overlay IP/CIDR + MTU → ToTunnelConfig() (overlay từ cert nếu không đè)
├─ DataChannel/
│  ├─ NebulaTransport.cs             Type-1 Message seal/open: header=AAD, nonce 0^4‖counter(8 BE), AES-256-GCM, counter u64 từ 1
│  ├─ NebulaChannel.cs               IPacketChannel: WriteIpPacketAsync seal → send; Deliver mở type-1 → InboundIpPacket
│  └─ NebulaReplayProtector.cs       Anti-replay 64-bit (tái dùng Crypto AntiReplayWindow per high-32 epoch — như WireGuardReplayProtector)
├─ Transport/
│  ├─ INebulaTransportFactory.cs     Seam dựng UDP transport tới endpoint (production socket / test loopback)
│  ├─ NebulaTransportHandle.cs       IDatagramTransport + SetReceiver + receive-pump trả về từ factory
│  └─ NebulaSocketTransportFactory.cs Socket thật: UDP (UdpClient) + receive loop dispatch — live-only, cross-TFM
└─ Enums/NebulaConnectionState.cs    Disconnected/Connecting/Connected/Reconnecting
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `NebulaDriver` | `IVpnProtocolDriver`: capabilities (`L3Ip`, **không PPP**, `Noise`, **Certificate** (Ed25519 host cert), `Udp`, `OutOfBand`); `ConnectAsync` dựng `NebulaConnection` từ `NebulaConfig` + endpoint | [NebulaDriver.cs:17](NebulaDriver.cs#L17) |
| `NebulaConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection<NebulaConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (supervisor F.6): override `EstablishAsync` (resolve peer endpoint → mở transport UDP qua `INebulaTransportFactory.ConnectAsync` → handshake **IX initiator** (`StartHandshake`: payload `NebulaHandshake{Details{Cert(strip pubkey),InitiatorIndex,Time}}` → `CreateInitiation` → header `Type=Handshake` → gửi), đợi stage-2 → `OnHandshakeResponse` (`ConsumeResponse` → verify cert responder → `Split` → `BindSession`) → `Facade.SetInner(channel)` → `MarkConnected`) + `CleanupAttemptResourcesAsync`/`StopAttemptLoop`; timer loop (`_timerRunning`) resend stage-1 chưa trả lời + **re-handshake make-before-break** (`_pending` session mới chạy nền, swap channel khi response về) + **demux** gói vào (`OnInboundDatagram` theo `NebulaMessageType`); fault → `OnLinkLost` của base arm reconnect | [NebulaConnection.cs:39](NebulaConnection.cs#L39) |
| `NebulaConfig` | Config tĩnh: `CaCertificate`/`ClientCertificate`/`ClientX25519PrivateKey`/`PeerEndpoint`/`OverlayAddress`+`PrefixLength`/`DnsServers`/`Routes`/`Mtu`; `ResolveOverlayAddress` (đè hoặc lấy IP từ cert `Ips[0]`) + `ToTunnelConfig` | [Config/NebulaConfig.cs:20](Config/NebulaConfig.cs#L20) |
| `NebulaTransport` | Data plane type-1 Message: `Seal` (header `Type=Message,RemoteIndex=responderIndex,MessageCounter=counter` = AAD; nonce `0^4‖counter(8 BE)`; AES-256-GCM) / `TryOpen` (drop tag sai / index sai / replay); counter u64 từ 1 + `NebulaReplayProtector` | [DataChannel/NebulaTransport.cs:26](DataChannel/NebulaTransport.cs#L26) |
| `NebulaChannel` | `IPacketChannel` (`Medium=Ip`, `MaxHeaderLength=0` — bare IP): `WriteIpPacketAsync` seal → send sink; `Deliver` mở type-1 → `InboundIpPacket`; callback sealed/received cho timer | [DataChannel/NebulaChannel.cs:22](DataChannel/NebulaChannel.cs#L22) |
| `NebulaReplayProtector` | Anti-replay 64-bit: tái dùng [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L8) cho low-32 trong mỗi high-32 epoch (mirror `WireGuardReplayProtector`) | [DataChannel/NebulaReplayProtector.cs:17](DataChannel/NebulaReplayProtector.cs#L17) |
| `NebulaVpnConnection` / `NebulaVpnSession` | `IVpnConnection` 1 session (point-to-point) + `IVpnSession` (`PacketChannel` facade + `Config` tĩnh) | [NebulaVpnConnection.cs:6](NebulaVpnConnection.cs#L6) / [NebulaVpnSession.cs:12](NebulaVpnSession.cs#L12) |
| `INebulaTransportFactory` / `NebulaTransportHandle` / `NebulaSocketTransportFactory` | Seam dựng UDP transport (1 datagram = 1 gói Nebula, **không framing**) + socket thật `UdpClient` + receive loop — live-only, cross-TFM | [Transport/INebulaTransportFactory.cs:11](Transport/INebulaTransportFactory.cs#L11) |
| `NebulaConnectionState` / `NebulaReconnectOptions` | `Disconnected/Connecting/Connected/Reconnecting` + kế thừa `VpnReconnectOptions` (F.6) | [Enums/NebulaConnectionState.cs:4](Enums/NebulaConnectionState.cs#L4) / [NebulaReconnectOptions.cs:10](NebulaReconnectOptions.cs#L10) |

## Luồng kết nối (as-built)

1. **Resolve peer endpoint** ([`ResolvePeerEndpointAsync`](NebulaConnection.cs#L161)): `NebulaConfig.PeerEndpoint` (static_host_map) nếu set; ngược lại resolve host:port của connect qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs).
2. **Mở transport UDP** qua `INebulaTransportFactory.ConnectAsync(endpoint, ct)` → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)` gắn demux; chạy receive-pump nền cho socket transport (loopback tự pump); `MarkRunning`.
3. **Handshake IX initiator** ([`StartHandshake`](NebulaConnection.cs#L170)): cấp **initiator index** random → dựng payload `NebulaHandshake{Details{Cert(strip pubkey field-7),InitiatorIndex,Time}}` (`NebulaHandshakePayloadCodec.Marshal`) → `NebulaNoiseIxHandshake.CreateInitiation(payload)` → header `Type=Handshake,SubType=ix_psk0` → gửi stage-1; lưu `LastInitiationPacket` cho resend.
4. **Đợi stage-2** (`WaitForHandshakeAsync`, cap `handshakeTimeoutMs`): demux `OnHandshakeResponse` khớp session theo `RemoteIndex` (echo initiator-index) → `ConsumeResponse` (AEAD) → `VerifyResponderCert` (recombine static pubkey từ Noise `s` token vào cert → `NebulaCertificateValidator.VerifySignature` against CA) → lưu `ResponderIndex` → complete. Cert sai/timeout ⇒ `VpnConnectionException`.
5. **Bind session** ([`BindSession`](NebulaConnection.cs#L206)): `Split` → `NebulaTransport(send,recv,responderIndex,initiatorIndex)` → `NebulaChannel(send qua transport)` → `Facade.SetInner` → `MarkConnected`.
6. **TunnelConfig**: `NebulaConfig.ToTunnelConfig()` (overlay từ cert/đè, routes = overlay subnet, MTU 1300) — tĩnh, không đàm phán.

## Vòng đời

- **Demux** ([`OnInboundDatagram`](NebulaConnection.cs#L236)): theo `NebulaMessageType` — `Handshake` (stage-2, `OnHandshakeResponse`), `Message` (type-1 data, `OnMessage` thử active rồi pending channel `Deliver`), `RecvError` (peer không có tunnel khớp → log; re-handshake recover).
- **Gửi data** (`NebulaChannel.WriteIpPacketAsync`): `NebulaTransport.Seal` (counter u64, overflow ⇒ ném) → send qua transport; callback cập nhật `LastActivity`.
- **Timer loop** (250ms): nếu handshake ban đầu chưa xong → resend stage-1 (~1s); nếu xong + tới `rehandshakeIntervalMs` (mặc định 5 phút) → **re-handshake make-before-break** (`_pending` session mới; khi stage-2 về → `BindSession` + `SetInner` swap channel, session cũ giữ tới đó); re-handshake treo quá timeout → bỏ, giữ session cũ.
- **Teardown** (`DisconnectAsync`/`DisposeAsync`): hủy reconnect đang chờ, hủy receive loop + timer, dispose transport.
- **Reconnect** (supervisor): ở base [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6) — `OnLinkLost` arm `ReconnectLoopAsync` (backoff+jitter) gọi `EstablishAsync` sau `SwappablePacketChannel` ổn định.
- **Logging (Q.2)**: ctor nhận `ILoggerFactory?` (mặc định no-op). Log state/handshake-sent/stage-2-consumed/HandshakeCompleted/HandshakeFailed/Rekey/PacketDropped (`VpnDropReason`)/LinkLost/Reconnect.

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Handshake | Noise `Noise_IX_25519_AESGCM_SHA256` | msg1 `e,s` plaintext / msg2 `e,ee,se,s,es` AEAD (xem [Nebula README](../TqkLibrary.VpnClient.Nebula/README-vi.md)) |
| Cert | Nebula cert_v1.proto + Ed25519 (RFC 8032) | CA ký `Marshal(Details)`; recombine static pubkey từ Noise `s` token |
| Data plane | type-1 Message + AES-256-GCM | header 16B = **AAD**, nonce `0^4‖counter(8 BE)`, anti-replay 64-gói trên counter u64 |
| Transport | UDP (Nebula không TCP) | 1 datagram = 1 gói, không framing |
| Address | out-of-band (overlay trong cert) | không IPCP/DHCP — `NebulaConfig` → `TunnelConfig` |

## Trạng thái & ghi chú

- **Đã có (V.7.1 phase b)**: end-to-end **offline** — handshake Noise IX (initiator) + verify cert responder against CA, data plane type-1 Message 2 chiều, **re-handshake make-before-break** (swap channel), supervisor reconnect; config tĩnh point-to-point; `UseNebula(config)`. Test offline qua **responder giả lập** (dùng chính `NebulaNoiseIxHandshake` responder + `NebulaTransport`) trên loopback UDP: handshake → cert verify → IP round-trip 2 chiều → connect-host-port fallback → re-handshake swap → reject untrusted CA (`NebulaConnectionTests`, 4 test); + `NebulaTransportTests` (seal/open 2 chiều, tamper/wrong-index/replay reject, counter monotonic — 5 test) = **9 test** tổng.
- **VALIDATE LIVE FULL-TUNNEL ✓ (lab [`nebula`](../../lab/nebula) — nebula v1.9.5 THẬT lighthouse+peer `tun` enabled overlay `192.168.100.1`, demo `--vpn /lab/client.nebula`)**: driver lên tunnel — nebula log `Handshake message received certName=client stage:1` → `sent stage:2` → `Tunnel status state:alive`; **ICMP 2 chiều qua overlay**: demo `Gateway nội bộ 192.168.100.1 (ICMP reachable, RTT 4 ms)`, **tcpdump nebula1**: `192.168.100.5 > 192.168.100.1 echo request` + `192.168.100.1 > 192.168.100.5 echo reply`. **0 bug data-plane** (layout message packet đúng byte-for-byte với nebula ngay lần đầu — đã verify ở phase a stretch). UDP-DNS tới 8.8.8.8: nebula **giải mã được** gói của ta (fwPacket đúng) nhưng drop vì 8.8.8.8 ngoài overlay (lab isolated) ⇒ data-plane AEAD đúng cả UDP.
- **Chưa**:
  - **lighthouse query động** (`NebulaMeta` discovery peer→endpoint runtime) — hiện endpoint tĩnh từ `static_host_map`/config.
  - **relay** (Nebula relay/punchy NAT hole-punching), **multi-peer mesh routing** (nhiều host overlay), **P256/ECDSA** cert path.
  - **liveness `Test` packet** native của nebula (hiện giữ tunnel bằng re-handshake định kỳ + traffic; đủ cho ICMP 2 chiều).
- **Tham chiếu**: nebula github.com/slackhq/nebula — **chỉ đọc spec/behavior + đối chiếu cert/handshake với binary thật, không copy GPL/source**; thiết kế Noise [`08`](../../.docs/08-crypto-primitives.md) + taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.7.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`WireGuardSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.WireGuard/Transport/WireGuardSocketTransportFactory.cs) (net5+ overload ct; ns2.0 cancel-by-dispose). `NebulaTransport.Seal` tính đồng bộ trước await (Span không qua await — an toàn).
