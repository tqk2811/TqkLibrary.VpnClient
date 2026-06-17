# TqkLibrary.VpnClient.Drivers.OpenVpn

Driver **OpenVPN** (tương thích OpenVPN community server) — ráp các khối protocol thuần ở [`OpenVpn`](../TqkLibrary.VpnClient.OpenVpn) (V2.a–V2.g) thành một tunnel chạy thật sau facade. Chọn **transport UDP** (1 datagram = 1 gói) hoặc **TCP** (16-bit length framing) theo `proto`, **demux opcode** control↔data trên cùng một transport, chạy control-channel handshake (reset → TLS → key-method-2 → PUSH) rồi cắm AEAD data channel vào device-link. **`dev tun`** (gói IP trần → `IPacketChannel`) bind thẳng L3; **`dev tap`** (khung Ethernet → `IEthernetChannel`) bắc cầu xuống **cùng** `IPacketChannel` qua **fabric L2 userspace** (`OpenVpnTapChannel` → `ArpResolver` + `VirtualHost`), IP lấy từ `ifconfig` mà `server-bridge` push — **1 host, IPv4/ARP**. Tap pure-DHCP-bridge (server không push ifconfig) còn cần **L2.5** DHCP nên bị từ chối kèm gợi ý.

## Vị trí kiến trúc

`PROTOCOL`-layer driver, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`OpenVpn`](../TqkLibrary.VpnClient.OpenVpn) thành 1 tunnel sống:

- **Transport**: [`OpenVpnUdpTransport`](../TqkLibrary.VpnClient.OpenVpn/Transport/OpenVpnUdpTransport.cs) (UDP) / [`OpenVpnTcpTransport`](../TqkLibrary.VpnClient.OpenVpn/Transport/OpenVpnTcpTransport.cs) (TCP) — driver dựng socket thật qua [`OpenVpnSocketTransportFactory`](Transport/OpenVpnSocketTransportFactory.cs) (seam `IOpenVpnTransportFactory`, test inject loopback).
- **Control plane**: [`OpenVpnControlChannel`](../TqkLibrary.VpnClient.OpenVpn/OpenVpnControlChannel.cs#L22) (reset HARD_RESET → `SslStream` trong reliability layer → key-method-2 → PUSH_REQUEST/PUSH_REPLY); wrap tls-auth/tls-crypt opt-in (`IOpenVpnControlWrap`).
- **Data plane**: [`OpenVpnDataPlane`](../TqkLibrary.VpnClient.OpenVpn/DataChannel/OpenVpnDataPlane.cs#L10) (P_DATA_V2 + AES-GCM, make-before-break) qua device-link — **tun** [`OpenVpnTunChannel`](../TqkLibrary.VpnClient.OpenVpn/Transport/OpenVpnTunChannel.cs) → `IPacketChannel` trực tiếp; **tap** [`OpenVpnTapChannel`](../TqkLibrary.VpnClient.OpenVpn/Transport/OpenVpnTapChannel.cs) → [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) + [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) → `IPacketChannel`.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`/`IByteStreamTransport`, exceptions, `IHostResolver` |
| Dùng | [OpenVpn](../TqkLibrary.VpnClient.OpenVpn) | `OpenVpnControlChannel`, transport TCP/UDP + tun/tap channel, key-method-2/NCP, data plane/keepalive/ping, config `OpenVpnProfile`, wrap tls-auth/tls-crypt |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | `OpenVpnTapChannel` → `VirtualHost` + `ArpResolver` + `MacAddress` bắc cầu L2→L3 cho **tap-mode** |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseOpenVpn(profile)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.OpenVpn/
├─ OpenVpnDriver.cs                    IVpnProtocolDriver: capabilities + ConnectAsync(profile+endpoint+creds) → OpenVpnConnection
├─ OpenVpnConnection.cs                Điều phối: transport → demux opcode → handshake → tun/tap-bridge + keepalive + rekey + reconnect
├─ OpenVpnVpnConnection.cs             IVpnConnection: 1 session; OpenSessionAsync ném NotSupportedException (tun = 1 IP)
├─ OpenVpnVpnSession.cs                IVpnSession: PacketChannel ổn định + TunnelConfig; ApplyReconnect khi reconnect
├─ OpenVpnReconnectOptions.cs          Chính sách auto-reconnect (backoff + jitter, mirror IKEv2/L2TP)
├─ Transport/
│  ├─ IOpenVpnTransportFactory.cs      Seam dựng transport tới endpoint (production socket / test loopback)
│  ├─ OpenVpnTransportHandle.cs        Transport + receive-pump + socket disposable trả về từ factory
│  └─ OpenVpnSocketTransportFactory.cs Socket thật: UDP (UdpClient) / TCP raw (TcpClient) — live-only, cross-TFM
├─ Enums/OpenVpnConnectionState.cs     Disconnected/Connecting/Connected/Reconnecting
└─ Models/OpenVpnReconnectInfo.cs      Địa chỉ mới + cờ AddressChanged sau reconnect
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `OpenVpnDriver` | `IVpnProtocolDriver`: capabilities **theo `dev` của profile** (L2.8) — **tun** ⇒ `L3Ip`/`MultiHostModel.None`/`SupportsMultiHost=false`; **tap** ⇒ `L2Ethernet`/`MultiHostModel.L2BroadcastDomain`/`SupportsMultiHost=true` (Ethernet frames qua L2 fabric); chung **không PPP**, TLS, **Cert\|UserPassword**, UDP\|TCP, ConfigPush; `ConnectAsync` dựng `OpenVpnConnection` từ `OpenVpnProfile` (device/proto/cipher/tls-auth) + endpoint + credentials; build wrap từ inline tls-auth/tls-crypt + OCC options string | [OpenVpnDriver.cs:20](OpenVpnDriver.cs#L20) |
| `OpenVpnConnection` | Bộ điều phối: resolve → `IOpenVpnTransportFactory.ConnectAsync` → **demux opcode** (P_DATA_V2 vào data plane, control vào `OpenVpnControlChannel`) → reset/TLS → key-method-2 (peer-info IV_CIPHERS + push-peer-info IV_MTU/IV_PLAT/UV_*) → PUSH_REPLY (NCP cipher) → **tun** `OpenVpnTunChannel` / **tap** `OpenVpnTapChannel`+`VirtualHost`+`ArpResolver`, đều qua `SwappablePacketChannel`; keepalive ping/ping-restart, rekey (re-establish khi packet-id tới hạn), teardown, supervisor reconnect | [OpenVpnConnection.cs:30](OpenVpnConnection.cs#L30) |
| `OpenVpnVpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (1 IP ảo — cả tun lẫn tap đều bridge xuống **1 phiên L3**; multi-station L2 broadcast domain cần L2.7+) | [OpenVpnVpnConnection.cs:6](OpenVpnVpnConnection.cs#L6) |
| `OpenVpnVpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config`; `ApplyReconnect` cập nhật config sau reconnect | [OpenVpnVpnSession.cs:9](OpenVpnVpnSession.cs#L9) |
| `OpenVpnReconnectOptions` | `Enabled`/`MaxAttempts`/backoff/jitter | [OpenVpnReconnectOptions.cs:10](OpenVpnReconnectOptions.cs#L10) |
| `IOpenVpnTransportFactory` / `OpenVpnTransportHandle` | Seam dựng transport: trả `IOpenVpnTransport` + receive-pump (UDP/TCP loop, null nếu self-pump) + socket disposable | [Transport/IOpenVpnTransportFactory.cs:9](Transport/IOpenVpnTransportFactory.cs#L9) |
| `OpenVpnSocketTransportFactory` | Production: UDP qua `UdpClient`, TCP raw qua `TcpClient` (TLS chạy **trong** control channel, không trên transport); cross-TFM (net5+ overload ct, ns2.0 cancel-by-dispose) — **live-only** | [Transport/OpenVpnSocketTransportFactory.cs:24](Transport/OpenVpnSocketTransportFactory.cs#L24) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`; IP-literal verbatim không-DNS.
2. **Transport**: `IOpenVpnTransportFactory.ConnectAsync(IPEndPoint, ct)` dựng socket (UDP/TCP) → `OpenVpnUdpTransport`/`OpenVpnTcpTransport`. Sub `OnTransportDatagram` (P_DATA_V2) + ctor `OpenVpnControlChannel` (control) gắn vào cùng `DatagramReceived` = **demux opcode**; chạy receive-pump nền (socket transport) — loopback tự pump.
3. **Reset + TLS** (`OpenVpnControlChannel.ConnectAsync`): HARD_RESET_CLIENT_V2 ⇄ HARD_RESET_SERVER_V2 (reliability id 0) → `SslStream` AuthenticateAsClient **bên trong** reliability layer (validate server cert qua callback; client cert tùy chọn).
4. **key-method-2** (`NegotiateKeyMaterialAsync`): gửi key_source2 + **peer-info** trên TLS (NCP `IV_CIPHERS` + **push-peer-info nâng cao** qua [`OpenVpnPeerInfoOptions`](../TqkLibrary.VpnClient.OpenVpn/DataChannel/OpenVpnPeerInfo.cs#L85) ở ctor — `IV_MTU` mặc định lấy tun MTU khi caller chưa đặt, cộng IV_PLAT/IV_PLAT_VER/IV_SSL_VER/IV_GUI_VER + user-var `UV_*`), đọc reply server → `OpenVpnKeyMaterial` (key2 256B, cipher-independent).
5. **PUSH** (`RequestConfigAsync`): PUSH_REQUEST → PUSH_REPLY → `OpenVpnPushReply` (ifconfig/route/DNS/peer-id/ping/cipher/topology). Không có ifconfig ⇒ `VpnServerRejectedException` (tap: thông điệp trỏ **L2.5** DHCP).
6. **NCP + data plane**: cipher = server chốt (mặc định AES-256-GCM; pushed-không-hỗ-trợ ⇒ `VpnConnectionException`) → `keyMaterial.DeriveDataKeys(cipher)` → `OpenVpnDataChannel(keys, peerId)` → `OpenVpnDataPlane`; compression từ PUSH (chỉ no-compression).
7. **Bind device-link**: **tun** → `OpenVpnTunChannel(dataPlane, compression, sink=transport.SendAsync, mtu)` → `_facade.SetInner(tun)`. **tap** → `OpenVpnTapChannel(..., mac)` (MAC locally-administered tự sinh, giữ qua reconnect) + `ArpResolver(mac, ifconfig, tap)` + `VirtualHost(mac, tap, arp)` (nối `InboundNonIpFrame`→`arp.HandleInboundFrame`) → `_facade.SetInner(virtualHost)` — IP stack vẫn bind `IPacketChannel`, MTU = link−14; ifconfig phải IPv4 (ARP), v6 ⇒ `VpnConnectionException` trỏ **L2.4** NDISC. `TunnelConfig` từ PUSH; bật keepalive.

## Vòng đời

- **Demux opcode**: mỗi datagram vào cả `OpenVpnControlChannel.OnDatagram` (chỉ control, `TryDecodeControl`) lẫn `OnTransportDatagram` (chỉ `P_DATA_V2`, lọc theo `ReadOpcode`) — mỗi handler tự bỏ gói không thuộc về mình. Gói data inbound → đếm keepalive-received → `OpenVpnTunChannel.Deliver` (giải mã + de-compress + **drop ping** + raise `InboundIpPacket`). Gói data outbound đi thẳng `sink`→`transport.SendAsync` (không qua `DatagramReceived`).
- **Keepalive** (ping/ping-restart từ PUSH): timer 1s — `OpenVpnKeepalive.ShouldSendPing` ⇒ gửi `OpenVpnPing.Magic` qua data plane (đếm sent), `IsPeerDead` ⇒ link lost. Gói data ra của user cũng reset ping-send timer. Cả 2 = 0 ⇒ không bật timer.
- **Rekey**: `OpenVpnDataPlane.RekeyNeeded` (packet-id tới ~2³²) ⇒ **re-establish** (reconnect) — fresh keys, packet-id về 0, không tái dùng nonce GCM. (Soft-reset make-before-break — TLS handshake thứ 2 trên key_id mới rồi `OpenVpnDataPlane.Swap` — là việc sau, cần control-channel hỗ trợ SOFT_RESET.)
- **Teardown** (`DisconnectAsync`): hủy reconnect đang chờ, hủy receive loop, dispose control channel + socket. (Explicit-exit-notify để best-effort sau.)
- **Reconnect** (supervisor): mirror IKEv2/L2TP — `EstablishAsync`/`ReconnectLoopAsync` backoff+jitter sau `SwappablePacketChannel` ổn định; `Reconnected` → `OpenVpnVpnSession.ApplyReconnect`.

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| Control reliability + TLS-in-control | OpenVPN wire protocol | reset/P_CONTROL/P_ACK + key-method-2 (xem [OpenVpn README](../TqkLibrary.VpnClient.OpenVpn/README-vi.md)) |
| Data channel AEAD | P_DATA_V2 + AES-256/128-GCM + CHACHA20-POLY1305 | NCP `data-ciphers` đàm phán qua `IV_CIPHERS`/PUSH `cipher` |
| Transport UDP/TCP | OpenVPN `proto udp`/`proto tcp` | UDP 1 datagram = 1 gói; TCP 16-bit length framing (seam F.2) |
| TLS PRF key derivation | TLS 1.0 PRF | `tls-ekm` (RFC 5705) chờ **F.5** |

## Trạng thái & ghi chú

- **Đã có (V2.h)**: tun **và** tap end-to-end UDP/TCP — handshake reset→TLS→key-method-2→PUSH, demux opcode, NCP AES-GCM/ChaCha20-Poly1305, **push-peer-info nâng cao** (`peerInfoOptions` ở ctor: IV_MTU từ tun MTU + IV_PLAT/IV_PLAT_VER/IV_SSL_VER/IV_GUI_VER + `UV_*`), keepalive ping/ping-restart, teardown, supervisor reconnect; tap bắc cầu Ethernet→L3 qua `OpenVpnTapChannel`+`ArpResolver`+`VirtualHost` (1 host, IPv4/ARP, IP từ server-bridge ifconfig); `UseOpenVpn(profile)`. Test offline: capabilities + `OpenSessionAsync` guard + **end-to-end tun** (handshake → bind địa chỉ → IP round-trip + demux → drop ping) + **NCP ChaCha** + **push-peer-info** (client advertise IV_MTU=tun MTU + IV_PLAT + `UV_*`) + **end-to-end tap** (handshake → ARP gateway → IP round-trip trong khung Ethernet lên facade L3 → drop ping; và không-ifconfig ⇒ `VpnServerRejectedException` trỏ L2.5).
- **Chưa**:
  - **tap pure-DHCP-bridge** (server `dev tap` không push ifconfig) — cần **L2.5** DHCPv4; driver từ chối kèm gợi ý. **tap IPv6** (ifconfig v6) — cần **L2.4** NDISC. **tap multi-host data-plane** — **năng lực đã phơi (L2.8)**: tap-mode capability nay khai báo `VpnLinkLayer.L2Ethernet` + `MultiHostModel.L2BroadcastDomain` + `SupportsMultiHost`, và `MultiHostSession` (`Ethernet`, L2.8) ráp sẵn N station; **còn lại** = gắn uplink VPN (`OpenVpnTapChannel`) vào `EthernetAdapter`/`MultiHostSession` như một port thay bắc-cầu-1-host.
  - **soft-reset make-before-break** (rekey không gián đoạn) — hiện rekey bằng re-establish; cần control-channel khởi tạo SOFT_RESET.
  - **client-cert auto-load từ profile PEM** (`cert`/`key`) — hiện nhận `X509CertificateCollection` dựng sẵn từ caller; tự nạp PEM cross-TFM là việc sau.
  - `tls-ekm` (chờ **F.5**), explicit-exit-notify khi teardown.
  - **validate live** (lab **Q.1** — OpenVPN community server Docker): OCC options string strict, direction key tls-auth, interop UDP/TCP thật.
- **Tham chiếu**: doc protocol OpenVPN (openvpn.net + source GPL **chỉ đọc spec/behavior, không copy code**); thiết kế [`06`](../../.docs/06-openvpn.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.2.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`TlsByteStream`](../TqkLibrary.VpnClient.Drivers.Sstp/Transport/TlsByteStream.cs) (net5+ overload ct; ns2.0 cancel-by-dispose + `MemoryMarshal.TryGetArray`). `OpenVpnConnection` giữ Span ngoài await (ping `Protect(WrapOutgoing(Magic))` tính đồng bộ trước await — an toàn C# 12).
