# TqkLibrary.VpnClient.Drivers.OpenVpn

Driver **OpenVPN** (tương thích OpenVPN community server) — ráp các khối protocol thuần ở [`OpenVpn`](../TqkLibrary.VpnClient.OpenVpn) (V2.a–V2.g) thành một tunnel chạy thật sau facade. Chọn **transport UDP** (1 datagram = 1 gói) hoặc **TCP** (16-bit length framing) theo `proto`, **demux opcode** control↔data trên cùng một transport, chạy control-channel handshake (reset → TLS → key-method-2 → PUSH) rồi cắm AEAD data channel vào kênh **tun** L3. Hiện thực **`dev tun`** (gói IP trần → `IPacketChannel`); **`dev tap`** (L2 Ethernet) cần fabric L2 (roadmap **L2.5**) nên bị từ chối.

## Vị trí kiến trúc

`PROTOCOL`-layer driver, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`OpenVpn`](../TqkLibrary.VpnClient.OpenVpn) thành 1 tunnel sống:

- **Transport**: [`OpenVpnUdpTransport`](../TqkLibrary.VpnClient.OpenVpn/Transport/OpenVpnUdpTransport.cs) (UDP) / [`OpenVpnTcpTransport`](../TqkLibrary.VpnClient.OpenVpn/Transport/OpenVpnTcpTransport.cs) (TCP) — driver dựng socket thật qua [`OpenVpnSocketTransportFactory`](Transport/OpenVpnSocketTransportFactory.cs) (seam `IOpenVpnTransportFactory`, test inject loopback).
- **Control plane**: [`OpenVpnControlChannel`](../TqkLibrary.VpnClient.OpenVpn/OpenVpnControlChannel.cs#L22) (reset HARD_RESET → `SslStream` trong reliability layer → key-method-2 → PUSH_REQUEST/PUSH_REPLY); wrap tls-auth/tls-crypt opt-in (`IOpenVpnControlWrap`).
- **Data plane**: [`OpenVpnDataPlane`](../TqkLibrary.VpnClient.OpenVpn/DataChannel/OpenVpnDataPlane.cs#L10) (P_DATA_V2 + AES-GCM, make-before-break) qua cầu nối [`OpenVpnTunChannel`](../TqkLibrary.VpnClient.OpenVpn/Transport/OpenVpnTunChannel.cs) → `IPacketChannel`.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`/`IByteStreamTransport`, exceptions, `IHostResolver` |
| Dùng | [OpenVpn](../TqkLibrary.VpnClient.OpenVpn) | `OpenVpnControlChannel`, transport TCP/UDP + tun channel, key-method-2/NCP, data plane/keepalive/ping, config `OpenVpnProfile`, wrap tls-auth/tls-crypt |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseOpenVpn(profile)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.OpenVpn/
├─ OpenVpnDriver.cs                    IVpnProtocolDriver: capabilities + ConnectAsync(profile+endpoint+creds) → OpenVpnConnection
├─ OpenVpnConnection.cs                Điều phối: transport → demux opcode → handshake → tun + keepalive + rekey + reconnect
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
| `OpenVpnDriver` | `IVpnProtocolDriver`: capabilities (L3Ip tun, **không PPP**, TLS, **Cert\|UserPassword**, UDP\|TCP, ConfigPush); `ConnectAsync` dựng `OpenVpnConnection` từ `OpenVpnProfile` (device/proto/cipher/tls-auth) + endpoint + credentials; build wrap từ inline tls-auth/tls-crypt + OCC options string | [OpenVpnDriver.cs:18](OpenVpnDriver.cs#L18) |
| `OpenVpnConnection` | Bộ điều phối: resolve → `IOpenVpnTransportFactory.ConnectAsync` → **demux opcode** (P_DATA_V2 vào data plane, control vào `OpenVpnControlChannel`) → reset/TLS → key-method-2 (peer-info IV_CIPHERS) → PUSH_REPLY (NCP cipher) → `OpenVpnTunChannel` qua `SwappablePacketChannel`; keepalive ping/ping-restart, rekey (re-establish khi packet-id tới hạn), teardown, supervisor reconnect | [OpenVpnConnection.cs:30](OpenVpnConnection.cs#L30) |
| `OpenVpnVpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (tun = 1 IP; multi-station là tap/L2 — L2.5) | [OpenVpnVpnConnection.cs:6](OpenVpnVpnConnection.cs#L6) |
| `OpenVpnVpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config`; `ApplyReconnect` cập nhật config sau reconnect | [OpenVpnVpnSession.cs:9](OpenVpnVpnSession.cs#L9) |
| `OpenVpnReconnectOptions` | `Enabled`/`MaxAttempts`/backoff/jitter | [OpenVpnReconnectOptions.cs:10](OpenVpnReconnectOptions.cs#L10) |
| `IOpenVpnTransportFactory` / `OpenVpnTransportHandle` | Seam dựng transport: trả `IOpenVpnTransport` + receive-pump (UDP/TCP loop, null nếu self-pump) + socket disposable | [Transport/IOpenVpnTransportFactory.cs:9](Transport/IOpenVpnTransportFactory.cs#L9) |
| `OpenVpnSocketTransportFactory` | Production: UDP qua `UdpClient`, TCP raw qua `TcpClient` (TLS chạy **trong** control channel, không trên transport); cross-TFM (net5+ overload ct, ns2.0 cancel-by-dispose) — **live-only** | [Transport/OpenVpnSocketTransportFactory.cs:24](Transport/OpenVpnSocketTransportFactory.cs#L24) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`; IP-literal verbatim không-DNS.
2. **Transport**: `IOpenVpnTransportFactory.ConnectAsync(IPEndPoint, ct)` dựng socket (UDP/TCP) → `OpenVpnUdpTransport`/`OpenVpnTcpTransport`. Sub `OnTransportDatagram` (P_DATA_V2) + ctor `OpenVpnControlChannel` (control) gắn vào cùng `DatagramReceived` = **demux opcode**; chạy receive-pump nền (socket transport) — loopback tự pump.
3. **Reset + TLS** (`OpenVpnControlChannel.ConnectAsync`): HARD_RESET_CLIENT_V2 ⇄ HARD_RESET_SERVER_V2 (reliability id 0) → `SslStream` AuthenticateAsClient **bên trong** reliability layer (validate server cert qua callback; client cert tùy chọn).
4. **key-method-2** (`NegotiateKeyMaterialAsync`): gửi key_source2 + **peer-info `IV_CIPHERS`** (NCP) trên TLS, đọc reply server → `OpenVpnKeyMaterial` (key2 256B, cipher-independent).
5. **PUSH** (`RequestConfigAsync`): PUSH_REQUEST → PUSH_REPLY → `OpenVpnPushReply` (ifconfig/route/DNS/peer-id/ping/cipher/topology). Không có ifconfig ⇒ `VpnServerRejectedException`.
6. **NCP + data plane**: cipher = server chốt (mặc định AES-256-GCM; pushed-không-hỗ-trợ ⇒ `VpnConnectionException`) → `keyMaterial.DeriveDataKeys(cipher)` → `OpenVpnDataChannel(keys, peerId)` → `OpenVpnDataPlane`; compression từ PUSH (chỉ no-compression).
7. **Bind tun**: `OpenVpnTunChannel(dataPlane, compression, sink=transport.SendAsync, mtu)` → `_facade.SetInner(tun)`; `TunnelConfig` từ PUSH; bật keepalive.

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
| Data channel AEAD | P_DATA_V2 + AES-256/128-GCM | NCP `data-ciphers` đàm phán qua `IV_CIPHERS`/PUSH `cipher` |
| Transport UDP/TCP | OpenVPN `proto udp`/`proto tcp` | UDP 1 datagram = 1 gói; TCP 16-bit length framing (seam F.2) |
| TLS PRF key derivation | TLS 1.0 PRF | `tls-ekm` (RFC 5705) chờ **F.5** |

## Trạng thái & ghi chú

- **Đã có (V2.h)**: tun-mode end-to-end UDP/TCP — handshake reset→TLS→key-method-2→PUSH, demux opcode, NCP AES-GCM, keepalive ping/ping-restart, teardown, supervisor reconnect; `UseOpenVpn(profile)`. Test offline: capabilities + guards (tap reject, OpenSessionAsync) + **end-to-end** (server giả lập in-process: handshake → bind địa chỉ → IP packet round-trip qua data channel + demux → drop ping).
- **Chưa**:
  - **tap-mode** (`dev tap` → L2 Ethernet) — cần **L2.5** (DHCP/ARP fabric); driver từ chối bằng `VpnConnectionException`.
  - **soft-reset make-before-break** (rekey không gián đoạn) — hiện rekey bằng re-establish; cần control-channel khởi tạo SOFT_RESET.
  - **client-cert auto-load từ profile PEM** (`cert`/`key`) — hiện nhận `X509CertificateCollection` dựng sẵn từ caller; tự nạp PEM cross-TFM là việc sau.
  - **CHACHA20-POLY1305** trong NCP (chờ **F.4**), `tls-ekm` (chờ **F.5**), explicit-exit-notify khi teardown.
  - **validate live** (lab **Q.1** — OpenVPN community server Docker): OCC options string strict, direction key tls-auth, interop UDP/TCP thật.
- **Tham chiếu**: doc protocol OpenVPN (openvpn.net + source GPL **chỉ đọc spec/behavior, không copy code**); thiết kế [`06`](../../.docs/06-openvpn.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.2.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`TlsByteStream`](../TqkLibrary.VpnClient.Drivers.Sstp/Transport/TlsByteStream.cs) (net5+ overload ct; ns2.0 cancel-by-dispose + `MemoryMarshal.TryGetArray`). `OpenVpnConnection` giữ Span ngoài await (ping `Protect(WrapOutgoing(Magic))` tính đồng bộ trước await — an toàn C# 12).
