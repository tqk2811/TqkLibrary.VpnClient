# TqkLibrary.VpnClient.Drivers.Ssh

Driver **VPN-over-SSH** (OpenSSH `-w` tun) — ráp các codec/handshake thuần ở [`Ssh`](../TqkLibrary.VpnClient.Ssh) thành một tunnel **L3 (point-to-point tun)** chạy thật sau facade. SSH chở control + data trên **MỘT kết nối TCP/22**: chạy state machine SSH-2 (version exchange → curve25519-sha256 KEX → ed25519 host-key verify → NEWKEYS cipher `chacha20-poly1305@openssh.com`/`aes256-gcm@openssh.com` → userauth publickey-ed25519/password → channel `tun@openssh.com`) → chở **gói IP trần** trong channel-data (framing AF-only) sau [`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs) ổn định. Config tĩnh [`SshConfig`](Config/SshConfig.cs) (login user + khóa ed25519/password, IP tunnel tĩnh + peer, MTU) → `TunnelConfig` **tĩnh** (SSH không thương lượng địa chỉ in-tunnel — admin đặt server tun qua `PermitTunnel`; **không IPCP/DHCP**). Point-to-point client ↔ 1 OpenSSH server; **client không cần elevate**, server cần `PermitTunnel point-to-point` + thiết bị tun.

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Ráp codec từ [`Ssh`](../TqkLibrary.VpnClient.Ssh) thành tunnel sống (mirror cấu trúc [`Drivers.Vtun`](../TqkLibrary.VpnClient.Drivers.Vtun) — cũng **1 kết nối TCP**, point-to-point, OutOfBand):

- **Transport (đơn)**: seam [`ISshTransportFactory`](Transport/ISshTransportFactory.cs) trả 1 byte-stream — production [`SshSocketTransportFactory`](Transport/SshSocketTransportFactory.cs) (tái dùng [`TcpByteStream`](../TqkLibrary.VpnClient.Transport.Tcp/TcpByteStream.cs) F.1), test inject loopback.
- **SSH client**: [`SshConnection`](SshConnection.cs) dựng [`SshClient`](../TqkLibrary.VpnClient.Ssh/SshClient.cs) (project `Ssh`) trên byte-stream — chạy handshake + mở channel `tun@openssh.com`. `SshClient` lộ `SendIpPacketAsync`/`RunReceiveLoopAsync`/`CloseAsync` + `HostKey`/`CipherClientToServer`.
- **Data plane** [`SshPacketChannel`](DataChannel/SshPacketChannel.cs): `IPacketChannel` L3 (bare IP, `Medium=Ip`, `MaxHeaderLength`=0). `WriteIpPacketAsync` → `SshClient.SendIpPacketAsync`; `Deliver` → `InboundIpPacket`.
- **Lifecycle** [`SshConnection`](SshConnection.cs): receive loop nền (`SshClient.RunReceiveLoopAsync` raise `InboundIpPacket`, trip link-loss khi channel close/EOF) + supervisor/auto-reconnect (F.6). Teardown gửi CHANNEL_CLOSE best-effort.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IByteStreamTransport`, `IHostResolver`, `Diagnostics` (`VpnLogExtensions`) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection<TState>`** (base supervisor F.6) + **`VpnReconnectOptions`** (`SshReconnectOptions` kế thừa) |
| Dùng | [Ssh](../TqkLibrary.VpnClient.Ssh) | `SshClient` + `SshClientOptions` + `SshEd25519HostKey` (handshake + tun channel + data plane) |
| Dùng | [Transport.Tcp](../TqkLibrary.VpnClient.Transport.Tcp) | `TcpByteStream` (control+data TCP/22, F.1) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseSsh(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Ssh/
├─ SshDriver.cs               IVpnProtocolDriver: caps (L3Ip/Tcp/Security=None/Auth=Certificate|UserPassword/OutOfBand) + ConnectAsync → SshConnection
├─ SshConnection.cs           Điều phối (kế thừa ReconnectingVpnConnection<SshConnectionState> F.6): TCP connect → SshClient.ConnectAsync (handshake+tun) → bind SshPacketChannel → receive loop; supervisor/reconnect ở base; DisconnectAsync gửi CHANNEL_CLOSE
├─ SshVpnConnection.cs        IVpnConnection: 1 session point-to-point; OpenSessionAsync ném NotSupportedException
├─ SshVpnSession.cs           IVpnSession: PacketChannel ổn định + TunnelConfig tĩnh
├─ SshReconnectOptions.cs     Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ SshDriverConstants.cs      DriverName "ssh", DefaultPort 22, DefaultMtu 1400
├─ Config/SshConfig.cs        user + ed25519 seed/password + RemoteTunUnit + IP tunnel tĩnh/peer + DNS + MTU + HostKeyValidator → ToClientOptions() + ToTunnelConfig() (route peer/32, OutOfBand)
├─ Enums/SshConnectionState.cs   Disconnected/Connecting/Connected/Reconnecting
├─ DataChannel/SshPacketChannel.cs  IPacketChannel L3 (Medium=Ip, MaxHeaderLength=0): WriteIpPacketAsync → SshClient.SendIpPacketAsync; Deliver → InboundIpPacket
└─ Transport/
   ├─ ISshTransportFactory.cs       Seam dựng 1 byte-stream tới endpoint
   └─ SshSocketTransportFactory.cs  Production: TcpByteStream (F.1)
```

## Luồng nội bộ (connect)

1. `SshDriver.ConnectAsync` ([`SshDriver.cs`](SshDriver.cs#L57)) → `SshConnection.ConnectAsync` → [`EstablishAsync`](SshConnection.cs#L85).
2. `IHostResolver.ResolveAsync` → `ISshTransportFactory.ConnectAsync` → TCP byte-stream (`TcpByteStream`).
3. [`SshClient.ConnectAsync`](../TqkLibrary.VpnClient.Ssh/SshClient.cs#L63): version exchange → KEXINIT (negotiate `curve25519-sha256`/`ssh-ed25519`/cipher) → curve25519 KEX → **ed25519 host-key verify** (chữ ký trên H + optional TOFU pin) → NEWKEYS (cài cipher 2 chiều) → **userauth** (publickey ed25519 nếu có khóa, ngược lại password — ném `SshProtocolException` nếu fail) → **CHANNEL_OPEN `tun@openssh.com`** point-to-point + `RemoteTunUnit`.
4. Bind [`SshPacketChannel`](DataChannel/SshPacketChannel.cs#L15) sau facade (`Facade.SetInner`); wire `SshClient.InboundIpPacket` → `channel.Deliver`; `MarkRunning`.
5. Khởi receive loop nền [`SshClient.RunReceiveLoopAsync`](../TqkLibrary.VpnClient.Ssh/SshClient.cs#L240) (raise `InboundIpPacket`, trip link-loss khi CHANNEL_CLOSE/EOF/DISCONNECT). `MarkConnected`.
6. Data: `WriteIpPacketAsync` → [`SshClient.SendIpPacketAsync`](../TqkLibrary.VpnClient.Ssh/SshClient.cs#L219) (bọc gói IP qua framing AF-only + CHANNEL_DATA) → TCP. Teardown [`DisconnectAsync`](SshConnection.cs#L124) gửi CHANNEL_CLOSE best-effort; link-loss → reconnect (F.6).

## Bảng chuẩn / nguồn

| Khía cạnh | Nguồn | Ghi chú |
|-----------|-------|---------|
| SSH transport / userauth / channel | RFC 4253 / 4252 / 4254 | qua project [`Ssh`](../TqkLibrary.VpnClient.Ssh) (clean-room, KHÔNG copy code) |
| tun forwarding `tun@openssh.com` | OpenSSH PROTOCOL §2.3 | point-to-point L3; framing **AF-only** `uint32 AF‖ip_packet` (xem README Ssh) |
| Address out-of-band | OpenSSH `PermitTunnel` + admin network script | server đặt tun của nó; client IP cấp tĩnh ⇒ `AddressAssignment.OutOfBand` |
| Quyền mở tun | OpenSSH `sys_tun_open` | server gắn tun vào **uid phiên** ⇒ phải login uid mở được tun (root trong lab) |

## Trạng thái & ghi chú

- **OFFLINE**: 6 test [`Drivers.Ssh.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Ssh.Tests) — `SshConnection` end-to-end vs `SimulatedSshServer` (dựng trên codec public của thư viện `Ssh`) qua loopback: full handshake + **IP round-trip** cho **CẢ** `chacha20-poly1305@openssh.com` **lẫn** `aes256-gcm@openssh.com` (Theory 2 case) + password auth + reject wrong-password + capabilities + state. Build XANH ns2.0 + net8.
- **VALIDATE LIVE ✓ (2026-06-25, OpenSSH 9.6p1 thật, lab [`ssh`](../../lab/ssh))**: client .NET → TCP/22 → full SSH handshake + KEX + NEWKEYS + cipher `chacha20-poly1305@openssh.com` (host key verify, cipher byte-exact vs sshd) → **publickey ed25519 ACCEPTED** (sshd `Accepted publickey for root … ED25519`) → channel `tun@openssh.com` open → **ICMP 2 chiều** (`10.10.0.2` ↔ `10.10.0.1`, gateway probe RTT ~3ms; tcpdump tun0 thấy CẢ `echo request` LẪN `echo reply`). Lab: OpenSSH server (Ubuntu 24.04 + `openssh-server`) `PermitTunnel point-to-point` + ed25519 authorized_key + watcher dựng tun0 `10.10.0.1` peer `10.10.0.2`; `gen-client-key.sh` sinh seed ed25519 32-byte trần (`?key=` của demo) + dòng `authorized_keys`.
- ⚠️ **Ràng buộc uid-cho-tun (live)**: OpenSSH gắn tun vào **uid phiên** ⇒ phải đăng nhập bằng uid mở được tun — **root** trong lab; `tunuser` (non-root) nhận `sys_tun_open: Operation not permitted` dù `PermitTunnel` bật.
- ⚠️ **1 bug interop sửa qua live** (self-pair offline BỎ SÓT vì `SimulatedSshServer` cùng framing 2 đầu): tun L3 framing trong channel-data string là `[uint32 address_family][ip_packet]` — **KHÔNG** có field `packet_length` dẫn đầu (phần "uint32 packet length" PROTOCOL §2.3 chính là length-prefix của SSH `string`). Codec cũ chèn thừa 4-byte length → sshd đọc AF = giá trị length → misframe; fix về AF-only (`SshTunFraming.Overhead`=4) ⇒ ICMP 2 chiều. Chi tiết ở [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md) "Khác biệt so với design docs".
- **CHƯA làm (stretch)**: KEX/cipher/auth bổ sung (rsa/ecdsa hostkey, `diffie-hellman-group*` KEX, aes-ctr + hmac EtM, keyboard-interactive); **rekey giữa phiên** (`SSH_MSG_KEXINIT` mid-session); **tap mode L2** (`SSH_TUNMODE_ETHERNET` → `IEthernetChannel`); parse khóa OpenSSH PEM trong demo (hiện chỉ seed ed25519 32-byte trần). **sshuttle** (TCP-over-SSH proxy) = ngoài phạm vi.
