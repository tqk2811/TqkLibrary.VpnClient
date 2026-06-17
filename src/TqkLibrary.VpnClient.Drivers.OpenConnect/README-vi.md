# TqkLibrary.VpnClient.Drivers.OpenConnect

Driver **OpenConnect** (Cisco AnyConnect SSL-VPN; server opensource **ocserv**) — ráp các khối protocol thuần ở [`OpenConnect`](../TqkLibrary.VpnClient.OpenConnect) (V5.a codec + V5.b data plane) thành một tunnel **L3** chạy thật sau facade, trên **một byte-stream TLS** (F.1). Chạy **HTTPS config-auth** (username/password → cookie `webvpn=`) → **HTTP CONNECT `/CSCOSSLC/tunnel`** (header `X-CSTP-*` = config in-band) trên cùng stream → bind [`CstpChannel`](../TqkLibrary.VpnClient.OpenConnect/CstpChannel.cs) (CSTP-over-TLS, **bare IP, không PPP**) qua [`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs), rồi bơm [`CstpDpdState`](../TqkLibrary.VpnClient.OpenConnect/CstpDpdState.cs) trong timer loop cho **DPD** (`X-CSTP-DPD`) + **keepalive** (`X-CSTP-Keepalive`). **TLS-only** — DTLS data path là V5.c (F.3).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`OpenConnect`](../TqkLibrary.VpnClient.OpenConnect) thành 1 tunnel sống (mirror cấu trúc [`Drivers.WireGuard`](../TqkLibrary.VpnClient.Drivers.WireGuard) / [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther) — biến thể byte-stream):

- **Transport**: TLS byte-stream qua seam [`IOpenConnectTransportFactory`](Transport/IOpenConnectTransportFactory.cs) — production [`OpenConnectSocketTransportFactory`](Transport/OpenConnectSocketTransportFactory.cs) (`TcpClient`+`SslStream` inline cùng shape SSTP `TlsByteStream` F.1), test inject loopback byte-stream.
- **Control plane**: [`OpenConnectHttpTransactor`](../TqkLibrary.VpnClient.OpenConnect/OpenConnectHttpTransactor.cs) chạy auth POST + CONNECT byte-exact; codec [`OpenConnectAuthCodec`](../TqkLibrary.VpnClient.OpenConnect/OpenConnectAuthCodec.cs) + [`OpenConnectConnectCodec`](../TqkLibrary.VpnClient.OpenConnect/OpenConnectConnectCodec.cs) (V5.a).
- **Data plane**: [`CstpChannel`](../TqkLibrary.VpnClient.OpenConnect/CstpChannel.cs) (CSTP framing 8-byte + DATA/DPD/keepalive/disconnect) → `IPacketChannel`.
- **Timer/lifecycle**: [`CstpDpdState`](../TqkLibrary.VpnClient.OpenConnect/CstpDpdState.cs) (`ShouldSendDpd`/`IsPeerDead`/`ShouldSendKeepalive` theo `nowMs`) + supervisor/auto-reconnect.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IByteStreamTransport`, exceptions, `IHostResolver` |
| Dùng | [OpenConnect](../TqkLibrary.VpnClient.OpenConnect) | `OpenConnectAuthCodec`/`OpenConnectConnectCodec` (V5.a codec), `OpenConnectHttpTransactor`/`CstpChannel`/`CstpDpdState` (V5.b data plane), `OpenConnectTunnelInfo`/`OpenConnectAuthForm`/`OpenConnectHttpResponse` (models) |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseOpenConnect()` đăng ký driver |

> **Không** ref [Crypto](../TqkLibrary.VpnClient.Crypto): mã hóa do TLS lo. **Không** ref [Drivers.Sstp](../TqkLibrary.VpnClient.Drivers.Sstp): TLS byte-stream production inline (F.1 sẽ hoist 1 `Transport.Tls` dùng chung SSTP/OpenConnect sau).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.OpenConnect/
├─ OpenConnectDriver.cs                     IVpnProtocolDriver: capabilities (L3Ip/Tls/ConfigPush/UserPassword/no-PPP) + ConnectAsync(endpoint+credentials) → OpenConnectConnection
├─ OpenConnectConnection.cs                 Điều phối: TLS stream → auth → CONNECT → bind CstpChannel → receive loop + DPD/keepalive timer + reconnect
├─ OpenConnectVpnConnection.cs              IVpnConnection: 1 session; OpenSessionAsync ném NotSupportedException (1 CSTP session/cookie)
├─ OpenConnectVpnSession.cs                 IVpnSession: PacketChannel ổn định + TunnelConfig in-band (X-CSTP-*)
├─ OpenConnectReconnectOptions.cs           Chính sách auto-reconnect (backoff + jitter, mirror WireGuard/OpenVPN/SoftEther)
├─ Transport/
│  ├─ IOpenConnectTransportFactory.cs       Seam dựng TLS byte-stream tới endpoint (production socket / test loopback)
│  ├─ OpenConnectTransportHandle.cs         IByteStreamTransport (đã handshake TLS) trả về từ factory
│  └─ OpenConnectSocketTransportFactory.cs  Socket thật: TcpClient + SslStream (inline TlsByteStream) — live-only, cross-TFM
├─ Enums/OpenConnectConnectionState.cs      Disconnected/Connecting/Connected/Reconnecting
└─ Models/OpenConnectReconnectInfo.cs       NewAddress + cờ AddressChanged sau reconnect
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `OpenConnectDriver` | `IVpnProtocolDriver`: capabilities (`L3Ip`, **không PPP**, `Tls`, **UserPassword**, `Tls` transport, `ConfigPush`); `ConnectAsync` dựng `OpenConnectConnection` từ endpoint (host/port) + `VpnCredentials` (username/password) | [OpenConnectDriver.cs:16](OpenConnectDriver.cs#L16) |
| `OpenConnectConnection` | Bộ điều phối: resolve → `IOpenConnectTransportFactory.ConnectAsync` (TLS) → **HTTPS config-auth** (`OpenConnectHttpTransactor.PostAsync` init→form→reply, điền username/password, lấy cookie) → **HTTP CONNECT** (`ConnectTunnelAsync` → `ParseConnectResponse` X-CSTP-*) → bind `CstpChannel` qua `SwappablePacketChannel` + receive loop + DPD/keepalive timer bơm `CstpDpdState`; DPD-REQ→DPD-RESP, peer-close/DPD-dead/fault → supervisor reconnect | [OpenConnectConnection.cs:28](OpenConnectConnection.cs#L28) |
| `OpenConnectVpnConnection` | `IVpnConnection`: 1 session; `OpenSessionAsync` ⇒ `NotSupportedException` (1 CSTP session/cookie) | [OpenConnectVpnConnection.cs:6](OpenConnectVpnConnection.cs#L6) |
| `OpenConnectVpnSession` | `IVpnSession`: `PacketChannel` (facade) + `Config` in-band (X-CSTP-*) | [OpenConnectVpnSession.cs:12](OpenConnectVpnSession.cs#L12) |
| `OpenConnectReconnectOptions` | `Enabled`/`MaxAttempts`/backoff/jitter (mirror WireGuard/OpenVPN/SoftEther) | [OpenConnectReconnectOptions.cs:14](OpenConnectReconnectOptions.cs#L14) |
| `IOpenConnectTransportFactory` / `OpenConnectTransportHandle` | Seam dựng TLS byte-stream: trả `IByteStreamTransport` đã handshake TLS (HTTP auth/CONNECT + CSTP chạy chung 1 pipe — không cần receive-pump riêng) | [Transport/IOpenConnectTransportFactory.cs:12](Transport/IOpenConnectTransportFactory.cs#L12) |
| `OpenConnectSocketTransportFactory` | Production: `TcpClient`+`SslStream` (inline `TlsByteStream`, giữ SNI/Host) + callback validate cert (null=accept any); cross-TFM (net5+ overload ct, ns2.0 cancel-by-dispose) — **live-only** | [Transport/OpenConnectSocketTransportFactory.cs:24](Transport/OpenConnectSocketTransportFactory.cs#L24) |
| `OpenConnectConnectionState` | `Disconnected`/`Connecting`/`Connected`/`Reconnecting` | [Enums/OpenConnectConnectionState.cs:5](Enums/OpenConnectConnectionState.cs#L5) |
| `OpenConnectReconnectInfo` | `NewAddress` + cờ `AddressChanged` sau reconnect | [Models/OpenConnectReconnectInfo.cs:10](Models/OpenConnectReconnectInfo.cs#L10) |

## Luồng kết nối (as-built)

1. **Resolve** host qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) theo `AddressFamilyPreference`; IP-literal verbatim không-DNS.
2. **Transport**: `IOpenConnectTransportFactory.ConnectAsync(host, IPEndPoint, ct)` dựng socket TCP + handshake TLS (giữ `host` làm SNI/`Host:`) → `IByteStreamTransport`.
3. **HTTPS config-auth** ([`AuthenticateAsync`](OpenConnectConnection.cs#L28)): `OpenConnectHttpTransactor.PostAsync("/", config-auth init)` → server trả `<auth><form>` → `OpenConnectAuthCodec.TryParseForm` → điền username/password (`FillForm`) → `BuildReplyRequest` POST tiếp; lặp tới khi `IsSuccess` (`id="success"`) kèm cookie `webvpn=…` (`ExtractCookie`). Status ≠200 hoặc form-loop quá hạn ⇒ `VpnAuthenticationException`.
4. **HTTP CONNECT** ([`EstablishAsync`](OpenConnectConnection.cs#L28)): `OpenConnectConnectCodec.BuildConnectRequest(host, cookie, mtu)` → `ConnectTunnelAsync` (byte-exact, không nuốt gói CSTP đầu) → `ParseConnectResponse` map `X-CSTP-*` → `OpenConnectTunnelInfo` → `TunnelConfig` (in-band, config-push). Không có địa chỉ ⇒ `VpnServerRejectedException`.
5. **Bind data plane**: `CstpChannel(stream, mtu)` + wire event (DPD-REQ→`OnDpdRequest` gửi DPD-RESP, peer-close→`OnLinkLost`, sent/received→`CstpDpdState`) → `_facade.SetInner(channel)`; chạy `RunReceiveLoopAsync` nền + timer 1s.
6. **TunnelConfig**: từ `OpenConnectTunnelInfo.ToTunnelConfig()` — address/netmask→prefix/DNS/Split-Include→routes/MTU; gói data ride L3 thẳng (không IPCP).

## Vòng đời

- **Demux** (`CstpChannel.RunReceiveLoopAsync`): đọc stream → `CstpFraming.Append`/`TryReadPacket` → DATA/COMPRESSED→`InboundIpPacket` (COMPRESSED drop — chưa giải nén, V5.c), DPD-REQ→event reply, DPD-RESP/KEEPALIVE→chỉ mark-alive, DISCONNECT/TERMINATE→`PeerClosed` (dừng loop). EOF stream (read 0) cũng `PeerClosed`.
- **Gửi data** (`CstpChannel.WriteIpPacketAsync`): `CstpFraming.Encode(Data, payload)` → ghi stream (serialise qua `SemaphoreSlim` để frame không xen kẽ); event `PacketSent` reset nhịp keepalive.
- **Timer loop** (1s tick, `CstpDpdState`): `IsPeerDead` ⇒ link lost; `ShouldSendDpd` ⇒ gửi DPD-REQ (`OnDpdSent` rate-limit); else `ShouldSendKeepalive` ⇒ gửi keepalive. Mỗi gói nhận (data/control) reset `IsPeerDead`.
- **Teardown** (`DisconnectAsync`): gửi best-effort **CSTP DISCONNECT**, hủy reconnect đang chờ, hủy receive loop + timer, dispose stream.
- **Reconnect** (supervisor): mirror WireGuard/OpenVPN/SoftEther — `EstablishAsync`/`ReconnectLoopAsync` backoff+jitter sau `SwappablePacketChannel` ổn định; `Reconnected` mang `NewAddress` + `AddressChanged` (ocserv thường cấp lại cùng IP theo cookie).

## Bảng chuẩn / RFC

| Khối | Chuẩn / nguồn | Ghi chú |
|------|---------------|---------|
| CSTP framing | draft-mavrogiannopoulos-openconnect + ocserv behavior | header `STF 0x01 \| len BE \| type \| 0x00` (xem [OpenConnect README](../TqkLibrary.VpnClient.OpenConnect/README-vi.md)) |
| HTTPS config-auth | ocserv `<config-auth>` XML | init/form/reply/success + cookie `webvpn=` |
| HTTP CONNECT | `CONNECT /CSCOSSLC/tunnel` + `X-CSTP-*` | Address/Netmask/DNS/Split-Include/MTU/DPD/Keepalive/Rekey-* |
| DPD/keepalive | `X-CSTP-DPD` / `X-CSTP-Keepalive` | clock-inject `CstpDpdState`, dead-window ×2 (miss-two-DPD) |
| Transport | TLS byte-stream (F.1) | DTLS (V5.c, F.3) song song sau |
| Address | in-band config-push (X-CSTP-*) | không IPCP/DHCP — `OpenConnectTunnelInfo` → `TunnelConfig` |

## Trạng thái & ghi chú

- **Đã có (V5.b)**: end-to-end **offline** — HTTPS config-auth (username/password→cookie), HTTP CONNECT (X-CSTP-* in-band), CSTP-over-TLS data plane 2 chiều, DPD (probe + reply) + keepalive clock-inject, teardown (DISCONNECT) + supervisor reconnect; `UseOpenConnect()`. Test offline qua **server ocserv giả lập** (auth form + CONNECT + CSTP echo + DPD) trên loopback byte-stream: auth→CONNECT→IP round-trip 2 chiều, sai mật khẩu ⇒ `VpnAuthenticationException`, DPD server-probe/client-probe, peer-disconnect teardown, driver facade.
- **Chưa**:
  - **rekey `X-CSTP-Rekey-Method`** (`ssl`/`new-tunnel`) — đã parse `RekeyMethod`/`RekeyTime` vào `OpenConnectTunnelInfo` nhưng chưa wire timer rekey; driver hiện sống nhờ DPD/keepalive + supervisor.
  - **DTLS data path** (V5.c, F.3 — DTLS client qua BouncyCastle cả 2 TFM), fallback TLS khi DTLS fail.
  - **COMPRESSED** payload (LZS/LZ4) — hiện drop, chỉ no-compression.
  - **dialect Fortinet/F5/GlobalProtect** (cùng họ TLS+DTLS, khác handshake HTTP).
  - **validate live** (lab **Q.1** — ocserv Docker): interop auth/CONNECT/CSTP/DPD thật + cert pinning.
- **Tham chiếu**: draft-mavrogiannopoulos-openconnect + OpenConnect/ocserv — **chỉ đọc spec/behavior, không copy GPL source**; roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.5 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. TLS byte-stream production theo TFM giống [`OpenVpnSocketTransportFactory`](../TqkLibrary.VpnClient.Drivers.OpenVpn/Transport/OpenVpnSocketTransportFactory.cs) / SSTP [`TlsByteStream`](../TqkLibrary.VpnClient.Drivers.Sstp/Transport/TlsByteStream.cs) (net5+ overload ct; ns2.0 cancel-by-dispose). `CstpChannel`/`OpenConnectHttpTransactor` giữ Span ngoài await (encode đồng bộ trước write — an toàn C# 12).
