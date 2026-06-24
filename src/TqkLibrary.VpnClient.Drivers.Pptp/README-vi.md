# TqkLibrary.VpnClient.Drivers.Pptp

> Driver VPN **PPTP** (RFC 2637): control connection TCP/1723, data plane GRE (IP proto-47), MPPE (RFC 3078/3079) qua CCP, và PPP/MS-CHAPv2. Đây là nơi lắp ráp các khối giao thức PPTP (đã có sẵn ở [`TqkLibrary.VpnClient.Pptp`](../TqkLibrary.VpnClient.Pptp)) thành một `IVpnConnection` hoàn chỉnh.
>
> ⚠️ **PPTP + MS-CHAPv2 + MPPE/RC4 đã bị phá về mặt mật mã — chỉ để tương thích với server PPTP legacy.** Ưu tiên L2TP/IPsec, IKEv2, OpenVPN hoặc WireGuard cho mọi triển khai mới.
>
> **Trạng thái:** code-done + test offline + **VALIDATE LIVE tới tầng MPPE (2026-06-24, lab [`pptp`](../../lab/pptp/README-vi.md) — accel-ppp PPTP Docker):** control TCP/1723 → GRE-47 → LCP → MS-CHAPv2 → CCP/MPPE đều OK, **MPPE encrypt byte-perfect, khớp byte-for-byte với reference `pptp`+`pppd`**. `EstablishAsync` nay hoãn IPCP qua `mppe.CcpOpened → ppp.StartNetworkLayer()` (gói IPCP đầu mã hóa). **IPCP blocked SERVER-SIDE** (accel-ppp không mở IPCP; reference `pppd` fail y hệt) ⇒ chờ server PPTP khác (poptop/Windows RRAS/MikroTik) để chốt full ICMP-2-chiều. Demo: scheme `pptp://user:pass@host` (`Vpn2ProxyDemo`, cần `CAP_NET_RAW`).

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối control plane cho giao thức PPTP. Nó lấy các khối giao thức rời rạc đã hiện thực sẵn (control codec/state machine, GRE codec/channel, MPPE decorator, PPP engine) và **lắp ráp chúng thành một đường hầm hoàn chỉnh**, rồi bọc lại sau interface trung lập `IVpnConnection` để tầng `TqkLibrary.VpnClient` ở trên tiêu thụ mà không cần biết giao thức cụ thể.

Driver PPTP ([PptpDriver.cs](PptpDriver.cs)) gồm: **control connection TCP/1723** (Start-Control-Connection + Outgoing-Call để lấy cặp Call-ID), **data plane GRE** trên IP proto-47 (qua một `IRawIpTransportFactory` — **bắt buộc elevate**), **MPPE** qua CCP, và **PPP/MS-CHAPv2** để nhận IP. Kèm **vòng đời**: keepalive Echo-Request trên control connection, teardown sạch (Call-Clear + Stop-Control-Connection), và auto-reconnect (exponential backoff) sau một facade kênh ổn định.

Vấn đề được giải quyết: tách phần "biết cách nói chuyện với server PPTP" ra khỏi phần "biết cách dùng đường hầm" (sockets/IP stack ở trên), nhờ đảo ngược phụ thuộc qua `IVpnProtocolDriver`/`IVpnConnection` trong `Abstractions`.

> So với [Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec): PPTP là "L2TP/IPsec **bỏ** IPsec/L2TP, **thêm** GRE + MPPE". Toàn bộ máy supervisor/reconnect/facade dùng chung [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6); PPP engine + MS-CHAPv2 **tái dùng nguyên** từ [`TqkLibrary.VpnClient.Ppp`](../TqkLibrary.VpnClient.Ppp).

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL/CRYPTO ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, `IByteStreamTransport`, [`IRawIpTransportFactory`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12), typed exception, `IHostResolver`...) + **`Diagnostics`** (`VpnEventIds`/`VpnLogExtensions` — log handshake/keepalive/state/reconnect, Q.2).
  - [TqkLibrary.VpnClient.Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) — base supervisor [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) + model reconnect chung [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14) (gom supervisor/backoff-jitter/StateChanged/link-loss/teardown — F.6).
  - [TqkLibrary.VpnClient.Ppp](../TqkLibrary.VpnClient.Ppp) — [`PppEngine`](../TqkLibrary.VpnClient.Ppp/PppEngine.cs#L14), [`MsChapV2Authenticator`](../TqkLibrary.VpnClient.Ppp/Auth/MsChapV2Authenticator.cs#L13), `IPppFrameChannel`.
  - [TqkLibrary.VpnClient.Pptp](../TqkLibrary.VpnClient.Pptp) — [`PptpControlConnection`](../TqkLibrary.VpnClient.Pptp/PptpControlConnection.cs#L22), [`PptpGreChannel`](../TqkLibrary.VpnClient.Pptp/Gre/PptpGreChannel.cs#L21), [`MppePppFrameChannel`](../TqkLibrary.VpnClient.Pptp/Ccp/MppePppFrameChannel.cs#L23).
  - **GRE data plane** chỉ phụ thuộc **interface** [`IRawIpTransportFactory`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12) (ở `Abstractions`) — driver **không** ProjectReference [`Transport.RawIp`](../TqkLibrary.VpnClient.Transport.RawIp); app tự cấp concrete `RawIpTransportFactory` (kéo project đó vào) khi muốn bật. Số hiệu proto-47 là const nội bộ `GreIpProtocol` (mirror const `EspIpProtocol = 50` ở driver L2TP), tránh phụ thuộc thừa.
  - Không có PackageReference đặc thù — chỉ dùng BCL.
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — [`VpnClientBuilder.UsePptp(IRawIpTransportFactory, ...)`](../TqkLibrary.VpnClient/VpnClientBuilder.cs) đăng ký driver này).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Pptp/
├── PptpDriver.cs                    IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
├── PptpConnection.cs                Bộ điều phối: control + GRE + MPPE + PPP handshake + Echo keepalive + teardown + reconnect
├── PptpVpnConnection.cs             Adapter IVpnConnection (1 session; OpenSessionAsync ⇒ NotSupported)
├── PptpVpnSession.cs                IVpnSession: TunnelConfig + PacketChannel (facade) + ApplyReconnect
├── PptpReconnectOptions.cs          Named subclass của VpnReconnectOptions (không thêm knob)
├── PptpTimeoutOptions.cs            HandshakeTimeout (30s) + EchoInterval (60s)
├── PptpControlTransportFactory.cs   delegate seam: (VpnEndpoint, ct) → Task<IByteStreamTransport> (default real TCP; test inject)
├── Enums/
│   └── PptpConnectionState.cs       Disconnected / Connecting / Connected / Reconnecting
├── Models/
│   └── PptpReconnectInfo.cs         Kết quả reconnect: AssignedAddress + AddressChanged
└── Transport/
    └── PptpControlTcpTransport.cs   IByteStreamTransport: TcpClient cổng 1723 (plaintext, KHÔNG TLS)
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`PptpDriver`](PptpDriver.cs) | `IVpnProtocolDriver`. `Name="pptp"`, `Capabilities` (Tcp+RawIp / Mppe / UserPassword / `RequiresElevation`+`RequiresRawIpSocket`), `ConnectAsync` dựng `PptpConnection` → `PptpVpnConnection`. Ctor nhận `IRawIpTransportFactory` (bắt buộc) + reconnect/timeout options + control-transport seam + `ILoggerFactory?`. |
| [`PptpConnection`](PptpConnection.cs) | Kế thừa [`ReconnectingVpnConnection<PptpConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24). Override `EstablishAsync`/`CleanupAttemptResourcesAsync`/`StopAttemptLoop` + 4 ánh xạ state + `OnReconnected`. Phơi `AssignedAddress`/`AssignedDns` + event `Reconnected`. `IDisposable`/`IAsyncDisposable`. |
| [`PptpVpnConnection`](PptpVpnConnection.cs) | Adapter `IVpnConnection` (1 session). `OpenSessionAsync` ⇒ `NotSupportedException` (PPTP 1 call/control connection). |
| [`PptpVpnSession`](PptpVpnSession.cs) | `IVpnSession`: `Config` (TunnelConfig) + `PacketChannel` (facade ổn định) + `ApplyReconnect` (cập nhật địa chỉ/DNS sau reconnect, raise `Reconfigured`). |
| [`PptpReconnectOptions`](PptpReconnectOptions.cs) | Named subclass của `VpnReconnectOptions` (chỉ để giữ public API; không thêm knob). |
| [`PptpTimeoutOptions`](PptpTimeoutOptions.cs) | `HandshakeTimeout` (PPP auth + CCP/MPPE + IPCP, mặc định 30s) + `EchoInterval` (Echo-Request keepalive, mặc định 60s). |
| [`PptpControlTransportFactory`](PptpControlTransportFactory.cs) | `delegate Task<IByteStreamTransport>(VpnEndpoint, CancellationToken)` — seam mở byte-stream control. Default = real TCP; test inject in-memory pair. |
| [`PptpControlTcpTransport`](Transport/PptpControlTcpTransport.cs) | `IByteStreamTransport`: `TcpClient` tới `host:1723` (plaintext — **không** TLS, khác `TlsByteStream` của SSTP). Cancel-by-dispose trên netstandard2.0. |
| [`PptpConnectionState`](Enums/PptpConnectionState.cs) | enum Disconnected/Connecting/Connected/Reconnecting. |
| [`PptpReconnectInfo`](Models/PptpReconnectInfo.cs) | Kết quả 1 lần reconnect thành công: `AssignedAddress` + `AddressChanged`. |

## Bảng chuẩn / RFC

| Chuẩn | Dùng ở đâu |
|-------|------------|
| RFC 2637 (PPTP) | Control connection TCP/1723 + GRE proto-47 (qua `PptpControlConnection`/`PptpGreChannel` ở `Pptp`). |
| RFC 2759 (MS-CHAPv2) | PPP authentication (qua `MsChapV2Authenticator` ở `Ppp`). |
| RFC 3078/3079 (MPPE) | Mã hóa data plane + suy khóa từ MS-CHAPv2 NT-Response (qua `MppePppFrameChannel`/`MppeSessionFactory` ở `Pptp`/`Crypto`). |
| RFC 1661/1332 (PPP/IPCP) | LCP + IPCP để nhận IP (qua `PppEngine` ở `Ppp`). |

## Luồng nội bộ — `EstablishAsync` ([PptpConnection.cs](PptpConnection.cs))

Một lần dựng tunnel (dùng lại cho connect đầu tiên + mọi reconnect), bám đúng pattern cleanup của driver L2TP:

1. **Control connection TCP/1723** — mở `IByteStreamTransport` qua seam `_controlTransportFactory` (default [`PptpControlTcpTransport`](Transport/PptpControlTcpTransport.cs)) → [`PptpControlConnection.EstablishControlConnectionAsync`](../TqkLibrary.VpnClient.Pptp/PptpControlConnection.cs#L68) (SCCRQ⇄SCCRP) → [`PlaceOutgoingCallAsync(localCallId)`](../TqkLibrary.VpnClient.Pptp/PptpControlConnection.cs#L99) (OCRQ⇄OCRP) → lấy `LocalCallId`/`PeerCallId`.
2. **GRE data plane** — resolve server IP + local bind IP (`GetLocalAddress`, socket connected throwaway) → `_rawIpFactory.Create(serverIp, GreIpProtocol=47, localBind)` → [`new PptpGreChannel(greTransport, LocalCallId, PeerCallId)`](../TqkLibrary.VpnClient.Pptp/Gre/PptpGreChannel.cs#L43).
3. **MPPE + PPP** — `new MsChapV2Authenticator(user, pass)` → [`new MppePppFrameChannel(gre, () => (pass, auth.NtResponse!))`](../TqkLibrary.VpnClient.Pptp/Ccp/MppePppFrameChannel.cs#L41) → `new PppEngine(mppe, magic, IPAddress.Any, authenticator: auth, deferNetworkLayer: true)` (**hoãn IPCP** tới khi CCP/MPPE mở).
4. **Wire + start** — `ppp.AuthSucceeded += () => mppe.StartCcp()` (CCP/MPPE chỉ bật **sau** khi MS-CHAPv2 xong vì NT-Response là key MPPE) + `mppe.CcpOpened += () => ppp.StartNetworkLayer()` (**mở gate IPCP sau khi MPPE active** — gói IPCP đầu mã hóa, tránh server ProtoRej cleartext 0x8021, bug live V.6); `gre.Start()` + `ppp.Start()`; chờ `mppe.CcpOpenedTask` + IPCP `LinkUp` trong `HandshakeTimeout` (`AwaitHandshakeAsync`). `AuthFailed` ⇒ `VpnAuthenticationException`; timeout ⇒ `VpnNetworkTimeoutException`.
5. **Publish + keepalive** — `Facade.SetInner(ppp.PacketChannel)` (bind kênh L3 vào facade ổn định) → `StartKeepalive` (`MarkConnected` + timer Echo-Request mỗi `EchoInterval`; gửi lỗi ⇒ `OnLinkLost` để supervisor reconnect).

**`CleanupAttemptResourcesAsync`/`StopAttemptLoop`** (mirror L2TP): dừng Echo timer → cancel loop CTS → **null-rồi-dispose** GRE channel (trip identity-guard + unblock receive) → Call-Clear + Stop-Control-Connection **time-box 2s** (chỉ chạy khi control-state là `CallEstablished`/`ControlConnectionEstablished`, không bao giờ deadlock teardown) → dispose control byte-stream.

`TunnelConfig` được dựng ở [`PptpDriver.ConnectAsync`](PptpDriver.cs) từ `connection.AssignedAddress`/`AssignedDns`; `Reconnected` cập nhật session qua `ApplyReconnect`.

## Trạng thái & ghi chú

- **Offline xong** (code + test). Build xanh cả `netstandard2.0` + `net8.0`. Test: `tests/TqkLibrary.VpnClient.Drivers.Pptp.Tests` (5 test, không socket thật) — xem header file test cho phần **covered vs deferred**.
- **Validate live chờ Q.1** (poptop/accel-ppp Docker, **cần raw-IP proto-47 + elevate**). Phần **deferred** trong test: MS-CHAPv2 server-auth đầy đủ + CCP/MPPE Opened end-to-end + IPCP→`Connected` (lib chưa có server-side PPP MS-CHAPv2 nên server giả lập offline không đáp được CHAP Challenge một cách trung thực).
- **Đã thêm dùng chung** [`MppeSessionFactory.CreateServerSessions`](../TqkLibrary.VpnClient.Pptp/Ccp/MppeSessionFactory.cs) (đối xứng `CreateClientSessions`, RFC 3079 `isServer:true`) cho vai server/test interop khóa MPPE.
- ⚠️ **Bảo mật:** MS-CHAPv2 (RFC 2759) + MPPE/RC4 (RFC 3078) đã bị phá — chỉ dùng để tương thích server PPTP legacy.
