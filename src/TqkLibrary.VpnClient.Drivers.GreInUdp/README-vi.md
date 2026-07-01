# TqkLibrary.VpnClient.Drivers.GreInUdp

> Driver runtime **GRE-in-UDP** (RFC 8086): chở đúng header GRE (RFC 2784/2890) trong **payload UDP, dst port 4754** thay vì raw-IP proto-47. Ráp một transport UDP đã-connect ([`UdpDatagramTransport`](UdpDatagramTransport.cs#L17)) với kênh data-plane GRE đã có sẵn ở [`TqkLibrary.VpnClient.IpEncap`](../TqkLibrary.VpnClient.IpEncap) ([`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21)) thành một `IVpnConnection` hoàn chỉnh, sau một facade kênh L3 ổn định.
>
> Khác với [Drivers.IpEncap](../TqkLibrary.VpnClient.Drivers.IpEncap) (GRE trên proto-47 raw-IP, **cần elevate**), GRE-in-UDP chỉ dùng **socket UDP thường** ⇒ **không cần admin/root/CAP_NET_RAW, không raw IP socket**, và đi qua được NAT/firewall cho phép UDP.
>
> ⚠️ **GRE-in-UDP TRẦN không mã hóa** — chỉ dùng trong mạng tin cậy hoặc **kèm IPsec ESP** ở trên.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối cho encapsulation GRE-in-UDP. Giống nhóm IP-encap thuần, nó **không có control plane**: không handshake, không auth, không keepalive/DPD — địa chỉ tunnel được dàn xếp **out-of-band**. Nó chỉ: mở transport UDP đã-connect tới `host:4754` rồi dựng kênh [`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21) và publish sau facade ổn định.

Điểm cốt lõi: **tái dùng nguyên** codec + kênh GRE ở project [IpEncap](../TqkLibrary.VpnClient.IpEncap). `GreTunnelChannel` nhận một [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10) trừu tượng và **tự lái receive-loop**; project này chỉ cung cấp một `IDatagramTransport` chạy trên **UDP** thay vì raw-IP. Vì cùng header GRE, gói lên dây khác IpEncap **duy nhất** ở lớp mang ngoài (UDP/4754 vs proto-47).

> So với [Drivers.IpEncap](../TqkLibrary.VpnClient.Drivers.IpEncap): cùng "WireGuard **bỏ** handshake" — toàn bộ máy supervisor/reconnect/facade dùng chung [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6); driver chỉ mở transport + start kênh. Khác biệt: transport là UDP (không elevate) thay vì raw-IP proto-47.

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10), `IHostResolver`/`DnsHostResolver`, `AddressFamilyPreference`...) + **`Diagnostics`** (`VpnLogExtensions` — log handshake/state/reconnect).
  - [TqkLibrary.VpnClient.Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) — base supervisor [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) + model reconnect chung [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14).
  - [TqkLibrary.VpnClient.IpEncap](../TqkLibrary.VpnClient.IpEncap) — kênh data-plane [`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21) + [`GreTunnelOptions`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelOptions.cs#L9) + codec `GreCodec`/`GrePacket` (dùng lại nguyên, không sửa).
  - **Transport UDP** là concrete nội bộ [`UdpDatagramTransport`](UdpDatagramTransport.cs#L17) (socket UDP thường qua BCL) — không PackageReference đặc thù, chỉ BCL.
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — [`VpnClientBuilder.UseGreInUdp(...)`](../TqkLibrary.VpnClient/VpnClientBuilder.cs) đăng ký driver này).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.GreInUdp/
├── GreInUdpDriver.cs               IVpnProtocolDriver: capabilities (no elevation/no raw socket) + ConnectAsync → IVpnConnection
├── GreInUdpConnection.cs           Bộ điều phối: resolve host → mở UDP:4754 → dựng GreTunnelChannel → publish facade + teardown
├── GreInUdpVpnConnection.cs        Adapter IVpnConnection (1 session; OpenSessionAsync ⇒ NotSupported)
├── GreInUdpVpnSession.cs           IVpnSession: TunnelConfig + PacketChannel (facade)
├── GreInUdpOptions.cs              Cấu hình tĩnh: Port (4754) + Mtu (1400) + GreTunnelOptions (RFC 2890 Key/Seq/Checksum)
├── GreInUdpReconnectOptions.cs     Named subclass của VpnReconnectOptions (không thêm knob)
├── IGreUdpTransportFactory.cs      Seam tạo IDatagramTransport UDP (injectable cho test)
├── UdpGreTransportFactory.cs       Factory production: tạo UdpDatagramTransport
└── UdpDatagramTransport.cs         IDatagramTransport UDP THỤ ĐỘNG (không tự chạy receive-pump; kênh tự lái)
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`GreInUdpDriver`](GreInUdpDriver.cs) | `IVpnProtocolDriver`. `Name="gre-udp"`, `Capabilities` (L3Ip / **Udp** / SecurityKinds=None / AuthMethods=None / `AddressAssignment=OutOfBand` / **`RequiresElevation=false`** / **`RequiresRawIpSocket=false`**), `ConnectAsync` dựng `GreInUdpConnection` → `GreInUdpVpnConnection`. Ctor nhận `GreInUdpOptions?`/`GreInUdpReconnectOptions?` + `IGreUdpTransportFactory?` (null ⇒ `UdpGreTransportFactory` production) + `ILoggerFactory?`. |
| [`GreInUdpConnection`](GreInUdpConnection.cs) | Kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24). Override `EstablishAsync`/`CleanupAttemptResourcesAsync`/`StopAttemptLoop` (no-op: encap không keepalive). Phơi `Port`/`Mtu`. `IDisposable`/`IAsyncDisposable`. |
| [`GreInUdpVpnConnection`](GreInUdpVpnConnection.cs) | Adapter `IVpnConnection` (1 session). `OpenSessionAsync` ⇒ `NotSupportedException` (1 encap / 1 remote). |
| [`GreInUdpVpnSession`](GreInUdpVpnSession.cs) | `IVpnSession`: `Config` (TunnelConfig) + `PacketChannel` (facade ổn định). |
| [`GreInUdpOptions`](GreInUdpOptions.cs) | Cấu hình tĩnh: `Port` (mặc định **4754** — IANA GRE-in-UDP) + `Mtu` (1400) + `Gre` (`GreTunnelOptions?` cho RFC 2890 Key/Sequence/Checksum). MTU kênh luôn lấy theo `Mtu` bất kể giá trị trên `Gre`. |
| [`GreInUdpReconnectOptions`](GreInUdpReconnectOptions.cs) | Named subclass của `VpnReconnectOptions` (chỉ để giữ public API; không thêm knob). |
| [`IGreUdpTransportFactory`](IGreUdpTransportFactory.cs) | Seam `IDatagramTransport Create(IPEndPoint remote)` — trả transport UDP **chưa-connect** (connection gọi `ConnectAsync` sau, giống cách IpEncap dùng `IRawIpTransportFactory.Create`). Injectable cho test. |
| [`UdpGreTransportFactory`](UdpGreTransportFactory.cs) | `IGreUdpTransportFactory` production: tạo `UdpDatagramTransport`. Ctor tuỳ chọn `localBind` (pin local source address). |
| [`UdpDatagramTransport`](UdpDatagramTransport.cs) | `internal sealed` `IDatagramTransport` UDP **thụ động** (bind ephemeral + connect tới remote; `ReceiveAsync` await đúng 1 datagram; **không** tự chạy receive-pump — `GreTunnelChannel` tự lái). Hỗ trợ IPv4/IPv6 theo `AddressFamily` của remote. netstandard2.0 fallback `ArraySegment` (không có overload `Memory<T>`). |
| [`VpnConnectionState`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) | enum Disconnected/Connecting/Connected/Reconnecting (dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) — state kế thừa từ base). |

## Bảng chuẩn / RFC

| Chuẩn | Dùng ở đâu |
|-------|------------|
| RFC 8086 (GRE-in-UDP) | Lớp mang: GRE header trong payload UDP, dst port **4754** (IANA "GRE-in-UDP"). [`GreInUdpOptions.Port`](GreInUdpOptions.cs#L13) + [`UdpDatagramTransport`](UdpDatagramTransport.cs#L17). |
| RFC 2784/2890 (GRE) | Header GRE v0 + tuỳ chọn Key/Sequence/Checksum — tái dùng [`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21)/`GreCodec` (nguyên, không sửa). |

## Luồng nội bộ — `EstablishAsync` ([GreInUdpConnection.cs](GreInUdpConnection.cs))

Một lần dựng tunnel (dùng lại cho connect đầu tiên + mọi reconnect). **Không handshake** — kênh live ngay khi socket connect:

1. **Cleanup** — gọi `CleanupAttemptResourcesAsync` (drop kênh của attempt trước nếu có).
2. **Resolve + open transport** — resolve server IP qua `IHostResolver` → `new IPEndPoint(serverIp, Port)` → `transportFactory.Create(endpoint)` → `transport.ConnectAsync` (bind UDP ephemeral + connect tới remote:4754; lỗi ⇒ dispose transport rồi throw).
3. **Dựng kênh** — `new GreTunnelChannel(transport, greOptions, Logger)` (pin MTU kênh theo `_options.Mtu`) → `channel.Start()` (mở receive loop; kênh tự gọi `transport.ReceiveAsync`).
4. **Publish** — `Facade.SetInner(channel)` (bind kênh L3 vào facade ổn định) → `MarkConnected`.

**`CleanupAttemptResourcesAsync`** (mirror IpEncap): **null-rồi-dispose** kênh (`channel.DisposeAsync()` đóng luôn UDP transport, unblock receive loop). `StopAttemptLoop` no-op (encap không có timer keepalive).

`TunnelConfig` được dựng ở [`GreInUdpDriver.ConnectAsync`](GreInUdpDriver.cs) từ `_options.Mtu` (không có IPCP/DHCP — địa chỉ out-of-band; server host là `VpnEndpoint.Host`).

## Trạng thái & ghi chú

- **Offline xong** (code + test). Build xanh cả `netstandard2.0` + `net8.0`. Test: [`tests/TqkLibrary.VpnClient.Drivers.GreInUdp.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.GreInUdp.Tests) (7 test) — round-trip **UDP loopback thật** trên `127.0.0.1` (transport ↔ peer socket echo GRE), GRE-in-UDP byte-for-byte v4/v6 qua `LoopbackDatagramLink` (chứng minh reuse kênh), driver capabilities (no elevation / no raw socket / `Name="gre-udp"`), Port mặc định 4754, và factory inject dựng `GreInUdpConnection` end-to-end.
- **Validate live — CHỜ.** Cần peer Linux dựng GRE-in-UDP: `ip link add name gre1 type gre remote <ip> local <ip>` **kèm FOU** (`ip fou add port 4754 ipproto 47` + `ip link ... encap fou encap-dport 4754`), hoặc `ip link add ... type gretap ... encap fou` cho biến thể L2. Client demo với `gre-udp://` + IP tunnel TĨNH (connectionless không có IPCP). Chưa chạy live trong lab.
- **Validate live còn lại** — reconnect chỉ kích khi caller báo link-loss tường minh (encap connectionless không tự phát hiện); GRE Key/Sequence/Checksum (RFC 2890) chưa kiểm live với gateway có key.
- ⚠️ **Bảo mật:** GRE-in-UDP trần — không mã hóa. Bảo mật (nếu cần) đặt ở tầng trên (IPsec ESP).
