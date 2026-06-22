# TqkLibrary.VpnClient.Drivers.IpEncap

> Driver runtime **IP-in-IP / GRE thuần** (RFC 2784/2890 GRE proto-47, RFC 2003 IPIP proto-4, RFC 4213 SIT/6in4 proto-41): ráp transport raw-IP F.9 ([`IRawIpTransportFactory`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12)) với các kênh data-plane đã có ở [`TqkLibrary.VpnClient.IpEncap`](../TqkLibrary.VpnClient.IpEncap) ([`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21) / [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20)) thành một `IVpnConnection` hoàn chỉnh, sau một facade kênh L3 ổn định. Đây là phase **(b)** của roadmap V.8 — phase (a) (codec + kênh) đã xong ở project codec.
>
> ⚠️ **GRE/IPIP/SIT TRẦN không mã hóa** — chỉ dùng trong mạng tin cậy hoặc **kèm IPsec ESP** ở trên. Transport raw-IP (F.9) **bắt buộc elevate**.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối cho nhóm encapsulation IP-trên-IP thuần. Khác mọi driver khác ở chỗ **không có control plane**: không handshake, không auth, không keepalive/DPD — địa chỉ tunnel được dàn xếp **out-of-band**. Nó chỉ: mở transport raw-IP theo đúng số hiệu proto của kiểu encap rồi dựng kênh data-plane tương ứng và publish sau facade ổn định.

Driver IpEncap ([IpEncapDriver.cs](IpEncapDriver.cs)) chọn kênh theo [`IpEncapKind`](Enums/IpEncapKind.cs):

- **GRE** (proto-47) → [`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21) (bọc header GRE RFC 2784/2890, tuỳ chọn Key/Sequence/Checksum).
- **IPIP** (proto-4) / **SIT** (proto-41) → [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) (header-less, gói IP trong IS payload raw-IP).

Vì là encap **connectionless**, một mất link âm thầm không phát hiện được nên auto-reconnect không tự kích; máy supervisor vẫn được kế thừa (đối xứng + để dành control-plane keepalive tương lai).

> So với [Drivers.Pptp](../TqkLibrary.VpnClient.Drivers.Pptp): IpEncap là "WireGuard **bỏ** handshake" — toàn bộ máy supervisor/reconnect/facade dùng chung [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6); driver chỉ mở transport + start kênh, không control connection, không PPP, không MPPE.

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, [`IRawIpTransportFactory`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12), `IHostResolver`/`DnsHostResolver`, `AddressFamilyPreference`...) + **`Diagnostics`** (`VpnLogExtensions` — log handshake/state/reconnect).
  - [TqkLibrary.VpnClient.Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) — base supervisor [`ReconnectingVpnConnection<TState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) + model reconnect chung [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14).
  - [TqkLibrary.VpnClient.IpEncap](../TqkLibrary.VpnClient.IpEncap) — các kênh data-plane [`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21) / [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) + [`GreTunnelOptions`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelOptions.cs#L9).
  - **Data plane** chỉ phụ thuộc **interface** [`IRawIpTransportFactory`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L12) (ở `Abstractions`) — driver **không** ProjectReference [`Transport.RawIp`](../TqkLibrary.VpnClient.Transport.RawIp); app tự cấp concrete `RawIpTransportFactory` (kéo project đó vào) khi muốn bật. Số hiệu proto (47/4/41) là const nội bộ trong [`IpEncapConnection`](IpEncapConnection.cs) (mirror const `GreIpProtocol = 47` ở driver PPTP), tránh phụ thuộc thừa.
  - Không có PackageReference đặc thù — chỉ dùng BCL.
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — [`VpnClientBuilder.UseIpEncap(IRawIpTransportFactory, ...)`](../TqkLibrary.VpnClient/VpnClientBuilder.cs) đăng ký driver này).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.IpEncap/
├── IpEncapDriver.cs                IVpnProtocolDriver: capabilities + ConnectAsync → IVpnConnection
├── IpEncapConnection.cs            Bộ điều phối: mở raw-IP theo proto-number → dựng kênh GRE/passthrough → publish facade + teardown
├── IpEncapVpnConnection.cs         Adapter IVpnConnection (1 session; OpenSessionAsync ⇒ NotSupported)
├── IpEncapVpnSession.cs            IVpnSession: TunnelConfig + PacketChannel (facade)
├── IpEncapOptions.cs               Cấu hình tĩnh: Kind (GRE/IPIP/SIT) + Mtu + GreTunnelOptions (RFC 2890 Key/Seq/Checksum)
├── IpEncapReconnectOptions.cs      Named subclass của VpnReconnectOptions (không thêm knob)
└── Enums/
    ├── IpEncapKind.cs              Gre / IpIp / Sit (chọn cả proto-number lẫn kênh)
    └── IpEncapConnectionState.cs   Disconnected / Connecting / Connected / Reconnecting
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`IpEncapDriver`](IpEncapDriver.cs) | `IVpnProtocolDriver`. `Name="ipencap"`, `Capabilities` (L3Ip / RawIp / SecurityKinds=None / AuthMethods=None / `AddressAssignment=OutOfBand` / `RequiresElevation`+`RequiresRawIpSocket`), `ConnectAsync` dựng `IpEncapConnection` → `IpEncapVpnConnection`. Ctor nhận `IRawIpTransportFactory` (bắt buộc, null ⇒ `ArgumentNullException`) + `IpEncapOptions`/`IpEncapReconnectOptions` + `ILoggerFactory?`. |
| [`IpEncapConnection`](IpEncapConnection.cs) | Kế thừa [`ReconnectingVpnConnection<IpEncapConnectionState>`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24). Override `EstablishAsync`/`CleanupAttemptResourcesAsync`/`StopAttemptLoop` (no-op: encap không keepalive) + 4 ánh xạ state. Phơi `Kind`/`Mtu`. `IDisposable`/`IAsyncDisposable`. |
| [`IpEncapVpnConnection`](IpEncapVpnConnection.cs) | Adapter `IVpnConnection` (1 session). `OpenSessionAsync` ⇒ `NotSupportedException` (1 encap / 1 remote). |
| [`IpEncapVpnSession`](IpEncapVpnSession.cs) | `IVpnSession`: `Config` (TunnelConfig) + `PacketChannel` (facade ổn định). |
| [`IpEncapOptions`](IpEncapOptions.cs) | Cấu hình tĩnh: `Kind` (mặc định GRE) + `Mtu` (1400) + `Gre` (`GreTunnelOptions?` cho RFC 2890 Key/Sequence/Checksum; bỏ qua với IPIP/SIT). MTU kênh luôn lấy theo `Mtu` bất kể giá trị trên `Gre`. |
| [`IpEncapReconnectOptions`](IpEncapReconnectOptions.cs) | Named subclass của `VpnReconnectOptions` (chỉ để giữ public API; không thêm knob). |
| [`IpEncapKind`](Enums/IpEncapKind.cs) | enum Gre(47) / IpIp(4) / Sit(41) — chọn cả proto-number mở transport lẫn kênh data-plane. |
| [`IpEncapConnectionState`](Enums/IpEncapConnectionState.cs) | enum Disconnected/Connecting/Connected/Reconnecting. |

## Bảng chuẩn / RFC

| Chuẩn | Dùng ở đâu |
|-------|------------|
| RFC 2784/2890 (GRE) | Kiểu `Gre` → `GreTunnelChannel` (proto-47), header GRE v0 + tuỳ chọn Key/Sequence/Checksum. |
| RFC 2003 (IP-in-IP) | Kiểu `IpIp` → `RawIpPassthroughChannel` (proto-4), IPv4-in-IPv4 header-less. |
| RFC 4213 (SIT/6in4) | Kiểu `Sit` → `RawIpPassthroughChannel` (proto-41), IPv6-in-IPv4 header-less. |

## Luồng nội bộ — `EstablishAsync` ([IpEncapConnection.cs](IpEncapConnection.cs))

Một lần dựng tunnel (dùng lại cho connect đầu tiên + mọi reconnect). **Không handshake** — kênh live ngay khi socket mở:

1. **Cleanup** — gọi `CleanupAttemptResourcesAsync` (drop kênh của attempt trước nếu có).
2. **Resolve + open transport** — resolve server IP qua `IHostResolver` + local bind IP (`GetLocalAddress`, socket connected throwaway) → `_rawIpFactory.Create(serverIp, protocol, localBind)` với `protocol` = `ProtocolNumber` theo `Kind` (47/4/41).
3. **Dựng kênh** — GRE: `new GreTunnelChannel(transport, greOptions, Logger)` (pin MTU kênh theo `_options.Mtu`); IPIP/SIT: `new RawIpPassthroughChannel(transport, _options.Mtu, Logger)`. Gọi `Start()` (mở receive loop).
4. **Publish** — `Facade.SetInner(channel)` (bind kênh L3 vào facade ổn định) → `MarkConnected`.

**`CleanupAttemptResourcesAsync`** (mirror Pptp): **null-rồi-dispose** kênh (`channel.DisposeAsync()` đóng luôn raw transport, unblock receive loop). `StopAttemptLoop` no-op (encap không có timer keepalive).

`TunnelConfig` được dựng ở [`IpEncapDriver.ConnectAsync`](IpEncapDriver.cs) từ `_options.Mtu` (không có IPCP/DHCP — địa chỉ out-of-band).

## Trạng thái & ghi chú

- **Offline xong** (code + test). Build xanh cả `netstandard2.0` + `net8.0`. Test: `tests/TqkLibrary.VpnClient.Drivers.IpEncap.Tests` (6 test, không socket thật) — driver capabilities/guard + round-trip gói IP cả 3 kiểu (GRE bọc/gỡ header; IPIP/SIT verbatim) qua transport raw-IP giả loopback.
- **Validate live còn lại** — cần raw-IP proto-47/4/41 + elevate (gateway GRE/IPIP/SIT thật). Reconnect chỉ kích khi caller báo link-loss tường minh (encap connectionless không tự phát hiện).
- **Chưa làm (để dành):** codec **EtherIP** (RFC 3378, proto-97, Ethernet-in-IP → `IEthernetChannel`) + **L2TPv3-over-IP** (RFC 3931, proto-115, session-id) — cần ghép L2 fabric, vượt phạm vi phase này; nếu thêm sẽ đặt codec ở project [IpEncap](../TqkLibrary.VpnClient.IpEncap) + hằng ở `RawIpProtocols`.
- ⚠️ **Bảo mật:** GRE/IPIP/SIT trần — không mã hóa. Bảo mật (nếu cần) đặt ở tầng trên (IPsec ESP).
