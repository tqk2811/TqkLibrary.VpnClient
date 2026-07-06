# TqkLibrary.VpnClient.Drivers.Fou

> Driver runtime **FOU + GUE** (Generic X-over-UDP encapsulation): chở một gói **inner IP-protocol** (IPIP proto-4/41 hoặc GRE proto-47) trong **payload UDP** — hoặc **trần** (Linux Foo-over-UDP: inner-proto suy từ UDP dst-port), hoặc sau **header GUE variant-0 4 byte** (draft-ietf-intarea-gue: header mang số hiệu inner-proto). **Tổng quát hoá GRE-in-UDP** (RFC 8086 = GUE proto=47 với port cố định). Ráp một transport UDP đã-connect ([`FouUdpDatagramTransport`](FouUdpDatagramTransport.cs#L18)) với **kênh data-plane có sẵn** ở [`TqkLibrary.VpnClient.IpEncap`](../TqkLibrary.VpnClient.IpEncap) ([`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21) cho GRE / [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) cho IPIP) thành một `IVpnConnection` hoàn chỉnh, sau một facade kênh L3 ổn định.
>
> Giống [Drivers.GreInUdp](../TqkLibrary.VpnClient.Drivers.GreInUdp) và khác [Drivers.IpEncap](../TqkLibrary.VpnClient.Drivers.IpEncap) (raw-IP, **cần elevate**): FOU/GUE chỉ dùng **socket UDP thường** ⇒ **không cần admin/root/CAP_NET_RAW, không raw IP socket**, và đi qua được NAT/firewall cho phép UDP.
>
> ⚠️ **FOU/GUE TRẦN không mã hóa** — chỉ dùng trong mạng tin cậy hoặc **kèm IPsec ESP** ở trên.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối cho encapsulation FOU/GUE. Giống nhóm IP-encap thuần + GRE-in-UDP, nó **không có control plane**: không handshake, không auth, không keepalive/DPD — địa chỉ tunnel được dàn xếp **out-of-band**. Nó chỉ: mở transport UDP đã-connect tới `host:port` → (GUE) bọc thêm header GUE → dựng kênh data-plane inner phù hợp rồi publish sau facade ổn định.

Điểm cốt lõi: **tái dùng tối đa**. Codec GRE + hai kênh data-plane (`GreTunnelChannel`, `RawIpPassthroughChannel`) lấy **nguyên** từ project [IpEncap](../TqkLibrary.VpnClient.IpEncap) (không sửa). Phần MỚI của project này chỉ gồm: (1) codec header GUE variant-0 thuần [`GueHeader`](GueHeader.cs#L20); (2) một decorator transport [`GueFramingTransport`](GueFramingTransport.cs#L17) thêm/bóc header GUE quanh transport UDP — nhờ vậy hai kênh inner **không cần biết gì về GUE**; (3) một transport UDP thụ động [`FouUdpDatagramTransport`](FouUdpDatagramTransport.cs#L18) (copy pattern của GreInUdp). Vì cùng inner data-plane, gói lên dây chỉ khác ở **lớp mang ngoài**.

> Quan hệ với [Drivers.GreInUdp](../TqkLibrary.VpnClient.Drivers.GreInUdp): GRE-in-UDP (RFC 8086) ≈ **FOU với inner-proto = GRE-47** trên port cố định 4754. Project này tổng quát hoá: thêm chế độ **GUE** (có header) và thêm inner-proto **IPIP** (proto-4/41, passthrough). Toàn bộ máy supervisor/reconnect/facade dùng chung [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6).

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10), `IHostResolver`/`DnsHostResolver`, `AddressFamilyPreference`, [`IpProtocol`](../TqkLibrary.VpnClient.Abstractions/Net/IpProtocol.cs#L8)...) + **`Diagnostics`** (`VpnLogExtensions`).
  - [TqkLibrary.VpnClient.Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) — base supervisor [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) + model reconnect chung [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14).
  - [TqkLibrary.VpnClient.IpEncap](../TqkLibrary.VpnClient.IpEncap) — kênh data-plane [`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21) + [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) + [`GreTunnelOptions`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelOptions.cs#L9) + codec `GreCodec`/`GrePacket` (dùng lại nguyên, không sửa).
  - **Transport UDP** là concrete nội bộ [`FouUdpDatagramTransport`](FouUdpDatagramTransport.cs#L18) (socket UDP thường qua BCL) — không PackageReference đặc thù.
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — [`VpnClientBuilder.UseFou(...)`](../TqkLibrary.VpnClient/VpnClientBuilder.cs#L142) và [`UseGue(...)`](../TqkLibrary.VpnClient/VpnClientBuilder.cs#L157) đăng ký driver này với `Name` là `fou` / `gue`).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Fou/
├── FouDriver.cs                  IVpnProtocolDriver: Name fou/gue theo Mode + capabilities (no elevation/no raw socket) + ConnectAsync → IVpnConnection
├── FouConnection.cs              Bộ điều phối: resolve host → mở UDP → (GUE) bọc GueFramingTransport → chọn kênh inner (GRE/IPIP) → publish facade + teardown
├── FouVpnConnection.cs           Adapter IVpnConnection (1 session; OpenSessionAsync ⇒ NotSupported)
├── FouVpnSession.cs              IVpnSession: TunnelConfig + PacketChannel (facade)
├── FouOptions.cs                 Cấu hình tĩnh (record): Mode (FOU/GUE) + InnerProtocol (4/41/47) + Port (6080) + Mtu (1400) + GreTunnelOptions?
├── FouReconnectOptions.cs        Named subclass của VpnReconnectOptions (không thêm knob)
├── Enums/FouEncapMode.cs         enum Fou / Gue
├── GueHeader.cs                  Codec thuần header GUE variant-0: Encode + TryDecode (kiểm Ver=0, drop C-bit, skip Hlen×4 extension)
├── GueFramingTransport.cs        Decorator IDatagramTransport: prepend/strip header GUE quanh transport UDP (chỉ dùng ở GUE mode)
├── IFouTransportFactory.cs       Seam tạo IDatagramTransport UDP (injectable cho test)
├── FouUdpTransportFactory.cs     Factory production: tạo FouUdpDatagramTransport
└── FouUdpDatagramTransport.cs    IDatagramTransport UDP THỤ ĐỘNG (không tự chạy receive-pump; kênh tự lái)
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`FouDriver`](FouDriver.cs#L21) | `IVpnProtocolDriver`. `Name` = `"gue"` khi `Mode=Gue`, ngược lại `"fou"` (tính từ options). `Capabilities` (L3Ip / **Udp** / SecurityKinds=None / AuthMethods=None / `AddressAssignment=OutOfBand` / **`RequiresElevation=false`** / **`RequiresRawIpSocket=false`**). `ConnectAsync` dựng `FouConnection` → `FouVpnConnection`. Ctor nhận `FouOptions?`/`FouReconnectOptions?` + `IFouTransportFactory?` (null ⇒ `FouUdpTransportFactory` production) + `ILoggerFactory?`. |
| [`FouConnection`](FouConnection.cs#L32) | Kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24). `EstablishAsync` chọn kênh inner theo `InnerProtocol` (4/41 ⇒ passthrough, 47 ⇒ GRE) và bọc `GueFramingTransport` khi `Mode=Gue`. Override `CleanupAttemptResourcesAsync`/`StopAttemptLoop` (no-op: encap không keepalive). Phơi `Port`/`Mtu`. `IDisposable`/`IAsyncDisposable`. `DriverNameFor(options)` (internal) suy `fou`/`gue`. |
| [`FouVpnConnection`](FouVpnConnection.cs#L10) | Adapter `IVpnConnection` (1 session). `OpenSessionAsync` ⇒ `NotSupportedException`. |
| [`FouVpnSession`](FouVpnSession.cs#L9) | `IVpnSession`: `Config` (TunnelConfig) + `PacketChannel` (facade ổn định). |
| [`FouOptions`](FouOptions.cs#L13) | Cấu hình tĩnh (**record** — builder ép `Mode` qua `with`): `Mode` ([`FouEncapMode`](Enums/FouEncapMode.cs#L7)) + `InnerProtocol` (byte — [`IpProtocol`](../TqkLibrary.VpnClient.Abstractions/Net/IpProtocol.cs#L8) IpInIp/Ipv6/Gre, mặc định **Gre**) + `Port` (mặc định **6080** — port IANA "gue") + `Mtu` (1400) + `Gre` (`GreTunnelOptions?` cho RFC 2890, chỉ khi inner=GRE). |
| [`FouReconnectOptions`](FouReconnectOptions.cs#L14) | Named subclass của `VpnReconnectOptions` (chỉ giữ public API; không thêm knob). |
| [`FouEncapMode`](Enums/FouEncapMode.cs#L7) | enum `Fou` (không header) / `Gue` (header variant-0). |
| [`GueHeader`](GueHeader.cs#L20) | `static` codec thuần GUE variant-0. `Encode(proto, payload)` = header 4B tối thiểu (Ver=0/C=0/Hlen=0/Flags=0 + Proto) ‖ payload. `TryDecode(datagram, out proto, out payloadOffset)`: false khi len<4 / Ver≠0 / **C-bit set (control)** / extension cụt; ngược lại trả `proto` + offset payload (**skip Hlen×4 byte extension** không diễn giải). |
| [`GueFramingTransport`](GueFramingTransport.cs#L17) | `internal` decorator `IDatagramTransport` (chỉ GUE): `SendAsync` prepend header GUE(InnerProtocol); `ReceiveAsync` bóc + kiểm header qua `GueHeader.TryDecode`, **drop (return 0)** nếu không hợp lệ / control / proto ≠ InnerProtocol. FOU mode KHÔNG dùng decorator. |
| [`IFouTransportFactory`](IFouTransportFactory.cs#L13) | Seam `IDatagramTransport Create(IPEndPoint remote)` — trả transport UDP **chưa-connect**. Injectable cho test. |
| [`FouUdpTransportFactory`](FouUdpTransportFactory.cs#L11) | `IFouTransportFactory` production: tạo `FouUdpDatagramTransport`. Ctor tuỳ chọn `localBind`. |
| [`FouUdpDatagramTransport`](FouUdpDatagramTransport.cs#L18) | `internal sealed` `IDatagramTransport` UDP **thụ động** (bind ephemeral + connect; `ReceiveAsync` await đúng 1 datagram; **không** tự chạy receive-pump). Hỗ trợ IPv4/IPv6 theo `AddressFamily` của remote. netstandard2.0 fallback `ArraySegment`. Mirror `UdpDatagramTransport` của GreInUdp. |
| [`VpnConnectionState`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) | enum trạng thái dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) (state kế thừa từ base). |

## Bảng chuẩn / RFC

| Chuẩn | Dùng ở đâu |
|-------|------------|
| draft-ietf-intarea-gue (GUE variant 0) | Header 4B `Ver(2)|C(1)|Hlen(5) ‖ Proto(8) ‖ Flags(16)` + `Hlen×4` byte extension. Codec [`GueHeader`](GueHeader.cs#L20); framing [`GueFramingTransport`](GueFramingTransport.cs#L17). |
| FOU (Linux Foo-over-UDP, `ip fou`) | Không header — payload UDP = gói inner IP-proto; proto suy từ UDP dst-port (cấu hình `InnerProtocol`). Không codec header ([`FouConnection`](FouConnection.cs#L32) dùng thẳng kênh inner). |
| RFC 8086 (GRE-in-UDP) | Trường hợp riêng: FOU/GUE inner=GRE-47. Tái dùng đúng [`GreTunnelChannel`](../TqkLibrary.VpnClient.IpEncap/Gre/GreTunnelChannel.cs#L21). |
| RFC 2784/2890 (GRE) | Inner-proto GRE-47: header GRE v0 + tuỳ chọn Key/Sequence/Checksum — tái dùng `GreCodec` (nguyên). |
| RFC 2003 (IPIP) / RFC 4213 (SIT/6in4) | Inner-proto 4 / 41: passthrough header-less — tái dùng [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20). |

## Luồng nội bộ — `EstablishAsync` ([FouConnection.cs](FouConnection.cs#L74))

Một lần dựng tunnel (dùng lại cho connect đầu tiên + mọi reconnect). **Không handshake** — kênh live ngay khi socket connect:

1. **Cleanup** — `CleanupAttemptResourcesAsync` (drop kênh của attempt trước nếu có).
2. **Resolve + open transport** — resolve server IP qua `IHostResolver` → `new IPEndPoint(serverIp, Port)` → `transportFactory.Create(endpoint)` → `transport.ConnectAsync` (bind UDP ephemeral + connect; lỗi ⇒ dispose transport rồi throw).
3. **(GUE) bọc header** — nếu `Mode=Gue`: `dataTransport = new GueFramingTransport(transport, InnerProtocol)`; nếu `Mode=Fou`: `dataTransport = transport` (trần).
4. **Dựng kênh inner** (`BuildInnerChannel`) — theo `InnerProtocol`: `47` ⇒ `GreTunnelChannel` (pin MTU theo `Mtu`); `4`/`41` ⇒ `RawIpPassthroughChannel`; khác ⇒ `NotSupportedException`. Gọi `channel.Start()`.
5. **Publish** — `Facade.SetInner(channel)` → `MarkConnected`.

**Chiều nhận (GUE):** `GueFramingTransport.ReceiveAsync` đọc datagram thô → `GueHeader.TryDecode` (drop nếu Ver≠0 / C-bit / proto sai) → trả **payload** cho kênh inner (kênh không thấy header GUE). **Chiều nhận (FOU):** kênh inner đọc thẳng datagram.

**`CleanupAttemptResourcesAsync`:** **null-rồi-dispose** kênh — `channel.DisposeAsync()` đóng luôn `dataTransport` (decorator ⇒ đóng UDP transport bên trong). `StopAttemptLoop` no-op.

`TunnelConfig` dựng ở [`FouDriver.ConnectAsync`](FouDriver.cs#L21) từ `Mtu` (không IPCP/DHCP — địa chỉ out-of-band; server host là `VpnEndpoint.Host`).

## Trạng thái & ghi chú

- **Offline xong** (code + test). Build xanh cả `netstandard2.0` + `net8.0`. Test: [`tests/TqkLibrary.VpnClient.Drivers.Fou.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Fou.Tests) (29 case) — GUE header round-trip (4 proto) + skip Hlen extension + reject Ver≠0/C-bit/runt/extension-cụt; dispatch end-to-end 2 chiều (FOU/GUE × IPIP/GRE × v4/v6, 8 case) qua `LoopbackDatagramLink`; GUE drop wrong-proto rồi deliver hợp lệ; round-trip **UDP loopback thật** trên `127.0.0.1` (FOU-IPIP echo); driver caps + Name `fou`/`gue`; default options (Mode=Fou/Inner=GRE/Port=6080); null-factory throws.
- **Validate live — CHỜ.** Cần peer Linux: FOU `ip fou add port <p> ipproto <4|41|47>` + `ip link ... encap fou encap-dport <p>`; GUE `ip fou add port <p> gue` + `ip link ... encap gue encap-dport <p>`. Client demo với IP tunnel TĨNH (connectionless không có IPCP). Chưa chạy live trong lab.
- **Không mirror GreInUdp 1:1:** (a) driver mang **Mode + InnerProtocol** (GreInUdp cố định GRE-47/port-4754); (b) `Name` tính từ Mode (`fou`/`gue`) nên **một `FouDriver` đăng ký 2 key** (builder `UseFou`/`UseGue` ép Mode qua `with`); (c) thay vì chỉ `GreTunnelChannel`, dùng thêm `RawIpPassthroughChannel` (IPIP) + decorator `GueFramingTransport` để tối đa tái dùng kênh inner.
- ⚠️ **Bảo mật:** FOU/GUE trần — không mã hóa. Bảo mật (nếu cần) đặt ở tầng trên (IPsec ESP).
