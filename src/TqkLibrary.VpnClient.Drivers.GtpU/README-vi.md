# TqkLibrary.VpnClient.Drivers.GtpU

> Driver runtime **GTP-U** (GPRS Tunnelling Protocol, User plane — `3GPP TS 29.281`) ở **chế độ static** (TEID + endpoint cấu hình sẵn, **KHÔNG** control-plane GTP-C): chở một gói **IP nội (IPv4/IPv6)** trong **payload UDP** (mặc định port **2152**) sau **header G-PDU** 8 byte (message type **255**) gắn **TEID** 32-bit cấu hình. Ráp một transport UDP đã-connect ([`GtpUUdpDatagramTransport`](GtpUUdpDatagramTransport.cs#L18)) bọc trong decorator thêm/bóc header [`GtpUFramingTransport`](GtpUFramingTransport.cs#L20) với **kênh data-plane có sẵn** [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) (L3 IP) của [`TqkLibrary.VpnClient.IpEncap`](../TqkLibrary.VpnClient.IpEncap) thành một `IVpnConnection` hoàn chỉnh, sau một facade kênh L3 ổn định.
>
> Giống [Drivers.Fou](../TqkLibrary.VpnClient.Drivers.Fou) / [Drivers.Ayiya](../TqkLibrary.VpnClient.Drivers.Ayiya): GTP-U chỉ dùng **socket UDP thường** ⇒ **không cần admin/root/CAP_NET_RAW, không raw IP socket**, và đi qua được NAT/firewall cho phép UDP.
>
> ⚠️ **GTP-U KHÔNG mã hóa và KHÔNG xác thực payload** — nó chỉ **gắn TEID** để định danh tunnel (TEID không phải bí mật). Chỉ dùng trên đường tin cậy hoặc **bọc thêm** một lớp bảo mật bên ngoài (vd IPsec ESP).

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối cho encapsulation GTP-U (static mode). GTP-U là giao thức user-plane của mạng di động (GPRS/3G/4G/5G) chở gói IP thuê bao giữa các node (SGSN↔GGSN, gNB↔UPF...). Ở **chế độ static**, kênh điều khiển **GTP-C** (tạo/xóa PDP context / PDU session) **bị bỏ qua**, mọi tham số (endpoint, TEID) cấu hình sẵn. Nó chỉ: mở transport UDP đã-connect tới `host:port` → bọc decorator thêm/bóc header GTP-U → dựng kênh IP passthrough rồi publish sau facade ổn định.

Điểm cốt lõi: **tái dùng tối đa**. Kênh data-plane [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) lấy **nguyên** từ project [IpEncap](../TqkLibrary.VpnClient.IpEncap) (không sửa) — nó chở gói IP trần 2 chiều, family-agnostic (nibble version 4/6 tự quyết). Phần MỚI của project này chỉ gồm: (1) codec thuần [`GtpUHeader`](GtpUHeader.cs#L25) (`readonly struct` + static `Encode`/`TryDecode`: dựng/parse header G-PDU + optional Sequence/N-PDU + skip extension header); (2) một decorator transport [`GtpUFramingTransport`](GtpUFramingTransport.cs#L20) thêm/bóc header G-PDU quanh transport UDP — nhờ vậy `RawIpPassthroughChannel` **không cần biết gì về GTP-U**; (3) một transport UDP thụ động [`GtpUUdpDatagramTransport`](GtpUUdpDatagramTransport.cs#L18) (copy pattern của Fou). Không thêm phụ thuộc crypto (GTP-U trần).

> Quan hệ với [Drivers.Fou](../TqkLibrary.VpnClient.Drivers.Fou) / [Drivers.Ayiya](../TqkLibrary.VpnClient.Drivers.Ayiya): cùng mô hình **L3-over-UDP + decorator framing quanh transport + tái dùng kênh IpEncap**. Khác: GTP-U dùng header G-PDU + TEID (Fou trần / GUE 4B; AYIYA ký SHA-1), và chở **cả IPv4 lẫn IPv6** trong cùng tunnel (khác AYIYA cố định IPv6). Toàn bộ máy supervisor/reconnect/facade dùng chung [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6).

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IVpnSession`, `IPacketChannel`, `TunnelConfig`, [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10), `IHostResolver`/`DnsHostResolver`, `AddressFamilyPreference`) + **`Diagnostics`** (`VpnLogExtensions`).
  - [TqkLibrary.VpnClient.Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) — base supervisor [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) + model reconnect chung [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14).
  - [TqkLibrary.VpnClient.IpEncap](../TqkLibrary.VpnClient.IpEncap) — kênh data-plane [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) (dùng lại nguyên, không sửa).
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — [`VpnClientBuilder.UseGtpU(...)`](../TqkLibrary.VpnClient/VpnClientBuilder.cs#L461) đăng ký driver này với `Name` là `gtpu`).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.GtpU/
├── GtpUDriver.cs                  IVpnProtocolDriver: Name "gtpu" + capabilities (no elevation/no raw socket, None auth) + ConnectAsync → IVpnConnection
├── GtpUConnection.cs              Bộ điều phối: resolve host → mở UDP → bọc GtpUFramingTransport → RawIpPassthroughChannel → publish facade + teardown
├── GtpUVpnConnection.cs           Adapter IVpnConnection (1 session; OpenSessionAsync ⇒ NotSupported)
├── GtpUVpnSession.cs              IVpnSession: TunnelConfig + PacketChannel (facade)
├── GtpUOptions.cs                Cấu hình tĩnh (record): Port (2152) + Teid (uint32) + ExpectedInboundTeid? + EnableSequence + Mtu (1400)
├── GtpUReconnectOptions.cs        Named subclass của VpnReconnectOptions (không thêm knob)
├── GtpUHeader.cs                  Codec thuần (readonly struct + static Encode/TryDecode): header G-PDU 8B + optional Sequence/NPDU/NextExt + skip extension header
├── GtpUFramingTransport.cs        Decorator IDatagramTransport: egress bọc G-PDU (TEID + optional Sequence) / ingress giữ chỉ G-PDU khớp TEID rồi bóc payload IP
├── IGtpUTransportFactory.cs       Seam tạo IDatagramTransport UDP (injectable cho test)
├── GtpUUdpTransportFactory.cs     Factory production: tạo GtpUUdpDatagramTransport
└── GtpUUdpDatagramTransport.cs    IDatagramTransport UDP THỤ ĐỘNG (không tự chạy receive-pump; kênh tự lái)
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`GtpUDriver`](GtpUDriver.cs#L21) | `IVpnProtocolDriver`. `Name="gtpu"`. `Capabilities` (L3Ip / **Udp** / SecurityKinds=**None** (payload không mã hóa) / AuthMethods=**None** (TEID không phải bí mật) / `AddressAssignment=OutOfBand` / **`RequiresElevation=false`** / **`RequiresRawIpSocket=false`**). `ConnectAsync` dựng `GtpUConnection` → `GtpUVpnConnection`. Ctor nhận `GtpUOptions?` + `GtpUReconnectOptions?` + `IGtpUTransportFactory?` (null ⇒ `GtpUUdpTransportFactory` production) + `ILoggerFactory?`. |
| [`GtpUConnection`](GtpUConnection.cs#L30) | Kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24). `EstablishAsync` bọc `GtpUFramingTransport` quanh UDP transport rồi dựng `RawIpPassthroughChannel`. Override `CleanupAttemptResourcesAsync`/`StopAttemptLoop` (no-op: static mode không keepalive). Phơi `Port`/`Mtu`. `IDisposable`/`IAsyncDisposable`. |
| [`GtpUVpnConnection`](GtpUVpnConnection.cs#L10) | Adapter `IVpnConnection` (1 session). `OpenSessionAsync` ⇒ `NotSupportedException`. |
| [`GtpUVpnSession`](GtpUVpnSession.cs#L9) | `IVpnSession`: `Config` (TunnelConfig) + `PacketChannel` (facade ổn định). |
| [`GtpUOptions`](GtpUOptions.cs#L11) | Cấu hình tĩnh (**record**): `Port` (**2152**) + `Teid` (uint32, TEID egress) + `ExpectedInboundTeid?` (uint?, null ⇒ nhận mọi G-PDU) + `EnableSequence` (bool) + `Mtu` (**1400**). |
| [`GtpUReconnectOptions`](GtpUReconnectOptions.cs#L13) | Named subclass của `VpnReconnectOptions` (chỉ giữ public API; không thêm knob). |
| [`GtpUHeader`](GtpUHeader.cs#L25) | `readonly struct` + **codec thuần** (static). `Encode(teid, payload, sequenceNumber?)` phát G-PDU tối giản (Version 1/PT 1, cờ S khi có Sequence) với Length đúng + TEID BE. `TryDecode(datagram, out GtpUHeader)`: validate `Version==1` + Length-field (drop khi claim > datagram) + đọc TEID/message-type + bóc optional block (Sequence/N-PDU/Next-Ext-Type khi E/S/PN) + **skip extension header** khi cờ E (Length×4-octet-unit; reject unit=0 / truncated) → trả `MessageType`/`Teid`/`HasSequence`/`SequenceNumber`/`PayloadOffset`/`PayloadLength` + `IsGPdu`. Hằng: `BaseLength`=8 / `OptionalBlockLength`=4 / `Version1`=1 / `MessageTypeGPdu`=255 / `MessageTypeEchoRequest`=1 / `MessageTypeEchoResponse`=2 / `MessageTypeErrorIndication`=26. |
| [`GtpUFramingTransport`](GtpUFramingTransport.cs#L20) | `internal` decorator `IDatagramTransport`: `SendAsync` bọc gói IP thành G-PDU (TEID cấu hình + Sequence tăng dần khi `EnableSequence`); `ReceiveAsync` `TryDecode` → **giữ chỉ G-PDU** (message-type 255) khớp `ExpectedInboundTeid` (khi set) → trả payload IP, **drop (return 0)** nếu non-version-1 / non-G-PDU (Echo/Error-Indication/type khác) / TEID-lệch / runt / length-sai / header-only. |
| [`IGtpUTransportFactory`](IGtpUTransportFactory.cs#L13) | Seam `IDatagramTransport Create(IPEndPoint remote)` — trả transport UDP **chưa-connect**. Injectable cho test. |
| [`GtpUUdpTransportFactory`](GtpUUdpTransportFactory.cs#L11) | `IGtpUTransportFactory` production: tạo `GtpUUdpDatagramTransport`. Ctor tuỳ chọn `localBind`. |
| [`GtpUUdpDatagramTransport`](GtpUUdpDatagramTransport.cs#L18) | `internal sealed` `IDatagramTransport` UDP **thụ động** (bind ephemeral + connect; `ReceiveAsync` await đúng 1 datagram; **không** tự chạy receive-pump). Hỗ trợ IPv4/IPv6 theo `AddressFamily` của remote. netstandard2.0 fallback `ArraySegment`. Mirror `FouUdpDatagramTransport` của Fou. |
| [`VpnConnectionState`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) | enum trạng thái dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) (state kế thừa từ base). |

## Bảng chuẩn / RFC

> **Clean-room:** codec viết từ **SPEC** — `3GPP TS 29.281` (layout header GTP-U + G-PDU + extension header). **KHÔNG** copy code (osmocom/free5GC/kernel `drivers/net/gtp.c`...).

| Chuẩn | Dùng ở đâu |
|-------|------------|
| 3GPP TS 29.281 (GTP-U header) | Toàn bộ header 8B + optional block + extension header: codec [`GtpUHeader`](GtpUHeader.cs#L25). Byte0 `Version(3)=1 \| PT(1) \| spare \| E \| S \| PN`, byte1 message-type, byte2-3 Length (BE, số octet sau 8B mandatory), byte4-7 TEID 32-bit BE. |
| G-PDU (message type 255) | [`GtpUHeader.Encode`](GtpUHeader.cs#L25) phát type 255; [`GtpUFramingTransport`](GtpUFramingTransport.cs#L20) chỉ deliver G-PDU (drop Echo Request 1/Response 2/Error Indication 26 + type khác). Payload G-PDU = gói IP nội → [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20). |
| Optional block + extension header (E/S/PN) | [`GtpUHeader.TryDecode`](GtpUHeader.cs#L25): khi E/S/PN đọc 4B (Sequence + N-PDU + Next-Ext-Header-Type); khi E lặp chuỗi extension header (Length 1B đơn vị 4 octet + content + Next-Type 1B) tới Next-Type 0, **skip** không diễn giải (forward-compat). |

## Luồng nội bộ — `EstablishAsync` ([GtpUConnection.cs](GtpUConnection.cs#L30))

Một lần dựng tunnel (dùng lại cho connect đầu tiên + mọi reconnect). **Không handshake** — kênh live ngay khi socket connect:

1. **Cleanup** — `CleanupAttemptResourcesAsync` (drop kênh của attempt trước nếu có).
2. **Resolve + open transport** — resolve gateway IP qua `IHostResolver` → `new IPEndPoint(serverIp, Port)` → `transportFactory.Create(endpoint)` → `transport.ConnectAsync` (bind UDP ephemeral + connect; lỗi ⇒ dispose transport rồi throw).
3. **Bọc framing** — `new GtpUFramingTransport(transport, Teid, ExpectedInboundTeid, EnableSequence)`.
4. **Dựng kênh IP** — `new RawIpPassthroughChannel(framing, Mtu, Logger)` → `channel.Start()`.
5. **Publish** — `Facade.SetInner(channel)` → `MarkConnected`.

**Chiều gửi:** kênh ghi gói IP → `GtpUFramingTransport.SendAsync` bọc G-PDU (message type 255, TEID cấu hình, thêm Sequence khi `EnableSequence`), tính Length đúng → UDP. **Chiều nhận:** `GtpUFramingTransport.ReceiveAsync` đọc datagram thô → `GtpUHeader.TryDecode` → giữ **chỉ G-PDU** khớp `ExpectedInboundTeid` (khi set) → trả **payload** (gói IP nội) cho kênh; **drop (return 0)** nếu non-version-1 / non-G-PDU (Echo/Error-Indication) / TEID-lệch / runt / length-sai / header-only (kênh không thấy header GTP-U).

**`CleanupAttemptResourcesAsync`:** **null-rồi-dispose** kênh — `channel.DisposeAsync()` đóng luôn `GtpUFramingTransport` (⇒ đóng UDP transport bên trong). `StopAttemptLoop` no-op (static mode không có timer keepalive).

`TunnelConfig` dựng ở [`GtpUDriver.ConnectAsync`](GtpUDriver.cs#L21) (chỉ `Mtu`; địa chỉ tunnel là out-of-band; gateway host là `VpnEndpoint.Host`).

## Trạng thái & ghi chú

- **Offline xong** (code + test). Build xanh cả `netstandard2.0` + `net8.0`. Test: [`tests/TqkLibrary.VpnClient.Drivers.GtpU.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.GtpU.Tests) (**30 case**) — header round-trip (flag byte Version/PT/S, message-type 255, Length đúng, TEID 32-bit BE, optional Sequence/NPDU/NextExt) + skip extension header (1/2/3) + control message parse-nhưng-không-G-PDU (Echo 1/2/Error-Indication 26) + reject non-version-1 (0/2/3) / runt (0/1/4/7) / length-too-long / truncated-ext / zero-len-ext; IP passthrough 2 chiều (IPv4/IPv6 × sequence on/off) qua `LoopbackDatagramLink` + receiver **drop Echo/Error-Indication rồi deliver G-PDU** + **drop wrong-inbound-TEID rồi deliver matching**; round-trip **UDP loopback thật** trên `127.0.0.1` (echo peer reflect G-PDU); driver caps + Name `gtpu` + default options (Port 2152/Teid 0/no-sequence/Mtu 1400) + null-guard.
- **Validate live — CHỜ (residual, như Fou/AYIYA).** Cần một **UPF/GGSN** (vd open5gs / srsRAN) hoặc một Linux peer `ip link add <dev> type gtp role sgsn ...` + `gtp-link`/`gtp-tunnel` để kiểm interop 2 chiều. **Điểm dễ sai cần kiểm live**: (a) đúng TEID uplink vs downlink (Linux GTP tách `i_teid` (nhận) và `o_teid` (gửi) — bất đối xứng; ở đây `Teid` = egress, `ExpectedInboundTeid` = ingress filter tùy chọn); (b) xử lý extension header thật (vd PDU Session Container của 5G) — hiện chỉ skip theo Length, không diễn giải; (c) giá trị Sequence Number peer mong đợi.
- **Static mode:** control-channel **GTP-C** (tạo/xóa PDP context / PDU session) **BỎ QUA** — không tự phát hiện link-loss ⇒ auto-reconnect F.6 chỉ kích khi caller báo tường minh. **KHÔNG** keepalive tự động (GTP-U có Echo Request/Response type 1/2 nhưng ở đây **drop** — chưa hiện thực trả lời Echo; điểm cộng tương lai).
- ⚠️ **Bảo mật:** GTP-U **KHÔNG mã hóa và KHÔNG xác thực payload** — chỉ gắn TEID định danh tunnel. Bảo mật nội dung (nếu cần) đặt ở tầng trên hoặc bọc thêm IPsec ESP (như kiến trúc N3/N9 dùng IPsec cho GTP-U giữa gNB↔UPF).
