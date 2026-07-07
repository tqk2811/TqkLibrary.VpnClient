# TqkLibrary.VpnClient.Drivers.Ayiya

> Driver runtime **AYIYA** (Anything In Anything, `draft-massar-v6ops-ayiya-02`) — tunnel-broker **IPv6-over-UDP** ở **chế độ static** (endpoint + shared secret cấu hình sẵn, **BỎ QUA control-channel TIC**): chở một gói **IPv6** trong **payload UDP** (mặc định port **5072**) sau **header AYIYA** (header trường 4 byte + epoch time 4 byte + identity + signature). Gói được **ký toàn vẹn** bằng thuật toán **shared-secret SHA-1** (theo hành vi aiccu) và **chống replay** bằng epoch time. Ráp một transport UDP đã-connect ([`AyiyaUdpDatagramTransport`](AyiyaUdpDatagramTransport.cs#L18)) bọc trong decorator ký/kiểm [`AyiyaFramingTransport`](AyiyaFramingTransport.cs#L21) với **kênh data-plane có sẵn** [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) (IPv6 L3) của [`TqkLibrary.VpnClient.IpEncap`](../TqkLibrary.VpnClient.IpEncap) thành một `IVpnConnection` hoàn chỉnh, sau một facade kênh L3 ổn định.
>
> Giống [Drivers.Fou](../TqkLibrary.VpnClient.Drivers.Fou) / [Drivers.GreInUdp](../TqkLibrary.VpnClient.Drivers.GreInUdp): AYIYA chỉ dùng **socket UDP thường** ⇒ **không cần admin/root/CAP_NET_RAW, không raw IP socket**, và đi qua được NAT/firewall cho phép UDP.
>
> ⚠️ **AYIYA KHÔNG mã hóa payload** — nó **chỉ ký toàn vẹn (SHA-1 shared-secret) + chống replay bằng epoch time**, KHÔNG bảo mật nội dung. Chỉ dùng trên đường tin cậy hoặc **bọc thêm** một lớp bảo mật bên ngoài.

## Mục đích

Project này là **một driver của tầng DRIVER** — điểm điều phối cho encapsulation AYIYA (static mode). Khác nhóm IP-encap thuần: AYIYA **có xác thực** (shared secret ký từng datagram) nhưng **không có control plane động** — ở chế độ static, kênh điều khiển TIC (`draft` §TIC / RFC 3053) **bị bỏ qua**, mọi tham số (endpoint, identity, shared secret) cấu hình sẵn. Nó chỉ: mở transport UDP đã-connect tới `host:port` → bọc decorator ký/kiểm AYIYA → dựng kênh IPv6 passthrough rồi publish sau facade ổn định.

Điểm cốt lõi: **tái dùng tối đa**. Kênh data-plane [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) lấy **nguyên** từ project [IpEncap](../TqkLibrary.VpnClient.IpEncap) (không sửa) — nó chở gói IPv6 trần 2 chiều. Phần MỚI của project này chỉ gồm: (1) codec datagram thuần [`AyiyaPacket`](AyiyaPacket.cs#L24) (encode/parse header + epoch + identity + signature, và **ký/kiểm SHA-1 shared-secret** theo thuật toán aiccu); (2) một decorator transport [`AyiyaFramingTransport`](AyiyaFramingTransport.cs#L21) thêm/bóc + **ký/kiểm** header AYIYA quanh transport UDP — nhờ vậy `RawIpPassthroughChannel` **không cần biết gì về AYIYA**; (3) một transport UDP thụ động [`AyiyaUdpDatagramTransport`](AyiyaUdpDatagramTransport.cs#L18) (copy pattern của Fou/GreInUdp). SHA-1 dùng thẳng `System.Security.Cryptography.SHA1` của BCL (có sẵn cả 2 TFM) — không thêm phụ thuộc Crypto.

> Quan hệ với [Drivers.Fou](../TqkLibrary.VpnClient.Drivers.Fou): cùng mô hình **L3-over-UDP + decorator framing quanh transport + tái dùng kênh IpEncap**. Khác: AYIYA **ký toàn vẹn + chống replay** ở lớp decorator (Fou/GUE trần hoàn toàn), và cố định inner = **IPv6** (next-header 41). Toàn bộ máy supervisor/reconnect/facade dùng chung [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) (F.6).

## Vị trí trong kiến trúc

- **Tầng:** DRIVER (giữa entry point `TqkLibrary.VpnClient` ở trên và các project PROTOCOL ở dưới).
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [src/Directory.Build.props](../Directory.Build.props)).
- **Phụ thuộc (ProjectReference):**
  - [TqkLibrary.VpnClient.Abstractions](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum (`IVpnProtocolDriver`, `IVpnConnection`, `IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `TunnelConfig`, [`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs#L10), `IHostResolver`/`DnsHostResolver`, `AddressFamilyPreference`, [`IpProtocol`](../TqkLibrary.VpnClient.Abstractions/Net/IpProtocol.cs#L8) — Ipv6=41 / NoNextHeader=59) + **`Diagnostics`** (`VpnLogExtensions`).
  - [TqkLibrary.VpnClient.Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) — base supervisor [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24) + model reconnect chung [`VpnReconnectOptions`](../TqkLibrary.VpnClient.Drivers.Core/Models/VpnReconnectOptions.cs#L14).
  - [TqkLibrary.VpnClient.IpEncap](../TqkLibrary.VpnClient.IpEncap) — kênh data-plane [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20) (dùng lại nguyên, không sửa).
  - **SHA-1** dùng thẳng `System.Security.Cryptography.SHA1` (BCL, cả 2 TFM) — **không** ref project `Crypto`.
- **Được dùng bởi:** [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (entry point — [`VpnClientBuilder.UseAyiya(...)`](../TqkLibrary.VpnClient/VpnClientBuilder.cs#L443) đăng ký driver này với `Name` là `ayiya`).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Ayiya/
├── AyiyaDriver.cs                 IVpnProtocolDriver: Name "ayiya" + capabilities (no elevation/no raw socket, PreSharedKey auth) + ConnectAsync → IVpnConnection
├── AyiyaConnection.cs             Bộ điều phối: resolve host → mở UDP → bọc AyiyaFramingTransport (ký/kiểm) → RawIpPassthroughChannel (IPv6) → publish facade + teardown; SendHeartbeatAsync (tùy chọn)
├── AyiyaVpnConnection.cs          Adapter IVpnConnection (1 session; OpenSessionAsync ⇒ NotSupported)
├── AyiyaVpnSession.cs             IVpnSession: TunnelConfig + PacketChannel (facade)
├── AyiyaOptions.cs               Cấu hình tĩnh (record): Port (5072) + Identity + IdType + Password (shared secret) + HashMethod + AuthMethod + Mtu (1280) + ClockSkewToleranceSeconds (120) + AssignedAddressV6?
├── AyiyaReconnectOptions.cs       Named subclass của VpnReconnectOptions (không thêm knob)
├── AyiyaPacket.cs                 Codec thuần: Encode/TryParse/VerifySignature + HashPassword + IdLenFor + HashSize (SHA-1/MD5 shared-secret, aiccu)
├── AyiyaHeader.cs                 readonly struct: kết quả parse (mọi trường + offset identity/signature/payload)
├── AyiyaFramingTransport.cs       Decorator IDatagramTransport: egress ký (opcode Forward, next-header 41) / ingress kiểm sig + epoch skew + next-header rồi bóc payload; SendHeartbeatAsync (echo, next-header 59)
├── IAyiyaTransportFactory.cs      Seam tạo IDatagramTransport UDP (injectable cho test)
├── AyiyaUdpTransportFactory.cs    Factory production: tạo AyiyaUdpDatagramTransport
├── AyiyaUdpDatagramTransport.cs   IDatagramTransport UDP THỤ ĐỘNG (không tự chạy receive-pump; kênh tự lái)
└── Enums/
    ├── AyiyaIdType.cs             enum Integer=1 / String=2 / Ipv4=4 / Ipv6=6
    ├── AyiyaHashMethod.cs         enum None=0 / Md5=1 / Sha1=2
    ├── AyiyaAuthMethod.cs         enum None=0 / SharedSecret=1 / Pgp=2
    └── AyiyaOpcode.cs             enum Noop=0 / Forward=1 / EchoRequest=2 / EchoRequestForward=3 / EchoResponse=4 / …
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`AyiyaDriver`](AyiyaDriver.cs#L21) | `IVpnProtocolDriver`. `Name="ayiya"`. `Capabilities` (L3Ip / **Udp** / SecurityKinds=**None** (payload không mã hóa) / AuthMethods=**PreSharedKey** (shared secret ký datagram) / `AddressAssignment=OutOfBand` / **`RequiresElevation=false`** / **`RequiresRawIpSocket=false`**). `ConnectAsync` dựng `AyiyaConnection` → `AyiyaVpnConnection`. Ctor nhận `AyiyaOptions` (bắt buộc) + `AyiyaReconnectOptions?` + `IAyiyaTransportFactory?` (null ⇒ `AyiyaUdpTransportFactory` production) + `Func<uint>? epochClock` + `ILoggerFactory?`. |
| [`AyiyaConnection`](AyiyaConnection.cs#L28) | Kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24). Ctor precompute `secretHash = H(password)` qua `AyiyaOptions.ValidateAndComputeSecretHash`. `EstablishAsync` bọc `AyiyaFramingTransport` quanh UDP transport rồi dựng `RawIpPassthroughChannel` (IPv6). Override `CleanupAttemptResourcesAsync`/`StopAttemptLoop` (no-op: static mode không keepalive). Phơi `Port`/`Mtu` + `SendHeartbeatAsync` (tùy chọn). `IDisposable`/`IAsyncDisposable`. |
| [`AyiyaVpnConnection`](AyiyaVpnConnection.cs#L10) | Adapter `IVpnConnection` (1 session). `OpenSessionAsync` ⇒ `NotSupportedException`. |
| [`AyiyaVpnSession`](AyiyaVpnSession.cs#L9) | `IVpnSession`: `Config` (TunnelConfig) + `PacketChannel` (facade ổn định). |
| [`AyiyaOptions`](AyiyaOptions.cs#L17) | Cấu hình tĩnh (**record**): `Port` (**5072**) + `Identity` (byte[] bắt buộc, độ dài = lũy thừa 2) + `IdType` ([`AyiyaIdType`](Enums/AyiyaIdType.cs#L7), mặc định Ipv6) + `Password` (shared secret bắt buộc) + `HashMethod` ([`AyiyaHashMethod`](Enums/AyiyaHashMethod.cs#L7), mặc định **Sha1**) + `AuthMethod` (mặc định SharedSecret) + `Mtu` (**1280**) + `ClockSkewToleranceSeconds` (**120**) + `AssignedAddressV6?`/`PrefixLengthV6`. `ValidateAndComputeSecretHash()` kiểm cấu hình + trả `H(password)`; `ToTunnelConfig()`. |
| [`AyiyaReconnectOptions`](AyiyaReconnectOptions.cs#L13) | Named subclass của `VpnReconnectOptions` (chỉ giữ public API; không thêm knob). |
| [`AyiyaPacket`](AyiyaPacket.cs#L24) | `static` codec thuần. `Encode(...)` = header 4B (`idlen\|idtype`, `siglen\|hshmeth`, `autmeth\|opcode`, `nextheader`) ‖ epoch BE ‖ identity (2^idlen) ‖ signature (siglen×4) ‖ payload, và **ký**: đặt `H(password)` vào ô signature → hash toàn gói → ghi đè ô signature. `TryParse` (structural: false khi runt / identity+signature cụt). `VerifySignature` (thay ô signature = `H(password)`, hash lại, so **constant-time**). `HashPassword`/`IdLenFor`/`HashSize`. |
| [`AyiyaHeader`](AyiyaHeader.cs#L10) | `readonly struct` kết quả parse: idLen/idType/sigLenWords/hashMethod/authMethod/opcode/nextHeader/epochTime + offset & độ dài identity/signature/payload. |
| [`AyiyaFramingTransport`](AyiyaFramingTransport.cs#L21) | `internal` decorator `IDatagramTransport`: `SendAsync` bọc gói IPv6 thành AYIYA `Forward`/next-header 41 đã ký (epoch từ clock); `ReceiveAsync` bóc + `TryParse` → `VerifySignature` → kiểm **epoch skew** ≤ tolerance → kiểm next-header 41 + opcode Forward → trả payload, **drop (return 0)** nếu sig sai / epoch lệch / next-header lạ (gồm heartbeat 59) / runt. `SendHeartbeatAsync` (echo-request, next-header 59, payload rỗng). |
| [`IAyiyaTransportFactory`](IAyiyaTransportFactory.cs#L13) | Seam `IDatagramTransport Create(IPEndPoint remote)` — trả transport UDP **chưa-connect**. Injectable cho test. |
| [`AyiyaUdpTransportFactory`](AyiyaUdpTransportFactory.cs#L11) | `IAyiyaTransportFactory` production: tạo `AyiyaUdpDatagramTransport`. Ctor tuỳ chọn `localBind`. |
| [`AyiyaUdpDatagramTransport`](AyiyaUdpDatagramTransport.cs#L18) | `internal sealed` `IDatagramTransport` UDP **thụ động** (bind ephemeral + connect; `ReceiveAsync` await đúng 1 datagram; **không** tự chạy receive-pump). Hỗ trợ IPv4/IPv6 theo `AddressFamily` của remote. netstandard2.0 fallback `ArraySegment`. Mirror `FouUdpDatagramTransport` của Fou. |
| [`VpnConnectionState`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) | enum trạng thái dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) (state kế thừa từ base). |

## Bảng chuẩn / RFC

> **Clean-room:** codec viết từ **SPEC** — `draft-massar-v6ops-ayiya-02` (layout header + thuật toán ký) + hành vi công khai của **aiccu/SixXS** (thứ tự ký shared-secret SHA-1). **KHÔNG** copy code GPL của aiccu.

| Chuẩn | Dùng ở đâu |
|-------|------------|
| draft-massar-v6ops-ayiya-02 (AYIYA) | Toàn bộ header + epoch + identity + signature: codec [`AyiyaPacket`](AyiyaPacket.cs#L24) + struct [`AyiyaHeader`](AyiyaHeader.cs#L10). Byte0 `idlen(4)\|idtype(4)` (identity = 2^idlen byte), byte1 `siglen(4)\|hshmeth(4)` (signature = siglen×4 byte), byte2 `autmeth(4)\|opcode(4)`, byte3 `nextheader`, rồi epoch BE. |
| Shared-secret SHA-1 signature (aiccu) | [`AyiyaPacket.Encode`](AyiyaPacket.cs#L24)/`VerifySignature`: ô signature = `SHA1(password)` khi ký, hash toàn gói ghi đè; kiểm ⇒ thay lại `SHA1(password)`, hash lại, so constant-time. |
| Epoch-time replay guard | [`AyiyaFramingTransport`](AyiyaFramingTransport.cs#L21): ingress drop nếu `|now − epoch| > ClockSkewToleranceSeconds`. |
| IPv6 payload (next-header 41) / no-next-header (59) | [`IpProtocol`](../TqkLibrary.VpnClient.Abstractions/Net/IpProtocol.cs#L8) Ipv6=41 (data plane forward) / NoNextHeader=59 (heartbeat/echo, payload rỗng). Kênh IPv6: tái dùng [`RawIpPassthroughChannel`](../TqkLibrary.VpnClient.IpEncap/RawIpPassthroughChannel.cs#L20). |

## Luồng nội bộ — `EstablishAsync` ([AyiyaConnection.cs](AyiyaConnection.cs))

Một lần dựng tunnel (dùng lại cho connect đầu tiên + mọi reconnect). **Không handshake** — kênh live ngay khi socket connect:

1. **Cleanup** — `CleanupAttemptResourcesAsync` (drop kênh của attempt trước nếu có).
2. **Resolve + open transport** — resolve broker IP qua `IHostResolver` → `new IPEndPoint(serverIp, Port)` → `transportFactory.Create(endpoint)` → `transport.ConnectAsync` (bind UDP ephemeral + connect; lỗi ⇒ dispose transport rồi throw).
3. **Bọc ký/kiểm** — `new AyiyaFramingTransport(transport, IdType, Identity, HashMethod, AuthMethod, secretHash, ClockSkewToleranceSeconds, epochClock)` (secretHash = `H(password)` precompute ở ctor).
4. **Dựng kênh IPv6** — `new RawIpPassthroughChannel(framing, Mtu, Logger)` → `channel.Start()`.
5. **Publish** — `Facade.SetInner(channel)` → `MarkConnected`.

**Chiều gửi:** kênh ghi gói IPv6 → `AyiyaFramingTransport.SendAsync` bọc AYIYA `Forward`/next-header 41, đóng epoch hiện tại, **ký** → UDP. **Chiều nhận:** `AyiyaFramingTransport.ReceiveAsync` đọc datagram thô → `TryParse` → `VerifySignature(secretHash)` → kiểm epoch skew ≤ tolerance → kiểm next-header=41 + opcode Forward → trả **payload** (gói IPv6) cho kênh; **drop (return 0)** nếu sig sai / password sai / epoch lệch / next-header lạ (gồm heartbeat 59) / runt (kênh không thấy header AYIYA).

**`CleanupAttemptResourcesAsync`:** **null-rồi-dispose** kênh — `channel.DisposeAsync()` đóng luôn `AyiyaFramingTransport` (⇒ đóng UDP transport bên trong). `StopAttemptLoop` no-op (static mode không có timer keepalive).

`TunnelConfig` dựng ở [`AyiyaDriver.ConnectAsync`](AyiyaDriver.cs#L21) qua `AyiyaOptions.ToTunnelConfig()` (luôn `Mtu`; `AssignedAddressV6`/`PrefixLengthV6` nếu cấu hình — địa chỉ khác là out-of-band; broker host là `VpnEndpoint.Host`).

## Trạng thái & ghi chú

- **Offline xong** (code + test). Build xanh cả `netstandard2.0` + `net8.0`. Test: [`tests/TqkLibrary.VpnClient.Drivers.Ayiya.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Ayiya.Tests) (37 case) — header round-trip (idlen/idtype/siglen/hshmeth/autmeth/opcode/nextheader) + identity length = 2^idlen + epoch BE + **signature compute→verify khớp** + reject signature sai / password sai / runt + `IdLenFor` reject non-power-of-2 + heartbeat encode (echo/59/rỗng); data plane 2 chiều IPv6 passthrough qua `LoopbackDatagramLink` + receiver **drop epoch lệch / next-header lạ / password sai rồi deliver hợp lệ**; round-trip **UDP loopback thật** trên `127.0.0.1` (echo peer); driver caps + Name `ayiya` + default options (Port 5072/Sha1/Ipv6/Mtu 1280/tolerance 120) + null-guard.
- **Validate live — CHỜ (residual, như Fou/GreInUdp).** Endpoint tunnel-broker AYIYA công cộng khan hiếm — **SixXS đóng 2017**; cần tự dựng AYIYA endpoint (vd tự host aiccu-server) để kiểm interop. **Điểm dễ sai cần kiểm live**: (a) thứ tự chính xác của thuật toán ký shared-secret SHA-1 (đặt `H(password)` vào ô signature TRƯỚC khi hash toàn gói) — self-consistent 2 đầu đã test, nhưng interop thật chưa; (b) giá trị opcode chính xác cho heartbeat (đang dùng `EchoRequest`=2 + next-header 59); (c) độ dung sai epoch của peer.
- **Static mode:** control-channel **TIC** (`draft`/RFC 3053) + heartbeat tự động **BỎ QUA** — không tự phát hiện link-loss ⇒ auto-reconnect F.6 chỉ kích khi caller báo tường minh. `SendHeartbeatAsync` có sẵn (echo/next-header 59) nhưng **không** được lịch tự động (tránh phức tạp, giống Fou no-keepalive).
- ⚠️ **Bảo mật:** AYIYA **KHÔNG mã hóa payload** — chỉ ký toàn vẹn SHA-1 (shared secret) + chống replay bằng epoch time. Bảo mật nội dung (nếu cần) đặt ở tầng trên hoặc bọc thêm.
