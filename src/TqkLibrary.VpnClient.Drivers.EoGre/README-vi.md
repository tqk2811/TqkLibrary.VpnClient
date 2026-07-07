# TqkLibrary.VpnClient.Drivers.EoGre

Driver **EoGRE / NVGRE over GRE-in-UDP** (RFC 8086 + RFC 2784/2890 + RFC 7637) — **L2-over-UDP** chế độ **static** — chở **Ethernet frame nguyên gói** sau một **header GRE chuẩn** (protocol-type **`0x6558`** Transparent Ethernet Bridging) đặt trong **payload UDP** (dst port **4754**), cắm vào **Ethernet fabric** ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet): ARP/VirtualHost) thành một tunnel **L2 Ethernet** chạy thật sau facade. Là **sibling L2 của driver [`gre-udp`](../TqkLibrary.VpnClient.Drivers.GreInUdp)** (cùng GRE-in-UDP nhưng protocol-type `0x6558` Ethernet → **L2 fabric** thay vì IPacketChannel L3) và của [`vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan)/[`geneve`](../TqkLibrary.VpnClient.Drivers.Geneve). Cũng **BỎ hết control plane**: KHÔNG registration, KHÔNG transform/mã hóa, KHÔNG keepalive, KHÔNG header-encryption. Remote là **unicast tĩnh** (host từ `VpnEndpoint`, port từ config = 4754). IP tĩnh (overlay address, **không DHCP**), no-elevation/no-raw socket + qua NAT.

**Một project, hai driver key** (nhái cách [`Drivers.Fou`](../TqkLibrary.VpnClient.Drivers.Fou) làm `fou`/`gue`) theo [`EoGreMode`](Enums/EoGreMode.cs):
- **`eogre`** — GRETAP thường (RFC 8086 + 2784/2890): **VSID tùy chọn** (khi cấu hình → nhét vào RFC 2890 Key), Checksum (C) / Sequence (S) tùy chọn.
- **`nvgre`** — NVGRE (RFC 7637): **VSID 24-bit + FlowID 8-bit BẮT BUỘC** đóng vào GRE Key (`VSID << 8 | FlowID`, K=1), **ép tắt** Checksum/Sequence (RFC 7637 cấm), **strict-VSID** drop datagram lệch VSID (tenant isolation).

## Tái dùng GRE codec (KHÔNG viết lại)

Driver **TÁI DÙNG NGUYÊN** GRE codec public sẵn có của [`IpEncap`](../TqkLibrary.VpnClient.IpEncap) — [`GreCodec`](../TqkLibrary.VpnClient.IpEncap/Gre/GreCodec.cs)/[`GrePacket`](../TqkLibrary.VpnClient.IpEncap/Gre/GrePacket.cs) (RFC 2784 base + RFC 2890 Key/Sequence, đã xử lý flags **C/K/S** + protocol-type `ushort` tùy ý + Key/Sequence/Checksum + validate Ver=0/runt/truncated/checksum). [`EoGreCodec`](EoGreCodec.cs) chỉ là **wrapper mỏng** cố định protocol-type `0x6558` và đóng/gỡ VSID/FlowID trong Key — **không nhân bản logic GRE**.

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp GRE codec tái dùng ([`IpEncap`](../TqkLibrary.VpnClient.IpEncap)) + fabric L2 ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet)) thành 1 tunnel sống; bridge L2↔L3 + supervisor/reconnect nhái [`Drivers.Geneve`](../TqkLibrary.VpnClient.Drivers.Geneve)/[`Drivers.Vxlan`](../TqkLibrary.VpnClient.Drivers.Vxlan) — **không có bước register/keepalive/transform**:

- **Transport**: UDP qua seam [`IEoGreTransportFactory`](Transport/IEoGreTransportFactory.cs) — production socket thật [`EoGreUdpTransportFactory`](Transport/EoGreUdpTransportFactory.cs) (`Socket` UDP: bind ephemeral + connect remote, IPv4/IPv6 + receive loop), test inject loopback. 1 transport tới remote; receive loop bơm `OnInboundDatagram`.
- **Không control plane**: EoGRE/NVGRE không đăng ký, không handshake — `EstablishAsync` chỉ mở transport rồi bind data plane. State `Connecting` là transient.
- **Data plane (L2)**: [`EoGreEthernetChannel`](DataChannel/EoGreEthernetChannel.cs) (`IEthernetChannel`): egress `EoGreCodec.EncodeEoGre(frame, vsid?, flowId, checksum, seq)` bọc GRE (proto `0x6558`) → gửi UDP; ingress (frame đã bóc header) → `InboundFrame`. Cắm vào [`ArpResolver`](../TqkLibrary.VpnClient.Ethernet/ArpResolver.cs) (IPv4 static) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2↔L3) → `IPacketChannel`.
- **Lifecycle**: supervisor/auto-reconnect (F.6) ở base — không timer keepalive.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `IDatagramTransport`, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions`) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection`** (base supervisor F.6) + **`VpnReconnectOptions`** (`EoGreReconnectOptions` kế thừa) + **`VpnConnectionState`** |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`ArpResolver`** (IPv4 next-hop, static IP) + **`VirtualHost`** (bridge L2↔L3) + `MacAddress`/`EthernetFrame` — **KHÔNG viết lại ARP/switch** |
| Dùng | [IpEncap](../TqkLibrary.VpnClient.IpEncap) | **`GreCodec`/`GrePacket`** (RFC 2784/2890, public) — **TÁI DÙNG codec GRE, KHÔNG viết lại** |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseEoGre(config)` / `UseNvgre(config)` đăng ký driver |

Không dùng `Vxlan`/`Geneve`/`N2n`/`Crypto` (codec riêng = GRE tái dùng, không mã hóa).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.EoGre/
├─ EoGreDriver.cs                      IVpnProtocolDriver: caps (L2Ethernet/Udp/None/None-auth/OutOfBand, no-elevation) + Name eogre/nvgre theo mode + ConnectAsync(config+mode+endpoint) → EoGreConnection
├─ EoGreConnection.cs                  Điều phối (kế thừa ReconnectingVpnConnection F.6): UDP → bind EoGreEthernetChannel vào ArpResolver+VirtualHost → demux; tính tham số wire theo mode (nvgre ép tắt C/S + strict-VSID); KHÔNG register/keepalive/transform
├─ EoGreVpnConnection.cs               IVpnConnection: 1 session L2 point-to-point; OpenSessionAsync ném NotSupportedException
├─ EoGreVpnSession.cs                  IVpnSession: PacketChannel ổn định (facade L3 bridge từ L2) + TunnelConfig tĩnh
├─ EoGreCodec.cs                       Static/stateless WRAPPER trên GreCodec (IpEncap): EncodeEoGre (proto 0x6558 + VSID Key/Checksum/Sequence tùy chọn) / TryDecodeEoGre (gọi GreCodec.TryDecode → proto-type/frame/key/seq) / PackKey/UnpackKey (VSID 24-bit + FlowID); const DefaultPort=4754/ProtocolTypeTransparentEthernet=0x6558/MaxVsid=0xFFFFFF
├─ EoGreReconnectOptions.cs            Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ EoGreDriverConstants.cs             DriverName eogre/nvgre, DefaultPort 4754, DefaultMtu 1400
├─ Enums/EoGreMode.cs                  enum EoGre / Nvgre
├─ Config/EoGreConfig.cs              Vsid uint32? + FlowId + Port(4754) + static overlay IP/prefix + LocalMac (null⇒random LAA) + EnableChecksum/EnableSequence/StrictVsid + DnsServers/Routes + Mtu → ToTunnelConfig() (static IP, KHÔNG DHCP); ResolveLocalMac + Validate(mode) (nvgre require VSID + VSID≤24-bit)
├─ DataChannel/EoGreEthernetChannel.cs IEthernetChannel: WriteFrameAsync EoGreCodec.EncodeEoGre (VSID/Checksum/Sequence) → sink UDP; Deliver raise InboundFrame
├─ Properties/AssemblyInfo.cs         InternalsVisibleTo test assembly (channel là internal)
└─ Transport/
   ├─ IEoGreTransportFactory.cs        Seam dựng UDP transport tới remote (production socket / test loopback)
   ├─ EoGreTransportHandle.cs          IDatagramTransport + SetReceiver + receive-pump trả về từ factory
   └─ EoGreUdpTransportFactory.cs      Socket thật: UDP bind ephemeral + connect remote (IPv4/IPv6) + receive loop — live-only, cross-TFM
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `EoGreDriver` | `IVpnProtocolDriver`: caps (**`L2Ethernet`**, không PPP, `None` security, `Udp`, **`None` auth**, `OutOfBand` static, **no-elevation/no-raw**); `Name` = `"eogre"`/`"nvgre"` theo `EoGreMode`; ctor validate config (nvgre require VSID); `ConnectAsync` dựng `EoGreConnection` từ `EoGreConfig` + mode + endpoint | [EoGreDriver.cs:24](EoGreDriver.cs#L24) |
| `EoGreConnection` | Bộ điều phối — kế thừa [`ReconnectingVpnConnection`](../TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24): override `EstablishAsync` (resolve remote → mở UDP qua `IEoGreTransportFactory` → `EoGreEthernetChannel` + `ArpResolver` static-IP + `VirtualHost` → `Facade.SetInner` → `MarkConnected`) + `CleanupAttemptResourcesAsync`; **demux** (`OnInboundDatagram`: `EoGreCodec.TryDecodeEoGre` → kiểm proto-type 0x6558 → strict-VSID kiểm Key → `Deliver`); tính tham số wire theo mode (nvgre: C/S off + strict-VSID); **KHÔNG** register/keepalive/transform | [EoGreConnection.cs:34](EoGreConnection.cs#L34) |
| `EoGreConfig` | Config tĩnh: `Vsid`(uint32? — tùy chọn eogre / bắt buộc nvgre, validate ≤0xFFFFFF)/`FlowId`/`Port`(4754)/`OverlayAddress`+`PrefixLength`/`LocalMac`(null⇒random LAA)/`EnableChecksum`/`EnableSequence`/`StrictVsid`/`DnsServers`/`Routes`/`Mtu`(1400); `ToTunnelConfig` (static IP + route mặc định = overlay subnet); `ResolveLocalMac`; `Validate(mode)` | [Config/EoGreConfig.cs:18](Config/EoGreConfig.cs#L18) |
| `EoGreCodec` | Static/stateless **wrapper** trên [`GreCodec`](../TqkLibrary.VpnClient.IpEncap/Gre/GreCodec.cs) (IpEncap): `EncodeEoGre(frame, vsid?, flowId, checksum, seq)` (proto 0x6558 + Key=VSID<<8|FlowID khi có VSID + C/S tùy chọn); `TryDecodeEoGre` (gọi `GreCodec.TryDecode` → trả proto-type/frame/key/seq); `PackKey`/`UnpackKey` VSID 24-bit + FlowID; const `DefaultPort`/`ProtocolTypeTransparentEthernet`/`MaxVsid`/`VsidShift` | [EoGreCodec.cs:26](EoGreCodec.cs#L26) |
| `EoGreMode` | enum `EoGre` (GRETAP: VSID/Checksum/Sequence tùy chọn) / `Nvgre` (RFC 7637: VSID+FlowID bắt buộc, C/S off, strict-VSID) | [Enums/EoGreMode.cs:8](Enums/EoGreMode.cs#L8) |
| `EoGreEthernetChannel` | `IEthernetChannel` (`Medium=Ethernet`, `MaxHeaderLength=14`, `RequiresLinkAddressResolution=true`): `WriteFrameAsync` bọc GRE (proto 0x6558 + VSID/Checksum/Sequence) → sink UDP; `Deliver` raise `InboundFrame`; Sequence tăng dần khi `emitSequence` | [DataChannel/EoGreEthernetChannel.cs:27](DataChannel/EoGreEthernetChannel.cs#L27) |
| `EoGreVpnConnection` / `EoGreVpnSession` | `IVpnConnection` 1 session (point-to-point) + `IVpnSession` (`PacketChannel` facade L3 + `Config` tĩnh) | [EoGreVpnConnection.cs:9](EoGreVpnConnection.cs#L9) / [EoGreVpnSession.cs:13](EoGreVpnSession.cs#L13) |
| `IEoGreTransportFactory` / `EoGreTransportHandle` / `EoGreUdpTransportFactory` | Seam dựng UDP transport (1 datagram = 1 message, **không framing**) + socket thật `Socket` UDP (bind ephemeral + connect, IPv4/IPv6) + receive loop — live-only, cross-TFM (nhái Geneve) | [Transport/IEoGreTransportFactory.cs:13](Transport/IEoGreTransportFactory.cs#L13) / [EoGreTransportHandle.cs:15](Transport/EoGreTransportHandle.cs#L15) / [EoGreUdpTransportFactory.cs:18](Transport/EoGreUdpTransportFactory.cs#L18) |
| `VpnConnectionState` / `EoGreReconnectOptions` | `Disconnected/Connecting/Connected/Reconnecting` (dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs)) + kế thừa `VpnReconnectOptions` (F.6) | [../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) / [EoGreReconnectOptions.cs:10](EoGreReconnectOptions.cs#L10) |

## Bảng chuẩn / RFC

| Khối | Chuẩn | Ghi chú |
|------|-------|---------|
| GRE header | **RFC 2784** (base) + **RFC 2890** (Key/Sequence) | byte0 flags `C \| Reserved0 \| K \| S \| ...`; byte1 low-3-bit Ver=0; byte2-3 Protocol Type `0x6558`; C→Checksum(2)+Reserved1(2); K→Key(4); S→Sequence(4); rồi payload = Ethernet frame. **Tái dùng `GreCodec`/`GrePacket` của IpEncap** — không viết lại |
| Encap trong UDP | **RFC 8086** (GRE-in-UDP) | gói GRE đặt trong payload UDP dst-port **4754** (IANA "GRE-in-UDP"); no raw proto-47 socket ⇒ no-elevation + qua NAT |
| Protocol Type | Transparent Ethernet Bridging `0x6558` | payload GRE = **Ethernet frame nguyên gói** → L2 fabric (KHÁC GRE-in-UDP L3 chở IP 0x0800/0x86DD) |
| NVGRE | **RFC 7637** | K=1 bắt buộc, Key = **VSID(24-bit) `<<` 8 `\|` FlowID(8-bit)**; Checksum/Sequence PHẢI = 0; drop VSID-mismatch (tenant isolation) |
| L2 fabric | ARP (RFC 826) + VirtualHost | tái dùng `Ethernet` — KHÔNG viết lại; IP **tĩnh**, không DHCP |
| Address | out-of-band (static) | không DHCP — `EoGreConfig` → `TunnelConfig` |
| Security | none | EoGRE/NVGRE **KHÔNG mã hóa** (chỉ tunnel L2) — dùng đường tin cậy hoặc bọc IPsec ESP |

## Luồng nội bộ (UDP ↔ fabric, as-built)

1. **Resolve remote** ([`ResolveRemoteEndpointAsync`](EoGreConnection.cs)): resolve host (từ `VpnEndpoint.Host`) qua [`IHostResolver`](../TqkLibrary.VpnClient.Abstractions/Net/IHostResolver.cs) → `IPEndPoint(ip, config.Port)`.
2. **Tính tham số wire theo mode** (ctor `EoGreConnection`): `config.Validate(mode)`; eogre → VSID/Checksum/Sequence theo config; nvgre → VSID bắt buộc, Checksum/Sequence **ép tắt**, strict-VSID **bật**.
3. **Mở transport UDP** qua `IEoGreTransportFactory.ConnectAsync` → `IDatagramTransport`; `SetReceiver(OnInboundDatagram)`; chạy receive-pump nền (loopback tự pump); `MarkRunning`.
4. **Bind data plane L2**: `EoGreEthernetChannel(vsid, flowId, checksum, seq, mac, sink)` → `ArpResolver(mac, overlayAddress, channel)` + `VirtualHost(mac, channel, arp)` → `Facade.SetInner(virtualHost)` → `MarkConnected`. **Không** handshake/register.
5. **Egress** (`EoGreEthernetChannel.WriteFrameAsync`): `EoGreCodec.EncodeEoGre(frame, vsid?, flowId, checksum, seq)` → `GreCodec.Encode(GrePacket{proto 0x6558, Key, ...})` → sink UDP.
6. **Ingress** (`OnInboundDatagram`): `EoGreCodec.TryDecodeEoGre` (`GreCodec.TryDecode` → loại Ver≠0/runt/truncated/checksum-sai); kiểm proto-type = 0x6558 (drop nếu khác); strict-VSID → unpack Key.VSID, drop nếu lệch config → `EoGreEthernetChannel.Deliver(frame)` → fabric → IP stack.
7. **TunnelConfig**: `EoGreConfig.ToTunnelConfig()` (static overlay IP + route + MTU 1400; `VirtualHost.Mtu` = link−14) — tĩnh, không đàm phán.
8. **Teardown/Reconnect**: hủy receive loop + dispose VirtualHost/ArpResolver/channel/transport; reconnect ở base (`OnLinkLost` → `ReconnectLoopAsync` backoff+jitter → `EstablishAsync`).

## Trạng thái & ghi chú

- **Đã có (V.22)**: end-to-end **offline code + test XONG** — `EstablishAsync` mở UDP → data plane L2 EoGRE/NVGRE 2 chiều qua ARP + VirtualHost; config tĩnh point-to-point; `UseEoGre(config)` / `UseNvgre(config)`. **34 test offline** qua **peer giả lập** (EoGRE echo) trên loopback UDP: codec round-trip (flags **C/K/S**, proto-type `0x6558`, Key **VSID 24-bit + FlowID**, checksum + corrupt-reject, sequence), `PackKey`/`UnpackKey`, reject **Ver≠0 / proto≠0x6558 / runt / truncated-optional-Key**; channel egress (NVGRE-Key/no-Key/sequence tăng dần) + deliver/runt; config projection + `Validate` (nvgre require VSID); connection IP round-trip 2 chiều qua fabric (eogre+VSID / eogre-no-VSID / nvgre) + **strict-VSID drop mismatch**; driver caps eogre/nvgre + NVGRE-no-VSID throw.
- **⚠️ KHÔNG mã hóa**: EoGRE/NVGRE chỉ tunnel L2, không bảo mật payload — dùng trên **đường tin cậy** hoặc **bọc IPsec ESP**.
- **Còn lại (residual live-validate)**: chờ **peer thật** — Linux `ip link add <name> type gretap ... encap fou/gue` (GRETAP-over-FOU/GUE), **OVS**, hoặc **Hyper-V NVGRE** — để round-trip ICMP thật qua L2 overlay (validate on-wire GRE header `0x6558` + Key VSID + fabric ARP).
- **Tham chiếu**: RFC 8086 + RFC 2784/2890 + RFC 7637; taxonomy [`02`](../../.docs/02-protocol-taxonomy.md) + roadmap [`11`](../../.docs/11-todo-roadmap.md) §V.22 + as-built [`10`](../../.docs/10-codebase-architecture-and-flow.md) §5/§9.

> Build xanh cả `netstandard2.0` + `net8.0`. Socket transport theo TFM giống [`Drivers.Geneve`](../TqkLibrary.VpnClient.Drivers.Geneve/Transport/GeneveUdpTransportFactory.cs) (net5+ overload ct; ns2.0 `ArraySegment` fallback). Bridge L2↔L3 (ARP + VirtualHost static-IP) nhái [`Drivers.Geneve`](../TqkLibrary.VpnClient.Drivers.Geneve) nhưng **codec = GRE tái dùng của [`IpEncap`](../TqkLibrary.VpnClient.IpEncap)** thay header VXLAN/Geneve tự chứa.
