# TqkLibrary.VpnClient.Drivers.ZeroTier

Driver **ZeroTier (VL1/VL2)** (overlay **L2** Ethernet-over-UDP) — ráp codec thuần ở [`ZeroTier`](../TqkLibrary.VpnClient.ZeroTier) (V.7.3 phase a/b: identity C25519 + VL1 packet/HELLO/OK + VL2 frame/dictionary/network-config codec) + **Ethernet fabric** ([`Ethernet`](../TqkLibrary.VpnClient.Ethernet): VirtualHost) thành một tunnel **L2 Ethernet** chạy thật sau facade, trên **transport UDP** (ZeroTier VL1 chỉ UDP; 1 datagram = 1 packet). Mở UDP tới node/controller, chạy **VL1 handshake** (HELLO cipher 0 ⇄ OK(HELLO) cipher 1 — Curve25519 agreement → Salsa20/12 + Poly1305 session; xác nhận bằng **timestamp echo**), trả OK(HELLO) cho HELLO của peer để xác lập path 2 chiều, rồi **join VL2 network** bằng **NETWORK_CONFIG_REQUEST → controller config** (assigned IP + **certificate of membership**), rồi chở **Ethernet frame nguyên gói** dạng **EXT_FRAME** (bare, seal Salsa20/12 + Poly1305; **COM present out-of-band qua NETWORK_CREDENTIALS**, không đính mỗi frame — flag đã deprecated) sau một [`ZeroTierEthernetChannel`](DataChannel/ZeroTierEthernetChannel.cs) (`IEthernetChannel`); kênh L2 này cắm vào fabric ([`ZeroTierNeighborResolver`](DataChannel/ZeroTierNeighborResolver.cs) derive peer MAC — **không ARP** + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs)) bridge xuống facade **L3** ([`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs)) ổn định mà IP stack bind. **ECHO** keepalive giữ path. **Driver L2 thứ tư** trong solution (sau SoftEther / OpenVPN-tap / n2n).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp codec phase a/b + fabric L2 thành 1 tunnel sống (transport seam nhái [`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n)/[`Drivers.Nebula`](../TqkLibrary.VpnClient.Drivers.Nebula); bridge L2↔L3 nhái [`Drivers.SoftEther`](../TqkLibrary.VpnClient.Drivers.SoftEther)):

- **Transport**: UDP qua seam [`IZeroTierTransportFactory`](Transport/IZeroTierTransportFactory.cs) — production socket thật [`ZeroTierSocketTransportFactory`](Transport/ZeroTierSocketTransportFactory.cs) (`UdpClient` connected + receive loop), test inject loopback. 1 transport tới node/controller; receive loop bơm chung `OnInboundDatagram`: `Open` (dearmor VL1) rồi demux theo verb.
- **VL1 handshake**: HELLO (cipher 0, **proto v10** để peer 1.6+ giữ Salsa20/12 thay vì AES-GMAC-SIV) ⇄ OK(HELLO) (cipher 1, **timestamp echo** xác nhận). Session key C25519 → SHA-512 ([`Vl1KeyDerivation`](../TqkLibrary.VpnClient.ZeroTier/Vl1/Vl1KeyDerivation.cs)) derive **1 lần trong ctor**. Trả OK(HELLO) cho HELLO inbound (bắt buộc — controller chờ mới xử lý request).
- **VL2 join**: gửi **NETWORK_CONFIG_REQUEST** (retry 2s) tới controller (= high 40 bit của network id) → decode config dict ([`NetworkConfigCodec`](../TqkLibrary.VpnClient.ZeroTier/Vl2/NetworkConfigCodec.cs)): assigned IP (`v4s` text / `I` binary) + **COM** (`C`/`com`) + mtu, scan body theo network id.
- **Data plane (L2)**: [`ZeroTierEthernetChannel`](DataChannel/ZeroTierEthernetChannel.cs) (`IEthernetChannel`): egress đọc dst/src-MAC từ header Ethernet → đóng frame thành **EXT_FRAME** (connection truyền `certificateOfMembership: null` ⇒ bare frame; channel vẫn hỗ trợ đính COM lần đầu khi được cấp COM) → seal Salsa20/12 VL1 → gửi UDP; ingress (EXT_FRAME/FRAME đã decode) → `InboundFrame`. Cắm vào [`ZeroTierNeighborResolver`](DataChannel/ZeroTierNeighborResolver.cs) (derive peer MAC, không ARP) + [`VirtualHost`](../TqkLibrary.VpnClient.Ethernet/VirtualHost.cs) (L2↔L3) → `IPacketChannel`.
- **COM credential**: COM (nếu controller cấp) present out-of-band qua **NETWORK_CREDENTIALS** (`PushNetworkCredentials`, [`NetworkCredentialsCodec`](../TqkLibrary.VpnClient.ZeroTier/Vl2/NetworkCredentialsCodec.cs) `EncodeMembershipOnly`) — proactive sau join + reactive khi nhận **ERROR `NEED_MEMBERSHIP_CERTIFICATE`** (code 6).
- **Timer/lifecycle**: ECHO keepalive timer + supervisor/auto-reconnect (F.6).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IDatagramTransport`, exceptions, `IHostResolver`, **`Diagnostics`** (log handshake/drop, Q.2) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection`** (base supervisor F.6) + **`VpnReconnectOptions`** (`ZeroTierReconnectOptions` kế thừa) + **`VpnConnectionState`** (enum state dùng chung) |
| Dùng | [ZeroTier](../TqkLibrary.VpnClient.ZeroTier) | `Vl1PacketCodec` (seal/open), `HelloMessageCodec`/`OkMessageCodec`, `Vl1KeyDerivation`, `NetworkConfigCodec`, `NetworkCredentialsCodec` (COM push), `Vl2FrameCodec`/`Vl2ExtFrameCodec`, models identity/network/frame (`ZeroTierAddress`/`NetworkId`/`InetAddressValue`/`ZeroTierNetworkConfig`/`Vl2ExtFrame`/`OkHelloMessage`…) |
| Dùng | [Ethernet](../TqkLibrary.VpnClient.Ethernet) | **`VirtualHost`** (bridge L2↔L3) + `MacAddress` + `INeighborResolver` (qua `ZeroTierNeighborResolver`) — **KHÔNG viết lại switch/bridge** |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | (gián tiếp qua ZeroTier) Salsa20/Poly1305/Curve25519/SHA-512 |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseZeroTier(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.ZeroTier/
├─ ZeroTierDriver.cs                  IVpnProtocolDriver: caps (L2Ethernet/Udp/None/Certificate/OutOfBand) + ConnectAsync(config+endpoint) → ZeroTierConnection
├─ ZeroTierConnection.cs              Điều phối (kế thừa ReconnectingVpnConnection F.6): UDP → HELLO⇄OK(HELLO) + reply OK(HELLO) → NETWORK_CONFIG_REQUEST → config → bind ZeroTierEthernetChannel vào ZeroTierNeighborResolver+VirtualHost → ECHO keepalive + demux verb; supervisor/reconnect ở base
├─ ZeroTierVpnConnection.cs           IVpnConnection: 1 session L2; OpenSessionAsync ném NotSupportedException
├─ ZeroTierVpnSession.cs              IVpnSession: PacketChannel ổn định (facade L3 bridge từ L2) + TunnelConfig
├─ ZeroTierReconnectOptions.cs        Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ ZeroTierDriverConstants.cs         DriverName "zerotier", port 9993, MTU 1400, proto v10, keepalive 30s
├─ Config/ZeroTierConfig.cs           identity ta (secret) + peer/controller identity (public) + network id + optional static overlay → ToTunnelConfig()
├─ DataChannel/
│  ├─ ZeroTierEthernetChannel.cs      IEthernetChannel: WriteFrameAsync đóng Ethernet frame thành EXT_FRAME (đính COM lần đầu nếu được cấp; connection truyền null ⇒ bare) + seal VL1; DeliverExtFrame/DeliverFrame raise InboundFrame
│  └─ ZeroTierNeighborResolver.cs     INeighborResolver: derive peer MAC từ ZT address (KHÔNG ARP — ZeroTier compute MAC)
└─ Transport/
   ├─ IZeroTierTransportFactory.cs    Seam dựng UDP transport tới node/controller (production socket / test loopback)
   ├─ ZeroTierTransportHandle.cs      IDatagramTransport + SetReceiver + receive-pump trả về từ factory
   └─ ZeroTierSocketTransportFactory.cs Socket thật: UDP (UdpClient) + receive loop dispatch — live-only, cross-TFM
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`ZeroTierDriver`](ZeroTierDriver.cs) | `IVpnProtocolDriver` — caps L2Ethernet/Udp/None/Certificate/OutOfBand; `ConnectAsync` dựng `ZeroTierConnection` |
| [`ZeroTierConnection`](ZeroTierConnection.cs) | Điều phối VL1/VL2 trên supervisor F.6 — HELLO⇄OK, network join, data plane bind, ECHO keepalive, demux verb |
| [`ZeroTierEthernetChannel`](DataChannel/ZeroTierEthernetChannel.cs) | `IEthernetChannel` — egress đóng frame thành EXT_FRAME + seal VL1; ingress decode → `InboundFrame` |
| [`ZeroTierNeighborResolver`](DataChannel/ZeroTierNeighborResolver.cs) | `INeighborResolver` — derive peer MAC (no ARP) |
| [`ZeroTierConfig`](Config/ZeroTierConfig.cs) | Config tĩnh (identity + peer + network id + overlay) → `TunnelConfig` |
| [`IZeroTierTransportFactory`](Transport/IZeroTierTransportFactory.cs) / [`ZeroTierSocketTransportFactory`](Transport/ZeroTierSocketTransportFactory.cs) / [`ZeroTierTransportHandle`](Transport/ZeroTierTransportHandle.cs) | Seam transport UDP |
| [`ZeroTierVpnConnection`](ZeroTierVpnConnection.cs) / [`ZeroTierVpnSession`](ZeroTierVpnSession.cs) | Adapter `IVpnConnection`/`IVpnSession` (1 session) |
| [`ZeroTierReconnectOptions`](ZeroTierReconnectOptions.cs) | Kế thừa `VpnReconnectOptions` (Drivers.Core, F.6) — backoff supervisor |
| [`ZeroTierDriverConstants`](ZeroTierDriverConstants.cs) | Hằng runtime: name `zerotier`, port 9993, MTU 1400, proto v10, version 1.14, keepalive 30s |
| [`VpnConnectionState`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) | enum vòng đời: Disconnected/Connecting/Connected/Reconnecting (dùng chung ở [`Drivers.Core`](../TqkLibrary.VpnClient.Drivers.Core/Enums/VpnConnectionState.cs) — state kế thừa từ base) |

## Trạng thái & ghi chú

- **VALIDATE LIVE VL1 OK peering + VL2 network join ✓** (lab [`zerotier`](../../lab/zerotier) [docker-compose.live146.yml](../../lab/zerotier/docker-compose.live146.yml), zerotier-one **1.4.6** thật làm controller + private network): **HELLO⇄OK timestamp echo** (`VL1 session up`) + **NETWORK_CONFIG_REQUEST → controller gán 10.144.0.2/24 + certificate of membership** → `Connected`. Chọn 1.4.6 vì zerotier-one **1.6+** negotiate **AES-GMAC-SIV (cipher 3)** mà client chưa hiện thực; 1.4.6 giữ **Salsa20/12 + Poly1305** (suite client implement byte-exact).
- **3 bug interop sửa qua live** (self-pair offline KHÔNG bắt — clean-room, KHÔNG copy BSL):
  1. **Salsa20/12 payload block-alignment** — ZeroTier lấy Poly1305 key từ block0 (32B đầu) rồi mã hóa payload từ **block KẾ** (Salsa20 block-granular, bỏ 32B đuôi block0); BouncyCastle byte-granular ⇒ decrypt cipher-1 ra rác dù MAC pass. Fix: `DiscardToNextBlock` ([`Vl1PacketCodec`](../TqkLibrary.VpnClient.ZeroTier/Vl1/Vl1PacketCodec.cs)). KAT HELLO là cipher 0 nên không bắt.
  2. **Handshake VL1 2 chiều** — controller gửi HELLO riêng + KHÔNG xử lý NETWORK_CONFIG_REQUEST tới khi thấy OK(HELLO) của ta. Fix: trả OK(HELLO) (echo timestamp) cho HELLO inbound + retry request.
  3. **Dict parse** — controller pre-1.6 gán IP qua key text **`v4s`** (không phải binary `I`) + value binary chứa **raw NUL** ⇒ deserializer không coi NUL là terminator cứng; OK in-re header gap 2B tùy version ⇒ scan config body theo network id.
  4. **DeriveMac byte-exact `MAC::fromAddress`** — first octet từ nwid (LAA-unicast, 0x52→0x32) ‖ 40-bit address **+ XOR-fold byte nwid vào MAC[1..5]**; KAT byte-exact vs 2 member zerotier-one thật. Trước đó derive `firstOctet‖address` (thiếu XOR-fold) ⇒ EXT_FRAME tới MAC node drop.
- **CÒN LẠI — data plane VL2 ICMP live 2 chiều**: MAC nay ĐÚNG ⇒ EXT_FRAME tới **đúng tap MAC** node (node **nhận**, không drop); driver push **COM** qua [`NETWORK_CREDENTIALS`](../TqkLibrary.VpnClient.ZeroTier/Vl2/NetworkCredentialsCodec.cs) (sau join + ERROR code-6). NHƯNG controller vẫn ERROR `NEED_MEMBERSHIP_CERTIFICATE` — **COM trích từ dict `C` controller 1.4.6 chưa được chấp nhận** (serialize COM 1.4.6 khác docs `dev` — qualifier alignment lệch khi echo verbatim). **2 member zerotier-one thật ping nhau OK** (10.144.0.3↔10.144.0.1, 0% loss) ⇒ lab + MAC đúng, residual thuần ở **COM exchange phía client** (cần serialize/verify COM 1.4.6 chính xác, hoặc MULTICAST_FRAME cho ARP-learn). EXT_FRAME egress 2 chiều đã proven **offline** (6 test).
- **AES-GMAC-SIV (cipher 3)** chưa hiện thực ⇒ chưa peer được với zerotier-one **1.6+** (chỉ Salsa20/12). **Planet/moon root discovery** out of scope (peer trực tiếp với node/controller).
- **Refs**: Abstractions + Drivers.Core + Ethernet + ZeroTier (Crypto chỉ dùng **gián tiếp** qua ZeroTier — không ProjectReference trực tiếp). **2 TFM** (netstandard2.0 + net8.0). **1 IVpnSession** (`OpenSessionAsync` ⇒ `NotSupported`). Demo: `--vpn <file>.zerotier` ([`ConnectZeroTierAsync`](../../demo/Vpn2ProxyDemo/VpnTunnel.cs)).
- **Test offline**: 6 ([`ZeroTierConnectionTests`](../../tests/TqkLibrary.VpnClient.Drivers.ZeroTier.Tests/ZeroTierConnectionTests.cs) HELLO/OK + network join + EXT_FRAME L2 round-trip 2 chiều + pinned-addr + timeout; [`ZeroTierDriverTests`](../../tests/TqkLibrary.VpnClient.Drivers.ZeroTier.Tests/ZeroTierDriverTests.cs) caps + guard) — node/controller loopback re-implement từ wire (no BSL).
