# TqkLibrary.VpnClient.Ppp

> PPP: HDLC framing (`Framing/`), engine LCP/IPCP/IPV6CP, và các authenticator (`Auth/`: MS-CHAPv2 trên CHAP).

## Mục đích

Project này hiện thực tầng **PPP (Point-to-Point Protocol)** thuần userspace cho VPN client: thương lượng liên kết, xác thực người dùng, và lấy địa chỉ IP trong tunnel — không dùng PPP driver của hệ điều hành.

Cụ thể nó giải quyết:

- **Thương lượng liên kết (LCP)** — MRU, Magic-Number, và chấp nhận yêu cầu xác thực MS-CHAPv2 của server.
- **Xác thực (MS-CHAPv2 trên CHAP)** — tính NT-Response 24 byte từ username/password, báo Success/Failure; đồng thời dẫn xuất HLAK 32 byte để SSTP làm crypto binding.
- **Cấu hình IP (IPCP)** — xin địa chỉ IP và DNS từ server, học lại giá trị server gán qua Configure-Nak.
- **Cấu hình IPv6 (IPV6CP, RFC 5072) — opt-in** — thương lượng Interface-Identifier 8 byte → địa chỉ link-local `fe80::/64`, chạy song song IPCP và không ảnh hưởng link-up IPv4. Địa chỉ IPv6 global (SLAAC/DHCPv6) chưa làm — chờ tầng L2 NDISC.
- **Đóng/mở khung (HDLC framing)** — khung hoá / giải khung byte-stuffed kèm FCS-16 cho transport dạng byte-stream (SSTP). L2TP dùng packet-mode nên không cần lớp HDLC này.
- **Cầu nối lên tầng L3** — sau khi link up, lộ ra một [`IPacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) để các tầng trên gửi/nhận gói IP qua tunnel.

Đây là một mảnh trong stack VPN userspace của TqkLibrary.VpnClient; project được hai driver [`TqkLibrary.VpnClient.Drivers.L2tpIpsec`](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) và [`TqkLibrary.VpnClient.Drivers.Sstp`](../TqkLibrary.VpnClient.Drivers.Sstp) lắp ráp vào (cả hai đều dựng `PppEngine`).

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (cùng nhóm với Ipsec, L2tp, IpStack).
- **Target frameworks:** `netstandard2.0; net8.0` (xem [Directory.Build.props:4](../Directory.Build.props#L4)).
- **Phụ thuộc (ProjectReference):**
  - [`TqkLibrary.VpnClient.Abstractions`](../TqkLibrary.VpnClient.Abstractions) — interface/model/enum dùng chung (vd `IPacketChannel`, `LinkMedium`) — [TqkLibrary.VpnClient.Ppp.csproj:8](TqkLibrary.VpnClient.Ppp.csproj#L8).
  - [`TqkLibrary.VpnClient.Crypto`](../TqkLibrary.VpnClient.Crypto) — primitive `Md4`, `Des` cho MS-CHAPv2 — [TqkLibrary.VpnClient.Ppp.csproj:9](TqkLibrary.VpnClient.Ppp.csproj#L9).
  - Không có PackageReference đặc thù riêng (chỉ thừa hưởng polyfill `System.Memory`,... và `TqkLibrary.CompilerServices` cho netstandard2.0 từ [Directory.Build.props:16-25](../Directory.Build.props#L16-L25)).
- **Được dùng bởi:** [`TqkLibrary.VpnClient.Drivers.L2tpIpsec`](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) và [`TqkLibrary.VpnClient.Drivers.Sstp`](../TqkLibrary.VpnClient.Drivers.Sstp) (cả hai driver đều dựng `PppEngine` trên một `IPppFrameChannel` của riêng chúng).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Ppp/
├─ PppEngine.cs            # Bộ điều phối phiên PPP: LCP -> (auth) -> IPCP, demux khung theo protocol, sự kiện LinkUp
├─ PppPacketChannel.cs     # IPacketChannel L3 lộ ra sau khi IPCP up (ghi/đọc gói IP)
├─ PppNegotiator.cs        # State machine thương lượng option dùng chung cho LCP & IPCP
├─ LcpNegotiator.cs        # LCP: MRU + Magic-Number, phát hiện server đòi MS-CHAPv2
├─ IpcpNegotiator.cs       # IPCP: xin IP/DNS (client) hoặc gán IP cho peer (server)
├─ Ipv6cpNegotiator.cs     # IPV6CP (RFC 5072): thương lượng Interface-Identifier -> link-local fe80::/64
├─ PppControlCodec.cs      # Encode/decode gói control + TLV option
├─ Auth/
│  └─ MsChapV2Authenticator.cs # Authenticator client trên CHAP: trả lời Challenge 49 byte, báo Success/Failure
│                              #   (codec MS-CHAPv2 thuần đã chuyển sang TqkLibrary.VpnClient.Crypto/MsChapV2.cs)
├─ Framing/
│  ├─ Fcs16.cs            # FCS-16 (CRC-CCITT phản chiếu, poly 0x8408)
│  ├─ HdlcFramer.cs       # Khung hoá HDLC-async: cờ 0x7E, byte-stuffing 0x7D, gắn FCS
│  ├─ HdlcDecoder.cs      # Giải khung HDLC-async dạng streaming, kiểm FCS, raise từng frame hợp lệ
│  └─ Enums/PppProtocol.cs    # Giá trị trường Protocol của PPP (IP/LCP/CHAP/IPCP...)
├─ Enums/
│  ├─ PppCode.cs              # Mã gói control (Configure-Request/Ack/Nak/Reject, Echo, Terminate...)
│  ├─ LcpOptionType.cs        # Loại option LCP (MRU, Auth-Protocol, Magic-Number...)
│  ├─ IpcpOptionType.cs       # Loại option IPCP (IP-Address, Primary/Secondary DNS/NBNS)
│  ├─ Ipv6cpOptionType.cs     # Loại option IPV6CP (Interface-Identifier, Compression)
│  ├─ PppNegotiationState.cs  # Trạng thái rút gọn của negotiator (Closed/RequestSent/Opened)
│  └─ PppAuthStatus.cs        # Kết quả xử lý gói auth (Pending/Success/Failure)
├─ Models/
│  ├─ PppOption.cs            # Một option (type byte + value) dạng TLV
│  └─ PppControlPacket.cs     # Gói control đã parse (Code/Identifier/Data)
└─ Interfaces/
   ├─ IPppFrameChannel.cs     # Kênh khung PPP (gửi/nhận frame), trừu tượng hoá transport bên dưới
   └─ IPppAuthenticator.cs    # Hợp đồng cho một giao thức xác thực PPP (CHAP/MS-CHAPv2)
```

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `PppEngine` | Điều phối toàn phiên: chạy LCP → (auth) → IPCP (+ IPV6CP nếu bật), demux khung vào theo trường Protocol, lộ `IPacketChannel`, raise `LinkUp`/`Ipv6Up`/`AuthSucceeded`/`AuthFailed` | [PppEngine.cs:14](PppEngine.cs#L14) |
| `PppPacketChannel` | `IPacketChannel` tầng L3 (LinkMedium.Ip, MaxHeaderLength=0, không ARP); ghi gói IP ra khung PPP, raise gói IP vào | [PppPacketChannel.cs:10](PppPacketChannel.cs#L10) |
| `PppNegotiator` | State machine thương lượng option dùng chung (RFC 1661 rút gọn); Opened khi cả hai chiều đã Ack | [PppNegotiator.cs:11](PppNegotiator.cs#L11) |
| `LcpNegotiator` | LCP cụ thể: yêu cầu MRU + Magic-Number, chấp nhận Auth-Protocol = MS-CHAPv2 (C223+algo 0x81), reject phần còn lại | [LcpNegotiator.cs:10](LcpNegotiator.cs#L10) |
| `IpcpNegotiator` | IPCP cụ thể: client xin IP (0.0.0.0) + DNS rồi học giá trị Nak; server gán IP cho peer | [IpcpNegotiator.cs:12](IpcpNegotiator.cs#L12) |
| `Ipv6cpNegotiator` | IPV6CP cụ thể (RFC 5072): thương lượng Interface-Identifier 8 byte (client xin/học Nak, server gán), reject Compression; lộ `LinkLocalAddress` fe80::/64 | [Ipv6cpNegotiator.cs:14](Ipv6cpNegotiator.cs#L14) |
| `PppControlCodec` | Encode/decode gói control (Code/Id/Length) và TLV option | [PppControlCodec.cs:9](PppControlCodec.cs#L9) |
| `MsChapV2Authenticator` | Authenticator client trên CHAP: nhận Challenge → trả Response 49 byte, báo Success/Failure, giữ NtResponse cho HLAK; codec mật mã ủy thác cho [`MsChapV2`](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs) ở Crypto | [Auth/MsChapV2Authenticator.cs:12](Auth/MsChapV2Authenticator.cs#L12) |
| `HdlcFramer` | Khung hoá HDLC-async: cờ 0x7E, byte-stuffing 0x7D, ACCM mặc định escape C0, gắn FCS-16 | [Framing/HdlcFramer.cs:7](Framing/HdlcFramer.cs#L7) |
| `HdlcDecoder` | Giải khung HDLC-async dạng streaming (`Push`): un-stuff, tách theo cờ, kiểm FCS, raise `FrameReceived` | [Framing/HdlcDecoder.cs:7](Framing/HdlcDecoder.cs#L7) |
| `Fcs16` | FCS-16 (CRC-CCITT phản chiếu, poly 0x8408) — `Compute`, `Update`, `GoodFcs` | [Framing/Fcs16.cs:4](Framing/Fcs16.cs#L4) |
| `IPppFrameChannel` | Trừu tượng kênh khung PPP (gửi/nhận frame) tách rời transport (HDLC/SSTP hay packet-mode/L2TP) | [Interfaces/IPppFrameChannel.cs:7](Interfaces/IPppFrameChannel.cs#L7) |
| `IPppAuthenticator` | Hợp đồng giao thức xác thực: `Handle(packet, out response)` trả `PppAuthStatus` | [Interfaces/IPppAuthenticator.cs:9](Interfaces/IPppAuthenticator.cs#L9) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Class / Namespace áp dụng | Vị trí (link code) | Ghi chú |
|-------|---------------------------|--------------------|---------|
| **RFC 1661** (PPP, automaton & option negotiation) | `PppNegotiator` | [PppNegotiator.cs:7](PppNegotiator.cs#L7) | Automaton §4 rút gọn cho client tự nguyện |
| **RFC 1661 §5–6** (control packet + TLV option) | `PppControlCodec`, `PppOption` | [PppControlCodec.cs:7](PppControlCodec.cs#L7), [Models/PppOption.cs:3](Models/PppOption.cs#L3) | Code/Id/Length + TLV |
| **RFC 1661 §5** (mã gói control) | `PppCode` | [Enums/PppCode.cs:3](Enums/PppCode.cs#L3) | Configure/Terminate/Echo... |
| **RFC 1661 §6** + **RFC 1570** (LCP option) | `LcpOptionType` | [Enums/LcpOptionType.cs:3](Enums/LcpOptionType.cs#L3) | MRU, Auth-Protocol, Magic-Number, PFC/ACFC |
| **RFC 1661 / IANA** (trường Protocol) | `PppProtocol` | [Framing/Enums/PppProtocol.cs:3](Framing/Enums/PppProtocol.cs#L3) | IP=0x0021, IPv6=0x0057, Compressed=0x00FD (MPPC/MPPE, PPTP V.6), LCP=0xC021, CHAP=0xC223, IPCP=0x8021, CCP=0x80FD (PPTP V.6), IPV6CP=0x8057 |
| **RFC 1332** (IPCP) + **RFC 1877** (DNS/NBNS) | `IpcpNegotiator`, `IpcpOptionType` | [IpcpNegotiator.cs:8](IpcpNegotiator.cs#L8), [Enums/IpcpOptionType.cs:3](Enums/IpcpOptionType.cs#L3) | IP-Address, Primary/Secondary DNS/NBNS |
| **RFC 5072** (IPV6CP) | `Ipv6cpNegotiator`, `Ipv6cpOptionType` | [Ipv6cpNegotiator.cs:14](Ipv6cpNegotiator.cs#L14), [Enums/Ipv6cpOptionType.cs:3](Enums/Ipv6cpOptionType.cs#L3) | Interface-Identifier §4.1 → link-local fe80::/64; Compression §4.2 reject |
| **RFC 1662** (PPP trong HDLC-like framing) | `HdlcFramer`, `HdlcDecoder` | [Framing/HdlcFramer.cs:4](Framing/HdlcFramer.cs#L4), [Framing/HdlcDecoder.cs:4](Framing/HdlcDecoder.cs#L4) | Cờ 0x7E, escape 0x7D, ACCM C0 |
| **RFC 1662** (FCS-16, CRC-CCITT poly 0x8408) | `Fcs16` | [Framing/Fcs16.cs:3](Framing/Fcs16.cs#L3) | `GoodFcs=0xF0B8` (§C.2) tại [Framing/Fcs16.cs:6](Framing/Fcs16.cs#L6) |
| **RFC 1994** (PPP CHAP) | `MsChapV2Authenticator` | [Auth/MsChapV2Authenticator.cs:9](Auth/MsChapV2Authenticator.cs#L9) | Khung Challenge/Response/Success/Failure |
| **RFC 2759** (MS-CHAPv2) | `MsChapV2Authenticator` (framing CHAP); codec ở [`MsChapV2`](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs) (Crypto) | [Auth/MsChapV2Authenticator.cs:9](Auth/MsChapV2Authenticator.cs#L9) | NtPasswordHash/ChallengeHash/GenerateNTResponse §8.x nay ở Crypto (xem README Crypto) |
| **RFC 3079** (dẫn xuất khoá MPPE) | `MsChapV2Authenticator.DeriveHlak` → [`MsChapV2.DeriveHlak`](../TqkLibrary.VpnClient.Crypto/MsChapV2.cs) (Crypto) | [Auth/MsChapV2Authenticator.cs:42](Auth/MsChapV2Authenticator.cs#L42) | HLAK 32 byte cho SSTP crypto binding; thuật toán Master/Send/Receive key ở Crypto |
| **[MS-CHAP]** (Microsoft, response value 49 byte) | `MsChapV2Authenticator.BuildResponse` | [Auth/MsChapV2Authenticator.cs:86-90](Auth/MsChapV2Authenticator.cs#L86-L90) | (suy luận) PeerChallenge(16)+Reserved(8)+NT-Response(24)+Flags(1) |

> Lưu ý: MS-CHAPv2 là cơ chế yếu, được dùng ở đây chỉ vì L2TP/IPsec và SSTP bắt buộc nó — xem ghi chú tại [Auth/MsChapV2.cs:9](Auth/MsChapV2.cs#L9).

## API / cách dùng

Các điểm vào public chính:

- `PppEngine(IPppFrameChannel channel, uint magic, IPAddress localAddress, IPAddress? assignPeerAddress = null, IPAddress? assignPeerDns = null, IPppAuthenticator? authenticator = null, int mtu = 1400, bool enableIpv6 = false, byte[]? interfaceId = null, byte[]? assignPeerInterfaceId = null)` — [PppEngine.cs:36](PppEngine.cs#L36). `enableIpv6` bật IPV6CP (mặc định tắt → không đổi hành vi IPv4).
- `PppEngine.Start()` — bắt đầu thương lượng (gửi LCP Configure-Request) — [PppEngine.cs:80](PppEngine.cs#L80).
- Sự kiện `PppEngine.LinkUp` / `Ipv6Up` / `AuthSucceeded` / `AuthFailed` — [PppEngine.cs:61-70](PppEngine.cs#L61-L70).
- `PppEngine.PacketChannel` (`IPacketChannel`), `AssignedAddress`, `AssignedDns`, `AssignedAddressV6` (link-local, null nếu chưa bật IPv6), `IsLinkUp`, `IsIpv6Up`, `IsAuthenticated` — [PppEngine.cs:73-91](PppEngine.cs#L73-L91).
- `MsChapV2Authenticator(string userName, string password)` + `DeriveHlak()` cho SSTP — [Auth/MsChapV2Authenticator.cs:23](Auth/MsChapV2Authenticator.cs#L23), [Auth/MsChapV2Authenticator.cs:42](Auth/MsChapV2Authenticator.cs#L42).
- Framing độc lập: `HdlcFramer.Encode(...)`, `new HdlcDecoder().Push(...)` + sự kiện `FrameReceived` — [Framing/HdlcFramer.cs:21](Framing/HdlcFramer.cs#L21), [Framing/HdlcDecoder.cs:16](Framing/HdlcDecoder.cs#L16).

Ví dụ ngắn (client L2TP/SSTP, transport được cung cấp qua một `IPppFrameChannel`):

```csharp
var auth = new MsChapV2Authenticator(userName, password);
var ppp = new PppEngine(
    frameChannel,                 // IPppFrameChannel của driver (L2TP packet-mode hoặc SSTP HDLC)
    magic: 0x12345678,
    localAddress: IPAddress.Any,  // 0.0.0.0 -> xin server gán
    authenticator: auth);

ppp.LinkUp += () =>
{
    IPacketChannel l3 = ppp.PacketChannel; // gửi/nhận gói IP qua tunnel
    Console.WriteLine($"Got IP {ppp.AssignedAddress}, DNS {ppp.AssignedDns}");
};
ppp.Start();
```

## Luồng nội bộ

Vòng đời một phiên (client) — `LCP → (MS-CHAPv2) → IPCP (+ IPV6CP) → LinkUp`:

1. **Khởi động.** `Start()` gọi `_lcp.Start()` → gửi LCP Configure-Request (MRU + Magic-Number) — [PppEngine.cs:94](PppEngine.cs#L94), [LcpNegotiator.cs:29](LcpNegotiator.cs#L29), [PppNegotiator.cs:32](PppNegotiator.cs#L32).
2. **Demux khung vào.** `OnFrame` bỏ qua Address/Control (FF 03 nếu có), đọc trường Protocol 2 byte rồi route tới LCP / CHAP / IPCP / IPV6CP / IP (cả `Ip` 0x0021 lẫn `Ipv6` 0x0057 đổ vào cùng một `IPacketChannel`) — [PppEngine.cs:146-168](PppEngine.cs#L146-L168).
3. **LCP thương lượng.** `PppNegotiator.HandlePacket` xử lý Configure-Request/Ack/Nak/Reject; LCP chấp nhận Auth-Protocol = MS-CHAPv2, đặt `RequiresMsChapV2`, reject option lạ — [PppNegotiator.cs:39](PppNegotiator.cs#L39), [LcpNegotiator.cs:46](LcpNegotiator.cs#L46). Khi cả hai chiều Ack → `Opened` — [PppNegotiator.cs:84](PppNegotiator.cs#L84).
4. **Rẽ nhánh sau LCP.** `OnLcpOpened`: nếu server đòi MS-CHAPv2 và có authenticator → chờ Challenge; nếu không → đánh dấu đã xác thực và gọi `StartNetworkLayer()` ngay (chạy IPCP, và IPV6CP nếu bật) — [PppEngine.cs:99-113](PppEngine.cs#L99-L113).
5. **Xác thực MS-CHAPv2.** Khung CHAP vào → `HandleAuth` → `authenticator.Handle(...)`; với Challenge thì `BuildResponse` tạo PeerChallenge ngẫu nhiên, `GenerateNTResponse` (challenge hash SHA-1 → NT hash MD4 → 3×DES) và đóng gói Response 49 byte; Success → `StartNetworkLayer()`, Failure → `AuthFailed` — [PppEngine.cs:127-144](PppEngine.cs#L127-L144), [Auth/MsChapV2Authenticator.cs:49](Auth/MsChapV2Authenticator.cs#L49), [Auth/MsChapV2Authenticator.cs:71](Auth/MsChapV2Authenticator.cs#L71), [Auth/MsChapV2.cs:50](Auth/MsChapV2.cs#L50).
6. **IPCP.** Client xin IP-Address (0.0.0.0) + Primary-DNS; server gán giá trị qua Configure-Nak, `OnNak` cập nhật `_localAddress`/`_dns` rồi gửi lại request — [IpcpNegotiator.cs:40](IpcpNegotiator.cs#L40), [IpcpNegotiator.cs:81](IpcpNegotiator.cs#L81).
7. **IPV6CP (nếu `enableIpv6`).** Song song IPCP: client xin Interface-Identifier; server gán qua Configure-Nak, `OnNak` cập nhật rồi gửi lại; `Opened` → `OnIpv6cpOpened` đặt `IsIpv6Up` + raise `Ipv6Up`, lộ `AssignedAddressV6` = fe80::/64 + IID — [Ipv6cpNegotiator.cs:14](Ipv6cpNegotiator.cs#L14), [PppEngine.cs:121-125](PppEngine.cs#L121-L125).
8. **LinkUp (IPv4).** IPCP `Opened` → `OnIpcpOpened` đặt `IsLinkUp = true` và raise `LinkUp` (không phụ thuộc IPV6CP); từ đây `PppPacketChannel` chuyển gói IP hai chiều — [PppEngine.cs:115-119](PppEngine.cs#L115-L119), [PppPacketChannel.cs:36](PppPacketChannel.cs#L36).

Data plane sau khi up (một `IPacketChannel` mang cả hai họ): ghi IP → `SendIpAsync` chọn Protocol theo version nibble — `0x0021` (IPv4) hoặc `0x0057` (IPv6) — [PppEngine.cs:172](PppEngine.cs#L172); IP vào (cả `Ip` lẫn `Ipv6`) → `RaiseInbound` → sự kiện `InboundIpPacket` — [PppEngine.cs:165](PppEngine.cs#L165), [PppPacketChannel.cs:39](PppPacketChannel.cs#L39). Tầng trên (`TcpIpStack` dual-stack) demux lại theo version nibble.

HDLC framing (chỉ dùng cho transport byte-stream như SSTP): `HdlcFramer.Encode` gắn FCS rồi byte-stuff giữa hai cờ 0x7E — [Framing/HdlcFramer.cs:21](Framing/HdlcFramer.cs#L21); `HdlcDecoder.Push` un-stuff, tách theo cờ, kiểm FCS rồi raise frame — [Framing/HdlcDecoder.cs:16](Framing/HdlcDecoder.cs#L16), [Framing/HdlcDecoder.cs:40](Framing/HdlcDecoder.cs#L40).

## Trạng thái & ghi chú

- **Đã hiện thực và chạy live:** LCP + IPCP (client), MS-CHAPv2 trên CHAP, HDLC framing với FCS-16, dẫn xuất HLAK cho SSTP crypto binding. Đường L2TP/IPsec đã xác minh hoạt động trên VPN Gate.
- **IPV6CP (RFC 5072) — opt-in, chưa test live:** `Ipv6cpNegotiator` thương lượng Interface-Identifier → link-local `fe80::/64`, bật qua `PppEngine(enableIpv6: true)`; chạy song song IPCP, không đổi đường IPv4 (mặc định tắt). Data plane đã **multiplex hai họ** trên một `IPacketChannel` (send chọn 0x0021/0x0057 theo version nibble, inbound `Ipv6` đổ chung kênh) — phủ test offline qua loopback (gói IPv6 đi/về đúng Protocol 0x0057). **Còn lại** (roadmap P1.1): chưa cấp địa chỉ IPv6 **global** (cần SLAAC/RA tầng L2 — L2.4); wire `TunnelConfig`/driver/`TcpIpStack` dual-stack ở mức driver xem README từng driver.
- **Vai trò transport theo driver:** SSTP dùng `HdlcFramer`/`HdlcDecoder` (PPP đóng trong HDLC trên byte-stream); L2TP dùng packet-mode nên cấp `IPppFrameChannel` riêng, không qua lớp HDLC — xem ghi chú tại [Framing/HdlcFramer.cs:5](Framing/HdlcFramer.cs#L5).
- **Hỗ trợ vai trò server (một phần):** `IpcpNegotiator`/`Ipv6cpNegotiator` có nhánh server (gán IP/DNS/Interface-Identifier cho peer qua Nak) và `PppEngine` nhận `assignPeerAddress`/`assignPeerInterfaceId` — nhưng các driver trong project hiện chỉ dùng vai trò **client**; nhánh server là khung mở rộng (chỉ dùng cho loopback test) — [IpcpNegotiator.cs:52-78](IpcpNegotiator.cs#L52-L78), [PppEngine.cs:33-58](PppEngine.cs#L33-L58).
- **Phạm vi hẹp có chủ đích:** chỉ thương lượng MRU/Magic-Number/Auth/IP/DNS + Interface-Identifier (IPV6CP); chưa làm PAP, PFC/ACFC, Van Jacobson compression, Echo/Terminate keepalive, hay IPV6CP-Compression. State machine là tập con đơn giản của RFC 1661, không có retransmit timer — [Enums/PppNegotiationState.cs:3](Enums/PppNegotiationState.cs#L3).
- **Auth mở rộng được:** đi qua interface `IPppAuthenticator`; hiện chỉ có một hiện thực `MsChapV2Authenticator` (Description .csproj còn nhắc PAP/CHAP nhưng code thực tế mới có MS-CHAPv2) — [Interfaces/IPppAuthenticator.cs:9](Interfaces/IPppAuthenticator.cs#L9).
- **netstandard2.0 vs net8.0:** code không rẽ nhánh theo framework; `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`). Trên netstandard2.0 thừa hưởng polyfill `System.Memory`/`Microsoft.Bcl.AsyncInterfaces` từ [Directory.Build.props:16-25](../Directory.Build.props#L16-L25). Crypto MS-CHAPv2 dựa vào `Md4`/`Des` của [`TqkLibrary.VpnClient.Crypto`](../TqkLibrary.VpnClient.Crypto), `SHA1`/`RandomNumberGenerator` của BCL.

Xem thêm tài liệu as-built toàn stack: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
