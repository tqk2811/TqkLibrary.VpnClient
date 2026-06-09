# TqkLibrary.Vpn.Ppp

> PPP: HDLC framing (`Framing/`), engine LCP/IPCP, và các authenticator (`Auth/`: MS-CHAPv2 trên CHAP).

## Mục đích

Project này hiện thực tầng **PPP (Point-to-Point Protocol)** thuần userspace cho VPN client: thương lượng liên kết, xác thực người dùng, và lấy địa chỉ IP trong tunnel — không dùng PPP driver của hệ điều hành.

Cụ thể nó giải quyết:

- **Thương lượng liên kết (LCP)** — MRU, Magic-Number, và chấp nhận yêu cầu xác thực MS-CHAPv2 của server.
- **Xác thực (MS-CHAPv2 trên CHAP)** — tính NT-Response 24 byte từ username/password, báo Success/Failure; đồng thời dẫn xuất HLAK 32 byte để SSTP làm crypto binding.
- **Cấu hình IP (IPCP)** — xin địa chỉ IP và DNS từ server, học lại giá trị server gán qua Configure-Nak.
- **Đóng/mở khung (HDLC framing)** — khung hoá / giải khung byte-stuffed kèm FCS-16 cho transport dạng byte-stream (SSTP). L2TP dùng packet-mode nên không cần lớp HDLC này.
- **Cầu nối lên tầng L3** — sau khi link up, lộ ra một [`IPacketChannel`](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) để các tầng trên gửi/nhận gói IP qua tunnel.

Đây là một mảnh trong stack VPN userspace của TqkLibrary.Vpn; project được [`TqkLibrary.Vpn.Drivers`](../TqkLibrary.Vpn.Drivers) lắp ráp vào driver L2TP/IPsec và SSTP.

## Vị trí trong kiến trúc

- **Tầng:** PROTOCOL (cùng nhóm với Ipsec, L2tp, IpStack).
- **Target frameworks:** `netstandard2.0; net8.0` (xem [Directory.Build.props:4](../Directory.Build.props#L4)).
- **Phụ thuộc (ProjectReference):**
  - [`TqkLibrary.Vpn.Abstractions`](../TqkLibrary.Vpn.Abstractions) — interface/model/enum dùng chung (vd `IPacketChannel`, `LinkMedium`) — [TqkLibrary.Vpn.Ppp.csproj:8](TqkLibrary.Vpn.Ppp.csproj#L8).
  - [`TqkLibrary.Vpn.Crypto`](../TqkLibrary.Vpn.Crypto) — primitive `Md4`, `Des` cho MS-CHAPv2 — [TqkLibrary.Vpn.Ppp.csproj:9](TqkLibrary.Vpn.Ppp.csproj#L9).
  - Không có PackageReference đặc thù riêng (chỉ thừa hưởng polyfill `System.Memory`,... cho netstandard2.0 từ [Directory.Build.props:16-21](../Directory.Build.props#L16-L21)).
- **Được dùng bởi:** [`TqkLibrary.Vpn.Drivers`](../TqkLibrary.Vpn.Drivers) (cả driver L2TP/IPsec lẫn SSTP đều dựng `PppEngine` trên một `IPppFrameChannel` của riêng chúng).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Ppp/
├─ PppEngine.cs            # Bộ điều phối phiên PPP: LCP -> (auth) -> IPCP, demux khung theo protocol, sự kiện LinkUp
├─ PppPacketChannel.cs     # IPacketChannel L3 lộ ra sau khi IPCP up (ghi/đọc gói IP)
├─ PppNegotiator.cs        # State machine thương lượng option dùng chung cho LCP & IPCP
├─ LcpNegotiator.cs        # LCP: MRU + Magic-Number, phát hiện server đòi MS-CHAPv2
├─ IpcpNegotiator.cs       # IPCP: xin IP/DNS (client) hoặc gán IP cho peer (server)
├─ PppControlCodec.cs      # Encode/decode gói control + TLV option
├─ Auth/
│  ├─ MsChapV2.cs              # Crypto MS-CHAPv2 (NT hash, challenge hash, NT-Response) + dẫn xuất HLAK/MPPE
│  └─ MsChapV2Authenticator.cs # Authenticator client trên CHAP: trả lời Challenge 49 byte, báo Success/Failure
├─ Framing/
│  ├─ Fcs16.cs            # FCS-16 (CRC-CCITT phản chiếu, poly 0x8408)
│  ├─ HdlcFramer.cs       # Khung hoá HDLC-async: cờ 0x7E, byte-stuffing 0x7D, gắn FCS
│  ├─ HdlcDecoder.cs      # Giải khung HDLC-async dạng streaming, kiểm FCS, raise từng frame hợp lệ
│  └─ Enums/PppProtocol.cs    # Giá trị trường Protocol của PPP (IP/LCP/CHAP/IPCP...)
├─ Enums/
│  ├─ PppCode.cs              # Mã gói control (Configure-Request/Ack/Nak/Reject, Echo, Terminate...)
│  ├─ LcpOptionType.cs        # Loại option LCP (MRU, Auth-Protocol, Magic-Number...)
│  ├─ IpcpOptionType.cs       # Loại option IPCP (IP-Address, Primary/Secondary DNS/NBNS)
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
| `PppEngine` | Điều phối toàn phiên: chạy LCP → (auth) → IPCP, demux khung vào theo trường Protocol, lộ `IPacketChannel`, raise `LinkUp`/`AuthSucceeded`/`AuthFailed` | [PppEngine.cs:14](PppEngine.cs#L14) |
| `PppPacketChannel` | `IPacketChannel` tầng L3 (LinkMedium.Ip, MaxHeaderLength=0, không ARP); ghi gói IP ra khung PPP, raise gói IP vào | [PppPacketChannel.cs:10](PppPacketChannel.cs#L10) |
| `PppNegotiator` | State machine thương lượng option dùng chung (RFC 1661 rút gọn); Opened khi cả hai chiều đã Ack | [PppNegotiator.cs:11](PppNegotiator.cs#L11) |
| `LcpNegotiator` | LCP cụ thể: yêu cầu MRU + Magic-Number, chấp nhận Auth-Protocol = MS-CHAPv2 (C223+algo 0x81), reject phần còn lại | [LcpNegotiator.cs:10](LcpNegotiator.cs#L10) |
| `IpcpNegotiator` | IPCP cụ thể: client xin IP (0.0.0.0) + DNS rồi học giá trị Nak; server gán IP cho peer | [IpcpNegotiator.cs:12](IpcpNegotiator.cs#L12) |
| `PppControlCodec` | Encode/decode gói control (Code/Id/Length) và TLV option | [PppControlCodec.cs:9](PppControlCodec.cs#L9) |
| `MsChapV2` | Crypto MS-CHAPv2 client-side: NT hash (MD4), challenge hash (SHA-1), NT-Response (3×DES) + dẫn xuất HLAK/MPPE | [Auth/MsChapV2.cs:11](Auth/MsChapV2.cs#L11) |
| `MsChapV2Authenticator` | Authenticator client trên CHAP: nhận Challenge → trả Response 49 byte, báo Success/Failure, giữ NtResponse cho HLAK | [Auth/MsChapV2Authenticator.cs:12](Auth/MsChapV2Authenticator.cs#L12) |
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
| **RFC 1661 / IANA** (trường Protocol) | `PppProtocol` | [Framing/Enums/PppProtocol.cs:3](Framing/Enums/PppProtocol.cs#L3) | IP=0x0021, LCP=0xC021, CHAP=0xC223, IPCP=0x8021 |
| **RFC 1332** (IPCP) + **RFC 1877** (DNS/NBNS) | `IpcpNegotiator`, `IpcpOptionType` | [IpcpNegotiator.cs:8](IpcpNegotiator.cs#L8), [Enums/IpcpOptionType.cs:3](Enums/IpcpOptionType.cs#L3) | IP-Address, Primary/Secondary DNS/NBNS |
| **RFC 1662** (PPP trong HDLC-like framing) | `HdlcFramer`, `HdlcDecoder` | [Framing/HdlcFramer.cs:4](Framing/HdlcFramer.cs#L4), [Framing/HdlcDecoder.cs:4](Framing/HdlcDecoder.cs#L4) | Cờ 0x7E, escape 0x7D, ACCM C0 |
| **RFC 1662** (FCS-16, CRC-CCITT poly 0x8408) | `Fcs16` | [Framing/Fcs16.cs:3](Framing/Fcs16.cs#L3) | `GoodFcs=0xF0B8` (§C.2) tại [Framing/Fcs16.cs:6](Framing/Fcs16.cs#L6) |
| **RFC 1994** (PPP CHAP) | `MsChapV2Authenticator` | [Auth/MsChapV2Authenticator.cs:9](Auth/MsChapV2Authenticator.cs#L9) | Khung Challenge/Response/Success/Failure |
| **RFC 2759** (MS-CHAPv2) | `MsChapV2`, `MsChapV2Authenticator` | [Auth/MsChapV2.cs:8](Auth/MsChapV2.cs#L8), [Auth/MsChapV2Authenticator.cs:9](Auth/MsChapV2Authenticator.cs#L9) | NtPasswordHash §8.3 [L13](Auth/MsChapV2.cs#L13), ChallengeHash §8.2 [L17](Auth/MsChapV2.cs#L17), ChallengeResponse §8.5 [L33](Auth/MsChapV2.cs#L33), GenerateNTResponse §8.1 [L49](Auth/MsChapV2.cs#L49) |
| **RFC 3079** (dẫn xuất khoá MPPE) | `MsChapV2.DeriveHlak` | [Auth/MsChapV2.cs:75](Auth/MsChapV2.cs#L75), [Auth/MsChapV2.cs:83-99](Auth/MsChapV2.cs#L83-L99) | Master/Send/Receive key → HLAK 32 byte cho SSTP crypto binding |
| **RFC 1320** (MD4) | qua `Md4.Hash` (NT password hash) | [Auth/MsChapV2.cs:15](Auth/MsChapV2.cs#L15), [Auth/MsChapV2.cs:90](Auth/MsChapV2.cs#L90) | (suy luận) MD4 ở `TqkLibrary.Vpn.Crypto`; gọi để tạo NT hash & password-hash-hash |
| **FIPS 46-3 / SP 800-67** (DES) | qua `Des.EncryptBlock` (3 khối NT-Response) | [Auth/MsChapV2.cs:43](Auth/MsChapV2.cs#L43) | (suy luận) DES ở `TqkLibrary.Vpn.Crypto`; key 7→8 byte parity tại [Auth/MsChapV2.cs:58-73](Auth/MsChapV2.cs#L58-L73) |
| **FIPS 180-4** (SHA-1) | `System.Security.Cryptography.SHA1` | [Auth/MsChapV2.cs:26](Auth/MsChapV2.cs#L26), [Auth/MsChapV2.cs:103](Auth/MsChapV2.cs#L103), [Auth/MsChapV2.cs:119](Auth/MsChapV2.cs#L119) | (suy luận) dùng cho ChallengeHash và dẫn xuất khoá MPPE |
| **[MS-CHAP]** (Microsoft, response value 49 byte) | `MsChapV2Authenticator.BuildResponse` | [Auth/MsChapV2Authenticator.cs:86-90](Auth/MsChapV2Authenticator.cs#L86-L90) | (suy luận) PeerChallenge(16)+Reserved(8)+NT-Response(24)+Flags(1) |

> Lưu ý: MS-CHAPv2 là cơ chế yếu, được dùng ở đây chỉ vì L2TP/IPsec và SSTP bắt buộc nó — xem ghi chú tại [Auth/MsChapV2.cs:9](Auth/MsChapV2.cs#L9).

## API / cách dùng

Các điểm vào public chính:

- `PppEngine(IPppFrameChannel channel, uint magic, IPAddress localAddress, IPAddress? assignPeerAddress = null, IPAddress? assignPeerDns = null, IPppAuthenticator? authenticator = null, int mtu = 1400)` — [PppEngine.cs:28](PppEngine.cs#L28).
- `PppEngine.Start()` — bắt đầu thương lượng (gửi LCP Configure-Request) — [PppEngine.cs:72](PppEngine.cs#L72).
- Sự kiện `PppEngine.LinkUp` / `AuthSucceeded` / `AuthFailed` — [PppEngine.cs:48-54](PppEngine.cs#L48-L54).
- `PppEngine.PacketChannel` (`IPacketChannel`), `AssignedAddress`, `AssignedDns`, `IsLinkUp`, `IsAuthenticated` — [PppEngine.cs:57-69](PppEngine.cs#L57-L69).
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

Vòng đời một phiên (client) — `LCP → (MS-CHAPv2) → IPCP → LinkUp`:

1. **Khởi động.** `Start()` gọi `_lcp.Start()` → gửi LCP Configure-Request (MRU + Magic-Number) — [PppEngine.cs:72](PppEngine.cs#L72), [LcpNegotiator.cs:29](LcpNegotiator.cs#L29), [PppNegotiator.cs:32](PppNegotiator.cs#L32).
2. **Demux khung vào.** `OnFrame` bỏ qua Address/Control (FF 03 nếu có), đọc trường Protocol 2 byte rồi route tới LCP / CHAP / IPCP / IP — [PppEngine.cs:111-132](PppEngine.cs#L111-L132).
3. **LCP thương lượng.** `PppNegotiator.HandlePacket` xử lý Configure-Request/Ack/Nak/Reject; LCP chấp nhận Auth-Protocol = MS-CHAPv2, đặt `RequiresMsChapV2`, reject option lạ — [PppNegotiator.cs:39](PppNegotiator.cs#L39), [LcpNegotiator.cs:46](LcpNegotiator.cs#L46). Khi cả hai chiều Ack → `Opened` — [PppNegotiator.cs:84](PppNegotiator.cs#L84).
4. **Rẽ nhánh sau LCP.** `OnLcpOpened`: nếu server đòi MS-CHAPv2 và có authenticator → chờ Challenge; nếu không → đánh dấu đã xác thực và `_ipcp.Start()` ngay — [PppEngine.cs:77-84](PppEngine.cs#L77-L84).
5. **Xác thực MS-CHAPv2.** Khung CHAP vào → `HandleAuth` → `authenticator.Handle(...)`; với Challenge thì `BuildResponse` tạo PeerChallenge ngẫu nhiên, `GenerateNTResponse` (challenge hash SHA-1 → NT hash MD4 → 3×DES) và đóng gói Response 49 byte; Success → `_ipcp.Start()`, Failure → `AuthFailed` — [PppEngine.cs:92-109](PppEngine.cs#L92-L109), [Auth/MsChapV2Authenticator.cs:49](Auth/MsChapV2Authenticator.cs#L49), [Auth/MsChapV2Authenticator.cs:71](Auth/MsChapV2Authenticator.cs#L71), [Auth/MsChapV2.cs:50](Auth/MsChapV2.cs#L50).
6. **IPCP.** Client xin IP-Address (0.0.0.0) + Primary-DNS; server gán giá trị qua Configure-Nak, `OnNak` cập nhật `_localAddress`/`_dns` rồi gửi lại request — [IpcpNegotiator.cs:40](IpcpNegotiator.cs#L40), [IpcpNegotiator.cs:81](IpcpNegotiator.cs#L81).
7. **LinkUp.** IPCP `Opened` → `OnIpcpOpened` đặt `IsLinkUp = true` và raise `LinkUp`; từ đây `PppPacketChannel` chuyển gói IP hai chiều — [PppEngine.cs:86-90](PppEngine.cs#L86-L90), [PppPacketChannel.cs:36](PppPacketChannel.cs#L36).

Data plane sau khi up: ghi IP → `SendIpAsync` đóng khung Protocol=0x0021 — [PppEngine.cs:136](PppEngine.cs#L136); IP vào → `RaiseInbound` → sự kiện `InboundIpPacket` — [PppEngine.cs:129](PppEngine.cs#L129), [PppPacketChannel.cs:39](PppPacketChannel.cs#L39).

HDLC framing (chỉ dùng cho transport byte-stream như SSTP): `HdlcFramer.Encode` gắn FCS rồi byte-stuff giữa hai cờ 0x7E — [Framing/HdlcFramer.cs:21](Framing/HdlcFramer.cs#L21); `HdlcDecoder.Push` un-stuff, tách theo cờ, kiểm FCS rồi raise frame — [Framing/HdlcDecoder.cs:16](Framing/HdlcDecoder.cs#L16), [Framing/HdlcDecoder.cs:40](Framing/HdlcDecoder.cs#L40).

## Trạng thái & ghi chú

- **Đã hiện thực và chạy live:** LCP + IPCP (client), MS-CHAPv2 trên CHAP, HDLC framing với FCS-16, dẫn xuất HLAK cho SSTP crypto binding. Đường L2TP/IPsec đã xác minh hoạt động trên VPN Gate.
- **Vai trò transport theo driver:** SSTP dùng `HdlcFramer`/`HdlcDecoder` (PPP đóng trong HDLC trên byte-stream); L2TP dùng packet-mode nên cấp `IPppFrameChannel` riêng, không qua lớp HDLC — xem ghi chú tại [Framing/HdlcFramer.cs:5](Framing/HdlcFramer.cs#L5).
- **Hỗ trợ vai trò server (một phần):** `IpcpNegotiator` có nhánh server (gán IP/DNS cho peer qua Nak) và `PppEngine` nhận `assignPeerAddress` — nhưng các driver trong project hiện chỉ dùng vai trò **client**; nhánh server là khung mở rộng — [IpcpNegotiator.cs:52-78](IpcpNegotiator.cs#L52-L78), [PppEngine.cs:28-35](PppEngine.cs#L28-L35).
- **Phạm vi hẹp có chủ đích:** chỉ thương lượng MRU/Magic-Number/Auth/IP/DNS; chưa làm PAP, PFC/ACFC, Van Jacobson compression, Echo/Terminate keepalive, hay IPv6CP (các enum giá trị có nhưng negotiator không xử lý). State machine là tập con đơn giản của RFC 1661, không có retransmit timer — [Enums/PppNegotiationState.cs:3](Enums/PppNegotiationState.cs#L3).
- **Auth mở rộng được:** đi qua interface `IPppAuthenticator`; hiện chỉ có một hiện thực `MsChapV2Authenticator` (Description .csproj còn nhắc PAP/CHAP nhưng code thực tế mới có MS-CHAPv2) — [Interfaces/IPppAuthenticator.cs:9](Interfaces/IPppAuthenticator.cs#L9).
- **netstandard2.0 vs net8.0:** code không rẽ nhánh theo framework; tránh `record`/`init` (netstandard2.0 thiếu `IsExternalInit`). Trên netstandard2.0 thừa hưởng polyfill `System.Memory`/`Microsoft.Bcl.AsyncInterfaces` từ [Directory.Build.props:16-21](../Directory.Build.props#L16-L21). Crypto MS-CHAPv2 dựa vào `Md4`/`Des` của [`TqkLibrary.Vpn.Crypto`](../TqkLibrary.Vpn.Crypto), `SHA1`/`RandomNumberGenerator` của BCL.

Xem thêm tài liệu as-built toàn stack: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
