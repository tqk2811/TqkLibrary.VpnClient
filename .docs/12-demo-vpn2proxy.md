# 12 — Demo `Vpn2ProxyDemo` (as-built)

> Tài liệu **bám sát code thực tế** cho demo tích hợp proxy (tách riêng khỏi [`10`](10-codebase-architecture-and-flow.md) §9
> để file 10 gọn). Hướng dẫn chạy chi tiết + bảng option đầy đủ ở [`demo/Vpn2ProxyDemo/README-vi.md`](../demo/Vpn2ProxyDemo/README-vi.md);
> file này tập trung kiến trúc/luồng + link `file:line`.

## 1. Mục đích & vị trí

Demo console chứng minh: kết nối VPN Gate (**MS-SSTP**, **L2TP/IPsec**, **SoftEther SSL-VPN** hoặc **OpenVPN** từ file `.ovpn`) → biến tunnel thành `IProxySource` của
**`TqkLibrary.Proxy` 1.0.35** → dựng HTTP/SOCKS proxy local định tuyến mọi kết nối **trong** tunnel, rồi **giữ proxy +
tunnel sống tới khi nhấn Enter** (Ctrl+C cũng dừng) để test VPN duy trì kết nối (keepalive/auto-reconnect) trong lúc
client trỏ traffic vào proxy.

Đây là **project demo** ([`demo/Vpn2ProxyDemo`](../demo/Vpn2ProxyDemo)), **không** phải project `src/`. Adapter
`IProxySource`/`IConnectSource` viết **inline trong demo** (chưa tách thành `TqkLibrary.VpnClient.Proxy` — xem roadmap
[`11`](11-todo-roadmap.md) mục "Adapter proxy"). Tham chiếu project: `Drivers.L2tpIpsec` + `Drivers.Sstp` + `Drivers.SoftEther` + `Drivers.OpenVpn` + `OpenVpn` (parse `.ovpn`) + `Sockets`;
NuGet `TqkLibrary.Proxy` 1.0.35 + `Microsoft.Extensions.Logging`/`.Console` 10.0.x (console log cho `ProxyServer` + `VpnProxySource` + driver SoftEther/OpenVPN).

## 2. Luồng

```
[chung]         SSTP / L2TP / SoftEther / OpenVPN        (kết nối VPN từ --vpn, nhận IP ảo + DNS + PacketChannel)
   -> new TcpIpStack(channel, ip)                       (userspace TCP/IP trong tunnel)
   -> VpnCapabilityProbe.RunAsync(tunnel).Print()       (panel "VPN hỗ trợ gì": UDP/LAN ảo PROBE thật + IPv6/listen-external SUY LUẬN — in NGAY sau connect, trước hành động)

[dns]           -> UdpDnsProbe.ResolveAsync(stack, dns, domain)  (DNS-over-UDP qua tunnel: VPN có hỗ trợ UDP? + IP của domain)

[proxy-server]  -> new VpnProxySource(stack) -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()
   -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
   => client (browser/curl) qua proxy: mọi traffic ra bằng IP công cộng của VPN server

[http-request]  -> (kế thừa proxy-server) GET --url qua proxy -> in response body -> THOÁT luôn
```

**Panel "VPN này hỗ trợ gì"** (in tự động sau MỌI lần connect, trước hành động — [`CommandModuleBase.PrintCapabilitiesAsync` @ :95](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L95)
gọi [`VpnCapabilityProbe.RunAsync` @ :26](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L26)): gộp **3 nguồn** — (1) **probe thật** qua tunnel: UDP =
DNS-over-UDP (tái dùng [`UdpDnsProbe.ResolveAsync`](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L29)), LAN ảo = ICMP ping gateway nội bộ
([`TcpIpStack.PingAsync`](../src/TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L107) — [`ProbeVirtualLanAsync` @ :99](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L99); **phát hiện LAN ảo thì panel thêm dòng "Gateway nội bộ"** ở phần Info); (2) **năng lực
driver tĩnh** đọc thẳng từ `Capabilities` của driver tương ứng ([`SstpDriver`](../src/TqkLibrary.VpnClient.Drivers.Sstp/SstpDriver.cs#L29)/[`L2tpIpsecDriver`](../src/TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L27)/[`SoftEtherDriver`](../src/TqkLibrary.VpnClient.Drivers.SoftEther/SoftEtherDriver.cs#L74)/[`OpenVpnDriver`](../src/TqkLibrary.VpnClient.Drivers.OpenVpn/OpenVpnDriver.cs#L72))
(transport/bảo mật/auth/cấp địa chỉ); (3) **heuristic** từ IP cấp: phân loại public/private (RFC1918/CGNAT) ⇒ suy listen-external,
IPv6 = No vì chưa có IPv6CP. Panel tự bao timeout (mỗi sub-probe ngắn + chặn-trên 20s) và **nuốt mọi lỗi** (trừ hủy của caller) nên
không bao giờ làm hỏng hành động chính. Các khả năng thư viện chưa hỗ trợ ⇒ xem §6.

Ba subcommand riêng (`dns` / `proxy-server` / `http-request`). Subcommand `dns` gọi [`ProbeUdpDnsAsync` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L44):
gửi một truy vấn DNS (bản ghi A) qua **UDP xuyên tunnel** bằng [`UdpDnsProbe.ResolveAsync` @ :29](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L29)
(`VpnUdpClient` → `TcpIpStack.BindUdp`). Nhận được phản hồi ⇒ **VPN có định tuyến UDP**, đồng thời in IPv4 phân giải
được. Đây là kênh data plane **độc lập** với proxy TCP (riêng với SOCKS5 UDP-ASSOCIATE — proxy đã `IsSupportUdp=true`).
`http-request` kế thừa `proxy-server`: dựng cùng proxy rồi GET `--url` **qua proxy đó** (in body, thoát) thay vì giữ tới khi Enter.

Mỗi kết nối TCP qua proxy: `ProxyServer` gọi [`VpnProxySource.GetConnectSourceAsync` @ :40](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L40)
→ [`VpnConnectSource.ConnectAsync` @ :36](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L36) resolve host ra IPv4 (host DNS) rồi
`VpnTcpClient.ConnectAsync` dial trong tunnel → [`GetStreamAsync` @ :67](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L67) trả
stream duplex cho proxy bơm traffic. **SOCKS5 UDP-ASSOCIATE** dùng [`VpnUdpAssociateSource` @ :21](../demo/Vpn2ProxyDemo/VpnProxySource.VpnUdpAssociateSource.cs#L21)
(egress UDP qua `UdpConnection`). **BIND** vẫn ném `NotSupportedException` — stack active-open-only + địa chỉ tunnel private
không routable từ internet ([VpnProxySource.cs:44-46](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L44-L46)). Chỉ IPv4.

## 3. Thành phần

| File | Vai trò |
|---|---|
| [Program.cs:10](../demo/Vpn2ProxyDemo/Program.cs#L10) | `RootCommand { dns, proxy-server, http-request }` → `Parse(args).InvokeAsync()` (System.CommandLine 2.0.7) |
| [VpnProxySource.cs:17](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L17) | `IProxySource` (partial) bọc `TcpIpStack`; `IsSupportUdp=true`, `Ipv6/Bind=false`; ctor nhận **`ILoggerFactory?`** → sinh `ILogger` cho mỗi `IConnectSource`/`IUdpAssociateSource` |
| [VpnProxySource.VpnConnectSource.cs:18](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L18) | `IConnectSource` (nested): mở `VpnTcpClient` qua tunnel, trả `Stream` (resolve IPv4 bằng host DNS); **log** resolve/connect/lỗi/đóng qua `ILogger?` |
| [VpnProxySource.VpnUdpAssociateSource.cs:21](../demo/Vpn2ProxyDemo/VpnProxySource.VpnUdpAssociateSource.cs#L21) | `IUdpAssociateSource` (nested): egress UDP qua `UdpConnection` (`SendTo`/`ReceiveAsync` đa đích), `UnbindUdp` khi `Dispose`; **log** associate/send/receive/unbind qua `ILogger?` |
| [UdpDnsProbe.cs:18](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L18) | Build/parse gói DNS (RFC 1035) trên `VpnUdpClient` → gửi truy vấn A qua UDP xuyên tunnel (kiểm tra UDP + phân giải domain), retry + timeout |
| [UdpDnsProbeResult.cs:11](../demo/Vpn2ProxyDemo/UdpDnsProbeResult.cs#L11) | Kết quả probe: `UdpSupported` + danh sách IPv4 + số lần thử/thời gian/lỗi |
| [VpnTunnel.cs:28](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L28) | Bọc `TcpIpStack` + vòng đời tunnel (`IAsyncDisposable`); lộ `AssignedAddress`/`AssignedDns`/`Mtu`/`Capabilities`/`ProtocolName` cho panel khả năng (ctor [@ :32](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L32)). **4 hàm static connect** (thêm giao thức = thêm 1 hàm + 1 nhánh dispatch): [`ConnectSstpAsync` @ :65](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L65) (MS-SSTP/TLS, `host`+`port`), [`ConnectL2tpAsync` @ :91](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L91) (L2TP/IPsec IKEv1, NAT-T — không port; `preSharedKey`), [`ConnectSoftEtherAsync` @ :122](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L122) (SoftEther SSL-VPN qua `SoftEtherDriver` → `connection.Sessions[0]`; nhận `hubName` + `watermarkPath` — nạp blob thật từ file nếu có, rỗng ⇒ placeholder + CẢNH BÁO 403) + [`ConnectOpenVpnAsync` @ :175](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L175) (parse `.ovpn` → `OpenVpnDriver` → `connection.Sessions[0]`, transport UDP/TCP theo `proto`) — SoftEther/OpenVPN có console logger cho driver ([`CreateDriverLoggerFactory` @ :220](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L220)); mỗi hàm dựng connection → `TcpIpStack` + đọc `driver.Capabilities` → `VpnTunnel` |
| [CapabilityStatus.cs:7](../demo/Vpn2ProxyDemo/CapabilityStatus.cs#L7) | Enum trạng thái 1 khả năng: `Yes`[✓]/`No`[✗]/`Likely`·`Unlikely`[~]/`Unknown`[?] |
| [VpnCapability.cs:8](../demo/Vpn2ProxyDemo/VpnCapability.cs#L8) | Một dòng khả năng: `Name` + `Status` (`CapabilityStatus`) + `Detail` (lý do/số đo) |
| [VpnCapabilityReport.cs:10](../demo/Vpn2ProxyDemo/VpnCapabilityReport.cs#L10) | Kết quả panel: `Info` (IP/DNS/MTU/transport/bảo mật/auth) + `Capabilities`; [`Print` @ :31](../demo/Vpn2ProxyDemo/VpnCapabilityReport.cs#L31) in ra Console (✓/✗/~/?) |
| [VpnCapabilityProbe.cs:23](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L23) | **Static probe** (mirror `UdpDnsProbe`): [`RunAsync` @ :26](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L26) gộp probe thật (UDP qua `UdpDnsProbe`; LAN ảo qua [`ProbeVirtualLanAsync` @ :99](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L99) → `PingAsync`, trả kèm gateway phát hiện) + năng lực driver + heuristic NAT/IPv6 → `VpnCapabilityReport`; mỗi sub-probe tự timeout, không ném khi hết giờ |
| [CommandModules/Interfaces/ICommandModule.cs:6](../demo/Vpn2ProxyDemo/CommandModules/Interfaces/ICommandModule.cs#L6) | Hợp đồng command: `Command Command { get; }` |
| [CommandModules/Enums/VpnProtocol.cs:4](../demo/Vpn2ProxyDemo/CommandModules/Enums/VpnProtocol.cs#L4) | Enum giao thức (`Sstp` / `L2tp` / `SoftEther` / `OpenVpn`) — map từ scheme của URI `--vpn` (hoặc đuôi `.ovpn`) |
| [CommandModules/Models/VpnTarget.cs:18](../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L18) | Tham số kết nối parse từ `--vpn`: **URI** `scheme://user:pass@host[:port][?psk=...][?hub=...]` (SSTP/L2TP/SoftEther) **hoặc đường dẫn một file `.ovpn`** (OpenVPN — host/port/proto/cert đọc từ file). [`TryParse` @ :56](../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L56): `.ovpn` ⇒ `OpenVpn` + `ConfigPath`; còn lại `System.Uri` → `Protocol/Host/Port/User/Pass/PreSharedKey/HubName` (scheme `ssl` = alias SoftEther; thiếu user:pass ⇒ `vpn:vpn`; SSTP/SoftEther thiếu port ⇒ 443; L2TP thiếu `?psk=` ⇒ `vpn`; SoftEther thiếu `?hub=` ⇒ `VPNGATE`) + thông báo lỗi |
| [CommandModules/CommandModuleBase.cs:18](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L18) | **Base abstract** cho mọi subcommand action: option chung `--vpn` + `--watermark` ([@ :39](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L39); **chỉ SoftEther** — đường dẫn file watermark blob thật, để trống ⇒ placeholder/403), parse target, in header (Protocol), connect VPN (giữ vòng đời), **in panel khả năng** [`PrintCapabilitiesAsync` @ :107](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L107) (sau connect, trước hành động) rồi gọi [`RunAsync` @ :100](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L100) (abstract); [`ConnectAsync` @ :133](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L133) dispatch theo `VpnTarget.Protocol` về 4 hàm static của `VpnTunnel` (Sstp/L2tp/SoftEther/OpenVpn — truyền `watermarkPath` cho SoftEther); [`ValidateOptions` @ :130](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L130) (virtual) cho subclass fail-fast option riêng |
| [CommandModules/ProbeUdpDnsCommandModule.cs:11](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L11) | Subcommand `dns`: thêm `--dns-server/--resolve`; [`RunAsync` → `ProbeUdpDnsAsync` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L44) probe UDP + phân giải domain qua tunnel (không dựng proxy) |
| [CommandModules/ProxyServerCommandModule.cs:18](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L18) | Subcommand `proxy-server` (NOT sealed): thêm `--proxy-host/--proxy-port` + [`ValidateOptions` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L44) (fail-fast bind); [`RunAsync` @ :55](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L55) dựng `ILoggerFactory` console ([`CreateLoggerFactory` @ :96](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L96)) + `VpnProxySource` + `ProxyServer` (cùng chia sẻ factory) rồi gọi [`OnProxyReadyAsync` @ :87](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L87) (virtual, mặc định: giữ tới khi nhấn Enter) |
| [CommandModules/HttpRequestProxyServerCommandModule.cs:12](../demo/Vpn2ProxyDemo/CommandModules/HttpRequestProxyServerCommandModule.cs#L12) | Subcommand `http-request` (kế thừa `ProxyServerCommandModule`): thêm `--url`, override [`OnProxyReadyAsync` @ :27](../demo/Vpn2ProxyDemo/CommandModules/HttpRequestProxyServerCommandModule.cs#L27) — GET `--url` qua proxy (WebProxy), in body rồi **thoát luôn** (không chờ Enter) |

Luồng điều phối chung nằm ở base [`CommandModuleBase.InvokeAsync` @ :40](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L40)
(parse `--vpn` bằng `VpnTarget.TryParse` → `ValidateOptions` (subclass) → in header → `ConnectAsync` dispatch theo giao thức →
gọi `RunAsync` của subclass). `dns` chạy [`ProbeUdpDnsAsync` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L44);
`proxy-server`/`http-request` dùng chung [`RunAsync` @ :55](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L55) (dựng proxy + `ILoggerFactory`) rồi phân nhánh ở
[`OnProxyReadyAsync`](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L87): giữ tới khi nhấn Enter (`proxy-server`)
**hoặc** GET `--url` qua proxy rồi thoát (`http-request`).

## 4. Tham số CLI (3 subcommand `dns` / `proxy-server` / `http-request`)

**Option chung** (mọi subcommand — từ `CommandModuleBase`):

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--vpn` | `sstp://vpn:vpn@public-vpn-226.opengw.net` | target VPN: **URI** `scheme://user:pass@host[:port][?psk=...][?hub=...]` **hoặc đường dẫn một file `.ovpn`** (OpenVPN — host/port/proto/cert đọc từ file). `scheme` = `sstp` (MS-SSTP/TLS, default port 443), `l2tp` (L2TP/IPsec IKEv1, NAT-T 500/4500 — bỏ qua port; PSK qua `?psk=`), `softether`/`ssl` (SoftEther SSL-VPN/TLS, default 443; Hub qua `?hub=`). Thiếu `user:pass` ⇒ `vpn:vpn`; L2TP thiếu `?psk=` ⇒ PSK `vpn`; SoftEther thiếu `?hub=` ⇒ `VPNGATE` (group PSK/hub VPN Gate) |
| `--watermark` | *(rỗng)* | **(Chỉ SoftEther)** đường dẫn file chứa **watermark blob THẬT** của SoftEther — server thật từ chối blob placeholder (HTTP 403). Rỗng ⇒ placeholder (chỉ chạy với server giả lập offline). Blob là dữ liệu GPL, KHÔNG có sẵn trong repo |

**`dns`** (probe UDP-DNS) thêm:

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--dns-server` | *(rỗng)* | DNS server (IPv4) cho probe UDP; rỗng = dùng DNS do VPN cấp, fallback `8.8.8.8` |
| `--resolve` | `google.com` | tên miền phân giải bằng DNS-over-UDP qua tunnel (đồng thời kiểm tra VPN có hỗ trợ UDP) |

**`proxy-server`** (dựng proxy, giữ tới khi nhấn Enter) thêm:

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--proxy-host` | `127.0.0.1` | IP cho proxy local nghe (`0.0.0.0` = mọi interface cho máy khác trong LAN) |
| `--proxy-port` | `0` | cổng proxy local (`0` = tự cấp; cố định để client trỏ vào ổn định) |

**`http-request`** (kế thừa `proxy-server` — có cả `--proxy-host/--proxy-port`) thêm:

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--url` | `https://checkip.amazonaws.com/` | URL GET **qua proxy** (qua tunnel); in response body rồi thoát luôn |

`proxy-server`/`http-request` validate `--proxy-host/--proxy-port` **trước** khi connect ([ProxyServerCommandModule.cs:44](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L44)).
Bind `0.0.0.0` thì client vẫn nối qua `127.0.0.1`; bind IP cụ thể thì nối thẳng IP đó
([ProxyServerCommandModule.cs:72](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L72)).

## 5. Trạng thái & chưa làm

- ✅ HTTP/HTTPS CONNECT + SOCKS4/5 CONNECT qua tunnel (chỉ IPv4, active-open) cho **cả 4 giao thức**: MS-SSTP, L2TP/IPsec, **SoftEther SSL-VPN** (`softether://user:pass@host?hub=VPNGATE`, alias `ssl`) và **OpenVPN** (`--vpn <file>.ovpn`). SoftEther/OpenVPN tái dùng thẳng `SoftEtherDriver`/`OpenVpnDriver` qua `IVpnConnection.Sessions[0]`.
- ✅ **SOCKS5 UDP-ASSOCIATE qua proxy** (`VpnUdpAssociateSource` → `UdpConnection`): client gửi UDP qua proxy, server
  relay datagram ra ngoài bằng userspace UDP của stack (đa đích, `SendTo`/`ReceiveAsync`); socket được `UnbindUdp` khi
  association đóng. IPv4-only (đích IPv6 bị từ chối).
- ✅ Giữ proxy + tunnel sống tới khi nhấn Enter (test duy trì kết nối: keepalive/auto-reconnect của driver chạy nền).
- ✅ **Probe UDP + DNS-over-UDP qua tunnel** (`UdpDnsProbe` → `VpnUdpClient`): vừa kiểm tra VPN có định tuyến UDP
  vừa phân giải `--resolve` ra IPv4 (đích DNS = `--dns-server` / DNS VPN cấp / `8.8.8.8`). Đây là data plane UDP
  thật, độc lập với proxy TCP.
- ✅ **Panel "VPN này hỗ trợ gì"** (`VpnCapabilityProbe` → `VpnCapabilityReport.Print`): in tự động sau mọi connect,
  trước hành động. Gộp probe thật (UDP, LAN ảo ICMP) + năng lực driver (transport/bảo mật/auth) + heuristic NAT/IPv6.
  Các khả năng thư viện chưa hỗ trợ ⇒ §6.
- ⚠️ **SoftEther cần watermark blob THẬT** để chạy live: VPN Gate trả **HTTP 403** với placeholder; truyền `--watermark <file>`
  (blob GPL, không có sẵn trong repo). Để trống ⇒ chỉ dùng được với server giả lập offline. **OpenVPN**: tun-UDP đã validate
  live VPN Gate (TCP nhỏ/UDP/ICMP), gói lớn (https) chưa qua — nghi MTU/MSS (xem [`11`](11-todo-roadmap.md) §V.2).
- ⏳ **Chưa:** BIND (stack active-open-only + địa chỉ tunnel private không routable từ internet ⇒ peer ngoài không
  dial vào được), proxy resolve host vẫn bằng host DNS, IPv6. Tách adapter thành project `TqkLibrary.VpnClient.Proxy` nếu
  cần tái dùng — xem [`11`](11-todo-roadmap.md).

## 6. Khả năng VPN hiển thị & phần thư viện chưa hỗ trợ (roadmap/plan)

Panel hiển thị 7 khả năng. Bảng dưới: trạng thái điển hình (VPN Gate SecureNAT) + nguồn xác định + **việc thư viện cần làm**
để chuyển một "✗/heuristic" thành "✓ thật".

| Khả năng | Hiện (VPN Gate) | Nguồn | Thư viện cần làm |
|---|---|---|---|
| IPv4 routing | ✓ | đã cấp IP ảo + định tuyến | — (đang chạy live) |
| IPv6 | ✗ | tĩnh | **IPv6 trong tunnel**: PPP chưa có IPv6CP (chỉ IPCP/IPv4) ⇒ không có nguồn địa chỉ v6. → [`11` P1.1](11-todo-roadmap.md) (IPV6CP + SLAAC/DHCPv6) + P1.2 (outer IPv6). IP stack đã dual-stack sẵn. |
| UDP | ✓ (probe) | gửi DNS-over-UDP **thật** | — (data plane UDP đã chạy; chỉ phụ thuộc server có route UDP hay không) |
| Listen TCP (mở port ra internet) | ✗ | heuristic NAT + tĩnh | (a) **TCP passive-open/listener** — `TcpIpStack` hiện chỉ active-open, chưa có trạng thái LISTEN/accept *(chưa có mục riêng ở [`11`](11-todo-roadmap.md) — ghi nhận tại đây)*; (b) reachability cần IP **public** (sau SecureNAT là private) ⇒ phụ thuộc server, phần lớn **ngoài tầm** một VPN client. |
| Listen UDP (mở port ra internet) | ✗ | heuristic NAT + tĩnh | (a) **UDP nhận-từ-mọi-nguồn** — `UdpConnection` hiện là connected-UDP (lọc đúng 1 remote), chưa có bind unconnected nhận datagram từ mọi nguồn *(chưa có mục riêng ở [`11`](11-todo-roadmap.md) — ghi nhận tại đây)*; (b) reachability NAT như trên. |
| LAN ảo trong VPN | ~ (probe) | ICMP ping gateway nội bộ + DNS cùng /24 (phát hiện ⇒ panel thêm dòng **Gateway nội bộ**) | Driver hiện model **điểm-điểm** (`MultiHostModel.None`); LAN multi-host thật cần tầng L2 → [`11` L2.4–L2.8](11-todo-roadmap.md) (NDISC/DHCP/`EthernetAdapter` + bật `MultiHostModel.L2BroadcastDomain`). Driver L2 thật đầu tiên: SoftEther (V.4). |
| MAC address (L2) | ✗ | tĩnh (`LinkLayer`) | Cả 2 driver là `LinkLayer.L3Ip` (PPP/IPCP point-to-point) ⇒ không có khung Ethernet/MAC. Nền L2 đã có (`MacAddress`/`EthernetSwitch`/`VirtualHost`/`IEthernetChannel.LinkAddress`) nhưng chưa driver nào phát ra `IEthernetChannel` → [`11` L2.7–L2.8](11-todo-roadmap.md) (`EthernetAdapter`) + driver L2 đầu SoftEther (V.4). |

> **Ghi chú heuristic (giới hạn cố ý của demo, không phải của thư viện):** "Listen TCP/UDP" luôn báo ✗ kèm lý do
> (không thử connect-back từ ngoài vì cần dịch vụ phản chiếu/IP public). LAN ảo chỉ ping **gateway nội bộ suy đoán**
> (DNS nếu cùng `/24`, ngược lại `x.y.z.1`) chứ **không quét toàn subnet** (tránh chậm/ồn) — nên kết quả dừng ở
> `Likely`/`Unknown`, đủ để thấy "có hub nội bộ" mà không khẳng định số host.
