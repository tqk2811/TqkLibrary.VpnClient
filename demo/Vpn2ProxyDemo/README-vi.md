# Vpn2ProxyDemo

Demo: kết nối VPN Gate (**MS-SSTP** / **L2TP/IPsec** / **SoftEther SSL-VPN** / **OpenVPN** từ file `.ovpn`) qua một URI (hoặc đường dẫn `.ovpn`) `--vpn`, rồi chạy **một hành động** (subcommand): probe UDP-DNS qua tunnel (`dns`), dựng proxy local giữ tới khi nhấn Enter (`proxy-server`), hoặc GET một URL qua proxy rồi thoát (`http-request`).

Luồng: **vpn → TcpIpStack → panel "VPN hỗ trợ gì" → (dns | proxy-server | http-request)**

```
[chung]         SSTP / L2TP / SoftEther / OpenVPN        (kết nối VPN từ --vpn, nhận IP ảo + DNS + PacketChannel)
   -> new TcpIpStack(channel, ip)                       (userspace TCP/IP trong tunnel)
   -> VpnCapabilityProbe.RunAsync(tunnel).Print()       (panel "VPN hỗ trợ gì": probe UDP/LAN ảo + suy luận IPv6/listen — tự in sau connect)

[dns]           -> UdpDnsProbe.ResolveAsync(...)         (DNS-over-UDP qua tunnel: VPN có hỗ trợ UDP? + IP của --resolve)

[proxy-server]  -> new VpnProxySource(stack) -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()
   -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
   => trỏ browser/curl tới proxy: mọi traffic đi qua IP công cộng của VPN server

[http-request]  -> (kế thừa proxy-server) HttpClient { Proxy }.GetStringAsync(--url) -> in body -> THOÁT luôn
```

> "SSL-VPN" mà VPN Gate liệt kê là **giao thức riêng của phần mềm SoftEther VPN** — demo nay hỗ trợ qua scheme `softether`/`ssl` ([`SoftEtherDriver`](../../src/TqkLibrary.VpnClient.Drivers.SoftEther)), **nhưng** server SoftEther thật từ chối watermark placeholder (HTTP 403) ⇒ cần `--watermark <file>` với blob THẬT (dữ liệu GPL, không có sẵn trong repo). **MS-SSTP** + **L2TP/IPsec** đã chạy live; **OpenVPN** tun-UDP đã validate live VPN Gate (gói lớn/https chưa qua — xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2).

## Cấu trúc (mẫu `ICommandModule` — như `TqkLibrary.WinDivert.Demo`)

```
Vpn2ProxyDemo/
├── Program.cs                        RootCommand { dns, proxy-server, http-request } -> Parse(args).InvokeAsync()
├── Properties/launchSettings.json    profile chạy nhanh từng case (proxy-server/http-request/dns × sstp/l2tp/openvpn/softether + help)
├── VpnProxySource.cs                 IProxySource (partial) bọc TcpIpStack; IsSupportUdp=true, Bind=false; IsSupportIpv6 theo cờ ctor supportIpv6 (bật khi tunnel có v6 global — P1.1(4)); ctor nhận ILoggerFactory? -> sinh ILogger cho mỗi nested source
├── VpnProxySource.VpnConnectSource.cs        IConnectSource (nested): mở VpnTcpClient qua tunnel, trả Stream cho ProxyServer; ResolveAsync hỗ trợ IPv6 literal + AAAA fallback (dual-stack); log resolve/connect/lỗi (ILogger?)
├── VpnProxySource.VpnUdpAssociateSource.cs   IUdpAssociateSource (nested): egress UDP đa đích qua UdpConnection (SOCKS5 UDP-ASSOCIATE); đích IPv6 dual-stack (bỏ ném NotSupported); log associate/send/receive/unbind (ILogger?)
├── UdpDnsProbe.cs                    build/parse gói DNS (RFC 1035) trên VpnUdpClient: probe UDP + phân giải domain qua tunnel
├── UdpDnsProbeResult.cs              kết quả probe: UdpSupported + danh sách IPv4 + số lần thử/thời gian/lỗi
├── CapabilityStatus.cs               enum trạng thái khả năng: Yes[✓]/No[✗]/Likely·Unlikely[~]/Unknown[?]
├── VpnCapability.cs                  1 dòng khả năng: Name + CapabilityStatus + Detail (lý do/số đo)
├── VpnCapabilityReport.cs            kết quả panel: Info (IP/DNS/MTU/transport/bảo mật/auth) + Capabilities; Print() in Console
├── VpnCapabilityProbe.cs             static probe (mirror UdpDnsProbe): UDP (DNS-over-UDP) + LAN ảo (ICMP ping gateway) thật + năng lực driver + heuristic NAT/IPv6 -> VpnCapabilityReport
├── VpnTunnel.cs                      bọc TcpIpStack + vòng đời (IAsyncDisposable); lộ AssignedAddress/AssignedAddressV6/AssignedDns/Mtu/Capabilities/ProtocolName cho panel; dựng TcpIpStack(channel, v4, v6global) dual-stack khi tunnel có IPv6 global (helper GlobalV6 lọc bỏ link-local fe80::/10 — P1.1(4)); 4 hàm static ConnectSstpAsync/ConnectL2tpAsync/ConnectSoftEtherAsync(hub,watermarkPath)/ConnectOpenVpnAsync(.ovpn) (dựng driver -> đọc Capabilities -> VpnTunnel; SoftEther/OpenVPN có console logger cho driver)
├── OvpnConfigureFiles/              4 file .ovpn mẫu (copy sang output qua csproj) cho --vpn <file>.ovpn
└── CommandModules/
    ├── Interfaces/ICommandModule.cs          hợp đồng: Command Command { get; }
    ├── Enums/VpnProtocol.cs                  enum giao thức: Sstp / L2tp / SoftEther / OpenVpn (map từ scheme của --vpn, hoặc đuôi .ovpn)
    ├── Models/VpnTarget.cs                   parse --vpn: URI scheme://user:pass@host[:port][?psk=][?hub=] (ssl=alias SoftEther) HOẶC đường dẫn .ovpn -> Protocol/Host/Port/User/Pass/PreSharedKey/HubName/ConfigPath; TryParse + thông báo lỗi
    ├── CommandModuleBase.cs                  base abstract: option chung --vpn + --watermark (chỉ SoftEther) + parse target + header (Protocol) + connect VPN (giữ vòng đời) -> PrintCapabilitiesAsync (panel khả năng) -> RunAsync (abstract); ConnectAsync dispatch theo VpnTarget.Protocol (4 nhánh); ValidateOptions (virtual, fail-fast option riêng)
    ├── ProbeUdpDnsCommandModule.cs           subcommand "dns": +--dns-server/--resolve; RunAsync -> ProbeUdpDnsAsync (probe UDP + phân giải domain qua tunnel)
    ├── ProxyServerCommandModule.cs           subcommand "proxy-server" (NOT sealed): +--proxy-host/--proxy-port (ValidateOptions fail-fast); RunAsync dựng ILoggerFactory console + VpnProxySource (supportIpv6: tunnel.AssignedAddressV6 is not null) + ProxyServer (chung factory) rồi OnProxyReadyAsync (virtual, mặc định giữ tới khi nhấn Enter)
    └── HttpRequestProxyServerCommandModule.cs  subcommand "http-request" (kế thừa ProxyServerCommandModule): +--url; override OnProxyReadyAsync -> GET url qua proxy, in body rồi thoát luôn
```

Phân tầng (base + subcommand theo **hành động**):

- `CommandModuleBase` (abstract): phần dùng chung — option `--vpn` (`scheme://user:pass@host[:port][?psk=][?hub=]` hoặc đường dẫn `.ovpn`, parse bằng `VpnTarget.TryParse`) + `--watermark` (chỉ SoftEther), in header (Protocol), **connect VPN** (giữ vòng đời tunnel), bắt lỗi; rồi gọi `RunAsync` (abstract) của subclass. `ConnectAsync` chỉ `switch` theo `VpnTarget.Protocol` (4 nhánh, truyền `watermarkPath` cho SoftEther).
- Subcommand = một subclass: `ProbeUdpDnsCommandModule` (`dns`) probe UDP-DNS; `ProxyServerCommandModule` (`proxy-server`) dựng proxy + giữ tới khi nhấn Enter, tách điểm-mở-rộng `OnProxyReadyAsync` (virtual); `HttpRequestProxyServerCommandModule` (`http-request`) **kế thừa** `proxy-server`, override `OnProxyReadyAsync` để GET `--url` qua proxy rồi thoát. Mỗi subclass tự khai option riêng + (tùy chọn) override `ValidateOptions` để fail-fast trước khi connect.
- Phần connect riêng từng giao thức là **hàm static của `VpnTunnel`** (`ConnectSstpAsync` / `ConnectL2tpAsync` / `ConnectSoftEtherAsync` / `ConnectOpenVpnAsync`) — dựng driver tương ứng (SoftEther/OpenVPN tái dùng thẳng `SoftEtherDriver`/`OpenVpnDriver` qua `IVpnConnection.Sessions[0]`, có console logger), trả **`VpnTunnel`** (bọc `TcpIpStack` + vòng đời, sống tới hết `await using`).
- **Thêm action mới:** thêm một subclass `CommandModuleBase` (hoặc `ProxyServerCommandModule` nếu cần proxy) + đăng ký `Command` trong `Program`. **Thêm giao thức mới:** thêm hàm static `ConnectXxxAsync` trong `VpnTunnel` + giá trị `VpnProtocol` (scheme) + một nhánh `switch`.

## Chạy

Args xử lý bằng **System.CommandLine 2.0.7** (subcommand + `--option`, có `--help`):

```powershell
dotnet run --project demo/Vpn2ProxyDemo -- proxy-server --vpn sstp://vpn:vpn@public-vpn-226.opengw.net   # dựng proxy, giữ tới khi Enter
dotnet run --project demo/Vpn2ProxyDemo -- proxy-server --vpn l2tp://vpn:vpn@public-vpn-226.opengw.net --proxy-host 0.0.0.0 --proxy-port 18080  # proxy nghe LAN, cổng cố định
dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn l2tp://vpn:vpn@public-vpn-226.opengw.net --resolve github.com --dns-server 8.8.8.8   # probe UDP-DNS
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn sstp://vpn:vpn@public-vpn-226.opengw.net --url https://checkip.amazonaws.com/   # GET qua proxy rồi thoát
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn "softether://vpn:vpn@public-vpn-226.opengw.net?hub=VPNGATE" --watermark wm.bin  # SoftEther SSL-VPN (cần watermark blob THẬT, nếu không server trả 403)
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn OvpnConfigureFiles/vpngate_public-vpn-206.opengw.net_udp_1195.ovpn   # OpenVPN từ file .ovpn (host/port/proto/cert đọc từ file)
dotnet run --project demo/Vpn2ProxyDemo -- --help                       # liệt kê subcommand
dotnet run --project demo/Vpn2ProxyDemo -- proxy-server --help          # option của 1 subcommand
```

Với `proxy-server`, proxy được **giữ chạy tới khi nhấn Enter** (hoặc Ctrl+C). Trong lúc đó trỏ browser/curl vào proxy để gửi traffic và quan sát VPN duy trì kết nối:

```powershell
curl -x http://127.0.0.1:18080 https://checkip.amazonaws.com/
```

Hoặc dùng **launch profile** ([Properties/launchSettings.json](Properties/launchSettings.json)) — chọn nhanh trong VS/Rider hoặc CLI (`--launch-profile "<tên>"`). Profile có sẵn: `proxy-server` cho sstp/l2tp/openvpn/softether (đều bind `0.0.0.0:18080`), `http-request` cho sstp/l2tp/openvpn/softether (GET checkip), `dns` cho sstp (resolve example.com qua DNS VPN cấp) và l2tp (github.com qua 8.8.8.8), và `help`. Profile softether kèm sẵn `--watermark watermark.bin` (cần blob THẬT), openvpn trỏ file `.ovpn` mẫu trong `OvpnConfigureFiles/`.

CLI gồm 3 subcommand; target VPN gói trong `--vpn` (URI hoặc đường dẫn `.ovpn`). Option:

**Chung** (mọi subcommand):

| Option | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--vpn` | `sstp://vpn:vpn@public-vpn-226.opengw.net` | target VPN: **URI** `scheme://user:pass@host[:port][?psk=][?hub=]` **hoặc đường dẫn `.ovpn`** (OpenVPN — host/port/proto/cert đọc từ file). `scheme` = `sstp` (MS-SSTP/TLS, default 443), `l2tp` (L2TP/IPsec IKEv1, NAT-T 500/4500 — bỏ qua port; PSK qua `?psk=`), `softether`/`ssl` (SoftEther SSL-VPN/TLS, default 443; Hub qua `?hub=`). Thiếu `user:pass` ⇒ `vpn:vpn`; L2TP thiếu `?psk=` ⇒ `vpn`; SoftEther thiếu `?hub=` ⇒ `VPNGATE` (PSK/hub VPN Gate) |
| `--watermark` | *(rỗng)* | **(Chỉ SoftEther)** đường dẫn file chứa **watermark blob THẬT** của SoftEther — server thật từ chối placeholder (HTTP 403). Rỗng ⇒ placeholder (chỉ chạy với server giả lập offline). Blob là dữ liệu GPL, không có sẵn trong repo |
| `--ipv6` | `false` | **(Chỉ SSTP/L2TP)** bật IPv6 trong tunnel: IPV6CP + lấy địa chỉ **global** qua SLAAC/DHCPv6 trên link PPP (P1.1). Best-effort — server không cấp IPv6 ⇒ vẫn IPv4 (chỉ thêm ~2s chờ). Khi có v6 global, `TcpIpStack` chạy dual-stack + proxy bật `IsSupportIpv6` (CONNECT/UDP nhận đích IPv6) |

**`dns`** thêm `--dns-server` (DNS IPv4 cho probe UDP; rỗng = DNS VPN cấp, fallback `8.8.8.8`) và `--resolve` (`google.com`; tên miền phân giải DNS-over-UDP qua tunnel).

**`proxy-server`** thêm `--proxy-host` (`127.0.0.1`; `0.0.0.0` = nghe mọi interface) và `--proxy-port` (`0` = tự cấp cổng).

**`http-request`** (kế thừa `proxy-server`, có cả `--proxy-host/--proxy-port`) thêm `--url` (`https://checkip.amazonaws.com/`; GET qua proxy, in body rồi thoát).

## Lưu ý

- **Cần mạng + server còn sống.** Host VPN Gate thay đổi liên tục; nếu `public-vpn-226` đã tắt, lấy host khác từ https://www.vpngate.net/ và đặt vào phần host của `--vpn` (vd `sstp://vpn:vpn@public-vpn-XXX.opengw.net`). Server phải bật đúng giao thức bạn chọn (cột MS-SSTP / L2TP / OpenVPN / SSL-VPN trên trang VPN Gate). **SoftEther (`softether`/`ssl`)** cần `--watermark <file>` với blob THẬT — không có blob, server thật trả HTTP 403. **OpenVPN**: tải file `.ovpn` từ VPN Gate (hoặc dùng mẫu trong `OvpnConfigureFiles/`) rồi trỏ `--vpn <đường-dẫn>.ovpn`; tun-UDP đã chạy live nhưng gói lớn (https) có thể chưa qua (MTU).
- **Không cần quyền admin** — toàn bộ stack là userspace (không TUN/TAP, không routing table).
- **Panel "VPN này hỗ trợ gì" (tự in sau mọi connect, trước hành động):** liệt kê IPv4/IPv6/UDP/Listen TCP/Listen UDP/LAN ảo/MAC (L2)
  kèm thông tin kết nối (IP ảo + public/private, DNS, MTU, transport, bảo mật, auth). **Probe thật**: UDP (DNS-over-UDP),
  LAN ảo (ICMP ping gateway nội bộ — phát hiện được thì panel thêm dòng **Gateway nội bộ**). **Suy luận**: IPv6 = ✓ khi
  bật `--ipv6` (SSTP/L2TP) **và** server cấp địa chỉ global qua SLAAC/DHCPv6 (P1.1; mặc định/không cấp ⇒ ✗), Listen TCP/UDP =
  ✗ (sau NAT + stack chưa listen). Mỗi mục ✗ ghi rõ lý do; chi tiết phần thư viện chưa hỗ trợ
  + roadmap ở [`.docs/12-demo-vpn2proxy.md`](../../.docs/12-demo-vpn2proxy.md) §6.
  Panel tự bao timeout + nuốt lỗi nên không làm hỏng hành động chính (cộng ~5–10s probe vào mọi lệnh).
- **Subcommand `dns` — kiểm tra UDP + DNS qua tunnel:** sau khi tunnel lên, gửi một truy vấn DNS (bản ghi A) qua **UDP xuyên tunnel** (`UdpDnsProbe` → `VpnUdpClient`, không dùng host DNS) tới `--dns-server` (mặc định: DNS do VPN cấp, fallback `8.8.8.8`). Nhận được phản hồi ⇒ in `VPN HỖ TRỢ UDP` + IPv4 của `--resolve`; timeout sau 3 lần thử ⇒ VPN có thể không định tuyến UDP (hoặc DNS server không reachable — thử `--dns-server` khác). Đây là kênh UDP đi thẳng IP stack.
- **Subcommand `http-request`** — GET nhanh `--url` qua proxy (vd checkip ⇒ thấy IP công cộng của VPN server), in body rồi thoát; tiện kiểm đường đi HTTP qua VPN mà không phải giữ proxy thủ công.
- **SOCKS5 UDP-ASSOCIATE:** proxy hỗ trợ UDP cho client SOCKS5 (`IsSupportUdp=true`). Client gửi datagram qua proxy, `VpnUdpAssociateSource` relay ra ngoài bằng UDP của tunnel rồi trả về (vd `curl --socks5 127.0.0.1:port --resolve ... ` hoặc một DNS client trỏ qua SOCKS5 UDP). **BIND không hỗ trợ** (stack active-open-only + địa chỉ tunnel private không routable từ internet).
- **IPv6 trong tunnel (P1.1(4), bật `--ipv6` cho SSTP/L2TP):** khi server cấp địa chỉ IPv6 **global** (SLAAC/DHCPv6 trên link PPP), `VpnTunnel` dựng `TcpIpStack` dual-stack (helper `GlobalV6` bỏ link-local `fe80::/10`) và proxy bật `IsSupportIpv6` ⇒ CONNECT/UDP nhận đích IPv6 (literal + AAAA fallback). Best-effort: server chỉ cấp IPv4/link-local ⇒ tự giữ IPv4-only (`IsSupportIpv6=false`). SoftEther/OpenVPN bật IPv6 theo cấu hình driver riêng (không qua `--ipv6`).
- **Giữ kết nối (`proxy-server`):** sau khi proxy lên, demo dừng tại bước `ProxyServer` và chờ Enter — tunnel vẫn chạy keepalive + auto-reconnect (xem driver), nên đây là chỗ test "duy trì kết nối": cứ gửi traffic qua proxy liên tục/định kỳ rồi quan sát log reconnect.
- `--proxy-host 0.0.0.0` mở proxy cho cả máy khác trong LAN — chỉ dùng trên mạng tin cậy (proxy không có auth).
- Demo `ProjectReference` thẳng tới **4 driver** (`Drivers.Sstp`/`Drivers.L2tpIpsec`/`Drivers.SoftEther`/`Drivers.OpenVpn`) + [`src/TqkLibrary.VpnClient.Sockets`](../../src/TqkLibrary.VpnClient.Sockets) (`VpnTcpClient`/`VpnUdpClient`/`TcpIpStack`); [`OpenVpn`](../../src/TqkLibrary.VpnClient.OpenVpn) (parse `.ovpn` qua `OpenVpnConfigParser`) đến **transitive** qua `Drivers.OpenVpn` và được dùng trực tiếp trong `VpnTunnel.ConnectOpenVpnAsync`. NuGet: `System.CommandLine` 2.0.7 + `TqkLibrary.Proxy` 1.0.35 + `Microsoft.Extensions.Logging` 10.0.8 / `.Console` 10.0.7. **SoftEther/OpenVPN** dựng một `ILoggerFactory` console riêng cho driver (trace handshake/state/reconnect khi chạy live).
- **Log:** `proxy-server`/`http-request` tạo một `ILoggerFactory` console (mức Information; riêng category `Vpn2ProxyDemo` ở Debug) rồi truyền cho cả `ProxyServer` (log của thư viện proxy) và `VpnProxySource` (log connect/UDP của adapter). `dns` không bật log.
