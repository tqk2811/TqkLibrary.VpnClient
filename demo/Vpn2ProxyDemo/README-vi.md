# Vpn2ProxyDemo

Demo: kết nối VPN qua **một trong 17 giao thức** (MS-SSTP, L2TP/IPsec, IKEv2-native, Cisco IPsec/EzVPN, SoftEther SSL-VPN, OpenVPN, WireGuard, OpenConnect, PPTP, IP-encap GRE/IPIP/SIT, Nebula, tinc, n2n, ZeroTier, vtun, Tailscale, VPN-over-SSH) — chỉ định bằng một URI hoặc đường dẫn file config qua `--vpn` — rồi chạy **một hành động** (subcommand): probe UDP-DNS qua tunnel (`dns`), dựng proxy local giữ tới khi nhấn Enter (`proxy-server`), GET một URL qua proxy rồi thoát (`http-request`), hoặc POST một payload lớn qua proxy rồi in throughput và thoát (`http-post-upload`).

Luồng: **vpn → TcpIpStack → panel "VPN hỗ trợ gì" → (dns | proxy-server | http-request | http-post-upload)**

```
[chung]         <giao thức từ --vpn>                     (kết nối VPN, nhận IP ảo + DNS + PacketChannel)
   -> new TcpIpStack(channel, ipv4, ipv6global?)         (userspace TCP/IP trong tunnel — dual-stack khi tunnel có IPv6 global)
   -> VpnCapabilityProbe.RunAsync(tunnel).Print()        (panel "VPN hỗ trợ gì": probe UDP/LAN ảo + suy luận IPv6/listen — tự in sau connect)

[dns]              -> UdpDnsProbe.ResolveAsync(...)       (DNS-over-UDP qua tunnel: VPN có hỗ trợ UDP? + IP của --resolve)

[proxy-server]     -> new VpnProxySource(stack, loggerFactory, supportIpv6) -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()
   -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
   => trỏ browser/curl tới proxy: mọi traffic đi qua IP công cộng của VPN server

[http-request]     -> (kế thừa proxy-server) HttpClient { Proxy }.GetStringAsync(--url) -> in body -> THOÁT luôn

[http-post-upload] -> (kế thừa proxy-server) HttpClient { Proxy }.PostAsync(--url, --size byte) -> in throughput -> THOÁT
   (re-validate Q.4 sender-SWS: upload lớn qua tunnel phải đầy-MSS, không "1 byte/segment")
```

> "SSL-VPN" mà VPN Gate liệt kê là **giao thức riêng của phần mềm SoftEther VPN** — demo hỗ trợ qua scheme `softether`/`ssl` ([`SoftEtherDriver`](../../src/TqkLibrary.VpnClient.Drivers.SoftEther)), **nhưng** server SoftEther thật từ chối watermark placeholder (HTTP 403) ⇒ cần `--watermark <file>` với blob THẬT (dữ liệu GPL, không có sẵn trong repo). **MS-SSTP** + **L2TP/IPsec** đã chạy live; **OpenVPN** tun-UDP đã validate live VPN Gate (gói lớn/https chưa qua — xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2). **PPTP / IP-encap / SSH** cần raw socket / `PermitTunnel` ⇒ chạy trong lab (CAP_NET_RAW). **Cisco IPsec** (Aggressive Mode + group PSK) là Phase 1 yếu, chỉ interop gateway legacy.

## Cấu trúc (mẫu `ICommandModule` — như `TqkLibrary.WinDivert.Demo`)

```
Vpn2ProxyDemo/
├── Program.cs                        RootCommand { dns, proxy-server, http-request, http-post-upload } -> Parse(args).InvokeAsync()
├── Properties/launchSettings.json    profile chạy nhanh từng case (proxy-server/http-request/dns × sstp/l2tp/openvpn/softether + help)
├── VpnProxySource.cs                 IProxySource (partial) bọc TcpIpStack; IsSupportUdp=true, Bind=false; IsSupportIpv6 theo cờ ctor supportIpv6 (bật khi tunnel có v6 global — P1.1(4)); ctor nhận ILoggerFactory? -> sinh ILogger cho mỗi nested source
├── VpnProxySource.VpnConnectSource.cs        IConnectSource (nested): mở VpnTcpClient qua tunnel, trả Stream cho ProxyServer; ResolveAsync hỗ trợ IPv4/IPv6 literal + DNS A→AAAA fallback (dual-stack); log resolve/connect/lỗi (ILogger?)
├── VpnProxySource.VpnUdpAssociateSource.cs   IUdpAssociateSource (nested): egress UDP đa đích qua UdpConnection (SOCKS5 UDP-ASSOCIATE); đích IPv4 + IPv6 dual-stack; log associate/send/receive/unbind (ILogger?)
├── UdpDnsProbe.cs                    build/parse gói DNS (RFC 1035) trên VpnUdpClient: probe UDP + phân giải domain qua tunnel
├── UdpDnsProbeResult.cs              kết quả probe: UdpSupported + danh sách IPv4 + số lần thử/thời gian/lỗi
├── CapabilityStatus.cs               enum trạng thái khả năng: Yes[✓]/No[✗]/Likely·Unlikely[~]/Unknown[?]
├── VpnCapability.cs                  1 dòng khả năng: Name + CapabilityStatus + Detail (lý do/số đo)
├── VpnCapabilityReport.cs            kết quả panel: Info (IP/DNS/MTU/transport/bảo mật/auth) + Capabilities; Print() in Console
├── VpnCapabilityProbe.cs             static probe (mirror UdpDnsProbe): UDP (DNS-over-UDP) + LAN ảo (ICMP ping gateway) thật + năng lực driver + heuristic NAT/IPv6 -> VpnCapabilityReport
├── VpnTunnel.cs                      bọc TcpIpStack + vòng đời (IAsyncDisposable); lộ AssignedAddress/AssignedAddressV6/AssignedDns/Mtu/Capabilities/ProtocolName cho panel; dựng TcpIpStack(channel, v4, v6global) dual-stack khi tunnel có IPv6 global (helper GlobalV6 lọc bỏ link-local fe80::/10 — P1.1(4)); 17 hàm static ConnectXxxAsync (mỗi giao thức một hàm: SSTP/L2TP/IKEv2/Cisco/SoftEther/OpenVPN/WireGuard/OpenConnect/PPTP/IpEncap/Nebula/Tailscale/SSH/ZeroTier/n2n/tinc/vtun) + helper parse file config (.conf/.nebula/.tinc/.n2n/.zerotier/.tailscale) + CreateDriverLoggerFactory (console Debug cho driver)
├── OvpnConfigureFiles/              4 file .ovpn mẫu VPN Gate (public-vpn-206 + 219.100.37.165, mỗi host 1 udp/1195 + 1 tcp/443 — copy sang output qua csproj) cho --vpn <file>.ovpn
└── CommandModules/
    ├── Interfaces/ICommandModule.cs          hợp đồng: Command Command { get; }
    ├── Enums/VpnProtocol.cs                  enum 17 giao thức: Sstp / L2tp / Ikev2 / CiscoIpsec / SoftEther / OpenVpn / WireGuard / OpenConnect / Pptp / IpEncap / Nebula / Tinc / N2n / ZeroTier / Vtun / Tailscale / Ssh (map từ scheme của --vpn — ssl→SoftEther, anyconnect→OpenConnect, gre/ipip/sit→IpEncap V.8, hoặc đuôi file .ovpn/.conf/.nebula/.tinc/.n2n/.zerotier/.tailscale)
    ├── Models/VpnTarget.cs                   parse --vpn: URI scheme://user:pass@host[:port][?psk=][?hub=][?group=][?addr=&peer=][?addr6=&peer6=][?key=] HOẶC đường dẫn một file config (.ovpn/.conf/.nebula/.tinc/.n2n/.zerotier/.tailscale) -> Protocol/Host/Port/User/Pass/PreSharedKey/HubName/GroupName/ConfigPath/IpEncapKind/TunnelAddress/TunnelPeerAddress; TryParse + thông báo lỗi
    ├── CommandModuleBase.cs                  base abstract: option chung --vpn + --watermark (chỉ SoftEther) + --ipv6 + --outer-ipv6 (SSTP/L2TP/IKEv2) + --native-esp (chỉ L2TP/IPsec native ESP proto-50, P0.8c) + --l2tp-extra-sessions (P1.7) + --ikev2-eap (chỉ IKEv2 EAP-MSCHAPv2, V.1) + --openconnect-dtls (chỉ OpenConnect, V.5); cờ chỉ-một-giao-thức bật với scheme khác ⇒ cảnh báo + bỏ qua; parse target + header (Protocol) + connect VPN (giữ vòng đời) -> PrintCapabilitiesAsync (panel khả năng) -> RunAsync (abstract); ConnectAsync dispatch theo VpnTarget.Protocol về 17 hàm static của VpnTunnel; ValidateOptions (virtual, fail-fast option riêng)
    ├── ProbeUdpDnsCommandModule.cs           subcommand "dns": +--dns-server/--resolve; RunAsync -> ProbeUdpDnsAsync (probe UDP + phân giải domain qua tunnel)
    ├── ProxyServerCommandModule.cs           subcommand "proxy-server" (NOT sealed): +--proxy-host/--proxy-port (ValidateOptions fail-fast); RunAsync dựng ILoggerFactory console + VpnProxySource (supportIpv6: tunnel.AssignedAddressV6 is not null) + ProxyServer (chung factory) rồi OnProxyReadyAsync (virtual, mặc định giữ tới khi nhấn Enter)
    ├── HttpRequestProxyServerCommandModule.cs  subcommand "http-request" (kế thừa ProxyServerCommandModule): +--url; override OnProxyReadyAsync -> GET url qua proxy, in body rồi thoát luôn
    └── HttpPostUploadProxyServerCommandModule.cs  subcommand "http-post-upload" (kế thừa ProxyServerCommandModule): +--url/--size; override OnProxyReadyAsync -> POST --size byte tới url qua proxy, in throughput + byte server xác nhận rồi thoát luôn (re-validate Q.4 sender-SWS)
```

Phân tầng (base + subcommand theo **hành động**):

- `CommandModuleBase` (abstract): phần dùng chung — option `--vpn` (`scheme://user:pass@host[:port][?psk=][?hub=][?group=][?addr=&peer=][?key=]` hoặc đường dẫn một file config, parse bằng `VpnTarget.TryParse`) + các cờ `--watermark`/`--ipv6`/`--outer-ipv6`/`--native-esp`/`--l2tp-extra-sessions`/`--ikev2-eap`/`--openconnect-dtls`, in header (Protocol), **gate các cờ chỉ-một-giao-thức** (bật với scheme khác ⇒ cảnh báo + bỏ qua, không crash), **connect VPN** (giữ vòng đời tunnel), bắt lỗi; rồi gọi `RunAsync` (abstract) của subclass. `ConnectAsync` chỉ `switch` theo `VpnTarget.Protocol` (một nhánh / giao thức) về hàm static tương ứng của `VpnTunnel`.
- Subcommand = một subclass: `ProbeUdpDnsCommandModule` (`dns`) probe UDP-DNS; `ProxyServerCommandModule` (`proxy-server`) dựng proxy + giữ tới khi nhấn Enter, tách điểm-mở-rộng `OnProxyReadyAsync` (virtual); `HttpRequestProxyServerCommandModule` (`http-request`) **kế thừa** `proxy-server`, override `OnProxyReadyAsync` để GET `--url` qua proxy rồi thoát; `HttpPostUploadProxyServerCommandModule` (`http-post-upload`) cũng **kế thừa** `proxy-server`, override `OnProxyReadyAsync` để POST `--size` byte tới `--url` qua proxy, in throughput rồi thoát (re-validate Q.4 sender-SWS). Mỗi subclass tự khai option riêng + (tùy chọn) override `ValidateOptions` để fail-fast trước khi connect.
- Phần connect riêng từng giao thức là **hàm static của `VpnTunnel`** (`ConnectSstpAsync` / `ConnectL2tpAsync` / `ConnectIkev2Async` / `ConnectCiscoIpsecAsync` / `ConnectSoftEtherAsync` / `ConnectOpenVpnAsync` / `ConnectWireGuardAsync` / `ConnectOpenConnectAsync` / `ConnectPptpAsync` / `ConnectIpEncapAsync` / `ConnectNebulaAsync` / `ConnectTincAsync` / `ConnectN2nAsync` / `ConnectZeroTierAsync` / `ConnectVtunAsync` / `ConnectTailscaleAsync` / `ConnectSshAsync` — 17 hàm) — dựng driver/connection tương ứng (các driver tái dùng thẳng qua `IVpnConnection.Sessions[0]` hoặc connection façade), **mỗi giao thức wire một console driver-logger** (`CreateDriverLoggerFactory`) để thấy trace handshake/keepalive/rekey/reconnect khi chạy live, trả **`VpnTunnel`** (bọc `TcpIpStack` + vòng đời, sống tới hết `await using`).
- **Thêm action mới:** thêm một subclass `CommandModuleBase` (hoặc `ProxyServerCommandModule` nếu cần proxy) + đăng ký `Command` trong `Program`. **Thêm giao thức mới:** thêm hàm static `ConnectXxxAsync` trong `VpnTunnel` + giá trị `VpnProtocol` (scheme/đuôi file) + một nhánh `switch` (vd `ikev2` → `ConnectIkev2Async`, validate live V.1).

## Chạy

Args xử lý bằng **System.CommandLine 2.0.7** (subcommand + `--option`, có `--help`):

```powershell
dotnet run --project demo/Vpn2ProxyDemo -- proxy-server --vpn sstp://vpn:vpn@public-vpn-226.opengw.net   # dựng proxy, giữ tới khi Enter
dotnet run --project demo/Vpn2ProxyDemo -- proxy-server --vpn l2tp://vpn:vpn@public-vpn-226.opengw.net --proxy-host 0.0.0.0 --proxy-port 18080  # proxy nghe LAN, cổng cố định
dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn l2tp://vpn:vpn@public-vpn-226.opengw.net --resolve github.com --dns-server 8.8.8.8   # probe UDP-DNS
sudo dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn l2tp://vpn:vpn@<IP>?psk=vpn --native-esp --resolve github.com --dns-server 8.8.8.8   # L2TP native-ESP proto-50 (no-NAT, P0.8c — cần CAP_NET_RAW/root)
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn sstp://vpn:vpn@public-vpn-226.opengw.net --url https://checkip.amazonaws.com/   # GET qua proxy rồi thoát
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn "softether://vpn:vpn@public-vpn-226.opengw.net?hub=VPNGATE" --watermark wm.bin  # SoftEther SSL-VPN (cần watermark blob THẬT, nếu không server trả 403)
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn OvpnConfigureFiles/vpngate_public-vpn-206.opengw.net_udp_1195.ovpn   # OpenVPN từ file .ovpn (host/port/proto/cert đọc từ file)
dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn /path/wg.conf --dns-server 10.50.0.1   # WireGuard từ file .conf wg-quick (PrivateKey/Address + [Peer] PublicKey/Endpoint/AllowedIPs); validate live V.3 (lab/wireguard)
dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn ikev2://vpn@<IP>?psk=vpn --ikev2-eap   # IKEv2-native (RFC 7296): PSK group + EAP-MSCHAPv2 với user:pass (V.1)
dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn "cisco://user:pass@<IP>?group=vpngroup&psk=grouppsk"   # Cisco IPsec/EzVPN: Aggressive Mode group PSK + XAUTH (V.12)
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn openconnect://user:pass@<IP> --openconnect-dtls   # OpenConnect (ocserv/AnyConnect): CSTP-over-TLS + DTLS data path (V.5)
sudo dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn pptp://user:pass@<IP>   # PPTP (RFC 2637): control TCP/1723 + GRE proto-47 raw socket (cần CAP_NET_RAW — V.6)
sudo dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn "gre://<IP>?addr=10.80.0.2/24&peer=10.80.0.1"   # plain GRE-47 raw socket, IP tĩnh (connectionless — cần CAP_NET_RAW — V.8); ipip/sit tương tự
sudo dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn "ssh://user:pass@<IP>?addr=10.0.0.2/30&peer=10.0.0.1"   # VPN-over-SSH (OpenSSH -w tun): ?key=<seed ed25519> hoặc password (V.10)
dotnet run --project demo/Vpn2ProxyDemo -- dns --vpn /path/peer.nebula   # Nebula từ file .nebula (ca/cert/key PEM + endpoint + overlay — V.7.1); .tinc/.n2n/.zerotier/.tailscale tương tự
dotnet run --project demo/Vpn2ProxyDemo -- http-post-upload --vpn /path/wg.conf --url http://10.60.0.1:8081/upload --size 10485760   # POST 10 MB qua proxy, in throughput (re-validate Q.4 sender-SWS)
dotnet run --project demo/Vpn2ProxyDemo -- --help                       # liệt kê subcommand
dotnet run --project demo/Vpn2ProxyDemo -- proxy-server --help          # option của 1 subcommand
```

Với `proxy-server`, proxy được **giữ chạy tới khi nhấn Enter** (hoặc Ctrl+C). Trong lúc đó trỏ browser/curl vào proxy để gửi traffic và quan sát VPN duy trì kết nối:

```powershell
curl -x http://127.0.0.1:18080 https://checkip.amazonaws.com/
```

Hoặc dùng **launch profile** ([Properties/launchSettings.json](Properties/launchSettings.json)) — chọn nhanh trong VS/Rider hoặc CLI (`--launch-profile "<tên>"`). Profile có sẵn: `proxy-server` cho sstp/l2tp/openvpn/softether (đều bind `0.0.0.0:18080`), `http-request` cho sstp/l2tp/openvpn/softether (GET checkip), `dns` cho sstp (resolve example.com qua DNS VPN cấp) và l2tp (github.com qua 8.8.8.8), và `help`. Profile softether kèm sẵn `--watermark watermark.bin` (cần blob THẬT), openvpn trỏ file `.ovpn` mẫu trong `OvpnConfigureFiles/`.

CLI gồm 4 subcommand (`dns` / `proxy-server` / `http-request` / `http-post-upload`); target VPN gói trong `--vpn` (URI hoặc đường dẫn một file config). Option:

**Chung** (mọi subcommand):

| Option | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--vpn` | `sstp://vpn:vpn@public-vpn-226.opengw.net` | target VPN: **URI** `scheme://user:pass@host[:port][?psk=][?hub=][?group=][?addr=&peer=][?addr6=&peer6=][?key=]` **hoặc đường dẫn một file config** (`.ovpn`/`.conf`/`.nebula`/`.tinc`/`.n2n`/`.zerotier`/`.tailscale`). `scheme` = `sstp` (MS-SSTP/TLS, default 443), `l2tp` (L2TP/IPsec IKEv1, NAT-T 500/4500 — bỏ qua port; PSK qua `?psk=`), `ikev2` (IKEv2-native RFC 7296, ESP tunnel — V.1; group PSK qua `?psk=`, EAP-MSCHAPv2 qua `--ikev2-eap`+user:pass), `cisco` (Cisco IPsec/EzVPN Aggressive Mode, ESP tunnel — V.12; group PSK qua `?psk=`, group name qua `?group=`, XAUTH user:pass), `softether`/`ssl` (SoftEther SSL-VPN/TLS, default 443; Hub qua `?hub=`), `openconnect`/`anyconnect` (Cisco AnyConnect/ocserv, default 443 — V.5), `pptp` (PPTP RFC 2637, control TCP/1723 + GRE raw — V.6; cần CAP_NET_RAW), `gre`/`ipip`/`sit` (plain IP-encap raw socket — V.8; connectionless, IP tĩnh `?addr=&peer=` hoặc `?addr6=&peer6=` cho SIT; cần CAP_NET_RAW), `vtun` (legacy daemon TCP — V.11; password ở userinfo, IP tĩnh `?addr=&peer=`), `ssh` (VPN-over-SSH OpenSSH `-w` tun — V.10; IP tĩnh `?addr=&peer=`, auth `?key=<seed ed25519>` hoặc password). Thiếu `user:pass` ⇒ `vpn:vpn`; L2TP/IKEv2/Cisco thiếu `?psk=` ⇒ `vpn`; SoftEther thiếu `?hub=` ⇒ `VPNGATE`; Cisco thiếu `?group=` ⇒ `vpngroup` (PSK/hub VPN Gate) |
| `--watermark` | *(rỗng)* | **(Chỉ SoftEther)** đường dẫn file chứa **watermark blob THẬT** của SoftEther — server thật từ chối placeholder (HTTP 403). Rỗng ⇒ placeholder (chỉ chạy với server giả lập offline). Blob là dữ liệu GPL, không có sẵn trong repo |
| `--ipv6` | `false` | **(Chỉ SSTP/L2TP)** bật IPv6 **trong** tunnel: IPV6CP + lấy địa chỉ **global** qua SLAAC/DHCPv6 trên link PPP (P1.1). Best-effort — server không cấp IPv6 ⇒ vẫn IPv4 (chỉ thêm ~2s chờ). Khi có v6 global, `TcpIpStack` chạy dual-stack + proxy bật `IsSupportIpv6` (CONNECT/UDP nhận đích IPv6) |
| `--outer-ipv6` | `false` | **(Chỉ SSTP/L2TP/IKEv2)** ưu tiên IPv6 cho transport **NGOÀI** — kết nối **TỚI** server qua IPv6 (resolve **AAAA**; SSTP=TLS/TCP6, L2TP/IKEv2=IKE/ESP-in-UDP over IPv6) — P1.2. Đặt `AddressFamilyPreference.IPv6`; **khác `--ipv6`** (IPv6 *trong* tunnel). Fallback IPv4 nếu host không có AAAA. Bật cùng `--native-esp` ⇒ bỏ native-ESP (raw proto-50 chưa hỗ trợ outer-v6). Scheme khác ⇒ bỏ qua |
| `--native-esp` | `false` | **(Chỉ L2TP/IPsec)** chở **ESP gốc trên IP proto-50** (native ESP) cho gateway **no-NAT**, dưới chế độ NAT-T `HonestFirst` (P0.8c) thay vì float UDP/4500 — **cần quyền raw socket/CAP_NET_RAW** (Administrator/root). Scheme khác L2TP ⇒ cờ bị **bỏ qua** (in cảnh báo, không crash) |
| `--l2tp-extra-sessions` | `0` | **(Chỉ L2TP/IPsec)** sau khi tunnel lên, mở thêm **N phiên L2TP** trên **cùng tunnel/IKE-SA** (RFC 2661 multi-session — P1.7); in địa chỉ độc lập từng phiên (mỗi phiên PPP/IPCP riêng). **Best-effort**: đa số remote-access server chỉ cho 1 phiên ⇒ đáp **CDN** ⇒ ném `VpnServerRejectedException`. Scheme khác L2TP ⇒ bỏ qua |
| `--ikev2-eap` | `false` | **(Chỉ IKEv2)** dùng **EAP-MSCHAPv2** (RFC 7296 §2.16) với `user:pass` của URI thay cho PSK AUTH (V.1, validate live). Mặc định tắt ⇒ **PSK-only** (group PSK từ `?psk=`, bỏ qua user:pass). Scheme khác IKEv2 ⇒ bỏ qua |
| `--openconnect-dtls` | `false` | **(Chỉ OpenConnect)** bật đường data **DTLS 1.2 (UDP)** song song khi gateway quảng bá `X-DTLS-*` (V.5) — data đi qua DTLS thay vì CSTP-over-TLS, fallback TLS nếu DTLS không lên. Mặc định tắt ⇒ TLS-only. Scheme khác OpenConnect ⇒ bỏ qua |

**`dns`** thêm `--dns-server` (DNS IPv4 cho probe UDP; rỗng = DNS VPN cấp, fallback `8.8.8.8`) và `--resolve` (`google.com`; tên miền phân giải DNS-over-UDP qua tunnel).

**`proxy-server`** thêm `--proxy-host` (`127.0.0.1`; `0.0.0.0` = nghe mọi interface) và `--proxy-port` (`0` = tự cấp cổng).

**`http-request`** (kế thừa `proxy-server`, có cả `--proxy-host/--proxy-port`) thêm `--url` (`https://checkip.amazonaws.com/`; GET qua proxy, in body rồi thoát).

**`http-post-upload`** (kế thừa `proxy-server`, có cả `--proxy-host/--proxy-port`) thêm `--url` (`http://10.60.0.1:8081/upload`; POST qua proxy) và `--size` (`10485760` = 10 MB; số byte payload upload — đủ lớn để phơi bày stall sender-SWS Q.4 nếu còn). In throughput + byte server xác nhận rồi thoát.

## Lưu ý

- **Cần mạng + server còn sống.** Host VPN Gate thay đổi liên tục; nếu `public-vpn-226` đã tắt, lấy host khác từ https://www.vpngate.net/ và đặt vào phần host của `--vpn` (vd `sstp://vpn:vpn@public-vpn-XXX.opengw.net`). Server phải bật đúng giao thức bạn chọn (cột MS-SSTP / L2TP / OpenVPN / SSL-VPN trên trang VPN Gate). **SoftEther (`softether`/`ssl`)** cần `--watermark <file>` với blob THẬT — không có blob, server thật trả HTTP 403. **OpenVPN**: tải file `.ovpn` từ VPN Gate (hoặc dùng mẫu trong `OvpnConfigureFiles/`) rồi trỏ `--vpn <đường-dẫn>.ovpn`; tun-UDP đã chạy live nhưng gói lớn (https) có thể chưa qua (MTU). Các giao thức **PPTP / IP-encap (`gre`/`ipip`/`sit`) / SSH** cần raw socket hoặc `PermitTunnel` server-side ⇒ chạy trong lab có CAP_NET_RAW/root; **mesh VPN** (Nebula/tinc/n2n/ZeroTier/Tailscale) cấu hình từ file ini riêng (`.nebula`/`.tinc`/`.n2n`/`.zerotier`/`.tailscale`) trỏ tới khóa/peer/overlay — cũng dựng & validate trong lab. **Cisco IPsec** (Aggressive Mode + group PSK) là Phase 1 yếu, chỉ interop gateway legacy.
- **Không cần quyền admin** — toàn bộ stack là userspace (không TUN/TAP, không routing table).
- **Panel "VPN này hỗ trợ gì" (tự in sau mọi connect, trước hành động):** liệt kê IPv4/IPv6/UDP/Listen TCP/Listen UDP/LAN ảo/MAC (L2)
  kèm thông tin kết nối (IP ảo + public/private, DNS, MTU, transport, bảo mật, auth). **Probe thật**: UDP (DNS-over-UDP),
  LAN ảo (ICMP ping gateway nội bộ — phát hiện được thì panel thêm dòng **Gateway nội bộ**). **Suy luận**: IPv6 = ✓ khi
  tunnel cấp địa chỉ **global** (SSTP/L2TP với `--ipv6` + server cấp prefix qua SLAAC/DHCPv6; SoftEther/OpenVPN/WireGuard theo
  cấu hình driver — P1.1; mặc định/chỉ link-local/không cấp ⇒ ✗), Listen TCP/UDP =
  ✗ (sau NAT + stack chưa listen). Mỗi mục ✗ ghi rõ lý do; chi tiết phần thư viện chưa hỗ trợ
  + roadmap ở [`.docs/12-demo-vpn2proxy.md`](../../.docs/12-demo-vpn2proxy.md) §6.
  Panel tự bao timeout + nuốt lỗi nên không làm hỏng hành động chính (cộng ~5–10s probe vào mọi lệnh).
- **Subcommand `dns` — kiểm tra UDP + DNS qua tunnel:** sau khi tunnel lên, gửi một truy vấn DNS (bản ghi A) qua **UDP xuyên tunnel** (`UdpDnsProbe` → `VpnUdpClient`, không dùng host DNS) tới `--dns-server` (mặc định: DNS do VPN cấp, fallback `8.8.8.8`). Nhận được phản hồi ⇒ in `VPN HỖ TRỢ UDP` + IPv4 của `--resolve`; timeout sau 3 lần thử ⇒ VPN có thể không định tuyến UDP (hoặc DNS server không reachable — thử `--dns-server` khác). Đây là kênh UDP đi thẳng IP stack.
- **Subcommand `http-request`** — GET nhanh `--url` qua proxy (vd checkip ⇒ thấy IP công cộng của VPN server), in body rồi thoát; tiện kiểm đường đi HTTP qua VPN mà không phải giữ proxy thủ công.
- **Subcommand `http-post-upload`** — POST một payload `--size` byte (mặc định 10 MB) tới `--url` qua proxy, in throughput (MB/s) + byte server xác nhận rồi thoát. Dùng để re-validate fix Q.4 (sender-side Silly-Window-Syndrome avoidance trong `TcpConnection`): upload HTTP lớn qua tunnel phải hoàn tất với segment đầy-MSS, không rơi vào "1 byte/segment". Đường gửi đi qua proxy → `VpnProxySource` → userspace `TcpConnection` (nơi nằm fix), nên đo được hành vi sender-SWS thật end-to-end.
- **SOCKS5 UDP-ASSOCIATE:** proxy hỗ trợ UDP cho client SOCKS5 (`IsSupportUdp=true`). Client gửi datagram qua proxy, `VpnUdpAssociateSource` relay ra ngoài bằng UDP của tunnel rồi trả về (vd `curl --socks5 127.0.0.1:port --resolve ... ` hoặc một DNS client trỏ qua SOCKS5 UDP). **BIND không hỗ trợ** (stack active-open-only + địa chỉ tunnel private không routable từ internet).
- **IPv6 trong tunnel (P1.1(4), bật `--ipv6` cho SSTP/L2TP):** khi server cấp địa chỉ IPv6 **global** (SLAAC/DHCPv6 trên link PPP), `VpnTunnel` dựng `TcpIpStack` dual-stack (helper `GlobalV6` bỏ link-local `fe80::/10`) và proxy bật `IsSupportIpv6` ⇒ CONNECT/UDP nhận đích IPv6 (literal + AAAA fallback). Best-effort: server chỉ cấp IPv4/link-local ⇒ tự giữ IPv4-only (`IsSupportIpv6=false`). SoftEther/OpenVPN/WireGuard bật IPv6 theo cấu hình driver riêng (không qua `--ipv6`).
- **Giữ kết nối (`proxy-server`):** sau khi proxy lên, demo dừng tại bước `ProxyServer` và chờ Enter — tunnel vẫn chạy keepalive + auto-reconnect (xem driver), nên đây là chỗ test "duy trì kết nối": cứ gửi traffic qua proxy liên tục/định kỳ rồi quan sát log reconnect.
- `--proxy-host 0.0.0.0` mở proxy cho cả máy khác trong LAN — chỉ dùng trên mạng tin cậy (proxy không có auth).
- Demo `ProjectReference` thẳng tới **17 driver** (`Drivers.Sstp`/`Drivers.L2tpIpsec`/`Drivers.Ikev2`/`Drivers.CiscoIpsec`/`Drivers.SoftEther`/`Drivers.OpenVpn`/`Drivers.WireGuard`/`Drivers.OpenConnect`/`Drivers.Pptp`/`Drivers.IpEncap`/`Drivers.Nebula`/`Drivers.Tinc`/`Drivers.N2n`/`Drivers.Vtun`/`Drivers.Ssh`/`Drivers.ZeroTier`/`Drivers.Tailscale`) + [`src/TqkLibrary.VpnClient.Sockets`](../../src/TqkLibrary.VpnClient.Sockets) (`VpnTcpClient`/`VpnUdpClient`/`TcpIpStack`) + [`src/TqkLibrary.VpnClient.Transport.RawIp`](../../src/TqkLibrary.VpnClient.Transport.RawIp) (`RawIpTransportFactory` — ESP/GRE/IPIP/SIT trên raw socket cho `--native-esp`/PPTP/IP-encap). Các project parse config (`OpenVpn`, `WireGuard`, `Nebula`, `Tinc`, `ZeroTier`...) đến **transitive** qua driver tương ứng và được dùng trực tiếp trong các hàm `VpnTunnel.Connect*Async`. NuGet: `System.CommandLine` 2.0.7 + `TqkLibrary.Proxy` 1.0.35 + `Microsoft.Extensions.Logging` 10.0.8 / `.Console` 10.0.7. **Mỗi giao thức** dựng một `ILoggerFactory` console riêng cho driver (trace handshake/state/reconnect khi chạy live).
- **Log:** `proxy-server`/`http-request`/`http-post-upload` tạo một `ILoggerFactory` console (mức Information; riêng category `Vpn2ProxyDemo` ở Debug) rồi truyền cho cả `ProxyServer` (log của thư viện proxy) và `VpnProxySource` (log connect/UDP của adapter); ngoài ra mỗi hàm `Connect*Async` của `VpnTunnel` còn dựng một `ILoggerFactory` console riêng (mức Debug) cho driver. `dns` không bật log proxy.
