# 12 — Demo `Vpn2ProxyDemo` (as-built)

> Tài liệu **bám sát code thực tế** cho demo tích hợp proxy (tách riêng khỏi [`10`](10-codebase-architecture-and-flow.md) §9
> để file 10 gọn). Hướng dẫn chạy chi tiết + bảng option đầy đủ ở [`demo/Vpn2ProxyDemo/README-vi.md`](../demo/Vpn2ProxyDemo/README-vi.md);
> file này tập trung kiến trúc/luồng + link `file:line`.

## 1. Mục đích & vị trí

Demo console chứng minh: kết nối VPN (qua một trong **17 giao thức** — xem §3) → biến tunnel thành `IProxySource` của
**`TqkLibrary.Proxy` 1.0.60** → dựng HTTP/SOCKS proxy local định tuyến mọi kết nối **trong** tunnel, rồi **giữ proxy +
tunnel sống tới khi nhấn Enter** (Ctrl+C cũng dừng) để test VPN duy trì kết nối (keepalive/auto-reconnect) trong lúc
client trỏ traffic vào proxy.

Đây là **project demo** ([`demo/Vpn2ProxyDemo`](../demo/Vpn2ProxyDemo)), **không** phải project `src/`. Adapter
`IProxySource`/`IConnectSource`/`IUdpAssociateSource` viết **inline trong demo** (chưa tách thành `TqkLibrary.VpnClient.Proxy` — xem roadmap
[`11`](11-todo-roadmap.md) mục "Adapter proxy"). Demo `ProjectReference` thẳng tới **toàn bộ 17 driver** (`Drivers.Sstp`, `Drivers.L2tpIpsec`,
`Drivers.Ikev2`, `Drivers.CiscoIpsec`, `Drivers.SoftEther`, `Drivers.OpenVpn`, `Drivers.WireGuard`, `Drivers.OpenConnect`, `Drivers.Pptp`,
`Drivers.IpEncap`, `Drivers.Nebula`, `Drivers.Tinc`, `Drivers.N2n`, `Drivers.ZeroTier`, `Drivers.Vtun`, `Drivers.Tailscale`, `Drivers.Ssh`)
+ `Sockets` (`VpnTcpClient`/`VpnUdpClient`/`TcpIpStack`) + `Transport.RawIp` (`RawIpTransportFactory` — ESP/GRE/IPIP/SIT proto raw socket cho
L2TP `--native-esp`/PPTP/IP-encap). Các project parse config (`OpenVpn`, `WireGuard`, `Nebula`, `Tinc`, `ZeroTier`...) đến transitive qua driver tương ứng,
dùng trực tiếp trong các hàm `VpnTunnel.Connect*Async`. NuGet `System.CommandLine` 2.0.7 + `TqkLibrary.Proxy` 1.0.60 +
`Microsoft.Extensions.Logging` 10.0.x / `.Console` 10.0.x (console log cho `ProxyServer` + `VpnProxySource` + logger driver).

## 2. Luồng

```
[chung]         <giao thức từ --vpn>                     (kết nối VPN, nhận IP ảo + DNS + PacketChannel)
   -> new TcpIpStack(channel, ipv4, ipv6global?)         (userspace TCP/IP trong tunnel — dual-stack khi tunnel có IPv6 global)
   -> VpnCapabilityProbe.RunAsync(tunnel).Print()        (panel "VPN hỗ trợ gì": UDP/LAN ảo PROBE thật + IPv6/listen-external SUY LUẬN — in NGAY sau connect, trước hành động)

[dns]           -> UdpDnsProbe.ResolveAsync(stack, dns, domain)  (DNS-over-UDP qua tunnel: VPN có hỗ trợ UDP? + IP của domain)

[proxy-server]  -> new VpnProxySource(stack, loggerFactory, supportIpv6) -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()
   -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
   => client (browser/curl) qua proxy: mọi traffic ra bằng IP công cộng của VPN server

[http-request]  -> (kế thừa proxy-server) GET --url qua proxy -> in response body -> THOÁT luôn

[http-post-upload] -> (kế thừa proxy-server) POST --size byte tới --url qua proxy -> in throughput -> THOÁT
   (re-validate Q.4 sender-SWS: upload lớn qua tunnel phải đầy-MSS, không "1 byte/segment")
```

**Panel "VPN này hỗ trợ gì"** (in tự động sau MỌI lần connect, trước hành động — [`CommandModuleBase.PrintCapabilitiesAsync` @ :217](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L217)
gọi [`VpnCapabilityProbe.RunAsync` @ :26](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L26)): gộp **3 nguồn** — (1) **probe thật** qua tunnel: UDP =
DNS-over-UDP (tái dùng [`UdpDnsProbe.ResolveAsync`](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L29) — [`ProbeUdpAsync` @ :87](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L87)), LAN ảo = ICMP ping gateway nội bộ
([`TcpIpStack.PingAsync`](../src/TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L107) — [`ProbeVirtualLanAsync` @ :110](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L110); **phát hiện LAN ảo thì panel thêm dòng "Gateway nội bộ"** ở phần Info); (2) **năng lực
driver tĩnh** đọc thẳng từ `Capabilities` của driver tương ứng ([`SstpDriver`](../src/TqkLibrary.VpnClient.Drivers.Sstp/SstpDriver.cs#L38)/[`L2tpIpsecDriver`](../src/TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L46)/[`SoftEtherDriver`](../src/TqkLibrary.VpnClient.Drivers.SoftEther/SoftEtherDriver.cs#L74)/[`OpenVpnDriver`](../src/TqkLibrary.VpnClient.Drivers.OpenVpn/OpenVpnDriver.cs#L77)/... — mỗi giao thức một driver)
(transport/bảo mật/auth/cấp địa chỉ); (3) **heuristic** từ IP cấp: phân loại public/private (RFC1918/CGNAT) ⇒ suy listen-external,
IPv6 = Yes khi tunnel cấp địa chỉ **global** (`AssignedAddressV6`, P1.1), No nếu chỉ link-local/không cấp. Panel tự bao timeout (mỗi sub-probe ngắn + chặn-trên 20s) và **nuốt mọi lỗi** (trừ hủy của caller) nên
không bao giờ làm hỏng hành động chính. Các khả năng thư viện chưa hỗ trợ ⇒ xem §6.

Bốn subcommand riêng (`dns` / `proxy-server` / `http-request` / `http-post-upload`). Subcommand `dns` gọi [`ProbeUdpDnsAsync` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L44):
gửi một truy vấn DNS (bản ghi A) qua **UDP xuyên tunnel** bằng [`UdpDnsProbe.ResolveAsync` @ :29](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L29)
(`VpnUdpClient` → `TcpIpStack.BindUdp`). Nhận được phản hồi ⇒ **VPN có định tuyến UDP**, đồng thời in IPv4 phân giải
được. Đây là kênh data plane **độc lập** với proxy TCP (riêng với SOCKS5 UDP-ASSOCIATE — proxy khai `IUdpCapable`, `IsSupportUdp=true`).
`http-request` kế thừa `proxy-server`: dựng cùng proxy rồi GET `--url` **qua proxy đó** (in body, thoát) thay vì giữ tới khi Enter.
`http-post-upload` cũng kế thừa `proxy-server`: POST một payload `--size` byte tới `--url` **qua proxy đó** rồi in throughput + byte server xác nhận
(re-validate Q.4 sender-SWS — upload lớn qua tunnel phải hoàn tất với segment đầy-MSS, không "1 byte/segment"; đường đi qua `VpnProxySource` → `TcpConnection`).

Mỗi kết nối TCP qua proxy: `ProxyServer` gọi [`VpnProxySource.GetConnectSourceAsync` @ :51](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L51)
→ [`VpnConnectSource.ConnectAsync` @ :37](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L37) resolve host ([`ResolveAsync` @ :78](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L78): IPv4/IPv6 literal as-is, hoặc DNS ưu tiên A rồi fallback AAAA — dual-stack P1.1) rồi
`VpnTcpClient.ConnectAsync` dial trong tunnel → [`GetStreamAsync` @ :68](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L68) trả
stream duplex cho proxy bơm traffic. **SOCKS5 UDP-ASSOCIATE** dùng [`VpnUdpAssociateSource` @ :21](../demo/Vpn2ProxyDemo/VpnProxySource.VpnUdpAssociateSource.cs#L21)
(egress UDP qua `UdpConnection`, đích IPv4 **và** IPv6 dual-stack — P1.1). **BIND** không có: source không khai `IBindCapable` nên server từ chối — stack active-open-only + địa chỉ tunnel private
không routable từ internet ([VpnProxySource.cs:24](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L24)). IPv6 chỉ bật khi tunnel cấp địa chỉ global (stack dual-stack; `IsSupportIpv6` theo cờ ctor `supportIpv6` chỉ để hiển thị — từ `TqkLibrary.Proxy` 1.0.60 thư viện không hỏi source cờ này).

## 3. Thành phần

| File | Vai trò |
|---|---|
| [Program.cs:18](../demo/Vpn2ProxyDemo/Program.cs#L18) | `RootCommand { dns, proxy-server, http-request, http-post-upload }` → `Parse(args).InvokeAsync()` (System.CommandLine 2.0.7) |
| [VpnProxySource.cs:24](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L24) | `IProxySource` + `IUdpCapable` (partial) bọc `TcpIpStack`; `IsSupportUdp=true`, không khai `IBindCapable` (không BIND), `IsSupportIpv6` (chỉ để hiển thị) theo cờ ctor `supportIpv6` (bật khi tunnel có IPv6 global — P1.1); `DisposeAsync` rỗng (stack thuộc `VpnTunnel`); ctor nhận **`ILoggerFactory?`** → sinh `ILogger` cho mỗi `IConnectSource`/`IUdpAssociateSource` |
| [VpnProxySource.VpnConnectSource.cs:19](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L19) | `IConnectSource` (nested): mở `VpnTcpClient` qua tunnel, trả `Stream`; [`ResolveAsync` @ :78](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L78) hỗ trợ IPv4/IPv6 literal + DNS A→AAAA fallback (dual-stack); **log** resolve/connect/lỗi/đóng qua `ILogger?` |
| [VpnProxySource.VpnUdpAssociateSource.cs:21](../demo/Vpn2ProxyDemo/VpnProxySource.VpnUdpAssociateSource.cs#L21) | `IUdpAssociateSource` (nested): egress UDP qua `UdpConnection` (`SendTo`/`ReceiveAsync` đa đích, IPv4 **+** IPv6 dual-stack), `UnbindUdp` khi `Dispose`; **log** associate/send/receive/unbind qua `ILogger?` |
| [UdpDnsProbe.cs:18](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L18) | Build/parse gói DNS (RFC 1035) trên `VpnUdpClient` → gửi truy vấn A qua UDP xuyên tunnel (kiểm tra UDP + phân giải domain), retry + timeout |
| [UdpDnsProbeResult.cs:11](../demo/Vpn2ProxyDemo/UdpDnsProbeResult.cs#L11) | Kết quả probe: `UdpSupported` + danh sách IPv4 + số lần thử/thời gian/lỗi |
| [VpnTunnel.cs:58](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L58) | Bọc `TcpIpStack` + vòng đời tunnel (`IAsyncDisposable`); lộ `AssignedAddress`/`AssignedAddressV6`/`AssignedDns`/`Mtu`/`Capabilities`/`ProtocolName` cho panel khả năng (ctor [@ :62](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L62)). **17 hàm static connect** (thêm giao thức = thêm 1 hàm + 1 nhánh dispatch) — xem bảng dưới. Helper: [`GlobalV6` @ :1336](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L1336) (lọc bỏ link-local `fe80::/10` ⇒ chỉ bật IPv6 egress khi có địa chỉ global), [`CreateDriverLoggerFactory` @ :1340](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L1340) (console logger Debug cho driver), [`ResolveConfigPath` @ :1346](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L1346) + các parser file config (`.tailscale`/`.zerotier`/`.n2n`/`.tinc`/`.nebula`/`.conf` wg-quick) |
| [CapabilityStatus.cs:7](../demo/Vpn2ProxyDemo/CapabilityStatus.cs#L7) | Enum trạng thái 1 khả năng: `Yes`[✓]/`No`[✗]/`Likely`·`Unlikely`[~]/`Unknown`[?] |
| [VpnCapability.cs:8](../demo/Vpn2ProxyDemo/VpnCapability.cs#L8) | Một dòng khả năng: `Name` + `Status` (`CapabilityStatus`) + `Detail` (lý do/số đo) |
| [VpnCapabilityReport.cs:10](../demo/Vpn2ProxyDemo/VpnCapabilityReport.cs#L10) | Kết quả panel: `Info` (IP/DNS/MTU/transport/bảo mật/auth) + `Capabilities`; [`Print` @ :31](../demo/Vpn2ProxyDemo/VpnCapabilityReport.cs#L31) in ra Console (✓/✗/~/?) |
| [VpnCapabilityProbe.cs:23](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L23) | **Static probe** (mirror `UdpDnsProbe`): [`RunAsync` @ :26](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L26) gộp probe thật (UDP qua [`ProbeUdpAsync` @ :87](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L87); LAN ảo qua [`ProbeVirtualLanAsync` @ :110](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L110) → `PingAsync`, trả kèm gateway phát hiện) + năng lực driver + heuristic NAT ([`ClassifyV4` @ :168](../demo/Vpn2ProxyDemo/VpnCapabilityProbe.cs#L168)) / IPv6 → `VpnCapabilityReport`; mỗi sub-probe tự timeout, không ném khi hết giờ |
| [CommandModules/Interfaces/ICommandModule.cs:6](../demo/Vpn2ProxyDemo/CommandModules/Interfaces/ICommandModule.cs#L6) | Hợp đồng command: `Command Command { get; }` |
| [CommandModules/Enums/VpnProtocol.cs:4](../demo/Vpn2ProxyDemo/CommandModules/Enums/VpnProtocol.cs#L4) | Enum giao thức (17 giá trị: `Sstp`/`L2tp`/`Ikev2`/`CiscoIpsec`/`SoftEther`/`OpenVpn`/`WireGuard`/`OpenConnect`/`Pptp`/`IpEncap`/`Nebula`/`Tinc`/`N2n`/`ZeroTier`/`Vtun`/`Tailscale`/`Ssh`) — map từ scheme của URI `--vpn` (hoặc đuôi file `.ovpn`/`.conf`/`.nebula`/`.tinc`/`.n2n`/`.zerotier`/`.tailscale`) |
| [CommandModules/Models/VpnTarget.cs:20](../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L20) | Tham số kết nối parse từ `--vpn`: **URI** `scheme://user:pass@host[:port][?psk=][?hub=][?group=][?addr=&peer=][?key=]` **hoặc đường dẫn một file config** (`.ovpn`/`.conf`/`.nebula`/`.tinc`/`.n2n`/`.zerotier`/`.tailscale`). [`TryParse` @ :79](../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L79): file → protocol + `ConfigPath`; còn lại `System.Uri` → `Protocol/Host/Port/User/Pass/PreSharedKey/HubName/GroupName/IpEncapKind/TunnelAddress/TunnelPeerAddress` (scheme `ssl`=alias SoftEther, `anyconnect`=alias OpenConnect, `gre`/`ipip`/`sit`→IpEncap; thiếu user:pass ⇒ `vpn:vpn`; SSTP/SoftEther/OpenConnect thiếu port ⇒ 443; L2TP/IKEv2/Cisco thiếu `?psk=` ⇒ `vpn`; SoftEther thiếu `?hub=` ⇒ `VPNGATE`; Cisco thiếu `?group=` ⇒ `vpngroup`) + thông báo lỗi |
| [CommandModules/CommandModuleBase.cs:18](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L18) | **Base abstract** cho mọi subcommand action: option chung `--vpn` + `--watermark` + `--ipv6` + `--outer-ipv6` + `--native-esp` + `--l2tp-extra-sessions` + `--ikev2-eap` + `--openconnect-dtls` (đăng ký ở ctor [@ :32](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L32)); cờ chỉ-một-giao-thức bật với scheme khác ⇒ cảnh báo + bỏ qua (không crash); parse target, in header (Protocol), connect VPN (giữ vòng đời), **in panel khả năng** [`PrintCapabilitiesAsync` @ :217](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L217) (sau connect, trước hành động) rồi gọi [`RunAsync` @ :210](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L210) (abstract); [`ConnectAsync` @ :243](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L243) dispatch theo `VpnTarget.Protocol` về 17 hàm static của `VpnTunnel`; [`ValidateOptions` @ :240](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L240) (virtual) cho subclass fail-fast option riêng |
| [CommandModules/ProbeUdpDnsCommandModule.cs:11](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L11) | Subcommand `dns`: thêm `--dns-server/--resolve`; [`RunAsync` → `ProbeUdpDnsAsync` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L44) probe UDP + phân giải domain qua tunnel (không dựng proxy) |
| [CommandModules/ProxyServerCommandModule.cs:18](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L18) | Subcommand `proxy-server` (NOT sealed): thêm `--proxy-host/--proxy-port` + [`ValidateOptions` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L44) (fail-fast bind); [`RunAsync` @ :55](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L55) dựng `ILoggerFactory` console ([`CreateLoggerFactory` @ :97](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L97)) + `VpnProxySource` (`supportIpv6: tunnel.AssignedAddressV6 is not null`) + `ProxyServer` (cùng chia sẻ factory) rồi gọi [`OnProxyReadyAsync` @ :88](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L88) (virtual, mặc định: giữ tới khi nhấn Enter) |
| [CommandModules/HttpRequestProxyServerCommandModule.cs:12](../demo/Vpn2ProxyDemo/CommandModules/HttpRequestProxyServerCommandModule.cs#L12) | Subcommand `http-request` (kế thừa `ProxyServerCommandModule`): thêm `--url`, override [`OnProxyReadyAsync` @ :27](../demo/Vpn2ProxyDemo/CommandModules/HttpRequestProxyServerCommandModule.cs#L27) — GET `--url` qua proxy (WebProxy), in body rồi **thoát luôn** (không chờ Enter) |
| [CommandModules/HttpPostUploadProxyServerCommandModule.cs:19](../demo/Vpn2ProxyDemo/CommandModules/HttpPostUploadProxyServerCommandModule.cs#L19) | Subcommand `http-post-upload` (kế thừa `ProxyServerCommandModule`): thêm `--url`/`--size`, override [`OnProxyReadyAsync` @ :50](../demo/Vpn2ProxyDemo/CommandModules/HttpPostUploadProxyServerCommandModule.cs#L50) — POST `--size` byte tới `--url` qua proxy (WebProxy), in throughput + byte server xác nhận rồi **thoát luôn**. Re-validate Q.4 (sender-SWS upload lớn qua `TcpConnection`) |

**17 hàm static connect của `VpnTunnel`** (dispatch ở [`CommandModuleBase.ConnectAsync` @ :243](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L243)):

| Giao thức (scheme/đuôi file) | Hàm | Ghi chú as-built |
|---|---|---|
| SSTP (`sstp`) | [`ConnectSstpAsync` @ :105](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L105) | MS-SSTP/TLS, `host`+`port`; nhận `enableIpv6` (P1.1) + `preferOuterIpv6` (P1.2) |
| L2TP/IPsec (`l2tp`) | [`ConnectL2tpAsync` @ :137](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L137) | IKEv1, NAT-T (không port); `preSharedKey`; `enableIpv6`/`useNativeEsp` (P0.8c → `RawIpTransportFactory` + NAT-T `HonestFirst`)/`extraSessions` (P1.7 multi-session)/`preferOuterIpv6`; console logger driver |
| IKEv2-native (`ikev2`) | [`ConnectIkev2Async` @ :202](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L202) | RFC 7296, ESP tunnel (KHÔNG PPP); group PSK, hoặc EAP-MSCHAPv2 khi truyền `eapUser/eapPass` (V.1); `preferOuterIpv6`; `ipComp` (RFC 3173); `ppk` (Post-quantum Preshared Key RFC 8784) |
| Cisco IPsec/EzVPN (`cisco`) | [`ConnectCiscoIpsecAsync` @ :234](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L234) | IKEv1 Aggressive Mode group PSK + XAUTH + Mode-Config, ESP tunnel (V.12); cảnh báo Phase 1 yếu |
| SoftEther (`softether`/`ssl`) | [`ConnectSoftEtherAsync` @ :277](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L277) | SSL-VPN qua `SoftEtherDriver` → `Sessions[0]`; `hubName` + `watermarkPath` (rỗng ⇒ placeholder + CẢNH BÁO 403) |
| OpenVPN (`.ovpn`) | [`ConnectOpenVpnAsync` @ :331](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L331) | parse `.ovpn` → `OpenVpnDriver` → `Sessions[0]`, transport UDP/TCP theo `proto` |
| WireGuard (`.conf`) | [`ConnectWireGuardAsync` @ :383](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L383) | Noise_IKpsk2/UDP từ file wg-quick (V.3) |
| OpenConnect (`openconnect`/`anyconnect`) | [`ConnectOpenConnectAsync` @ :424](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L424) | HTTPS config-auth → CSTP-over-TLS (+ DTLS với `enableDtls`/`--openconnect-dtls`), bare IP (V.5) |
| PPTP (`pptp`) | [`ConnectPptpAsync` @ :473](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L473) | control TCP/1723 + GRE proto-47 raw socket, PPP MS-CHAPv2/MPPE — cần CAP_NET_RAW (V.6) |
| IP-encap (`gre`/`ipip`/`sit`) | [`ConnectIpEncapAsync` @ :511](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L511) | plain GRE-47/IPIP-4/SIT-41 raw socket, connectionless, IP tĩnh `?addr=&peer=` — cần CAP_NET_RAW (V.8) |
| Nebula (`.nebula`) | [`ConnectNebulaAsync` @ :569](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L569) | Noise_IX/AES-256-GCM/UDP, ca/cert/key PEM + endpoint + overlay từ file ini (V.7.1) |
| Tailscale (`.tailscale`) | [`ConnectTailscaleAsync` @ :607](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L607) | control ts2021 (Noise IK + Headscale preauth + netmap) → WireGuard data plane tái dùng (V.7.5) |
| SSH (`ssh`) | [`ConnectSshAsync` @ :836](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L836) | VPN-over-SSH (OpenSSH `-w` tun) curve25519/ed25519/chacha20-poly1305, IP tĩnh `?addr=&peer=`, `?key=` seed ed25519 32B hoặc password (V.10) |
| ZeroTier (`.zerotier`) | [`ConnectZeroTierAsync` @ :900](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L900) | VL1 HELLO/OK (Curve25519/Salsa20-12/Poly1305) + NETWORK_CONFIG + VL2 EXT_FRAME L2-over-UDP (V.7.3) |
| n2n (`.n2n`) | [`ConnectN2nAsync` @ :744](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L744) | v3 L2 mesh, REGISTER_SUPER + PACKET (NULL/AES, tùy chọn header-encryption `-H`) qua supernode (V.7.4) |
| tinc (`.tinc`) | [`ConnectTincAsync` @ :707](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L707) | 1.1 SPTPS, TCP meta + UDP data (V.7.2) |
| vtun (`vtun`) | [`ConnectVtunAsync` @ :783](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L783) | legacy daemon TCP challenge-response (MD5+Blowfish) → bare IP, IP tĩnh `?addr=&peer=` (V.11) |

Luồng điều phối chung nằm ở base [`CommandModuleBase.InvokeAsync` @ :115](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L115)
(parse `--vpn` bằng `VpnTarget.TryParse` → `ValidateOptions` (subclass) → in header → đọc + gate các cờ chỉ-một-giao-thức →
`ConnectAsync` dispatch theo giao thức → `PrintCapabilitiesAsync` → gọi `RunAsync` của subclass). `dns` chạy [`ProbeUdpDnsAsync` @ :44](../demo/Vpn2ProxyDemo/CommandModules/ProbeUdpDnsCommandModule.cs#L44);
`proxy-server`/`http-request`/`http-post-upload` dùng chung [`RunAsync` @ :55](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L55) (dựng proxy + `ILoggerFactory`) rồi phân nhánh ở
[`OnProxyReadyAsync`](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L88): giữ tới khi nhấn Enter (`proxy-server`),
GET `--url` qua proxy rồi thoát (`http-request`), **hoặc** POST `--size` byte tới `--url` qua proxy rồi in throughput và thoát (`http-post-upload` — re-validate Q.4 sender-SWS).

## 4. Tham số CLI (4 subcommand `dns` / `proxy-server` / `http-request` / `http-post-upload`)

**Option chung** (mọi subcommand — từ `CommandModuleBase`):

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--vpn` | `sstp://vpn:vpn@public-vpn-226.opengw.net` | target VPN: **URI** `scheme://user:pass@host[:port][?psk=][?hub=][?group=][?addr=&peer=][?key=]` **hoặc đường dẫn một file config** (`.ovpn`/`.conf`/`.nebula`/`.tinc`/`.n2n`/`.zerotier`/`.tailscale`). `scheme`: `sstp` (MS-SSTP/TLS 443), `l2tp` (L2TP/IPsec IKEv1, NAT-T 500/4500, PSK qua `?psk=`), `ikev2` (IKEv2-native RFC 7296, PSK qua `?psk=`, EAP qua `--ikev2-eap`+user:pass), `cisco` (Cisco IPsec/EzVPN Aggressive Mode, `?psk=`+`?group=`+XAUTH user:pass — V.12), `softether`/`ssl` (SoftEther SSL-VPN/TLS 443, Hub qua `?hub=`), `openconnect`/`anyconnect` (Cisco AnyConnect/ocserv — V.5), `pptp` (PPTP RFC 2637, raw GRE — V.6), `gre`/`ipip`/`sit` (plain IP-encap, IP tĩnh `?addr=&peer=` hoặc `?addr6=&peer6=` cho SIT — V.8), `vtun` (V.11), `ssh` (VPN-over-SSH, IP tĩnh + `?key=`/password — V.10). Thiếu `user:pass` ⇒ `vpn:vpn`; L2TP/IKEv2/Cisco thiếu `?psk=` ⇒ `vpn`; SoftEther thiếu `?hub=` ⇒ `VPNGATE`; Cisco thiếu `?group=` ⇒ `vpngroup` |
| `--watermark` | *(rỗng)* | **(Chỉ SoftEther)** đường dẫn file chứa **watermark blob THẬT** của SoftEther — server thật từ chối blob placeholder (HTTP 403). Rỗng ⇒ placeholder (chỉ chạy với server giả lập offline). Blob là dữ liệu GPL, KHÔNG có sẵn trong repo |
| `--ipv6` | `false` | **(Chỉ SSTP/L2TP)** bật IPv6 **trong** tunnel: IPV6CP + lấy địa chỉ **global** qua SLAAC/DHCPv6 trên link PPP (P1.1). Best-effort — server không cấp ⇒ vẫn IPv4 (chỉ thêm ~2s chờ). Khi có v6 global, `TcpIpStack` chạy dual-stack + proxy bật `IsSupportIpv6` (CONNECT/UDP nhận đích IPv6). Scheme khác ⇒ bỏ qua |
| `--outer-ipv6` | `false` | **(Chỉ SSTP/L2TP/IKEv2)** ưu tiên IPv6 cho transport **NGOÀI** — kết nối **TỚI** server qua IPv6 (resolve **AAAA**) — P1.2. Đặt `AddressFamilyPreference.IPv6`; **khác `--ipv6`** (IPv6 *trong* tunnel). Fallback IPv4 nếu host không có AAAA. Bật cùng `--native-esp` ⇒ bỏ native-ESP (raw proto-50 chưa hỗ trợ outer-v6). Scheme khác ⇒ bỏ qua |
| `--native-esp` | `false` | **(Chỉ L2TP/IPsec)** chở **ESP gốc trên IP proto-50** (native ESP) cho gateway **no-NAT**, dưới chế độ NAT-T `HonestFirst` (P0.8c) thay vì float UDP/4500 — **cần quyền raw socket/CAP_NET_RAW** (Administrator/root). Cấp `RawIpTransportFactory` cho `L2tpIpsecConnection`. Scheme khác L2TP ⇒ cờ **bỏ qua** (cảnh báo, không crash) |
| `--l2tp-extra-sessions` | `0` | **(Chỉ L2TP/IPsec)** sau khi tunnel lên, mở thêm **N phiên L2TP** trên **cùng tunnel/IKE-SA** (RFC 2661 multi-session — P1.7); in địa chỉ độc lập từng phiên (PPP/IPCP riêng). **Best-effort**: đa số remote-access server chỉ cho 1 phiên ⇒ đáp **CDN** (ném). Scheme khác L2TP ⇒ bỏ qua |
| `--ikev2-eap` | `false` | **(Chỉ IKEv2)** dùng **EAP-MSCHAPv2** (RFC 7296 §2.16) với `user:pass` của URI thay cho PSK AUTH (V.1). Mặc định tắt ⇒ **PSK-only** (group PSK từ `?psk=`, bỏ qua user:pass). Scheme khác IKEv2 ⇒ bỏ qua |
| `--ppk` | *(rỗng)* | **(Chỉ IKEv2)** bí mật **Post-quantum Preshared Key** (RFC 8784) trộn vào SK_d/SK_pi/SK_pr — client chào **USE_PPK** (IKE_SA_INIT) rồi **PPK_IDENTITY** (IKE_AUTH). Chuỗi **UTF-8**, hoặc **`0x`+hex** ⇒ byte thô. Chỉ đường **PSK** (`?psk=`); **KHÔNG** dùng chung `--ikev2-eap` (bật cả hai ⇒ ưu tiên PSK+PPK, bỏ EAP). Scheme khác IKEv2 ⇒ bỏ qua. Rỗng ⇒ không dùng PPK |
| `--ppk-id` | `ppk1` | **(Chỉ IKEv2, kèm `--ppk`)** định danh PPK (**PPK_ID**, RFC 8784 §4.1) gửi trong PPK_IDENTITY (wire = octet type `1` ‖ id). Chuỗi UTF-8 hoặc `0x`+hex. Phải **khớp** id cấu hình trên gateway (strongSwan `swanctl` `ppk`) |
| `--ppk-mandatory` | `false` | **(Chỉ IKEv2, kèm `--ppk`)** **bắt buộc** dùng PPK: gateway không chào USE_PPK ⇒ **hủy** kết nối. Mặc định tắt ⇒ **tùy chọn** (server từ chối ⇒ fallback PSK thường kèm **NO_PPK_AUTH**) |
| `--openconnect-dtls` | `false` | **(Chỉ OpenConnect)** bật đường data **DTLS 1.2 (UDP)** song song khi gateway quảng bá `X-DTLS-*` (V.5) — data đi qua DTLS thay vì CSTP-over-TLS, fallback TLS nếu DTLS không lên. Mặc định tắt ⇒ TLS-only. Scheme khác ⇒ bỏ qua |

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

**`http-post-upload`** (kế thừa `proxy-server` — có cả `--proxy-host/--proxy-port`) thêm:

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--url` | `http://10.60.0.1:8081/upload` | URL POST **qua proxy** (qua tunnel); server đếm byte body, in throughput rồi thoát luôn |
| `--size` | `10485760` (10 MB) | số byte payload upload — đủ lớn để vượt cwnd ban đầu nhiều lần, phơi bày stall sender-SWS (Q.4) nếu còn |

`proxy-server`/`http-request`/`http-post-upload` validate `--proxy-host/--proxy-port` **trước** khi connect ([ProxyServerCommandModule.cs:44](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L44)).
Bind `0.0.0.0` thì client vẫn nối qua `127.0.0.1`; bind IP cụ thể thì nối thẳng IP đó
([ProxyServerCommandModule.cs:73](../demo/Vpn2ProxyDemo/CommandModules/ProxyServerCommandModule.cs#L73)).

## 5. Trạng thái & chưa làm

- ✅ HTTP/HTTPS CONNECT + SOCKS4/5 CONNECT qua tunnel (active-open) cho **cả 17 giao thức** (xem bảng §3). Các driver dùng `IVpnConnection.Sessions[0]` hoặc connection trực tiếp.
- ✅ **SOCKS5 UDP-ASSOCIATE qua proxy** (`VpnUdpAssociateSource` → `UdpConnection`): client gửi UDP qua proxy, server
  relay datagram ra ngoài bằng userspace UDP của stack (đa đích, `SendTo`/`ReceiveAsync`, IPv4 **+** IPv6 dual-stack); socket được `UnbindUdp` khi
  association đóng.
- ✅ **IPv6 dual-stack qua proxy (P1.1):** khi tunnel cấp địa chỉ IPv6 **global** (SSTP/L2TP với `--ipv6` + server cấp prefix;
  SoftEther/OpenVPN/WireGuard theo cấu hình driver), `TcpIpStack` dựng dual-stack ([`GlobalV6`](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L1336) lọc bỏ link-local)
  và proxy bật `IsSupportIpv6` ⇒ CONNECT/UDP nhận đích IPv6 (literal + AAAA fallback). Best-effort: server chỉ cấp IPv4/link-local ⇒ tự giữ IPv4-only.
- ✅ Giữ proxy + tunnel sống tới khi nhấn Enter (test duy trì kết nối: keepalive/auto-reconnect của driver chạy nền).
- ✅ **Probe UDP + DNS-over-UDP qua tunnel** (`UdpDnsProbe` → `VpnUdpClient`): vừa kiểm tra VPN có định tuyến UDP
  vừa phân giải `--resolve` ra IPv4 (đích DNS = `--dns-server` / DNS VPN cấp / `8.8.8.8`). Đây là data plane UDP
  thật, độc lập với proxy TCP.
- ✅ **Panel "VPN này hỗ trợ gì"** (`VpnCapabilityProbe` → `VpnCapabilityReport.Print`): in tự động sau mọi connect,
  trước hành động. Gộp probe thật (UDP, LAN ảo ICMP) + năng lực driver (transport/bảo mật/auth) + heuristic NAT/IPv6.
  Các khả năng thư viện chưa hỗ trợ ⇒ §6.
- ⚠️ **SoftEther cần watermark blob THẬT** để chạy live: VPN Gate trả **HTTP 403** với placeholder; truyền `--watermark <file>`
  (blob GPL, không có sẵn trong repo). Để trống ⇒ chỉ dùng được với server giả lập offline. **OpenVPN**: tun-UDP đã validate
  live VPN Gate (TCP nhỏ/UDP/ICMP), gói lớn (https) chưa qua — nghi MTU/MSS (xem [`11`](11-todo-roadmap.md) §V.2). **PPTP/IP-encap/SSH**:
  cần raw socket/PermitTunnel — chạy trong lab có CAP_NET_RAW. **Cisco IPsec** dùng Phase 1 yếu (chỉ interop legacy).
- ⏳ **Chưa:** BIND (stack active-open-only + địa chỉ tunnel private không routable từ internet ⇒ peer ngoài không
  dial vào được), proxy resolve host vẫn bằng host DNS. Tách adapter thành project `TqkLibrary.VpnClient.Proxy` nếu
  cần tái dùng — xem [`11`](11-todo-roadmap.md).

## 6. Khả năng VPN hiển thị & phần thư viện chưa hỗ trợ (roadmap/plan)

Panel hiển thị 7 khả năng. Bảng dưới: trạng thái điển hình (VPN Gate SecureNAT, driver L3 point-to-point) + nguồn xác định + **việc thư viện cần làm**
để chuyển một "✗/heuristic" thành "✓ thật". Một số driver L2 mesh (SoftEther/OpenVPN-tap/n2n/ZeroTier) có hành vi khác (LAN ảo/MAC) — xem cột nguồn.

| Khả năng | Hiện (điển hình) | Nguồn | Thư viện cần làm |
|---|---|---|---|
| IPv4 routing | ✓ | đã cấp IP ảo + định tuyến | — (đang chạy live) |
| IPv6 | ✓ khi tunnel cấp global, ngược lại ✗ | `AssignedAddressV6` (P1.1) | **Đã có IPv6 trong tunnel** (IPV6CP + SLAAC/DHCPv6 qua `--ipv6`, P1.1; outer-IPv6 P1.2). Server VPN Gate phần lớn chỉ cấp link-local/IPv4 ⇒ vẫn ✗ ở đó. Stack dual-stack sẵn. |
| UDP | ✓ (probe) | gửi DNS-over-UDP **thật** | — (data plane UDP đã chạy; chỉ phụ thuộc server có route UDP hay không) |
| Listen TCP (mở port ra internet) | ✗ | heuristic NAT + tĩnh | (a) **TCP passive-open/listener** — `TcpIpStack` hiện chỉ active-open, chưa có trạng thái LISTEN/accept *(chưa có mục riêng ở [`11`](11-todo-roadmap.md) — ghi nhận tại đây)*; (b) reachability cần IP **public** (sau SecureNAT là private) ⇒ phụ thuộc server, phần lớn **ngoài tầm** một VPN client. |
| Listen UDP (mở port ra internet) | ✗ | heuristic NAT + tĩnh | (a) **UDP nhận-từ-mọi-nguồn** — `UdpConnection` hiện là connected-UDP (lọc đúng 1 remote), chưa có bind unconnected nhận datagram từ mọi nguồn *(chưa có mục riêng ở [`11`](11-todo-roadmap.md) — ghi nhận tại đây)*; (b) reachability NAT như trên. |
| LAN ảo trong VPN | ~ (probe) | ICMP ping gateway nội bộ + DNS cùng /24 (phát hiện ⇒ panel thêm dòng **Gateway nội bộ**) | SSTP/L2TP/IKEv2/OpenVPN-tun/PPTP/SSH... là model **điểm-điểm** (`MultiHostModel.None`); **SoftEther**/**OpenVPN-tap**/**n2n**/**ZeroTier** khai L2 broadcast domain (Ethernet fabric). Demo vẫn chỉ probe ICMP gateway nội bộ (chưa duyệt host L2) — quét/định danh host trong broadcast domain → [`11` L2.x](11-todo-roadmap.md). |
| MAC address (L2) | ✗/? | tĩnh (`LinkLayer` của driver đang chạy) | Driver `LinkLayer.L3Ip` (PPP/IPCP/config-push điểm-điểm) ⇒ không có khung Ethernet/MAC ⇒ panel báo `[✗] No`. Driver khai `LinkLayer.L2Ethernet` (SoftEther/OpenVPN-tap/n2n/ZeroTier) ⇒ panel báo `[?] Unknown` (có khung Ethernet nhưng demo chưa đọc `LinkAddress` từ kênh L2). Nền L2 đã có → còn lại: demo đọc & hiển thị MAC từ kênh L2 ([`11` L2.x](11-todo-roadmap.md)). |

> **Ghi chú heuristic (giới hạn cố ý của demo, không phải của thư viện):** "Listen TCP/UDP" luôn báo ✗ kèm lý do
> (không thử connect-back từ ngoài vì cần dịch vụ phản chiếu/IP public). LAN ảo chỉ ping **gateway nội bộ suy đoán**
> (DNS nếu cùng `/24`, ngược lại `x.y.z.1`) chứ **không quét toàn subnet** (tránh chậm/ồn) — nên kết quả dừng ở
> `Likely`/`Unknown`, đủ để thấy "có hub nội bộ" mà không khẳng định số host.
