# Vpn2ProxyDemo

Demo: kết nối VPN Gate (**MS-SSTP** và **L2TP/IPsec**) rồi dựng một proxy local chạy trên tunnel, **giữ proxy sống tới khi nhấn Enter** để test VPN duy trì kết nối (keepalive/auto-reconnect) trong khi client trỏ vào proxy.

Luồng: **vpn → IProxySource → ProxyServer → (giữ sống tới khi nhấn Enter)**

```
SstpConnection / L2tpIpsecConnection      (kết nối VPN, nhận IP ảo + DNS + PacketChannel)
        -> new TcpIpStack(channel, ip)    (userspace TCP/IP trong tunnel)
        -> UdpDnsProbe.ResolveAsync(...)   (DNS-over-UDP qua tunnel: VPN có hỗ trợ UDP? + IP của --resolve)
        -> new VpnProxySource(stack)       (IProxySource — adapter inline trong demo này)
        -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()   (HTTP/SOCKS proxy local)
        -> sanity-check 1 lần: HttpClient { Proxy = http://<host>:<port> }.GetStringAsync(checkip)
        -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
        => trỏ browser/curl tới proxy: mọi traffic đi qua IP công cộng của VPN server
```

> "SSL-VPN (comfortable)" mà VPN Gate liệt kê là **giao thức riêng của phần mềm SoftEther VPN**, thư viện này chưa hiện thực — nên demo dùng 2 driver đã chạy live: **MS-SSTP** và **L2TP/IPsec**.

## Cấu trúc (mẫu `ICommandModule` — như `TqkLibrary.WinDivert.Demo`)

```
Vpn2ProxyDemo/
├── Program.cs                        RootCommand { sstp, l2tp } -> Parse(args).InvokeAsync()
├── Properties/launchSettings.json    profile chạy nhanh từng case (sstp / l2tp / help)
├── VpnProxySource.cs                 IProxySource bọc TcpIpStack của tunnel (adapter inline)
├── VpnConnectSource.cs               IConnectSource: mở VpnTcpClient qua tunnel, trả Stream cho ProxyServer
├── UdpDnsProbe.cs                    build/parse gói DNS (RFC 1035) trên VpnUdpClient: probe UDP + phân giải domain qua tunnel
├── UdpDnsProbeResult.cs              kết quả probe: UdpSupported + danh sách IPv4 + số lần thử/thời gian/lỗi
└── CommandModules/
    ├── Interfaces/ICommandModule.cs          hợp đồng: Command Command { get; }
    ├── CommandModuleBase.cs                  base GENERIC: --check-url/--proxy-host/--proxy-port/--dns-server/--resolve + header/IP/bắt lỗi + probe UDP-DNS + TcpIpStack -> VpnProxySource -> ProxyServer (giữ tới khi nhấn Enter); abstract ConnectAsync(ParseResult)
    ├── HostCredentialCommandModuleBase.cs    base cho VPN dùng host+user+pass: thêm --host/--user/--pass -> ConnectAsync(host,user,pass)
    ├── VpnTunnel.cs                          bọc TcpIpStack + AssignedDns + vòng đời tunnel (IAsyncDisposable) — kiểu mà ConnectAsync trả về
    ├── SstpCommandModule.cs                  "sstp": ConnectAsync(host,user,pass) -> VpnTunnel (MS-SSTP)
    └── L2tpCommandModule.cs                  "l2tp": ConnectAsync(host,user,pass) -> VpnTunnel (L2TP/IPsec)
```

Phân tầng để **mở rộng nhiều dạng VPN**:

- `CommandModuleBase` (generic, không gắn protocol/credential): giữ phần dùng chung **`TcpIpStack → VpnProxySource → ProxyServer`** + sanity-check IP 1 lần qua proxy + **giữ proxy sống tới khi nhấn Enter** + bắt lỗi; lớp con chỉ `ConnectAsync(ParseResult)` → trả **`VpnTunnel`** (bọc `TcpIpStack` + vòng đời, sống tới hết `await using`).
- `HostCredentialCommandModuleBase` (cho VPN kiểu host+user+pass): thêm sẵn `--host/--user/--pass`, rút gọn còn `ConnectAsync(host,user,pass,ct)`.
- **Thêm dạng VPN mới:** dùng credential giống → kế thừa `HostCredentialCommandModuleBase`; dùng credential khác (cert/config/key…) → kế thừa thẳng `CommandModuleBase`, tự khai option + `ConnectAsync(ParseResult)`. Không phải sửa base.

## Chạy

Args xử lý bằng **System.CommandLine 2.0.7** (subcommand + `--option`, có `--help`):

```powershell
dotnet run --project demo/Vpn2ProxyDemo -- sstp                  # MS-SSTP (proxy ở 127.0.0.1:cổng-tự-cấp)
dotnet run --project demo/Vpn2ProxyDemo -- l2tp                  # L2TP/IPsec
dotnet run --project demo/Vpn2ProxyDemo -- sstp --host public-vpn-XXX.opengw.net   # đổi server
dotnet run --project demo/Vpn2ProxyDemo -- l2tp --proxy-host 0.0.0.0 --proxy-port 18080  # proxy nghe LAN, cổng cố định
dotnet run --project demo/Vpn2ProxyDemo -- --help                # liệt kê subcommand
dotnet run --project demo/Vpn2ProxyDemo -- sstp --help           # option của 1 subcommand
```

Proxy được **giữ chạy tới khi nhấn Enter** (hoặc Ctrl+C). Trong lúc đó trỏ browser/curl vào proxy để gửi traffic và quan sát VPN duy trì kết nối:

```powershell
curl -x http://127.0.0.1:18080 https://checkip.amazonaws.com/
```

Hoặc dùng **launch profile** ([Properties/launchSettings.json](Properties/launchSettings.json)) — chọn nhanh trong VS/Rider hoặc CLI:

```powershell
dotnet run --project demo/Vpn2ProxyDemo --launch-profile sstp
dotnet run --project demo/Vpn2ProxyDemo --launch-profile l2tp
```

Profile có sẵn: `sstp`, `l2tp`, `sstp (as proxy)`, `l2tp (as proxy)`, `sstp resolve example.com (UDP DNS)`, `l2tp resolve github.com (UDP DNS via 8.8.8.8)`, `help`.

Subcommand: `sstp` | `l2tp`. Option mỗi subcommand:

| Option | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--host` | `public-vpn-226.opengw.net` | host VPN Gate (MS-SSTP / L2TP) |
| `--user` / `--pass` | `vpn` / `vpn` | tài khoản VPN Gate |
| `--check-url` | `https://checkip.amazonaws.com/` | URL sanity-check IP (gọi 1 lần qua proxy khi vừa lên) |
| `--proxy-host` | `127.0.0.1` | IP cho proxy local nghe (`0.0.0.0` = mọi interface để máy khác trong LAN dùng) |
| `--proxy-port` | `0` | cổng proxy local (`0` = tự cấp cổng trống; chỉ định cố định để client trỏ vào ổn định) |
| `--dns-server` | *(rỗng)* | DNS server (IPv4) cho probe UDP qua tunnel; rỗng = dùng DNS do VPN cấp, fallback `8.8.8.8` |
| `--resolve` | `google.com` | tên miền phân giải bằng DNS-over-UDP qua tunnel (đồng thời kiểm tra VPN có hỗ trợ UDP) |

## Lưu ý

- **Cần mạng + server còn sống.** Host VPN Gate thay đổi liên tục; nếu `public-vpn-226` đã tắt, lấy host khác từ https://www.vpngate.net/ và truyền qua `--host`. Server phải bật đúng giao thức bạn chọn (cột MS-SSTP / L2TP trên trang VPN Gate).
- **Không cần quyền admin** — toàn bộ stack là userspace (không TUN/TAP, không routing table).
- IP `[direct]` (không VPN) in ra đầu tiên để so sánh với IP `[sstp]`/`[l2tp]` đi qua tunnel.
- **Kiểm tra UDP + DNS qua tunnel:** ngay sau khi tunnel lên, demo gửi một truy vấn DNS (bản ghi A) qua **UDP xuyên tunnel** (`UdpDnsProbe` → `VpnUdpClient`, không dùng host DNS) tới `--dns-server` (mặc định: DNS do VPN cấp, fallback `8.8.8.8`). Nhận được phản hồi ⇒ in `VPN HỖ TRỢ UDP` + IPv4 của `--resolve`; timeout sau 3 lần thử ⇒ VPN có thể không định tuyến UDP (hoặc DNS server không reachable — thử `--dns-server` khác). Đây là kênh UDP đi thẳng IP stack, **khác** với UDP-ASSOCIATE qua proxy (chưa làm).
- **Giữ kết nối:** sau khi proxy lên, demo dừng tại bước `ProxyServer` và chờ Enter — tunnel vẫn chạy keepalive + auto-reconnect (xem driver), nên đây là chỗ test "duy trì kết nối": cứ gửi traffic qua proxy liên tục/định kỳ rồi quan sát log reconnect. Sanity-check checkip lúc đầu lỗi cũng **không** dừng proxy.
- `--proxy-host 0.0.0.0` mở proxy cho cả máy khác trong LAN — chỉ dùng trên mạng tin cậy (proxy không có auth).
- Demo tham chiếu project tới [`src/TqkLibrary.Vpn.Drivers`](../../src/TqkLibrary.Vpn.Drivers) (driver façades) và [`src/TqkLibrary.Vpn.Sockets`](../../src/TqkLibrary.Vpn.Sockets) (`VpnTcpClient`/`VpnUdpClient`/`TcpIpStack`), cùng NuGet `TqkLibrary.Proxy` 1.0.35.
