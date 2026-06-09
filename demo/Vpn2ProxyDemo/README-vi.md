# Vpn2ProxyDemo

Demo: kết nối VPN Gate (**MS-SSTP** và **L2TP/IPsec**) rồi định tuyến `HttpClient` qua một proxy local chạy trên tunnel để kiểm tra IP công cộng.

Luồng: **vpn → IProxySource → ProxyServer → HttpClient → https://checkip.amazonaws.com/**

```
SstpConnection / L2tpIpsecConnection      (kết nối VPN, nhận IP ảo + PacketChannel)
        -> new TcpIpStack(channel, ip)    (userspace TCP/IP trong tunnel)
        -> new VpnProxySource(stack)       (IProxySource — adapter inline trong demo này)
        -> new ProxyServer(127.0.0.1:0, source).StartListen()   (HTTP/SOCKS proxy local)
        -> HttpClient { Proxy = http://127.0.0.1:<port> }.GetStringAsync(checkip)
        => IP trả về = IP công cộng của VPN server
```

> "SSL-VPN (comfortable)" mà VPN Gate liệt kê là **giao thức riêng của phần mềm SoftEther VPN**, thư viện này chưa hiện thực — nên demo dùng 2 driver đã chạy live: **MS-SSTP** và **L2TP/IPsec**.

## Cấu trúc (mẫu `ICommandModule` — như `TqkLibrary.WinDivert.Demo`)

```
Vpn2ProxyDemo/
├── Program.cs                        RootCommand { sstp, l2tp } -> Parse(args).InvokeAsync()
├── Properties/launchSettings.json    profile chạy nhanh từng case (sstp / l2tp / help)
├── VpnProxySource.cs                 IProxySource bọc TcpIpStack của tunnel (adapter inline)
├── VpnConnectSource.cs               IConnectSource: mở VpnTcpClient qua tunnel, trả Stream cho ProxyServer
└── CommandModules/
    ├── Interfaces/ICommandModule.cs          hợp đồng: Command Command { get; }
    ├── CommandModuleBase.cs                  base GENERIC: --check-url + header/IP/bắt lỗi + TcpIpStack -> VpnProxySource -> ProxyServer -> HttpClient; abstract ConnectAsync(ParseResult)
    ├── HostCredentialCommandModuleBase.cs    base cho VPN dùng host+user+pass: thêm --host/--user/--pass -> ConnectAsync(host,user,pass)
    ├── VpnTunnel.cs                          bọc TcpIpStack + vòng đời tunnel (IAsyncDisposable) — kiểu mà ConnectAsync trả về
    ├── SstpCommandModule.cs                  "sstp": ConnectAsync(host,user,pass) -> VpnTunnel (MS-SSTP)
    └── L2tpCommandModule.cs                  "l2tp": ConnectAsync(host,user,pass) -> VpnTunnel (L2TP/IPsec)
```

Phân tầng để **mở rộng nhiều dạng VPN**:

- `CommandModuleBase` (generic, không gắn protocol/credential): giữ phần dùng chung **`TcpIpStack → VpnProxySource → ProxyServer → HttpClient → checkip`** + bắt lỗi; lớp con chỉ `ConnectAsync(ParseResult)` → trả **`VpnTunnel`** (bọc `TcpIpStack` + vòng đời, sống tới hết `await using`).
- `HostCredentialCommandModuleBase` (cho VPN kiểu host+user+pass): thêm sẵn `--host/--user/--pass`, rút gọn còn `ConnectAsync(host,user,pass,ct)`.
- **Thêm dạng VPN mới:** dùng credential giống → kế thừa `HostCredentialCommandModuleBase`; dùng credential khác (cert/config/key…) → kế thừa thẳng `CommandModuleBase`, tự khai option + `ConnectAsync(ParseResult)`. Không phải sửa base.

## Chạy

Args xử lý bằng **System.CommandLine 2.0.7** (subcommand + `--option`, có `--help`):

```powershell
dotnet run --project demo/Vpn2ProxyDemo -- sstp                  # MS-SSTP
dotnet run --project demo/Vpn2ProxyDemo -- l2tp                  # L2TP/IPsec
dotnet run --project demo/Vpn2ProxyDemo -- sstp --host public-vpn-XXX.opengw.net   # đổi server
dotnet run --project demo/Vpn2ProxyDemo -- --help                # liệt kê subcommand
dotnet run --project demo/Vpn2ProxyDemo -- sstp --help           # option của 1 subcommand
```

Hoặc dùng **launch profile** ([Properties/launchSettings.json](Properties/launchSettings.json)) — chọn nhanh trong VS/Rider hoặc CLI:

```powershell
dotnet run --project demo/Vpn2ProxyDemo --launch-profile sstp
dotnet run --project demo/Vpn2ProxyDemo --launch-profile l2tp
```

Profile có sẵn: `sstp`, `l2tp`, `sstp (host khác)`, `l2tp (host khác)`, `help`.

Subcommand: `sstp` | `l2tp`. Option mỗi subcommand:

| Option | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--host` | `public-vpn-226.opengw.net` | host VPN Gate (MS-SSTP / L2TP) |
| `--user` / `--pass` | `vpn` / `vpn` | tài khoản VPN Gate |
| `--check-url` | `https://checkip.amazonaws.com/` | URL kiểm tra IP |

## Lưu ý

- **Cần mạng + server còn sống.** Host VPN Gate thay đổi liên tục; nếu `public-vpn-226` đã tắt, lấy host khác từ https://www.vpngate.net/ và truyền qua `--host`. Server phải bật đúng giao thức bạn chọn (cột MS-SSTP / L2TP trên trang VPN Gate).
- **Không cần quyền admin** — toàn bộ stack là userspace (không TUN/TAP, không routing table).
- IP `[direct]` (không VPN) in ra đầu tiên để so sánh với IP `[sstp]`/`[l2tp]` đi qua tunnel.
- Demo tham chiếu project tới [`src/TqkLibrary.Vpn.Drivers`](../../src/TqkLibrary.Vpn.Drivers) (driver façades) và [`src/TqkLibrary.Vpn.Sockets`](../../src/TqkLibrary.Vpn.Sockets) (`VpnTcpClient`/`TcpIpStack`), cùng NuGet `TqkLibrary.Proxy` 1.0.35.
