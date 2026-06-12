# TqkLibrary.Vpn

> **VPN client thuần userspace cho .NET** (`netstandard2.0` + `net8.0`) — không TUN/TAP, không kernel driver, không ghi bảng route hệ điều hành, không cần quyền admin. Ứng dụng nhận một IP ảo trong đường hầm rồi mở TCP/UDP socket chạy **bên trong** tunnel, cắm thẳng vào `HttpClient`.

Toàn bộ ngăn xếp giao thức — IKE, ESP, L2TP, PPP, SSTP, và cả TCP/IP — được tự hiện thực ở tầng ứng dụng. App chỉ cần xcopy-run.

## Tính năng

- **2 driver VPN chạy live** (đã kiểm chứng trên VPN Gate):
  - **MS-SSTP** — TLS/443 + handshake `[MS-SSTP]` + PPP RAW + MS-CHAPv2 + crypto binding chống MITM.
  - **L2TP/IPsec** — IKEv1 PSK (Main + Quick Mode) qua NAT-T (UDP 500→4500, RFC 3948), ESP transport mode (AES-CBC+HMAC-SHA1 hoặc AES-GCM negotiate được), L2TPv2, PPP/MS-CHAPv2.
- **Vòng đời đầy đủ** ở cả 2 driver: keepalive (L2TP HELLO + IKE DPD / SSTP Echo), rekey ESP make-before-break (theo lifetime + sequence-exhaustion, riêng L2TP/IPsec), teardown sạch, **auto-reconnect** (exponential backoff) sau facade kênh ổn định — socket trong tunnel **sống sót qua reconnect** khi IP không đổi.
- **Userspace TCP/IP stack dual-stack (IPv4 + IPv6)**: TCP active-open đầy đủ (retransmit/RTO RFC 6298, flow control + zero-window persist, congestion control NewReno, SACK, window scaling, PMTUD động, MSS theo MTU), UDP, ICMP/ICMPv6 (ping, port-unreachable, RST cho port đóng), phân mảnh/ráp gói 2 chiều.
- **Socket API quen thuộc**: `VpnTcpClient` trả `Stream` chuẩn (cắm `HttpClient`), `VpnUdpClient` (DNS-over-tunnel), tất cả chạy trong tunnel.
- **Plugin theo driver**: mỗi giao thức là một `IVpnProtocolDriver` đăng ký theo tên; driver tự định nghĩa cũng nạp được qua `AddDriver`.
- **Phân loại lỗi typed**: `VpnConnectionException` + 3 lớp con (sai credential / server từ chối / network timeout).
- **Sẵn cho tương lai**: IKEv2 (IKE_SA_INIT + IKE_AUTH) đã build + test đầy đủ (chưa wire driver); nền tầng L2 Ethernet (codec frame/MAC + switch học MAC + `VirtualHost` + ARP RFC 826) cho LAN ảo multi-host.
- **Demo tích hợp**: [demo/Vpn2ProxyDemo](demo/Vpn2ProxyDemo/README-vi.md) — biến tunnel thành HTTP/SOCKS proxy local (TCP CONNECT + SOCKS5 UDP-ASSOCIATE + probe DNS-over-UDP).

## Dùng nhanh

```csharp
using TqkLibrary.Vpn;

// 1) Đăng ký driver rồi build client
var vpn = new VpnClientBuilder()
    .UseSstp()
    .UseL2tpIpsec()       // auto-reconnect bật mặc định
    .Build();

// 2) Kết nối theo tên giao thức
var endpoint = new VpnEndpoint("public-vpn-226.opengw.net", 443);
var creds    = new VpnCredentials { Username = "vpn", Password = "vpn" };
await using IVpnConnection conn = await vpn.ConnectAsync("sstp", endpoint, creds);

// 3) Mở socket chạy TRONG tunnel
IVpnSession session = conn.Sessions[0];
var stack = session.CreateTcpStack();                          // userspace TCP/IP
var tcp   = await VpnTcpClient.ConnectAsync(stack, remoteIp, 443);
Stream s  = tcp.GetStream();                                   // cắm thẳng HttpClient
```

## Kiến trúc

Hai triết lý: **plugin theo driver** (mỗi giao thức một `IVpnProtocolDriver`) và **đảo ngược phụ thuộc** (mọi tầng chỉ phụ thuộc `Abstractions`, không phụ thuộc ngang). Mọi giao thức hội tụ về một "đường ống gói IP" — [`IPacketChannel`](src/TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) — và stack TCP/IP **chỉ** bind vào interface đó.

```
                        Ứng dụng (.NET)
                HttpClient / code nhận Stream / UDP
              ┌──────────────┴────────────────────┐
        control plane                         data plane
              │                                   │
 ┌────────────▼──────────────┐     ┌──────────────▼──────────────┐
 │ TqkLibrary.Vpn   (APP)    │     │ TqkLibrary.Vpn.Sockets      │
 │ VpnClientBuilder/VpnClient│     │ VpnTcpClient / VpnUdpClient │
 └────────────┬──────────────┘     │ VpnNetworkStream            │
              │ IVpnProtocolDriver └─────────────┬───────────────┘
 ┌────────────▼─────────────┐     ┌──────────────▼──────────────┐
 │ DRIVER                   │     │ TqkLibrary.Vpn.IpStack      │
 │ Drivers.Sstp             │     │ TCP·UDP·ICMP / IPv4+IPv6    │
 │ Drivers.L2tpIpsec        │     │ (userspace, dual-stack)     │
 └────────────┬─────────────┘     └──────────────┬──────────────┘
              │ lắp ráp protocol                 │ bind
              ▼                                  ▼
        ════════════ IPacketChannel (kênh gói IP thô) ════════════
              (SwappablePacketChannel — bền qua reconnect)
              ▲
 ┌────────────┴─────────────────────────────────────────────────┐
 │ PROTOCOL   Ppp (LCP/IPCP/MS-CHAPv2/HDLC)                     │
 │            L2tp (L2TPv2 control + data)                      │
 │            Ipsec (Ike/V1 · Ike/V2 · Esp · Nat NAT-T)         │
 │            Ethernet (L2 fabric: switch + VirtualHost)        │
 ├──────────────────────────────────────────────────────────────┤
 │ CRYPTO     Crypto (AES-CBC/CTR/GCM · DH MODP · HMAC-PRF      │
 │                    · MD4 · DES)                              │
 ├──────────────────────────────────────────────────────────────┤
 │ CORE       Abstractions (interface + model + enum — đáy,     │
 │                          không phụ thuộc project nào)        │
 └──────────────────────────────────────────────────────────────┘
```

### Ngăn xếp đóng gói (data plane)

```
 L2TP/IPsec (outbound)                      SSTP (outbound)
 ─────────────────────                      ───────────────
 IP ứng dụng                                IP ứng dụng
  └─ PPP [FF 03 | 00 21 | IP]                └─ PPP [FF 03 | 00 21 | IP]  (RAW, không HDLC)
      └─ L2TP [tunnelId | sessionId]             └─ SSTP data [10 | 00 | length]
          └─ UDP/1701 (checksum 0)                   └─ TLS record
              └─ ESP [SPI|Seq|IV|ct|ICV]                 └─ TCP/443 (socket OS)
                  └─ UDP/4500 (NAT-T)
                      └─ IP thật → gateway
```

### Các project trong `src/`

| Tầng | Project | Vai trò | README |
|---|---|---|---|
| APP | `TqkLibrary.Vpn` | Façade: `VpnClient`/`VpnClientBuilder`, đăng ký driver | [README](src/TqkLibrary.Vpn/README-vi.md) |
| APP | `TqkLibrary.Vpn.Sockets` | `VpnTcpClient`/`VpnUdpClient`/`VpnNetworkStream` trong tunnel | [README](src/TqkLibrary.Vpn.Sockets/README-vi.md) |
| DRIVER | `TqkLibrary.Vpn.Drivers.Sstp` | Driver MS-SSTP (TLS + PPP + crypto binding) | [README](src/TqkLibrary.Vpn.Drivers.Sstp/README-vi.md) |
| DRIVER | `TqkLibrary.Vpn.Drivers.L2tpIpsec` | Driver L2TP/IPsec (IKEv1 + ESP + L2TP + PPP) | [README](src/TqkLibrary.Vpn.Drivers.L2tpIpsec/README-vi.md) |
| PROTOCOL | `TqkLibrary.Vpn.Ipsec` | IKEv1/IKEv2 + ESP + NAT-T (`Nat/`) | [README](src/TqkLibrary.Vpn.Ipsec/README-vi.md) |
| PROTOCOL | `TqkLibrary.Vpn.L2tp` | L2TPv2 control + data (RFC 2661) | [README](src/TqkLibrary.Vpn.L2tp/README-vi.md) |
| PROTOCOL | `TqkLibrary.Vpn.Ppp` | PPP: LCP/IPCP/MS-CHAPv2 + HDLC framing | [README](src/TqkLibrary.Vpn.Ppp/README-vi.md) |
| PROTOCOL | `TqkLibrary.Vpn.IpStack` | TCP/IP userspace dual-stack (IPv4+IPv6) | [README](src/TqkLibrary.Vpn.IpStack/README-vi.md) |
| PROTOCOL | `TqkLibrary.Vpn.Ethernet` | Nền L2: codec Ethernet + switch học MAC + `VirtualHost` | [README](src/TqkLibrary.Vpn.Ethernet/README-vi.md) |
| CRYPTO | `TqkLibrary.Vpn.Crypto` | Primitive: AES, DH MODP, HMAC-PRF, MD4, DES, AES-GCM shim | [README](src/TqkLibrary.Vpn.Crypto/README-vi.md) |
| CORE | `TqkLibrary.Vpn.Abstractions` | Hợp đồng + model + enum (đáy đồ thị phụ thuộc) | [README](src/TqkLibrary.Vpn.Abstractions/README-vi.md) |

## Trạng thái

| Hạng mục | Trạng thái |
|---|---|
| Driver MS-SSTP + L2TP/IPsec | ✅ Live (VPN Gate), keepalive/rekey/teardown/auto-reconnect |
| Userspace TCP/IP (IPv4+IPv6, TCP đầy đủ, UDP, ICMP) | ✅ Hoàn chỉnh, 300 test offline |
| IKEv2 | ✅ Build + test, ⏳ chưa wire vào driver |
| Tầng L2 Ethernet (LAN ảo multi-host) | ⏳ Nền L2.0–L2.3 xong (codec/switch/VirtualHost/ARP); NDISC/DHCP/`EthernetAdapter` chưa |
| IKEv2-native / OpenVPN / WireGuard / SoftEther / OpenConnect / PPTP | ⏳ Roadmap đa-VPN opensource (xem [.docs/11](.docs/11-todo-roadmap.md)) |
| IPv6 end-to-end qua tunnel (IPV6CP) | ⏳ Stack đã dual-stack, PPP chưa có IPV6CP |

## Build & test

```powershell
dotnet build                                          # xanh cả netstandard2.0 + net8.0
dotnet test --filter "Category!=Integration"          # 300 test offline (test live VPN Gate đánh dấu Integration)
```

## Tài liệu

- [.docs/00–09](.docs/00-architecture-overview.md) — design-intent: kiến trúc tổng quan, ràng buộc no-install, taxonomy giao thức, multi-host L2/L3, từng giao thức, crypto, userspace stack.
- [.docs/10](.docs/10-codebase-architecture-and-flow.md) — **as-built**: kiến trúc & luồng hoạt động bám sát code (kèm bảng khác biệt so với design).
- [.docs/11](.docs/11-todo-roadmap.md) — roadmap & TODO.
- [.docs/12](.docs/12-demo-vpn2proxy.md) — demo Vpn2Proxy as-built.
- Mỗi project trong `src/` có `README-vi.md` riêng (bảng trên).

> ⚠️ MS-CHAPv2/MD4/DES là cơ chế yếu — dùng vì giao thức L2TP/SSTP bắt buộc, không dùng cho mục đích bảo mật mới. SSTP **mặc định** chấp nhận mọi cert TLS (danh tính xác thực bằng crypto binding chứ không PKI); có thể truyền `RemoteCertificateValidationCallback` qua `UseSstp(...)` / `SstpDriver` để validate cert khi cần. Chỉ nên dùng với server tin cậy.
