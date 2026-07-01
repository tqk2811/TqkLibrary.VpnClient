# TqkLibrary.VpnClient

> **VPN client thuần userspace cho .NET** (`netstandard2.0` + `net8.0`) — không TUN/TAP, không kernel driver, không ghi bảng route hệ điều hành. Phần lớn driver **không cần quyền admin** (ngoại lệ: các driver dùng raw-IP — PPTP/GRE/IPIP/SIT và native-ESP — cần elevate). Ứng dụng nhận một IP ảo trong đường hầm rồi mở TCP/UDP socket chạy **bên trong** tunnel, cắm thẳng vào `HttpClient`.

Toàn bộ ngăn xếp giao thức — IKE, ESP, L2TP, PPP, SSTP, Noise/WireGuard, OpenVPN, các overlay mesh (Nebula/tinc/ZeroTier/n2n/Tailscale), và cả TCP/IP — được tự hiện thực ở tầng ứng dụng. App chỉ cần xcopy-run.

## Tính năng

- **19 driver VPN** đăng ký qua `VpnClientBuilder.Use*`, gần như tất cả đã **kiểm chứng live** (xem bảng [Trạng thái](#trạng-thái)):
  - **Live trên VPN Gate (internet thật):** **MS-SSTP** (TLS/443 + handshake `[MS-SSTP]` + PPP RAW + MS-CHAPv2 + crypto binding chống MITM) và **L2TP/IPsec** (IKEv1 PSK Main+Quick Mode, NAT-T RFC 3948, ESP transport mode AES-CBC+HMAC-SHA1 / AES-GCM negotiate, L2TPv2, PPP/MS-CHAPv2).
  - **Live trong lab Docker (server opensource thật):** **IKEv2-native** (RFC 7296 PSK/EAP/cert + ESP tunnel), **Cisco IPsec/EzVPN** (IKEv1 Aggressive + XAUTH + Mode-Config), **OpenVPN** (community server, UDP/TCP, tun & tap, NCP AEAD), **WireGuard** (Noise_IKpsk2), **SoftEther** SSL-VPN (Ethernet-over-TLS + DHCP), **OpenConnect** (Cisco AnyConnect/ocserv, CSTP + DTLS 1.2), **Nebula**, **tinc** 1.1 SPTPS, **ZeroTier** VL1/VL2, **n2n** v3 (kể cả header-encryption `-H`), **Tailscale** (ts2021 control + WireGuard data), **GRE/IPIP/SIT** (IpEncap), **vtun**, **VPN-over-SSH** (`tun@openssh.com`).
  - **Built + test offline (live còn chờ):** **PPTP** (RFC 2637 GRE + MPPE + MS-CHAPv2 — chờ raw-IP proto-47 + elevate; legacy/interop), **GRE-in-UDP** (RFC 8086 — header GRE trong UDP/4754, userspace KHÔNG elevate/raw socket, qua NAT; tái dùng `GreTunnelChannel` của IpEncap), **VXLAN** (RFC 7348 — L2-over-UDP/4789, VXLAN header 8B + VNI 24-bit → Ethernet L2 fabric; userspace KHÔNG elevate/raw socket, KHÔNG mã hóa).
- **Vòng đời đầy đủ** dùng chung qua supervisor base `ReconnectingVpnConnection`: keepalive (DPD / Echo / ping theo từng giao thức), rekey make-before-break (ESP theo lifetime + sequence; WireGuard/OpenVPN/IKEv2 theo cơ chế riêng), teardown sạch, **auto-reconnect** (exponential backoff + jitter) — socket trong tunnel **sống sót qua reconnect** khi IP không đổi.
- **IPv6 trong tunnel — đã hiện thực + validate live:** PPP có **IPV6CP** (`Ipv6cpNegotiator` + `PppIpv6Autoconfigurator`); tap-mode/SoftEther/OpenVPN chạy **SLAAC + DHCPv6 + NDISC v6** trên cùng L2 segment (opt-in qua `enableIpv6`). Outer-IPv6 (kết nối tới server qua AAAA/IPv6) cũng đã chạy live.
- **Tầng L2 Ethernet dùng thật:** `EthernetSwitch` (học MAC) + `VirtualHost` + `ArpResolver` (ARP RFC 826) + NDISC/SLAAC/DHCP(v4/v6) — bắc cầu L2→L3 cho **SoftEther / OpenVPN-tap / n2n / ZeroTier / tinc / vtun**.
- **Userspace TCP/IP stack dual-stack (IPv4 + IPv6):** TCP active-open đầy đủ (retransmit/RTO RFC 6298, flow control + zero-window persist, congestion control NewReno, SACK, window scaling, PMTUD động, MSS theo MTU), UDP, ICMP/ICMPv6 (ping, port-unreachable, RST cho port đóng), phân mảnh/ráp gói 2 chiều.
- **Socket API quen thuộc:** `VpnTcpClient` trả `Stream` chuẩn (cắm `HttpClient`), `VpnUdpClient` (DNS-over-tunnel), tất cả chạy trong tunnel.
- **Plugin theo driver:** mỗi giao thức là một `IVpnProtocolDriver` đăng ký theo tên; driver tự định nghĩa cũng nạp được qua `AddDriver`.
- **Phân loại lỗi typed:** `VpnConnectionException` + lớp con (sai credential / server từ chối / network timeout).
- **Demo tích hợp:** [demo/Vpn2ProxyDemo](demo/Vpn2ProxyDemo/README-vi.md) — biến tunnel thành HTTP/SOCKS proxy local (TCP CONNECT + SOCKS5 UDP-ASSOCIATE + probe DNS-over-UDP), CLI scheme `sstp://`, `l2tp://`, `ikev2://`, `openvpn://`, `wg://`, `cisco://`, `nebula://`, `tinc://`, `zerotier://`, `n2n://`, `tailscale://`, `gre://`/`ipip://`/`sit://`, `vtun://`, `ssh://`, …

## Dùng nhanh

```csharp
using TqkLibrary.VpnClient;

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

Mỗi driver có một `Use*` riêng (vài driver nhận config tĩnh thay vì `VpnCredentials`) — xem [`VpnClientBuilder`](src/TqkLibrary.VpnClient/VpnClientBuilder.cs#L37):

```csharp
new VpnClientBuilder()
    .UseIkev2()                                  // IKEv2-native PSK/EAP
    .UseOpenVpn(profile)                          // OpenVPN từ profile
    .UseWireGuard(wgConfig)                        // WireGuard static config
    .UseSoftEther("VPN")                          // SoftEther hub
    .UseOpenConnect()                             // Cisco AnyConnect / ocserv
    .UseNebula(nebulaConfig).UseTinc(tincConfig)  // mesh overlay
    .UsePptp(new RawIpTransportFactory())         // raw-IP proto-47 (cần elevate)
    .Build();
```

## Kiến trúc

Hai triết lý: **plugin theo driver** (mỗi giao thức một `IVpnProtocolDriver`) và **đảo ngược phụ thuộc** (mọi tầng chỉ phụ thuộc `Abstractions`, không phụ thuộc ngang). Mọi giao thức hội tụ về một "đường ống gói IP" — [`IPacketChannel`](src/TqkLibrary.VpnClient.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) — và stack TCP/IP **chỉ** bind vào interface đó. Reconnect/keepalive/teardown dùng chung ở base [`ReconnectingVpnConnection`](src/TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24).

```
                        Ứng dụng (.NET)
                HttpClient / code nhận Stream / UDP
              ┌──────────────┴────────────────────┐
        control plane                         data plane
              │                                   │
 ┌────────────▼──────────────┐     ┌──────────────▼──────────────┐
 │ TqkLibrary.VpnClient (APP) │     │ TqkLibrary.VpnClient.Sockets │
 │ VpnClientBuilder/VpnClient │     │ VpnTcpClient / VpnUdpClient  │
 └────────────┬──────────────┘     │ VpnNetworkStream             │
              │ IVpnProtocolDriver  └─────────────┬───────────────┘
 ┌────────────▼───────────────┐    ┌──────────────▼──────────────┐
 │ DRIVERS (19 × Use*)        │    │ TqkLibrary.VpnClient.IpStack │
 │ Sstp · L2tpIpsec · Ikev2   │    │ TCP·UDP·ICMP / IPv4+IPv6     │
 │ CiscoIpsec · OpenVpn · WG  │    │ (userspace, dual-stack)      │
 │ SoftEther · OpenConnect    │    └──────────────┬──────────────┘
 │ Nebula · Tinc · ZeroTier   │                   │ bind
 │ N2n · Tailscale · Vtun     │                   │
 │ Ssh · Pptp · IpEncap       │                   │
 │ GreInUdp · Vxlan           │                   │
 │ (base: Drivers.Core F.6)   │                   │
 └────────────┬───────────────┘                   │
              │ lắp ráp protocol                   ▼
              ▼
        ════════════ IPacketChannel (kênh gói IP thô) ════════════
              (SwappablePacketChannel — bền qua reconnect)
              ▲
 ┌────────────┴─────────────────────────────────────────────────┐
 │ PROTOCOL   Ppp (LCP/IPCP/IPV6CP/MS-CHAPv2/HDLC)              │
 │            L2tp (L2TPv2 control + data, multi-session)       │
 │            Ipsec (Ike/V1 · Ike/V2 · Esp · Nat NAT-T)         │
 │            Ethernet (L2 fabric: switch + VirtualHost + ARP   │
 │                      + NDISC/SLAAC/DHCP v4/v6)               │
 │            OpenVpn · WireGuard · Nebula · Tinc · ZeroTier    │
 │            N2n · Tailscale · Vtun · Ssh · SoftEther · IpEncap│
 ├──────────────────────────────────────────────────────────────┤
 │ TRANSPORT  Transport.Tcp · Transport.Tls · Transport.Dtls    │
 │            · Transport.RawIp (raw socket — cần elevate)      │
 ├──────────────────────────────────────────────────────────────┤
 │ CRYPTO     Crypto (AES-CBC/CTR/GCM · ChaCha20-Poly1305 ·     │
 │                    DH MODP · X25519 · BLAKE2s · HKDF/Noise · │
 │                    HMAC-PRF · MD4 · DES)                     │
 ├──────────────────────────────────────────────────────────────┤
 │ CORE       Abstractions (interface + model + enum — đáy,     │
 │                          không phụ thuộc project nào)        │
 └──────────────────────────────────────────────────────────────┘
```

### Ngăn xếp đóng gói (data plane) — vài ví dụ

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

 WireGuard (outbound)                       OpenVPN tap (outbound)
 ────────────────────                       ──────────────────────
 IP ứng dụng                                IP ứng dụng
  └─ WG type-4 [counter | AEAD ct]           └─ Ethernet [dst|src|type|IP]  (L2 fabric)
      └─ UDP → gateway                            └─ OpenVPN P_DATA_V2 [opcode/key-id | AEAD]
                                                      └─ UDP/TCP(+TLS) → gateway
```

### Các project trong `src/` (46 project)

Bảng dưới gom theo tầng; mỗi project có `README-vi.md` riêng (as-built). Cột "Driver" đánh dấu project hiện thực `IVpnProtocolDriver` (wire qua `VpnClientBuilder.Use*`).

| Tầng | Project | Vai trò |
|---|---|---|
| APP | [TqkLibrary.VpnClient](src/TqkLibrary.VpnClient/README-vi.md) | Façade `VpnClient`/`VpnClientBuilder`, đăng ký driver |
| APP | [TqkLibrary.VpnClient.Sockets](src/TqkLibrary.VpnClient.Sockets/README-vi.md) | `VpnTcpClient`/`VpnUdpClient`/`VpnNetworkStream` trong tunnel |
| DRIVER | [Drivers.Sstp](src/TqkLibrary.VpnClient.Drivers.Sstp/README-vi.md) | MS-SSTP (TLS + PPP + crypto binding) |
| DRIVER | [Drivers.L2tpIpsec](src/TqkLibrary.VpnClient.Drivers.L2tpIpsec/README-vi.md) | L2TP/IPsec (IKEv1 + ESP + L2TP + PPP) |
| DRIVER | [Drivers.Ikev2](src/TqkLibrary.VpnClient.Drivers.Ikev2/README-vi.md) | IKEv2-native (PSK/EAP/cert + ESP tunnel) |
| DRIVER | [Drivers.CiscoIpsec](src/TqkLibrary.VpnClient.Drivers.CiscoIpsec/README-vi.md) | Cisco IPsec/EzVPN (Aggressive + XAUTH + Mode-Config) |
| DRIVER | [Drivers.OpenVpn](src/TqkLibrary.VpnClient.Drivers.OpenVpn/README-vi.md) | OpenVPN (UDP/TCP, tun/tap, NCP AEAD) |
| DRIVER | [Drivers.WireGuard](src/TqkLibrary.VpnClient.Drivers.WireGuard/README-vi.md) | WireGuard (Noise_IKpsk2, multi-peer) |
| DRIVER | [Drivers.SoftEther](src/TqkLibrary.VpnClient.Drivers.SoftEther/README-vi.md) | SoftEther SSL-VPN (Ethernet-over-TLS + DHCP) |
| DRIVER | [Drivers.OpenConnect](src/TqkLibrary.VpnClient.Drivers.OpenConnect/README-vi.md) | OpenConnect (AnyConnect/ocserv, CSTP + DTLS) |
| DRIVER | [Drivers.Nebula](src/TqkLibrary.VpnClient.Drivers.Nebula/README-vi.md) | Nebula (Noise IX + cert CA) |
| DRIVER | [Drivers.Tinc](src/TqkLibrary.VpnClient.Drivers.Tinc/README-vi.md) | tinc 1.1 (SPTPS) |
| DRIVER | [Drivers.ZeroTier](src/TqkLibrary.VpnClient.Drivers.ZeroTier/README-vi.md) | ZeroTier (VL1/VL2) |
| DRIVER | [Drivers.N2n](src/TqkLibrary.VpnClient.Drivers.N2n/README-vi.md) | n2n v3 (+ header-encryption `-H`) |
| DRIVER | [Drivers.Tailscale](src/TqkLibrary.VpnClient.Drivers.Tailscale/README-vi.md) | Tailscale (ts2021 control + WireGuard data) |
| DRIVER | [Drivers.Vtun](src/TqkLibrary.VpnClient.Drivers.Vtun/README-vi.md) | vtun (tunnel daemon legacy) |
| DRIVER | [Drivers.Ssh](src/TqkLibrary.VpnClient.Drivers.Ssh/README-vi.md) | VPN-over-SSH (`tun@openssh.com`) |
| DRIVER | [Drivers.Pptp](src/TqkLibrary.VpnClient.Drivers.Pptp/README-vi.md) | PPTP (GRE + MPPE + MS-CHAPv2; cần raw-IP) |
| DRIVER | [Drivers.IpEncap](src/TqkLibrary.VpnClient.Drivers.IpEncap/README-vi.md) | GRE / IPIP / SIT (6in4) thuần; cần raw-IP |
| DRIVER | [Drivers.GreInUdp](src/TqkLibrary.VpnClient.Drivers.GreInUdp/README-vi.md) | Driver GRE-in-UDP (RFC 8086): chở header GRE trong UDP/4754 — userspace, KHÔNG elevate/raw socket, qua NAT; tái dùng `GreTunnelChannel` của IpEncap |
| DRIVER | [Drivers.Vxlan](src/TqkLibrary.VpnClient.Drivers.Vxlan/README-vi.md) | Driver VXLAN (RFC 7348): L2-over-UDP/4789 (VXLAN header 8B + VNI 24-bit) → Ethernet L2 fabric; userspace KHÔNG elevate/raw socket, KHÔNG mã hóa |
| DRIVER | [Drivers.Core](src/TqkLibrary.VpnClient.Drivers.Core/README-vi.md) | Base `ReconnectingVpnConnection` (supervisor/reconnect/backoff — F.6), KHÔNG phải driver giao thức |
| PROTOCOL | [Ipsec](src/TqkLibrary.VpnClient.Ipsec/README-vi.md) | IKEv1/IKEv2 + ESP + NAT-T (`Nat/`) |
| PROTOCOL | [L2tp](src/TqkLibrary.VpnClient.L2tp/README-vi.md) | L2TPv2 control + data, multi-session (RFC 2661) |
| PROTOCOL | [Ppp](src/TqkLibrary.VpnClient.Ppp/README-vi.md) | PPP: LCP/IPCP/**IPV6CP**/MS-CHAPv2 + HDLC framing |
| PROTOCOL | [IpStack](src/TqkLibrary.VpnClient.IpStack/README-vi.md) | TCP/IP userspace dual-stack (IPv4+IPv6) |
| PROTOCOL | [Ethernet](src/TqkLibrary.VpnClient.Ethernet/README-vi.md) | L2 fabric: switch + `VirtualHost` + ARP + NDISC/SLAAC/DHCP |
| PROTOCOL | [OpenVpn](src/TqkLibrary.VpnClient.OpenVpn/README-vi.md) | Codec OpenVPN (control/data channel, NCP, profile parser) |
| PROTOCOL | [WireGuard](src/TqkLibrary.VpnClient.WireGuard/README-vi.md) | Codec WireGuard (handshake Noise + transport) |
| PROTOCOL | [Nebula](src/TqkLibrary.VpnClient.Nebula/README-vi.md) | Codec Nebula (Noise IX + cert + transport) |
| PROTOCOL | [Tinc](src/TqkLibrary.VpnClient.Tinc/README-vi.md) | Codec tinc SPTPS |
| PROTOCOL | [ZeroTier](src/TqkLibrary.VpnClient.ZeroTier/README-vi.md) | Codec ZeroTier VL1/VL2 |
| PROTOCOL | [N2n](src/TqkLibrary.VpnClient.N2n/README-vi.md) | Codec n2n v3 (+ header-encryption) |
| PROTOCOL | [Tailscale](src/TqkLibrary.VpnClient.Tailscale/README-vi.md) | Control plane ts2021 (netmap → WireGuardConfig) |
| PROTOCOL | [Vtun](src/TqkLibrary.VpnClient.Vtun/README-vi.md) | Codec vtun (challenge-response + data frame) |
| PROTOCOL | [Ssh](src/TqkLibrary.VpnClient.Ssh/README-vi.md) | SSH-2 transport + `tun@openssh.com` channel |
| PROTOCOL | [SoftEther](src/TqkLibrary.VpnClient.SoftEther/README-vi.md) | Codec SoftEther (PACK + session) |
| PROTOCOL | [IpEncap](src/TqkLibrary.VpnClient.IpEncap/README-vi.md) | Codec GRE/IPIP/SIT |
| TRANSPORT | [Transport.Tcp](src/TqkLibrary.VpnClient.Transport.Tcp/README-vi.md) | TCP byte-stream dùng chung (F.1) |
| TRANSPORT | [Transport.Tls](src/TqkLibrary.VpnClient.Transport.Tls/README-vi.md) | TLS byte-stream (bọc TCP) |
| TRANSPORT | [Transport.Dtls](src/TqkLibrary.VpnClient.Transport.Dtls/README-vi.md) | DTLS 1.2 datagram (OpenConnect) |
| TRANSPORT | [Transport.RawIp](src/TqkLibrary.VpnClient.Transport.RawIp/README-vi.md) | Raw socket IP protocol tùy ý (ESP-50/GRE-47…) — cần elevate |
| CRYPTO | [Crypto](src/TqkLibrary.VpnClient.Crypto/README-vi.md) | AES-CBC/CTR/GCM, ChaCha20-Poly1305, DH MODP, X25519, BLAKE2s, HKDF/Noise, HMAC-PRF, MD4, DES |
| CORE | [Abstractions](src/TqkLibrary.VpnClient.Abstractions/README-vi.md) | Hợp đồng + model + enum (đáy đồ thị phụ thuộc) |

## Trạng thái

| Hạng mục | Trạng thái |
|---|---|
| MS-SSTP, L2TP/IPsec | ✅ Live trên **VPN Gate** (internet thật): keepalive/rekey/teardown/auto-reconnect; L2TP/IPsec gồm IPv6-in-tunnel, outer-IPv6, rekey Phase 1 (forced NAT-T + native-ESP), multi-session |
| IKEv2-native, Cisco IPsec/EzVPN | ✅ Live (lab Docker strongSwan): PSK/EAP, Aggressive+XAUTH+Mode-Config, ESP tunnel; live-rekey timer-dài là residual |
| OpenVPN, WireGuard, SoftEther, OpenConnect | ✅ Live (lab Docker server opensource): full tunnel + rekey make-before-break; OpenConnect gồm DTLS 1.2 data plane |
| Nebula, tinc, ZeroTier, n2n, Tailscale | ✅ Live (lab Docker daemon thật): full L2/L3 overlay 2 chiều; n2n gồm header-encryption `-H` |
| vtun, VPN-over-SSH, GRE/IPIP/SIT (IpEncap) | ✅ Live (lab Docker): vtun (cả encrypt + tap mode), SSH `tun@openssh.com`, GRE/IPIP/SIT 2 chiều cả 3 kiểu |
| PPTP | ⏳ Build + test offline; live chờ raw-IP proto-47 + elevate (legacy/interop) |
| Userspace TCP/IP (IPv4+IPv6, TCP đầy đủ, UDP, ICMP/ICMPv6) | ✅ Hoàn chỉnh |
| IPv6 trong tunnel (IPV6CP cho PPP; SLAAC/DHCPv6/NDISC cho L2) | ✅ Hiện thực + validate live |
| Tầng L2 Ethernet (switch + VirtualHost + ARP + NDISC/SLAAC/DHCP) | ✅ Dùng thật cho SoftEther/OpenVPN-tap/n2n/ZeroTier/tinc/vtun |

> Roadmap (việc **chưa** làm) ở [.docs/11](.docs/11-todo-roadmap.md). Trạng thái as-built đầy đủ + giới hạn server-side đã chứng minh ở [.docs/10](.docs/10-codebase-architecture-and-flow.md) §9 và README từng project.

## Build & test

```powershell
dotnet build                                          # xanh cả netstandard2.0 + net8.0
dotnet test --filter "Category!=Integration"          # bộ test offline đầy đủ (test live VPN Gate/lab đánh dấu Integration)
```

- `record`/`init`/`required` dùng được cả 2 TFM nhờ package source-only **`TqkLibrary.CompilerServices`** (ref ở [`src/Directory.Build.props`](src/Directory.Build.props), chỉ netstandard2.0).
- Test live phụ thuộc VPN Gate / lab Docker đánh dấu `[Trait("Category","Integration")]` — chạy offline bằng `--filter "Category!=Integration"`.

## Tài liệu

- [.docs/00–09](.docs/00-architecture-overview.md) — design-intent: kiến trúc tổng quan, ràng buộc no-install, taxonomy giao thức, multi-host L2/L3, từng giao thức, crypto, userspace stack.
- [.docs/10](.docs/10-codebase-architecture-and-flow.md) — **as-built**: kiến trúc & luồng hoạt động bám sát code (kèm bảng khác biệt so với design).
- [.docs/11](.docs/11-todo-roadmap.md) — roadmap & TODO (chỉ chứa việc chưa làm).
- [.docs/12](.docs/12-demo-vpn2proxy.md) — demo Vpn2Proxy as-built.
- Mỗi project trong `src/` có `README-vi.md` riêng (bảng trên).

> ⚠️ Một số cơ chế là **legacy/yếu** — dùng vì giao thức bắt buộc, không dùng cho mục đích bảo mật mới: MS-CHAPv2/MD4/DES (SSTP/L2TP/PPTP), MPPE/RC4 + MS-CHAPv2 (PPTP — đã bị phá), IKEv1 Aggressive + group PSK (Cisco IPsec — dictionary attack offline), Blowfish-ECB (vtun). GRE/IPIP/SIT **không mã hóa** (bọc IPsec ESP nếu cần). SSTP/OpenConnect/OpenVPN **mặc định** chấp nhận mọi cert TLS (SSTP xác thực danh tính bằng crypto binding, không PKI); truyền `RemoteCertificateValidationCallback` qua `UseSstp(...)`/`UseOpenConnect(...)`/`UseOpenVpn(...)` để validate cert khi cần. Chỉ nên dùng với server tin cậy.
