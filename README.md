# TqkLibrary.VpnClient

> **A pure userspace VPN client for .NET** (`netstandard2.0` + `net8.0`) — no TUN/TAP, no kernel driver, no writes to the OS routing table. Most drivers **require no admin rights** (exceptions: drivers that use raw IP — PPTP/GRE/IPIP/SIT and native ESP — need elevation). Your app receives a virtual IP inside the tunnel, then opens TCP/UDP sockets that run **inside** the tunnel and plug straight into `HttpClient`.

The entire protocol stack — IKE, ESP, L2TP, PPP, SSTP, Noise/WireGuard, OpenVPN, the mesh overlays (Nebula/tinc/ZeroTier/n2n/Tailscale), and even TCP/IP — is implemented in the application layer. The app just needs to xcopy-run.

## Features

- **19 VPN drivers** registered via `VpnClientBuilder.Use*`, almost all already **validated live** (see the [Status](#status) table):
  - **Live on VPN Gate (the real internet):** **MS-SSTP** (TLS/443 + the `[MS-SSTP]` handshake + PPP RAW + MS-CHAPv2 + crypto binding against MITM) and **L2TP/IPsec** (IKEv1 PSK Main+Quick Mode, NAT-T RFC 3948, ESP transport mode AES-CBC+HMAC-SHA1 / AES-GCM negotiated, L2TPv2, PPP/MS-CHAPv2).
  - **Live in a Docker lab (real open-source servers):** **IKEv2-native** (RFC 7296 PSK/EAP/cert + ESP tunnel), **Cisco IPsec/EzVPN** (IKEv1 Aggressive + XAUTH + Mode-Config), **OpenVPN** (community server, UDP/TCP, tun & tap, NCP AEAD), **WireGuard** (Noise_IKpsk2), **SoftEther** SSL-VPN (Ethernet-over-TLS + DHCP), **OpenConnect** (Cisco AnyConnect/ocserv, CSTP + DTLS 1.2), **Nebula**, **tinc** 1.1 SPTPS, **ZeroTier** VL1/VL2, **n2n** v3 (including header encryption `-H`), **Tailscale** (ts2021 control + WireGuard data), **GRE/IPIP/SIT** (IpEncap), **vtun**, and **VPN-over-SSH** (`tun@openssh.com`).
  - **Built + offline-tested (live still pending):** **PPTP** (RFC 2637 GRE + MPPE + MS-CHAPv2 — pending raw-IP proto-47 + elevation; legacy/interop), **GRE-in-UDP** (RFC 8086 — the GRE header inside UDP/4754, userspace with NO elevation/raw socket, NAT-friendly; reuses IpEncap's `GreTunnelChannel`), **VXLAN** (RFC 7348 — L2-over-UDP/4789, an 8-byte VXLAN header + 24-bit VNI → the Ethernet L2 fabric; userspace with NO elevation/raw socket, NO encryption).
- **Full lifecycle** shared through the supervisor base `ReconnectingVpnConnection`: keepalive (DPD / Echo / ping, per protocol), make-before-break rekey (ESP by lifetime + sequence; WireGuard/OpenVPN/IKEv2 by their own mechanisms), clean teardown, and **auto-reconnect** (exponential backoff + jitter) — in-tunnel sockets **survive a reconnect** when the IP does not change.
- **IPv6 in the tunnel — implemented + validated live:** PPP has **IPV6CP** (`Ipv6cpNegotiator` + `PppIpv6Autoconfigurator`); tap-mode/SoftEther/OpenVPN run **SLAAC + DHCPv6 + NDISC v6** over the same L2 segment (opt-in via `enableIpv6`). Outer IPv6 (connecting to the server over AAAA/IPv6) also runs live.
- **An L2 Ethernet fabric that is actually used:** `EthernetSwitch` (MAC learning) + `VirtualHost` + `ArpResolver` (ARP RFC 826) + NDISC/SLAAC/DHCP (v4/v6) — bridging L2→L3 for **SoftEther / OpenVPN-tap / n2n / ZeroTier / tinc / vtun**.
- **Userspace dual-stack TCP/IP (IPv4 + IPv6):** full TCP active-open (retransmit/RTO RFC 6298, flow control + zero-window persist, NewReno congestion control, SACK, window scaling, dynamic PMTUD, MSS per MTU), UDP, ICMP/ICMPv6 (ping, port-unreachable, RST for closed ports), two-way fragmentation/reassembly.
- **A familiar socket API:** `VpnTcpClient` returns a standard `Stream` (plug into `HttpClient`), `VpnUdpClient` (DNS-over-tunnel) — all running inside the tunnel.
- **Per-driver plugins:** every protocol is an `IVpnProtocolDriver` registered by name; a custom-defined driver can also be loaded via `AddDriver`.
- **Typed error classification:** `VpnConnectionException` + subclasses (wrong credentials / server rejected / network timeout).
- **Integration demo:** [demo/Vpn2ProxyDemo](demo/Vpn2ProxyDemo/README-vi.md) — turns the tunnel into a local HTTP/SOCKS proxy (TCP CONNECT + SOCKS5 UDP-ASSOCIATE + DNS-over-UDP probe), CLI schemes `sstp://`, `l2tp://`, `ikev2://`, `openvpn://`, `wg://`, `cisco://`, `nebula://`, `tinc://`, `zerotier://`, `n2n://`, `tailscale://`, `gre://`/`ipip://`/`sit://`, `vtun://`, `ssh://`, …

## Quick start

```csharp
using TqkLibrary.VpnClient;

// 1) Register drivers, then build the client
var vpn = new VpnClientBuilder()
    .UseSstp()
    .UseL2tpIpsec()       // auto-reconnect enabled by default
    .Build();

// 2) Connect by protocol name
var endpoint = new VpnEndpoint("public-vpn-226.opengw.net", 443);
var creds    = new VpnCredentials { Username = "vpn", Password = "vpn" };
await using IVpnConnection conn = await vpn.ConnectAsync("sstp", endpoint, creds);

// 3) Open a socket that runs INSIDE the tunnel
IVpnSession session = conn.Sessions[0];
var stack = session.CreateTcpStack();                          // userspace TCP/IP
var tcp   = await VpnTcpClient.ConnectAsync(stack, remoteIp, 443);
Stream s  = tcp.GetStream();                                   // plug straight into HttpClient
```

Each driver has its own `Use*` (some drivers take a static config instead of `VpnCredentials`) — see [`VpnClientBuilder`](src/TqkLibrary.VpnClient/VpnClientBuilder.cs#L37):

```csharp
new VpnClientBuilder()
    .UseIkev2()                                  // IKEv2-native PSK/EAP
    .UseOpenVpn(profile)                          // OpenVPN from a profile
    .UseWireGuard(wgConfig)                        // WireGuard static config
    .UseSoftEther("VPN")                          // SoftEther hub
    .UseOpenConnect()                             // Cisco AnyConnect / ocserv
    .UseNebula(nebulaConfig).UseTinc(tincConfig)  // mesh overlay
    .UsePptp(new RawIpTransportFactory())         // raw-IP proto-47 (needs elevation)
    .Build();
```

## Architecture

Two principles: **per-driver plugins** (each protocol is one `IVpnProtocolDriver`) and **dependency inversion** (every layer depends only on `Abstractions`, never sideways). Every protocol converges onto a single "IP packet pipe" — [`IPacketChannel`](src/TqkLibrary.VpnClient.Abstractions/Channels/Interfaces/IPacketChannel.cs#L6) — and the TCP/IP stack binds **only** to that interface. Reconnect/keepalive/teardown are shared in the base [`ReconnectingVpnConnection`](src/TqkLibrary.VpnClient.Drivers.Core/ReconnectingVpnConnection.cs#L24).

```
                        Application (.NET)
                HttpClient / code taking a Stream / UDP
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
              │ assemble protocol                  ▼
              ▼
        ════════════ IPacketChannel (raw IP packet pipe) ════════════
              (SwappablePacketChannel — durable across reconnect)
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
 │            · Transport.RawIp (raw socket — needs elevation)  │
 ├──────────────────────────────────────────────────────────────┤
 │ CRYPTO     Crypto (AES-CBC/CTR/GCM · ChaCha20-Poly1305 ·     │
 │                    DH MODP · X25519 · BLAKE2s · HKDF/Noise · │
 │                    HMAC-PRF · MD4 · DES)                     │
 ├──────────────────────────────────────────────────────────────┤
 │ CORE       Abstractions (interfaces + models + enums — the   │
 │                          bottom, depends on no project)      │
 └──────────────────────────────────────────────────────────────┘
```

### Encapsulation stack (data plane) — a few examples

```
 L2TP/IPsec (outbound)                      SSTP (outbound)
 ─────────────────────                      ───────────────
 Application IP                             Application IP
  └─ PPP [FF 03 | 00 21 | IP]                └─ PPP [FF 03 | 00 21 | IP]  (RAW, no HDLC)
      └─ L2TP [tunnelId | sessionId]             └─ SSTP data [10 | 00 | length]
          └─ UDP/1701 (checksum 0)                   └─ TLS record
              └─ ESP [SPI|Seq|IV|ct|ICV]                 └─ TCP/443 (OS socket)
                  └─ UDP/4500 (NAT-T)
                      └─ real IP → gateway

 WireGuard (outbound)                       OpenVPN tap (outbound)
 ────────────────────                       ──────────────────────
 Application IP                             Application IP
  └─ WG type-4 [counter | AEAD ct]           └─ Ethernet [dst|src|type|IP]  (L2 fabric)
      └─ UDP → gateway                            └─ OpenVPN P_DATA_V2 [opcode/key-id | AEAD]
                                                      └─ UDP/TCP(+TLS) → gateway
```

### Projects in `src/` (46 projects)

The table below is grouped by layer; every project has its own `README-vi.md` (as-built). The "DRIVER" tier marks projects that implement `IVpnProtocolDriver` (wired through `VpnClientBuilder.Use*`).

| Layer | Project | Role |
|---|---|---|
| APP | [TqkLibrary.VpnClient](src/TqkLibrary.VpnClient/README-vi.md) | Façade `VpnClient`/`VpnClientBuilder`, driver registration |
| APP | [TqkLibrary.VpnClient.Sockets](src/TqkLibrary.VpnClient.Sockets/README-vi.md) | `VpnTcpClient`/`VpnUdpClient`/`VpnNetworkStream` inside the tunnel |
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
| DRIVER | [Drivers.N2n](src/TqkLibrary.VpnClient.Drivers.N2n/README-vi.md) | n2n v3 (+ header encryption `-H`) |
| DRIVER | [Drivers.Tailscale](src/TqkLibrary.VpnClient.Drivers.Tailscale/README-vi.md) | Tailscale (ts2021 control + WireGuard data) |
| DRIVER | [Drivers.Vtun](src/TqkLibrary.VpnClient.Drivers.Vtun/README-vi.md) | vtun (legacy tunnel daemon) |
| DRIVER | [Drivers.Ssh](src/TqkLibrary.VpnClient.Drivers.Ssh/README-vi.md) | VPN-over-SSH (`tun@openssh.com`) |
| DRIVER | [Drivers.Pptp](src/TqkLibrary.VpnClient.Drivers.Pptp/README-vi.md) | PPTP (GRE + MPPE + MS-CHAPv2; needs raw IP) |
| DRIVER | [Drivers.IpEncap](src/TqkLibrary.VpnClient.Drivers.IpEncap/README-vi.md) | Plain GRE / IPIP / SIT (6in4); needs raw IP |
| DRIVER | [Drivers.GreInUdp](src/TqkLibrary.VpnClient.Drivers.GreInUdp/README-vi.md) | GRE-in-UDP driver (RFC 8086): carries the GRE header inside UDP/4754 — userspace, NO elevation/raw socket, NAT-friendly; reuses IpEncap's `GreTunnelChannel` |
| DRIVER | [Drivers.Vxlan](src/TqkLibrary.VpnClient.Drivers.Vxlan/README-vi.md) | VXLAN driver (RFC 7348): L2-over-UDP/4789 (an 8-byte VXLAN header + 24-bit VNI) → the Ethernet L2 fabric; userspace, NO elevation/raw socket, NO encryption |
| DRIVER | [Drivers.Core](src/TqkLibrary.VpnClient.Drivers.Core/README-vi.md) | Base `ReconnectingVpnConnection` (supervisor/reconnect/backoff — F.6); NOT a protocol driver |
| PROTOCOL | [Ipsec](src/TqkLibrary.VpnClient.Ipsec/README-vi.md) | IKEv1/IKEv2 + ESP + NAT-T (`Nat/`) |
| PROTOCOL | [L2tp](src/TqkLibrary.VpnClient.L2tp/README-vi.md) | L2TPv2 control + data, multi-session (RFC 2661) |
| PROTOCOL | [Ppp](src/TqkLibrary.VpnClient.Ppp/README-vi.md) | PPP: LCP/IPCP/**IPV6CP**/MS-CHAPv2 + HDLC framing |
| PROTOCOL | [IpStack](src/TqkLibrary.VpnClient.IpStack/README-vi.md) | Userspace dual-stack TCP/IP (IPv4+IPv6) |
| PROTOCOL | [Ethernet](src/TqkLibrary.VpnClient.Ethernet/README-vi.md) | L2 fabric: switch + `VirtualHost` + ARP + NDISC/SLAAC/DHCP |
| PROTOCOL | [OpenVpn](src/TqkLibrary.VpnClient.OpenVpn/README-vi.md) | OpenVPN codec (control/data channel, NCP, profile parser) |
| PROTOCOL | [WireGuard](src/TqkLibrary.VpnClient.WireGuard/README-vi.md) | WireGuard codec (Noise handshake + transport) |
| PROTOCOL | [Nebula](src/TqkLibrary.VpnClient.Nebula/README-vi.md) | Nebula codec (Noise IX + cert + transport) |
| PROTOCOL | [Tinc](src/TqkLibrary.VpnClient.Tinc/README-vi.md) | tinc SPTPS codec |
| PROTOCOL | [ZeroTier](src/TqkLibrary.VpnClient.ZeroTier/README-vi.md) | ZeroTier VL1/VL2 codec |
| PROTOCOL | [N2n](src/TqkLibrary.VpnClient.N2n/README-vi.md) | n2n v3 codec (+ header encryption) |
| PROTOCOL | [Tailscale](src/TqkLibrary.VpnClient.Tailscale/README-vi.md) | ts2021 control plane (netmap → WireGuardConfig) |
| PROTOCOL | [Vtun](src/TqkLibrary.VpnClient.Vtun/README-vi.md) | vtun codec (challenge-response + data frame) |
| PROTOCOL | [Ssh](src/TqkLibrary.VpnClient.Ssh/README-vi.md) | SSH-2 transport + `tun@openssh.com` channel |
| PROTOCOL | [SoftEther](src/TqkLibrary.VpnClient.SoftEther/README-vi.md) | SoftEther codec (PACK + session) |
| PROTOCOL | [IpEncap](src/TqkLibrary.VpnClient.IpEncap/README-vi.md) | GRE/IPIP/SIT codec |
| TRANSPORT | [Transport.Tcp](src/TqkLibrary.VpnClient.Transport.Tcp/README-vi.md) | Shared TCP byte-stream (F.1) |
| TRANSPORT | [Transport.Tls](src/TqkLibrary.VpnClient.Transport.Tls/README-vi.md) | TLS byte-stream (wraps TCP) |
| TRANSPORT | [Transport.Dtls](src/TqkLibrary.VpnClient.Transport.Dtls/README-vi.md) | DTLS 1.2 datagram (OpenConnect) |
| TRANSPORT | [Transport.RawIp](src/TqkLibrary.VpnClient.Transport.RawIp/README-vi.md) | Raw socket for an arbitrary IP protocol (ESP-50/GRE-47…) — needs elevation |
| CRYPTO | [Crypto](src/TqkLibrary.VpnClient.Crypto/README-vi.md) | AES-CBC/CTR/GCM, ChaCha20-Poly1305, DH MODP, X25519, BLAKE2s, HKDF/Noise, HMAC-PRF, MD4, DES |
| CORE | [Abstractions](src/TqkLibrary.VpnClient.Abstractions/README-vi.md) | Contracts + models + enums (bottom of the dependency graph) |

## Status

| Item | Status |
|---|---|
| MS-SSTP, L2TP/IPsec | ✅ Live on **VPN Gate** (real internet): keepalive/rekey/teardown/auto-reconnect; L2TP/IPsec includes IPv6-in-tunnel, outer IPv6, Phase 1 rekey (forced NAT-T + native ESP), multi-session |
| IKEv2-native, Cisco IPsec/EzVPN | ✅ Live (Docker lab, strongSwan): PSK/EAP, Aggressive+XAUTH+Mode-Config, ESP tunnel; long-timer live-rekey is residual |
| OpenVPN, WireGuard, SoftEther, OpenConnect | ✅ Live (Docker lab, open-source servers): full tunnel + make-before-break rekey; OpenConnect includes a DTLS 1.2 data plane |
| Nebula, tinc, ZeroTier, n2n, Tailscale | ✅ Live (Docker lab, real daemons): full two-way L2/L3 overlay; n2n includes header encryption `-H` |
| vtun, VPN-over-SSH, GRE/IPIP/SIT (IpEncap) | ✅ Live (Docker lab): vtun (both encrypt + tap mode), SSH `tun@openssh.com`, GRE/IPIP/SIT two-way for all three kinds |
| PPTP | ⏳ Built + offline-tested; live pending raw-IP proto-47 + elevation (legacy/interop) |
| Userspace TCP/IP (IPv4+IPv6, full TCP, UDP, ICMP/ICMPv6) | ✅ Complete |
| IPv6 in the tunnel (IPV6CP for PPP; SLAAC/DHCPv6/NDISC for L2) | ✅ Implemented + validated live |
| L2 Ethernet fabric (switch + VirtualHost + ARP + NDISC/SLAAC/DHCP) | ✅ Used for real by SoftEther/OpenVPN-tap/n2n/ZeroTier/tinc/vtun |

> The roadmap (work **not yet** done) is in [.docs/11](.docs/11-todo-roadmap.md). The full as-built status + the proven server-side limitations are in [.docs/10](.docs/10-codebase-architecture-and-flow.md) §9 and each project's README.

## Build & test

```powershell
dotnet build                                          # green on both netstandard2.0 + net8.0
dotnet test --filter "Category!=Integration"          # the full offline test suite (live VPN Gate/lab tests are marked Integration)
```

- `record`/`init`/`required` work on both TFMs thanks to the source-only package **`TqkLibrary.CompilerServices`** (referenced in [`src/Directory.Build.props`](src/Directory.Build.props), netstandard2.0 only).
- Live tests that depend on VPN Gate / the Docker lab are marked `[Trait("Category","Integration")]` — run offline with `--filter "Category!=Integration"`.

## Documentation

- [.docs/00–09](.docs/00-architecture-overview.md) — design intent: architecture overview, the no-install constraints, protocol taxonomy, multi-host L2/L3, each protocol, crypto, the userspace stack.
- [.docs/10](.docs/10-codebase-architecture-and-flow.md) — **as-built**: architecture & runtime flow tracked against the code (with a table of differences vs the design).
- [.docs/11](.docs/11-todo-roadmap.md) — roadmap & TODO (contains only work not yet done).
- [.docs/12](.docs/12-demo-vpn2proxy.md) — the Vpn2Proxy demo as-built.
- Every project in `src/` has its own `README-vi.md` (see the table above).

> ⚠️ Some mechanisms are **legacy/weak** — used because the protocol mandates them, not for new security purposes: MS-CHAPv2/MD4/DES (SSTP/L2TP/PPTP), MPPE/RC4 + MS-CHAPv2 (PPTP — broken), IKEv1 Aggressive + group PSK (Cisco IPsec — offline dictionary attack), Blowfish-ECB (vtun). GRE/IPIP/SIT are **unencrypted** (wrap them in IPsec ESP if needed). SSTP/OpenConnect/OpenVPN **by default** accept any TLS cert (SSTP authenticates identity by crypto binding, not PKI); pass a `RemoteCertificateValidationCallback` via `UseSstp(...)`/`UseOpenConnect(...)`/`UseOpenVpn(...)` to validate the cert when needed. Use only with trusted servers.
