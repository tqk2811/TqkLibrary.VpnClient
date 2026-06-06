# 02 — Taxonomy giao thức VPN công khai

> Mỗi driver = một toạ độ trên 6 trục. Bảng này quyết định driver nào cắm ở đâu và tier triển khai.

## 6 trục phân loại

1. **Transport:** byte-stream tin cậy (TCP/TLS) | datagram (UDP) | **raw-IP proto-less** (ESP/50, GRE/47, EtherIP/97, L2TPv3/115 — cần elevate).
2. **Crypto:** TLS | DTLS | IPsec-ESP (keyed by IKE hoặc in-band) | Noise | bespoke | MPPE-RC4 | none.
3. **Framing:** length-prefix | HDLC-async | fixed-header datagram | TLV.
4. **Link layer:** L3 (IP) | L2 (Ethernet) | both.
5. **PPP hay không.**
6. **Multi-host:** single | routed-prefix (L3) | L2-broadcast-domain.

## Bảng phân loại

| Giao thức | Transport | Crypto | L2/L3 | PPP | Multi-host | C# feasible | Tier |
|---|---|---|---|---|---|---|---|
| **MS-SSTP** | TLS/443 | TLS | L3 | ✅ | 1 IP/conn | high | **0** |
| **L2TP/IPsec** | UDP/4500 (NAT-T) | ESP+IKE | L3 | ✅ | 1 (multi best-effort) | medium | **0** |
| OpenVPN (tun/tap) | UDP/TCP | TLS+AEAD | both | ❌ | routed / L2(tap) | high | 0 |
| SoftEther | TLS/443 (PACK) | TLS(+RC4) | L2 | ❌ | L2 multi-MAC | medium | 0 |
| WireGuard | UDP | Noise IKpsk2 | L3 | ❌ | routed (AllowedIPs) | high | 1 |
| Cisco AnyConnect (CSTP) | TLS+DTLS | TLS/DTLS | L3 | ❌ | 1 IP/conn | high | 1 |
| Fortinet SSL (v1) | TLS(+DTLS) | TLS | L3 | ✅ | 1 IP/conn | high | 1 |
| F5 BIG-IP Edge | TLS+DTLS | TLS/DTLS | L3 | ✅ | 1 IP/conn | high | 1 |
| Nebula | UDP | Noise IX | L3 | ❌ | routed | high | 1 |
| IKEv2 route-based | UDP/4500 | ESP+IKE | L3 | ❌ | CFG / TS-routed | medium | 2 |
| Palo Alto GlobalProtect | TLS + ESP-UDP/4501 | TLS/ESP(in-band) | L3 | ❌ | 1 IP/conn | medium | 2 |
| Juniper NC (oNCP) | TLS + ESP-UDP | TLS/ESP(in-band) | L3 | ❌ | 1 IP/conn | medium | 2 |
| Pulse/Ivanti (IF-T) | TLS + ESP-UDP | TLS/ESP + EAP | L3 | ❌ | 1 IP/conn | medium | 2 |
| VXLAN | UDP/4789 | none | L2 | ❌ | L2 (VNI) | medium | 2 |
| tinc (router) | TCP-meta + UDP | SPTPS/legacy | both | ❌ | routed/L2 | medium | 2 |
| **PPTP** | TCP/1723 + **GRE/47** | MPPE-RC4 (hỏng) | L3 | ✅ | Call-ID mux | medium\* | 3† |
| IKEv1 IPsec | UDP/4500 | ESP+IKEv1 | L3 | ❌ | CFG/TS | low | 3 |
| GRE / EtherIP / L2TPv3 | **raw-IP** | none(+IPsec) | L3/L2 | ❌ | routed/L2 | low | 3† |
| Array Networks | TLS+DTLSv1.0 | TLS/DTLS | L3 | ❌ | 1 IP/conn | medium | 3 |
| ZeroTier | UDP (custom) | Salsa20/AES-GMAC-SIV | L2 | ❌ | L2 planet-scale | low | 3 |

\* PPTP feasible *về logic* nhưng data plane = Enhanced-GRE/47 → **cần raw socket (elevate)**.
† **Tier 3† = nhánh `Transport.RawIp` cần đặc quyền** (xem `01-constraint-no-install.md`). Windows-receive bấp bênh.

## Tier triển khai

- **Tier 0** (đã chốt làm): L2TP/IPsec, MS-SSTP → dựng PPP engine, TLS/UDP transport, IKE+ESP, reliability layer, IpStack, Sockets.
- **Tier 1** (sau v1, userspace-thuần dễ): WireGuard, AnyConnect-CSTP, Fortinet, F5, Nebula.
- **Tier 2** (1 subsystem nặng): IKEv2, GlobalProtect, Juniper, Pulse, VXLAN, tinc.
- **Tier 3** (raw-IP/legacy/bespoke, opt-in elevate): PPTP, IKEv1, GRE, EtherIP, L2TPv3, ZeroTier, Array.

## Khối dùng chung (DLL) ↔ giao thức

| Khối | DLL | Dùng bởi |
|---|---|---|
| PPP engine | `Ppp(+Framing+Auth)` | L2TP, SSTP, PPTP, Fortinet, F5 |
| IKE | `Ipsec.Ike` | L2TP/IPsec, IKEv2, IKEv1, GRE-over-IPsec |
| ESP | `Ipsec.Esp` | L2TP/IPsec, IKEv2/v1, Juniper, Pulse, GlobalProtect |
| ESP-in-UDP NAT-T | `Transport.Udp` | mọi ESP-over-UDP |
| TLS transport | `Transport.Tls` | SSTP, SoftEther, OpenVPN-tcp, mọi SSL-VPN |
| DTLS | `Transport.Dtls` | AnyConnect, F5, Array, Fortinet |
| Noise | `Crypto.Noise` | WireGuard, Nebula |
| MPPE | `Crypto.Mppe` | PPTP, SSTP-optional |
| Reliability | `Reliability` | L2TP, L2TPv3, PPTP-control, oNCP, IF-T |
| Ethernet adapter | `Ethernet` | SoftEther, OpenVPN-tap, VXLAN, EtherIP, L2TPv3-ETH, ZeroTier, tinc-switch |
| Raw-IP transport | `Transport.RawIp` | PPTP, GRE, EtherIP, L2TPv3, native-ESP |

Nguồn chi tiết: xem `references.md` và các file `04`–`07`.
