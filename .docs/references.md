# References — nguồn tham chiếu (đã verify đối kháng)

## PPP / L2TP / SSTP (Tier 0)
- RFC 1661 PPP — https://www.rfc-editor.org/rfc/rfc1661.html
- RFC 1662 PPP HDLC framing — https://datatracker.ietf.org/doc/html/rfc1662
- RFC 1332 IPCP — https://www.rfc-editor.org/rfc/rfc1332.html
- RFC 1877 IPCP DNS/NBNS — https://datatracker.ietf.org/doc/html/rfc1877
- RFC 2759 MS-CHAPv2 — https://datatracker.ietf.org/doc/html/rfc2759
- RFC 2661 L2TPv2 — https://www.rfc-editor.org/rfc/rfc2661.txt
- [MS-SSTP] overview — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/70adc1df-c4fe-4b02-8872-f1d8b9ad806a
- [MS-SSTP] packet 2.2.1 — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/2991892f-fefc-4129-adac-cd6a5d04bb48

## IPsec / IKE / ESP / NAT-T
- RFC 7296 IKEv2 — https://datatracker.ietf.org/doc/html/rfc7296
- RFC 4301 IPsec architecture — https://datatracker.ietf.org/doc/html/rfc4301
- RFC 4303 ESP — https://datatracker.ietf.org/doc/html/rfc4303
- RFC 3948 UDP-encap ESP (NAT-T) — https://datatracker.ietf.org/doc/html/rfc3948
- RFC 2409 IKEv1 — https://datatracker.ietf.org/doc/html/rfc2409
- RFC 3526 MODP DH groups — https://datatracker.ietf.org/doc/html/rfc3526
- strongSwan NAT-T — https://docs.strongswan.org/docs/latest/features/natTraversal.html
- L2TP/IPsec server behind NAT-T (AssumeUDPEncapsulationContextOnSendRule) — https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-l2tp-ipsec-server-behind-nat-t-device

## OpenVPN (Tier 1)
- Wire protocol (WIP RFC) — https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html
- Network protocol doxygen — https://build.openvpn.net/doxygen/network_protocol.html
- Cipher negotiation — https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/cipher-negotiation.rst

## SoftEther (Tier 0/L2)
- Spec — https://www.softether.org/3-spec
- Comm protocol 2.1 — https://www.softether.org/4-docs/1-manual/2._SoftEther_VPN_Essential_Architecture/2.1_VPN_Communication_Protocol
- SecureNAT/Virtual DHCP/NAT 3.7 — https://www.softether.org/4-docs/1-manual/3/3.7
- Virtual Hub security (Max-MAC) 3.5 — https://www.softether.org/4-docs/1-manual/3._SoftEther_VPN_Server_Manual/3.5_Virtual_Hub_Security_Features
- Source — https://github.com/SoftEtherVPN/SoftEtherVPN
- go-softether (PoC client) — https://github.com/march1993/go-softether

## Modern / overlay (Tier 1–3)
- WireGuard protocol — https://www.wireguard.com/protocol/
- WireGuard paper — https://www.wireguard.com/papers/wireguard.pdf
- Noise framework — https://noiseprotocol.org/noise.html
- RFC 8439 ChaCha20-Poly1305 — https://www.rfc-editor.org/rfc/rfc8439
- Nebula — https://github.com/slackhq/nebula
- ZeroTier protocol — https://docs.zerotier.com/protocol/
- tinc SPTPS — http://tinc-vpn.org/documentation-1.1/Simple-Peer_002dto_002dpeer-Security.html

## OpenConnect family (Tier 1–3, RE'd)
- OpenConnect — https://www.infradead.org/openconnect/
- Cisco AnyConnect draft — https://www.ietf.org/archive/id/draft-mavrogiannopoulos-openconnect-04.html
- Fortinet — https://www.infradead.org/openconnect/fortinet.html ; openfortivpn — https://github.com/adrienverge/openfortivpn
- F5 — https://www.infradead.org/openconnect/f5.html
- Juniper oNCP — https://www.infradead.org/openconnect/juniper.html
- Pulse — https://www.infradead.org/openconnect/pulse.html
- GlobalProtect — https://github.com/dlenski/openconnect/blob/master/PAN_GlobalProtect_protocol_doc.md

## L2 pseudowire / tunneling (Tier 3, raw-IP)
- RFC 2637 PPTP — https://datatracker.ietf.org/doc/html/rfc2637
- RFC 3078 MPPE — https://www.rfc-editor.org/rfc/rfc3078
- RFC 3079 MPPE key derivation — https://datatracker.ietf.org/doc/html/rfc3079
- RFC 2784 GRE — https://datatracker.ietf.org/doc/html/rfc2784
- RFC 3378 EtherIP — https://www.rfc-editor.org/rfc/rfc3378.html
- RFC 3931 L2TPv3 — https://datatracker.ietf.org/doc/html/rfc3931
- RFC 7348 VXLAN — https://datatracker.ietf.org/doc/rfc7348/

## Userspace stack precedent
- gVisor netstack — https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/stack
- smoltcp Medium — https://docs.rs/smoltcp/latest/smoltcp/phy/enum.Medium.html
- lwIP netif — https://www.nongnu.org/lwip/2_1_x/group__netif.html
- gvisor-tap-vsock — https://github.com/containers/gvisor-tap-vsock
- RFC 6298 TCP RTO — https://datatracker.ietf.org/doc/html/rfc6298

## Userspace / raw socket constraint
- MS TCP/IP raw sockets — https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2
- Linux raw(7) — https://man7.org/linux/man-pages/man7/raw.7.html
- .NET SocketType — https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.sockettype
