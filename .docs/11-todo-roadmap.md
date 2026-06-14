# 11 — Roadmap & TODO (chỉ chứa việc chưa làm)

> **Mục tiêu dài hạn: clone lại mọi VPN opensource** thành driver userspace thuần .NET trong thư viện này
> (đối chiếu plan gốc `wild-stargazing-spark.md` + as-built [`10-codebase-architecture-and-flow.md`](10-codebase-architecture-and-flow.md)).
> Lộ trình: **P0** dọn kiến trúc → **P1** hoàn thành 100% SSTP + L2TP/IPsec (kể cả IPv6) → **F** nền dùng chung
> đa-VPN (điểm chung ưu tiên đứng sau interface, tái sử dụng tối đa) → **V** từng driver VPN mới theo thứ tự
> tái-dùng-tối-đa → **L2** tầng Ethernet còn lại → **Q** chất lượng/hạ tầng (chạy song song).
>
> **Quy ước** (theo [CLAUDE.md](../CLAUDE.md)): mục hoàn thành thì **xóa khỏi file này** — không đánh dấu
> `[x]`/✅; trạng thái as-built ghi ở file `10` + README từng project.

---

## P0 — Dọn kiến trúc & nợ review 2026-06-12 (làm trước nhất)

> Kết quả review kiến trúc 12/06/2026 (đọc toàn bộ `.md` + đối chiếu code). **Đây là plan — chưa sửa code.**
> Khi thực hiện: tuân thủ 2 quy ước trong [CLAUDE.md](../CLAUDE.md) (**hạn chế hàm static**; **tái sử dụng
> tối đa, không viết lại tính năng có sẵn**), và mỗi mục xong phải cập nhật [`10`](10-codebase-architecture-and-flow.md)
> + README project bị ảnh hưởng.

- [ ] **P0.8 — Fallback khi gateway từ chối forced-NAT-T** (rủi ro #1 plan gốc): **(a) phân loại lỗi + (b) honest-first đã xong** (as-built ở [`10`](10-codebase-architecture-and-flow.md) §6 bước 1-3/§9): (a) [`IkeV1Client.TryReadRejectNotify`](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs#L18) — NOTIFY lỗi ⇒ `VpnServerRejectedException`, im lặng sau float 4500 ⇒ `VpnNetworkTimeoutException` nghi forced-NAT-T; (b) opt-in [`L2tpIpsecNatTraversalMode.HonestFirst`](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/Enums/L2tpIpsecNatTraversalMode.cs) — bind cổng 500 thật + NAT-D trung thực + [`IkeV1Client.DetectNat`](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs#L183) → *có NAT* float 4500, *không NAT*/không-bind-được ⇒ fallback forced (test offline [`IkeV1NatDetectionTests`](../tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/IkeV1NatDetectionTests.cs) + `IkeV1HandshakeTests`). **Còn lại — (c) native ESP proto-50** cho gateway IP-public không-NAT: gửi ESP gốc (IP proto-50) qua **F.9** `Transport.RawIp` (raw socket — **bắt buộc admin**, không có đường userspace cho proto-50); **chỉ chạy khi IP-public** (NAT chặn proto-50). **Đổi ràng buộc design `01`: no-admin → no-install** (admin chỉ cho nhánh (c); ghi bảng 'Khác biệt' ở [`10`](10-codebase-architecture-and-flow.md) khi build (c)). **Cần lab Docker Q.1** kiểm chứng từng server: (b) trước khi đổi default live ForcedNatT→HonestFirst, và (c).

---

## P1 — Hoàn thành 100% SSTP + L2TP/IPsec (kể cả IPv6)

> Mục tiêu: 2 driver đang chạy live **không còn hạng mục dở** trước khi mở driver mới. Lưu ý mục
> P0.8 cũng thuộc 2 driver này nhưng nằm ở §P0 (làm trước; P0.6/P0.7 + P0.8a/b đã xong, còn P0.8c chờ lab Q.1).

- [ ] **P1.1 — IPv6 trong tunnel (IPV6CP, RFC 5072)** — bật IPv6 end-to-end qua SSTP/L2TP. IP stack **đã dual-stack**, chỉ thiếu **nguồn địa chỉ IPv6**: PPP hiện chỉ chạy IPCP ([IpcpNegotiator.cs:32](../src/TqkLibrary.Vpn.Ppp/IpcpNegotiator.cs#L32)); số hiệu `Ipv6cp = 0x8057` ([PppProtocol.cs:28](../src/TqkLibrary.Vpn.Ppp/Framing/Enums/PppProtocol.cs#L28)) đã khai báo nhưng **chưa có negotiator**. Việc: (1) **IPV6CP negotiator** thương lượng Interface-Identifier → địa chỉ link-local `fe80::/64`; (2) địa chỉ **global** qua SLAAC-từ-RA trên link hoặc DHCPv6 (tùy server — tái dùng codec NDISC khi có **L2.4**); (3) thêm `AssignedAddressV6` ở [`PppEngine`](../src/TqkLibrary.Vpn.Ppp/PppEngine.cs#L60) + [`TunnelConfig`](../src/TqkLibrary.Vpn.Abstractions/Drivers/Models/TunnelConfig.cs#L12), dựng stack qua overload dual-stack [`TcpIpStack(channel, v4, v6)` @ :49](../src/TqkLibrary.Vpn.IpStack/TcpIpStack.cs#L49) ở **cả 2 driver**; (4) demo bật `IsSupportIpv6=true` + bỏ chặn đích IPv6 ở `VpnConnectSource`/`VpnUdpAssociateSource`. **Rủi ro**: đa số server VPN Gate chỉ cấp IPv4 ⇒ test live cần lab (**Q.1**, SoftEther/RRAS bật IPv6 pool).
- [ ] **P1.2 — Outer IPv6 (kết nối tới server qua IPv6)**: SSTP — `TcpClient` connect theo `AddressFamily` của endpoint/AAAA; L2TP/IPsec — kiểm tra + bổ sung socket UDP IPv6 ở `NatTraversal` (IKE/NAT-T trên UDP/IPv6 vẫn là UDP encap bình thường; checksum UDP **bắt buộc** trên v6). Resolve hostname: chọn họ địa chỉ (ưu tiên theo config, fallback họ còn lại). Test qua lab dual-stack.
- [ ] **P1.3 — Rekey Phase 1 in-place (IKEv1)**: hiện Phase 1 hết hạn (~8h) xử lý **by-reconnect** (gián đoạn ngắn) — làm re-Main-Mode in-place + chuyển Phase 2/ESP sang ISAKMP SA mới, không rớt tunnel (mirror mô hình make-before-break của Phase 2 rekey sẵn có).
- [ ] **P1.7 — Multi-session per tunnel (L2TP)**: `OpenSessionAsync` hiện ném `NotSupportedException` ([L2tpIpsecVpnConnection.cs:22-23](../src/TqkLibrary.Vpn.Drivers.L2tpIpsec/L2tpIpsecVpnConnection.cs#L22-L23)). RFC 2661 cho 1 tunnel mang nhiều session (ICRQ/ICRP/ICCN, dùng lại cùng IKE/IPsec SA, mỗi session = 1 PPP = 1 IP) — cần `L2tpClient` mở thêm session + nhiều `PppEngine`/`IpStack`. **Best-effort theo server** (đa số remote-access server chỉ cho 1 session; design `03`). SSTP **strictly 1:1** (header không có session ID — không mux được, giữ `NotSupportedException` + docs).

---

## F — Nền dùng chung đa-VPN (foundation)

> Nguyên tắc: **điểm chung giữa các driver phải đứng sau interface trong `Abstractions`**, concrete đặt ở
> project dùng chung; **interface chỉ thiết kế từ ≥2 consumer thật** (bài học P0.1 — không thiết kế chay).
> Mỗi mục F làm **đúng lúc driver V đầu tiên cần nó**, không làm trước hàng loạt.

- [ ] **F.1 — `Transport.Tcp`/`Transport.Tls`** (implement [`IByteStreamTransport`](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs)): nâng [`TlsByteStream`](../src/TqkLibrary.Vpn.Drivers.Sstp/Transport/TlsByteStream.cs#L20) (đã tách ở P0.1 trong driver SSTP) ra project dùng chung + cert-callback (P0.6). Consumer: SSTP, SoftEther (V.4), OpenConnect CSTP (V.5), OpenVPN-TCP (V.2).
- [ ] **F.2 — Tái thiết kế `ISecuritySession` + `IPacketEncapsulator`** (sau khi P0.1 xóa bản cũ): thiết kế từ consumer thật — `ISecuritySession`: [`EspSession`](../src/TqkLibrary.Vpn.Ipsec/Esp/EspSession.cs) + WireGuard transport keys (V.3) + OpenVPN data channel (V.2) (+ MPPE V.6); shape phải có `TryUnprotect` bool + slot rekey/sequence như ESP đã chứng minh. `IPacketEncapsulator`: SSTP 4-byte framing + OpenVPN packet framing (opcode/key-id + 2-byte length trên TCP) + CSTP 8-byte header (V.5). Làm cùng driver V đầu tiên chạm tới.
- [ ] **F.3 — `Transport.Dtls`** (implement [`IDatagramTransport`](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IDatagramTransport.cs)): DTLS client qua BouncyCastle (cả 2 TFM — `SslStream` không làm DTLS). Consumer: OpenConnect-family data path (V.5).
- [ ] **F.4 — `Crypto.Noise`**: X25519 (implement [`IDhGroup`](../src/TqkLibrary.Vpn.Crypto/Interfaces/IDhGroup.cs) — IANA group 31, BouncyCastle ns2.0), ChaCha20-Poly1305 (implement [`IAeadCipher`](../src/TqkLibrary.Vpn.Crypto/Interfaces/IAeadCipher.cs) — `System.Security.Cryptography.ChaCha20Poly1305` net8.0 + BouncyCastle fallback, **mô hình y hệt AES-GCM shim sẵn có**), BLAKE2s (implement [`IHashAlgo`](../src/TqkLibrary.Vpn.Crypto/Interfaces/IHashAlgo.cs)), HKDF-Noise trên [`PrfPlus`](../src/TqkLibrary.Vpn.Crypto/PrfPlus.cs)-style; state machine Noise_IKpsk2. Consumer: WireGuard (V.3), Nebula (V.7). Test vector từ whitepaper WireGuard + Noise spec.
- [ ] **F.5 — Crypto legacy bổ sung**: MPPE/RC4 (PPTP V.6), SHA-0 (SoftEther auth V.4), TLS-PRF/`tls-ekm` RFC 5705 (OpenVPN key derivation V.2 — kiểm tra `SslStream` có export keying material không, net8.0 có `TlsExporter`?; không có ⇒ BouncyCastle TLS).
- [ ] **F.6 — Tách scaffolding supervisor/reconnect/keepalive dùng chung**: 2 driver hiện **duplicate** cùng mô hình (`EstablishAsync`/`ReconnectLoopAsync`/backoff jitter/`StateChanged`/[SwappablePacketChannel](../src/TqkLibrary.Vpn.Abstractions/Channels/SwappablePacketChannel.cs)/guard `_attemptId`) — trừu tượng hóa thành base class/helper (Abstractions hoặc project `Drivers.Core`) **thiết kế từ 2 consumer thật sẵn có**, để 6+ driver mới không chép lần 3. Reconnect/timeout options gom về model chung (hiện `L2tpIpsecReconnectOptions`/`SstpReconnectOptions` gần trùng nhau).
- [ ] **F.7 — IKEv2 hoàn thiện protocol-level** (hiện chỉ có IKE_SA_INIT + IKE_AUTH; `CreateChildSa`/`Informational`/`Eap` **mới có enum**, chưa có logic client): (1) **Configuration Payload (CP)** model — nhận virtual IP/DNS (hiện chỉ `RawPayload`) → [Ipsec/Ike/V2/Payloads/](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/Payloads/); (2) **INFORMATIONAL** — DPD (liveness) + DELETE (teardown); (3) **CREATE_CHILD_SA** — rekey CHILD SA + IKE SA (make-before-break, mirror mô hình IKEv1 Phase 2 rekey sẵn có); (4) **EAP-MSCHAPv2** (tái dùng MS-CHAPv2 từ Ppp) — để sau cùng, PSK trước. Consumer: V.1.
- [ ] **F.8 — ESP tunnel mode**: `nextHeader` **đã tham số hóa** ([EspSession.Protect @ :39](../src/TqkLibrary.Vpn.Ipsec/Esp/EspSession.cs#L39), trailer RFC 4303 sẵn) — chỉ cần đường wire payload = **full IP packet** với `nextHeader=4` (IPv4-in-ESP) / `41` (IPv6), decap demux theo nextHeader → đẩy thẳng `IPacketChannel` (không PPP/L2TP). Chi phí thấp. Consumer: V.1, P0.8c.
- [ ] **F.9 — `Transport.RawIp`** (opt-in, cần elevate, tự detect quyền Administrators/CAP_NET_RAW): raw socket IP protocol tùy ý — **đường duy nhất** gửi/nhận protocol tùy chọn (ESP-50, GRE-47…) trong userspace. **Ràng buộc design `01` đổi: no-admin → no-install** ⇒ admin/raw nay là **tùy chọn hạng nhất** (bỏ 'ngoại lệ'), kích hoạt khi consumer cần; chênh lệch ghi bảng 'Khác biệt' [`10`](10-codebase-architecture-and-flow.md). Consumer: PPTP/GRE (V.6), native ESP proto-50 (P0.8c), EtherIP/L2TPv3 (tương lai).

### Ma trận tái dùng (driver × thành phần)

| Driver | Transport | Bảo mật data plane | Framing | PPP | L2 fabric | Nền cần |
|---|---|---|---|---|---|---|
| SSTP (live) | TCP+TLS → F.1 | TLS | SSTP 4-byte | ✅ | — | — (P0.6 ✓) |
| L2TP/IPsec (live) | UDP `Ipsec/Nat` | ESP transport | L2TP + HDLC-PPP | ✅ | — | — |
| IKEv2-native (V.1) | UDP `Ipsec/Nat` | **ESP tunnel** | non-ESP marker (có sẵn) | — | — | F.7 F.8 |
| OpenVPN (V.2) | UDP + TCP (F.1) | OpenVPN DC (F.2) | opcode/key-id (F.2) | — | tap-mode: L2.x | F.1 F.2 F.5 |
| WireGuard (V.3) | UDP | Noise (F.4) | WG 4-type header | — | — | F.4 |
| SoftEther (V.4) | TCP+TLS (F.1) | TLS | PACK codec | — | **✅ cần** L2.5+ | F.1 F.5 L2 |
| OpenConnect (V.5) | TLS (F.1) + DTLS (F.3) | TLS/DTLS | CSTP 8-byte (F.2) | — | — | F.1 F.2 F.3 |
| PPTP (V.6) | RawIP/GRE (F.9) | MPPE (F.5) | GRE | ✅ | — | F.5 F.9 |

> Điểm tái dùng lớn: **PPP** phục vụ 3 driver (SSTP/L2TP/PPTP); **ESP + Nat (NAT-T)** phục vụ 2 (L2TP/IPsec, IKEv2);
> **TLS transport** phục vụ 4 (SSTP/OpenVPN-TCP/SoftEther/OpenConnect); **L2 fabric** phục vụ SoftEther + OpenVPN-tap;
> **IpStack/Sockets/SwappablePacketChannel/supervisor (F.6)** phục vụ tất cả.

---

## V — Driver VPN opensource mới (thứ tự tái-dùng-tối-đa)

- [ ] **V.1 — IKEv2-native** (tương thích strongSwan/libreswan; **rẻ nhất** — protocol đã build): driver `Drivers.Ikev2` mới — IKE_SA_INIT + IKE_AUTH (PSK trước) → **CP** nhận virtual IP/DNS (F.7) → **ESP tunnel mode** (F.8) → `IPacketChannel` trực tiếp (**không PPP**); NAT-T detect + float 4500 (tái dùng [`NatDetection`](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/NatDetection.cs) + `Ipsec/Nat`); keepalive DPD + rekey CHILD_SA (F.7) + teardown DELETE; supervisor/reconnect tái dùng F.6. Sau cùng: EAP-MSCHAPv2 cho server username/password. Lab: strongSwan Docker (Q.1).
- [ ] **V.2 — OpenVPN** (tương thích OpenVPN community server, làm theo phase):
  - [ ] **V2.a** control-channel **reliability layer** (packet-id + ACK + retransmit — đặc thù OpenVPN, chạy trên cả UDP lẫn TCP);
  - [ ] **V2.b** TLS handshake **bên trong** control channel: `SslStream` trên `Stream`-bridge in-memory nối vào reliability layer (fallback BouncyCastle TLS nếu cần export keying material — F.5);
  - [ ] **V2.c** `tls-auth` (HMAC bọc control packet) + `tls-crypt` (mã hóa control packet);
  - [ ] **V2.d** key derivation (key method 2 TLS-PRF / `tls-ekm` — F.5) + **data channel** AES-256-GCM (tái dùng [`AesGcmCipher`](../src/TqkLibrary.Vpn.Crypto/Aead/AesGcmCipher.cs)) + packet-id anti-replay (mirror mô hình anti-replay ESP) — consumer thật cho `ISecuritySession` F.2;
  - [ ] **V2.e** PUSH_REQUEST/PUSH_REPLY (ifconfig/route/DNS → [`TunnelConfig`](../src/TqkLibrary.Vpn.Abstractions/Drivers/Models/TunnelConfig.cs)); topology `subnet`/`net30`; keepalive ping/ping-restart; **soft-reset renegotiation** (TLS rekey make-before-break — mirror swap `EspSession`);
  - [ ] **V2.f** NCP cipher negotiation (`data-ciphers`); nén: chào **stub no-compression** (`comp-lzo no`);
  - [ ] **V2.g** transport TCP (2-byte length framing — consumer `IPacketEncapsulator` F.2) sau khi UDP chạy; **tap-mode** (Ethernet frame trong data channel → cắm L2 fabric) sau tun-mode.
  - Lab: OpenVPN server Docker (Q.1). Tham chiếu: doc protocol OpenVPN (openvpn.net + source GPL **chỉ đọc spec/behavior, không copy code**).
- [ ] **V.3 — WireGuard**: Noise_IKpsk2 (F.4) handshake initiation/response (đúng từng byte — có test vector), cookie-reply chống DoS, **timers chuẩn whitepaper** (Rekey-After-Time 120s, Reject-After-Time 180s, Rekey-Attempt-Time, persistent-keepalive), data: counter nonce + sliding-window anti-replay (mirror ESP), MTU mặc định 1420; config tĩnh (private key, peer pubkey, preshared, endpoint, allowed-ips) → `TunnelConfig` tĩnh (không IPCP/DHCP); 1 peer allowed-ips `0.0.0.0/0, ::/0` = point-to-point `IPacketChannel` (khớp mô hình hiện tại — multi-peer routing để sau). Dual-stack inner sẵn (stack đã v4+v6). Lab: WireGuard Docker (Q.1).
- [ ] **V.4 — SoftEther SSL-VPN** (re-implement từ protocol behavior/spec, **không copy GPL source**): HTTPS watermark POST + **PACK codec** (binary serialization riêng) + auth password (SHA-0 — F.5) + session multi-connection over TLS (F.1); data plane = **Ethernet frame over TLS** ⇒ **driver L2 thật đầu tiên**: sinh `IEthernetChannel` cắm vào L2 fabric — cần tối thiểu **L2.5 DHCPv4** (SecureNAT cấp IP qua DHCP) + ARP (L2.3 ✅) + `VirtualHost` (L2.2 ✅) → `IPacketChannel`; full multi-host cần L2.7 `EthernetAdapter`. Lab: SoftEther server chính chủ (Q.1 — cũng phục vụ test L2TP/SSTP).
- [ ] **V.5 — OpenConnect-family** (chuẩn mở AnyConnect; server opensource **ocserv**): HTTPS auth (XML/form → cookie) → **CSTP** (HTTP CONNECT + header `X-CSTP-*`, framing 8-byte — consumer `IPacketEncapsulator` F.2) over TLS (F.1) → IP packet thẳng (không PPP); **DTLS data path** song song (F.3, fallback TLS khi DTLS fail); keepalive/DPD theo `X-CSTP-DPD`; rekey theo `X-CSTP-Rekey-Method`. Mở rộng sau: dialect Fortinet/F5/GlobalProtect (cùng họ TLS+DTLS, khác handshake HTTP). Lab: ocserv Docker (Q.1).
- [ ] **V.6 — PPTP** (accel-ppp/poptop; **legacy, ưu tiên cuối**): TCP/1723 control (Start-Control-Connection/Outgoing-Call) + data **GRE proto 47** → cần `Transport.RawIp` (F.9, elevate opt-in); PPP **tái dùng nguyên** (LCP/MS-CHAPv2/IPCP) + thêm **CCP negotiator + MPPE** RC4 (F.5). Ghi rõ cảnh báo bảo mật (MS-CHAPv2+MPPE đã bị phá — chỉ để tương thích).
- [ ] **V.7 — Khảo sát thêm (chưa cam kết)**: **Nebula** (Noise — tái dùng F.4), **ZeroTier** (L2, crypto riêng Salsa20/Poly1305), **tinc**, **n2n**; **Tailscale** = data plane WireGuard (V.3) + control plane riêng (coordination server — khác bài toán). **Ngoài phạm vi** (proxy, không phải VPN tunnel L3/L2 — không làm): Shadowsocks/Outline, V2Ray/Xray, Hysteria.

---

## L2 — Tầng Ethernet còn lại (LAN ảo multi-host)

> L2.0 codec + L2.1 `EthernetSwitch` + L2.2 `VirtualHost` + L2.3 ARP **đã xong** (as-built: [`10`](10-codebase-architecture-and-flow.md) + [README Ethernet](../src/TqkLibrary.Vpn.Ethernet/README-vi.md)).
> Quy tắc vàng giữ nguyên: IpStack chỉ bind `IPacketChannel`, mọi ARP/ND/DHCP nằm trong tầng L2.
> **Driver L2 thật** tiêu thụ fabric này: SoftEther (V.4), OpenVPN tap-mode (V2.g).

- [ ] **L2.4 — NDISC (IPv6 neighbor)** `INeighborResolver` v6: codec ICMPv6 NS/NA (tái dùng [`Icmpv6`](../src/TqkLibrary.Vpn.IpStack/Icmpv6.cs#L7)), solicited-node multicast, neighbor cache, DAD; parse RS/RA lấy gateway/prefix (RFC 4861) — RA cũng phục vụ **P1.1** (SLAAC global address). Hook seam [`VirtualHost.InboundNonIpFrame`](../src/TqkLibrary.Vpn.Ethernet/VirtualHost.cs#L66) như ARP. **Phụ thuộc L2.2.**
- [ ] **L2.5 — DHCPv4 client** `IAddressConfigurator`: DISCOVER/OFFER/REQUEST/ACK qua Ethernet/UDP broadcast → lease IP/gw/DNS (RFC 2131); khớp SoftEther SecureNAT virtual-DHCP ([`07`](07-softether.md)) — **chặn đường V.4**. **Phụ thuộc L2.2 + L2.3.**
- [ ] **L2.6 — SLAAC + DHCPv6 client** `IAddressConfigurator` v6: SLAAC từ RA (RFC 4862) + DHCPv6 stateful tùy chọn (RFC 8415). **Phụ thuộc L2.4.**
- [ ] **L2.7 — `EthernetAdapter` ráp**: compose `EthernetSwitch` + N×`VirtualHost`{MAC, resolver, configurator} sau `EthernetAdapter` (IPacketChannel-provider); backpressure (design `09`). **Phụ thuộc L2.2–L2.6.**
- [ ] **L2.8 — Năng lực + multi-host session**: bật `VpnLinkLayer.L2Ethernet` + `MultiHostModel.L2BroadcastDomain`; model N VirtualHost = N "máy LAN". **Phụ thuộc L2.7.**
- [ ] **L2.9 — Test + docs**: kịch bản multi-host ARP/ND/DHCP **dual-stack** qua switch in-memory; cập nhật [`10`](10-codebase-architecture-and-flow.md) + đồng bộ `00`–`09` + README. **Phụ thuộc tất cả.**

---

## Q — Chất lượng / hạ tầng (chạy song song mọi giai đoạn)

- [ ] **Q.1 — Lab server Docker** thay server công khai (VPN Gate flaky): compose strongSwan (IKEv1/IKEv2/IPsec) + SoftEther (SSTP/L2TP + SSL-VPN + IPv6 pool) + OpenVPN + WireGuard + ocserv — phục vụ integration test ổn định cho **mọi** driver hiện tại lẫn V.x, và là điều kiện test của P0.8/P1.1/P1.2/P1.7.
- [ ] **Q.2 — Logging/diagnostics xuyên suốt** (trace handshake, drop reason) — chuẩn `ILoggerFactory` như demo đã làm, đưa vào các driver/protocol.
- [ ] **Q.3 — Review cancellation/timeout & thread-safety toàn cục** (các receive-loop, channel).
- [ ] **Q.4 — Hiệu năng data plane (zero-alloc + backpressure)**: design `09` đặt mục tiêu `ArrayPool`/`IMemoryOwner`/span không-alloc-mỗi-gói + `System.Threading.Channels`/Pipe để backpressure rõ. Hiện data plane copy `byte[]` mỗi gói (`System.IO.Pipelines` mới chỉ ref ở [Directory.Build.props](../src/Directory.Build.props), chưa dùng) — đo + tối ưu khi cần throughput.
- [ ] **Q.5 — CI đa OS** (plan M0): đã có workflow GitHub Actions Linux ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) build 2 TFM + chạy offline suite trên push/PR `master`/`dev` (as-built ở [`10`](10-codebase-architecture-and-flow.md)). **Còn lại**: mở rộng matrix sang Windows/macOS + (sau Q.1) job integration lab.
- [ ] **Q.6 — Adapter proxy tách project**: hiện inline trong [`demo/Vpn2ProxyDemo`](../demo/Vpn2ProxyDemo) ([`12`](12-demo-vpn2proxy.md)) — `IConnectSource` + `IUdpAssociateSource` + probe DNS. Còn thiếu: BIND (không khả thi với VPN Gate — [`12`](12-demo-vpn2proxy.md) §5), resolve host qua tunnel (hiện dùng DNS của host), IPv6 (chờ **P1.1**). Nếu cần tái dùng → tách thành `TqkLibrary.Vpn.Proxy`.
- [ ] **Q.7 — NuGet packaging** nếu phát hành: version (GitVersion), `GenerateDocumentationFile`, symbols/snupkg.
- [ ] **Q.8 — Đồng bộ design docs 00–09 ↔ as-built**: cập nhật/đánh dấu rõ design-intent theo bảng khác biệt trong [`10`](10-codebase-architecture-and-flow.md) (L2TP dùng IKEv1; không có `EspIkeDemuxTransport`; …).

---

## Gợi ý thứ tự

0. **P0** — dọn kiến trúc & nợ review (P0.8c, như §P0; **P0.1–P0.7 + P0.8a/b + P0.9 + P0.10 + P0.11 đã xong** — `IByteStreamTransport`/`TlsByteStream` seam + xóa `ISecuritySession`/`IPacketEncapsulator`; bỏ ref `Crypto` thừa ở façade; `VpnNetworkStream`/`TcpConnection.SendAsync` backpressure + propagate fault; bỏ PSK mặc định `"vpn"` khỏi `L2tpIpsecDriver` → ném `ArgumentException`, demo nhận PSK qua `?psk=`; gom `GetCapabilities`/`ConnectAsync` về 1 helper `ResolveDriver` → cùng ném `NotSupportedException`; callback `RemoteCertificateValidationCallback` tùy chọn cho SSTP qua `SstpDriver`/`UseSstp` → wire vào `SslStream`, không truyền ⇒ chấp nhận mọi cert; xác thực HASH(2) responder ở Quick Mode + rekey (`ProcessQuickMode2`/`ProcessRekeyQuickMode2`, RFC 2409 §5.5) → `VpnServerRejectedException` khi sai; **P0.8a** phân loại forced-NAT-T — `IkeV1Client.TryReadRejectNotify`: NOTIFY lỗi handshake ⇒ `VpnServerRejectedException`, im lặng post-float-4500 ⇒ `VpnNetworkTimeoutException` nghi forced-NAT-T; **P0.9** đồng bộ README Sockets với as-built TCP (reliability/NewReno/SACK/PMTUD/window-scaling đầy đủ — sửa stale "bỏ qua retransmission/SACK" + preamble RFC cited-in-code + line-drift `ConnectAsync`/`OnInbound`/`VpnNetworkStream`); **P0.10** sửa mâu thuẫn nội bộ `10` §3 (bảng hợp đồng `IEthernetChannel` ghi "chưa có implementation" → khớp §5/§9: đã có impl `EthernetSwitch.Port` nền L2.0–L2.3, chưa có driver L2 production end-to-end); **P0.11** dọn cấu trúc thư mục `IpStack/Tcp/` — chuyển `TcpIpStack` ra gốc project (namespace `TqkLibrary.Vpn.IpStack`) + `UdpConnection`/`UdpReceiveResult` sang `Udp/` (namespace `…IpStack.Udp`), **breaking nội bộ** → cập nhật `using` Sockets/demo/tests + toàn bộ link README/`10`/`11`/`12`; **P0.8b** honest-first NAT-T (opt-in `L2tpIpsecNatTraversalMode.HonestFirst` — bind cổng 500 thật + NAT-D trung thực + `DetectNat`, fallback forced; test offline); **còn P0.8c** (native ESP proto-50, F.9) chờ lab Q.1).
1. **P1** — SSTP + L2TP/IPsec đạt 100%: P1.1 IPV6CP → P1.2 outer IPv6 → P1.3 rekey Phase 1 in-place → P1.7 multi-session L2TP (best-effort) (P1.4 retransmit-backoff + P1.5 read-timeout `SstpTransport` đã xong, as-built ở [`10`](10-codebase-architecture-and-flow.md) §9 + README Sstp/L2tp/L2tpIpsec). **Q.1 lab Docker dựng sớm** trong giai đoạn này (điều kiện test P1.1/P1.2/P1.7 + P0.8).
2. **V.1 IKEv2-native** + F.7/F.8 (driver mới đầu tiên, chi phí thấp nhất — validate mô hình F + F.6 supervisor chung).
3. **V.2 OpenVPN** (tun + UDP trước) + F.1/F.2/F.5 — driver "đinh" của hệ opensource, sinh consumer thật cho contracts F.2.
4. **V.3 WireGuard** + F.4 Crypto.Noise.
5. **L2.4–L2.7** + **V.4 SoftEther** (driver L2 thật đầu tiên, kéo theo DHCP/NDISC).
6. **V.5 OpenConnect** + F.3 Transport.Dtls.
7. **V.6 PPTP** + F.9 Transport.RawIp (kèm P0.8c native ESP) — cuối cùng, legacy.
8. **Q.2–Q.8** chạy song song theo nhu cầu từng giai đoạn.
