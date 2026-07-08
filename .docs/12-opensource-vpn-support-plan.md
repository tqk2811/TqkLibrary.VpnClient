# 12 — Kế hoạch hỗ trợ VPN opensource / public-doc còn lại (chương trình theo wave)

> **Trình tự thực thi** cho backlog `V★` của [`11-todo-roadmap.md`](11-todo-roadmap.md). File `11` là backlog *phẳng* (gom theo họ); file này thêm **thứ tự**: nền dùng chung nào làm trước → mở khóa họ giao thức nào, **seam tái dùng** (kèm `file:line`), **gap crypto** nào chặn gì, và nhãn **`offline`** (test self-consistent, làm tự chủ) vs **`[LIVE]`** (cần server/interop thật).
>
> Đây là **tài liệu định hướng** — không thay `11` (mô tả từng mục ở `11`); mỗi mục dưới đây trỏ ID `↔V★`. Cập nhật khi hoàn thành: xóa mục xong khỏi `11` + ghi as-built ở [`10`](10-codebase-architecture-and-flow.md) + README project (theo [CLAUDE.md](../CLAUDE.md)).

## §0. Nguyên tắc
- **Offline-first.** Codec/handshake test được offline (round-trip byte-exact, self-consistent) → làm tự chủ bằng subagent. Cần server/interop thật để chứng minh → nhãn **`[LIVE]`**, chờ lab (VM Docker — nạp key `id_ed25519_lab5`) hoặc chỉ định của user.
- **Nền trước → họ sau.** Interface chỉ chốt shape từ **≥2 consumer thật** (bài học P0.1 — không thiết kế chay).
- **Tái dùng tối đa · clean-room** (đọc spec/RFC, KHÔNG copy code GPL/AGPL) · build xanh cả `netstandard2.0` + `net8.0`.
- Effort: **S**=nhỏ, **M**=vừa, **L**=lớn/refactor.

> **Đã xong đêm 2026-07-07** (không còn trong wave): V.20 AYIYA · V.21 FOU/GUE + GTP-U · V.22 Geneve + VXLAN-GPE + GRE-in-UDP-TEB/GRETAP/EoGRE/NVGRE · V.23 L2TPv3-eth. As-built ở [`10`](10-codebase-architecture-and-flow.md) §5/§9.

---

## §1. WAVE 0 — NỀN dùng chung (offline; mỗi mục mở khóa cả một họ)

| # | Nền | Cách làm — seam đã khảo sát | Mở khóa | Effort |
|---|---|---|---|---|
| **F.A** | **Transport-decorator seam** | Pattern wrap ĐÃ tồn tại: [`TlsByteStream:25`](../src/TqkLibrary.VpnClient.Transport.Tls/TlsByteStream.cs#L25) bọc [`TcpByteStream:59`](../src/TqkLibrary.VpnClient.Transport.Tcp/TcpByteStream.cs#L59) (phơi inner `Stream`), [`DtlsDatagramTransport:28`](../src/TqkLibrary.VpnClient.Transport.Dtls/DtlsDatagramTransport.cs#L28) bọc `IDatagramTransport`. Việc: **(a)** thêm ctor-overload nhận *inner transport* cho `TlsByteStream` + `OpenVpnSocketTransportFactory` (nay hardcode `new TcpByteStream`/`UdpDatagramSocket` bên trong ⇒ chưa chèn được lớp dưới); **(b)** luồng builder→driver-ctor nhận transport-factory tùy biến, mirror **nguyên** cách [`IRawIpTransportFactory`](../src/TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IRawIpTransportFactory.cs#L19) được luồn qua `UsePptp/UseIpEncap`. | Cả họ V.29 anti-DPI | M |
| **F.B** | **`WireGuardControlPlaneConnection` base + `IWireGuardControlPlane`** | Seam control↔data của Tailscale thu về **đúng 1 DTO** [`WireGuardConfig:20`](../src/TqkLibrary.VpnClient.WireGuard/Config/WireGuardConfig.cs#L20) (multi-peer + per-peer `Endpoint` + `acceptInbound`); adapter mẫu [`NetmapToWireGuardConfig:41`](../src/TqkLibrary.VpnClient.Tailscale/Netmap/NetmapToWireGuardConfig.cs#L41); data-plane [`WireGuardConnection:92`](../src/TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardConnection.cs#L92) **decoupled hoàn toàn** (không tham chiếu ngược control). Rút base `control.FetchConfig()→WireGuardConfig→up WG→outer-reconnect` từ [`TailscaleConnection:73`](../src/TqkLibrary.VpnClient.Drivers.Tailscale/TailscaleConnection.cs#L73) (đang hand-rolled ~90% cái base cần có). | V.26 innernet / Netmaker / wesher / Pritunl-WG | M |
| **F.C** | **`IEapMethod` abstraction** | Codec generic đã tách: [`EapPacket:7`](../src/TqkLibrary.VpnClient.Ipsec/Ike/V2/Eap/EapPacket.cs#L7) + `EapResult` + `EapPayload`. Nay [`IkeClient:46`](../src/TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeClient.cs#L46) hard-code `EapMsChapV2Client` (`:280`/`:337`). Rút `IEapMethod`; crypto tái dùng thật = `MsChapV2` (project Crypto), dùng chung với [`MsChapV2Authenticator`](../src/TqkLibrary.VpnClient.Ppp/Auth/MsChapV2Authenticator.cs). | V.16 EAP-pack (dùng lại cho IKEv2 + V.9/V.13) | M |
| **F.D** | **SSL-VPN HTTP-transactor tổng quát** | Tổng quát hóa [`OpenConnectHttpTransactor:18`](../src/TqkLibrary.VpnClient.OpenConnect/OpenConnectHttpTransactor.cs#L18) (login-POST→cookie→CONNECT) — **raw HTTP trên `IByteStreamTransport`, KHÔNG `HttpClient` ⇒ cross-TFM** (ns2.0 thiếu HTTP/2/`ConnectCallback`). Tách form-loop + cookie-jar + "promote-to-tunnel" khỏi semantics ocserv/CSTP. Mẫu POST-trên-byte-stream thứ 2: SoftEther. | V.9, V.13, V.27 | M-L |
| **F.2** | **`ISecuritySession` + `IPacketEncapsulator`** | **2 seam tách biệt**: *security-session* (`Protect`/`bool TryUnprotect`+counter+replay+rekey-on-exhaustion) đồng dạng cao ở [`EspSession:56`](../src/TqkLibrary.VpnClient.Ipsec/Esp/EspSession.cs#L56), [`IOpenVpnDataChannel:15`](../src/TqkLibrary.VpnClient.OpenVpn/DataChannel/IOpenVpnDataChannel.cs#L15), [`WireGuardTransport:70`](../src/TqkLibrary.VpnClient.WireGuard/WireGuardTransport.cs#L70); *framing* (không key) = `CstpFraming`/`SstpControlCodec`/`OpenVpnPacketCodec`. Khác biệt cần adapter: ESP có thêm `out nextHeader`, session-demux khác nhau, datagram-vs-stream, **MPPE=outlier** (RC4 in-place → impl riêng). Tiền lệ make-before-break: `OpenVpnDataPlane`. | Dọn kiến trúc; nền chung cho driver security tương lai | L (refactor) |
| **F.E** | **Trám gap crypto** (làm lẻ theo nhu cầu) | Thêm: **HSalsa20+XSalsa20** (NaCl secretbox — THIẾU; có sẵn Salsa20 core [`Salsa20:24`](../src/TqkLibrary.VpnClient.Crypto/Salsa20.cs#L24)), **BLAKE2b** (BC có engine, chỉ thiếu wrapper — nay chỉ BLAKE2s), **P-256 ECDH keygen** (nay chỉ ECDSA-verify), **nâng BouncyCastle 2.4.0→≥2.5.0** (mở `MLKem` FIPS 203), (tùy) **UMAC**. | Quicktun/cjdns · Yggdrasil · Nebula-P256/FreeLAN · IKEv2-PQ · fastd | M (lẻ) |
| **F.9b** | **outer-IPv6 receive cho RawIp** | [`RawIpv4`](../src/TqkLibrary.VpnClient.Transport.RawIp/Helpers/RawIpv4.cs) nay strip chỉ header v4; thêm nhánh v6. | Cả họ V.18 IPv6-transition | S |
| **F.F** | **Khối ICE / STUN / TURN** (RFC 8445/8489/8656) — *lớn, độc lập* | Xác nhận repo **= 0** code NAT-traversal. Cần state machine gather-candidate + connectivity-check + cắm vào `IDatagramTransport`. | NetBird · Tailscale-disco · hole-punch n2n/Nebula | L |

---

## §2. WAVE 1 — Quick wins OFFLINE (cưỡi Wave 0)

- **Obfuscation `[sau F.A]` ↔V.29:** AmneziaWG *(junk Jc/Jmin/Jmax + magic-header H1–H4 + padding S1–S4 trên WG-UDP; crypto WG nguyên; phổ biến nhất)* · **stunnel** *(= compose Transport.Tls bọc TCP, gần free)* · **wstunnel** *(WebSocket-over-TLS RFC 6455; net8 có `ClientWebSocket`, ns2.0 tự framing)* · OpenVPN-XOR/scramble *(xormask/xorptrpos/reverse)* · Cloak *(giả HTTPS + multiplex)* · obfs4 *(elligator2+ntor — crypto-note)* · phantun *(FakeTCP nhẹ, ghép dưới WG)*.
- **OpenVPN variants ↔V.28:** OpenVPN-over-TCP *(kiểm lại — matrix báo tun-TCP đã live)* · static-key `--secret` *(4×256-bit key, bỏ TLS control — ⚠️ deprecated no-PFS)* · tls-crypt-v2 · data-v2 AEAD · peer-fingerprint.
- **WG control-plane `[sau F.B]` ↔V.26:** **innernet** *(REST + invitation `.toml`, no hole-punch — DỄ NHẤT)* · wesher *(gossip SWIM/memberlist, không cần central)* · Pritunl-WG *(profile/API)* · Netmaker-client *(mode endpoint tĩnh/relay; server SSPL → chỉ client)*.
- **EAP `[sau F.C]` ↔V.16:** EAP-TLS *(5216/9190, client-cert + MSK exporter)* · EAP-TTLS *(5281, inner PAP/CHAP/MSCHAPv2 dùng lại codec)* · EAP-PEAP *(inner EAP-MSCHAPv2 đã có)* · EAP-GTC *(3748 §5.6, bọc trong TTLS/PEAP)*.
- **IKEv2/IPsec offline-pack ↔V.15:** **PPK RFC 8784** *(pre-shared trộn PRF — không cần KEM, dùng `PrfPlus`/HMAC sẵn)* · **IPsec-over-TCP+TLS RFC 8229** *(tái dùng Transport.Tcp+Tls + length-prefix framing; vượt firewall chặn UDP)* · AH (4302) · IPComp (3173 — **wire IKEv2 XONG** end-to-end opt-in, IKEv1 còn) · ESP-NULL (2410) · Childless-IKE (6023) · QCD crash-detect (6290) · Session-Resumption (5723) · Redirect (5685) · Repeated-auth (4478) · NULL-auth (7619) · EAP-only (5998) · IKEv1 DPD(3706)/Hybrid-auth/IPComp.
- **Mesh opensource ↔V.25:** Quicktun `raw` + **`nacltai`** *(`[F.E crypto_box (NaclBox) XONG — chỉ còn wire giao thức + TAI64]`; Curve25519+XSalsa20-Poly1305+TAI64 — dễ nhất mảng mesh)* · **PeerVPN/MeshVPN** *(AES-256-GCM+HMAC-SHA256 PSK, L2 TAP — crypto gần đủ)* · GVPE *(RSA-auth + AES/Blowfish, L2, đa-transport UDP/TCP/ICMP/DNS)* · CIPE *(UDP Blowfish/IDEA — ⚠️ obsolete, cân nhắc bỏ)*.
- **n2n / vtun residual ↔V.7.4/V.11:** n2n ChaCha20 transform *(class transform ChaCha20 chưa impl — mới có Aes/Null/Speck)* + key-derivation Pearson · vtun cipher-modes AES/BF-CBC/CFB/OFB *(cần `lfd_encrypt` IV-exchange per-packet)* + compression zlib/lzo + UDP-transport.
- **IPv6-transition tunnels `[sau F.9b]` ↔V.18** *(⚠️ tất cả TRẦN, cần raw+admin):* 6to4 (3056) · 6rd (5969) · ISATAP (5214) · 4in6/IP-in-IPv6 (2473) · DS-Lite (6333) · lw4o6 (7596) · MAP-E (7597 — stateless, sống khỏe ISP JP/EU).
- **X-over-UDP / overlay còn lại ↔V.21/V.22/V.23:** MPLS-in-UDP static-label (7510, UDP/6635) · AMT (7450, UDP/2268 multicast) · MPLS-in-IP/GRE static (4023) · NSH (8300 service-chain — niche) · PWE3 static-label.
- **IP-in-IP raw còn lại ↔V.8c** *(codec offline; live cần RawIp + IP-public):* **EtherIP** (proto-97, RFC 3378, Ethernet-in-IP → Ethernet fabric) · **L2TPv3-over-IP** (proto-115, RFC 3931, session-id).
- **Translation engine ↔V.19** *(KHÔNG admin — tái dùng IpStack):* **SIIT** (7915 + EAM 7757 — engine dịch header in-place, **nền, làm trước**) → **MAP-T** (7599 double-translation) → **464XLAT/CLAT** (6877 + PREF64 discovery 7050/8781 — rất phổ biến mobile IPv6-only).
- **SSH extensions ↔V.10:** thêm KEX/cipher/auth (hostkey rsa/ecdsa, DH-group*, aes-ctr+HMAC-EtM, keyboard-interactive) · rekey mid-session · tap-mode L2 (`SSH_TUNMODE_ETHERNET`) · parse khóa OpenSSH PEM.

---

## §3. WAVE 2 — Control-plane / doanh nghiệp `[LIVE]` (sau F.D/F.C)

- **SSL-VPN doanh nghiệp `[sau F.D]` ↔V.9:** Fortinet FortiGate *(logincheck→cookie→PPP-over-TLS+DTLS)* · F5 BIG-IP APM *(form/SAML→PPP-over-TLS/DTLS)* · GlobalProtect *(portal/gateway→SSL tunnel hoặc IPsec fallback)* · Array AG *(HTTPS→SSL+DTLSv1.0 — BouncyCastle dựng được, BCL SslStream không)*.
- **Juniper / Pulse `[sau F.D+ESP]` ↔V.13:** Juniper NC **oNCP** *(auth `/dana-na/`→tunnel TLV)* · Pulse/Ivanti **IF-T/TLS** (TNC + EAP; data TLS hoặc ESP-in-UDP tái dùng `EspSession`+`NatTraversalChannel`).
- **SSL-VPN còn lại `[sau F.D]` ↔V.27:** **SonicWall NetExtender** *(PPP-over-SSL, "trivial" theo nxBender — dễ)* · Citrix/NetScaler *(protocol `nc`, cookie `NSC_*`)* · CheckPoint SNX *(ưu tiên nhánh IPsec/IKE + RawIp)*.
- **WG control-plane cloud ↔V.26:** Netmaker-full *(API+ACL)* · Firezone *(data plane boringtun; portal WebSocket)* · Husarnet.
- **IKEv2 feature-pack ↔V.15:** MOBIKE (4555 → map `SwappablePacketChannel`+F.6) · **Fragmentation** (7383 — *tiền đề PQ*, ưu tiên) · EAP-only auth.
- **Cisco route-based ↔V.17** *(tái dùng GRE/IPIP của IpEncap + IKE/ESP):* DMVPN — NHRP (2332) + mGRE + IPsec · FlexVPN — IKEv2 CFG-payload + VTI · Route-based VTI/GRE-over-IPsec (4023) · GETVPN/GDOI (6407/8263 — ⚠️ thiếu client opensource đối chiếu).
- **Rebrand → CHỈ profile/loader (KHÔNG project mới) ↔V.28-rebrand:** OpenVPN-profile *(Sophos SSL/WatchGuard-SSL/OpenVPN-Access-Server)* · IKEv2/L2TP-profile *(WatchGuard-IKEv2/Aruba-VIA/SonicWall-Mobile-Connect/Barracuda-CloudGen)*.

---

## §4. WAVE 3 — NAT-traversal / nâng cao (cần F.F + crypto/routing lớn)

- **NAT-traversal `[sau F.F ICE]`:** **NetBird** *(gRPC management + signal + ICE/STUN/TURN)* · Tailscale **disco + DERP** ↔V.7.5 *(Curve25519-boxed ping/pong + WS relay)* · hole-punching **n2n-P2P** (QUERY_PEER/PEER_INFO) + **Nebula relay/punchy** ↔V.7.1/V.7.4.
- **Post-quantum ↔V.15** *(thứ tự 7383→9242→9370):* Intermediate-Exchange (9242) · Multiple-KE hybrid (9370, `[sau nâng BC 2.5 → ML-KEM]`).
- **Mesh đắt ↔V.25:** fastd `[sau UMAC]` *(Curve25519+salsa2012+UMAC)* · FreeLAN `[P-256 ECDH XONG — chỉ còn FSCP wire]` *(FSCP cert/RSA+ECDHE+AES-GCM)* · cjdns `[XSalsa20-Poly1305 + crypto_box XONG — chỉ còn routing engine]` *(CryptoAuth + crypto-routed IPv6 fc00::/8 + DHT — routing engine khổng lồ, dự án gần ngừng)* · Yggdrasil `[BLAKE2b XONG — chỉ còn wire tree-routing/DHT]` *(Ed25519+Noise+ChaCha20, IPv6 200::/7, tree-routing+DHT — wire chưa ổn định)*.
- **Routing nhà mạng (gần out-of-scope userspace) ↔V.24/V.23:** SRv6 (8754 SRH + 8986 + 9800 cSID — cần SR control + kernel seg6) · PWE3/Ethernet-over-MPLS (3985/4448/4385 — cần control plane MPLS/LDP).
- **Phần cứng ↔V.16:** EAP-SIM/AKA/AKA' (4186/4187/9048 — cần SIM/USIM qua PC/SC).

---

## §5. Bảng gap crypto (khảo sát 2026-07-07 — BouncyCastle 2.4.0, cả 2 TFM)

| Primitive | Trạng thái | Chặn gì | Hướng trám |
|---|---|---|---|
| ~~**UMAC**~~ **XONG** | **CÓ** ([`Umac`](../src/TqkLibrary.VpnClient.Crypto/Umac.cs), tag 32/64/96/128-bit, key AES-128/256) | (đã trám — fastd method mặc định salsa2012+umac; **còn phần giao thức wire**) | UHASH (NH little-endian + POLY mod 2^64-59 + inner-product 2^36-5) + AES-CTR KDF/PDF; KAT RFC 4418 §9 byte-exact (single-step POLY khớp vector & reference, KHÔNG ramp p128) |
| ~~**BLAKE2b**~~ **XONG** | **CÓ** ([`Blake2b`](../src/TqkLibrary.VpnClient.Crypto/Blake2b.cs) + [`Blake2bKeyedMac`](../src/TqkLibrary.VpnClient.Crypto/Blake2bKeyedMac.cs), output 1..64B) | (đã trám — Yggdrasil node-ID/tree hash) | Wrapper BC `Blake2bDigest`; KAT RFC 7693 App.A + blake2b-kat.txt |
| **ML-KEM / Kyber** | **Chưa wired** (BC 2.4 có Kyber tên cũ; `MLKem` FIPS 203 từ BC ≥2.5) | IKEv2 PQ hybrid (RFC 9370) | Nâng BC 2.4→2.5 rồi bind `MLKem` vào IKE transform |
| ~~**P-256 ECDH keygen**~~ **XONG** | **CÓ** ([`NistP256DhGroup`](../src/TqkLibrary.VpnClient.Crypto/NistP256DhGroup.cs), IANA group 19, wire x‖y 64B / shared x 32B) | (đã trám — mở khóa Nebula-P256 networks + FreeLAN ECDHE; **còn phần giao thức wire**) | ECDH P-256 qua BC `CustomNamedCurves("P-256")` + `ECPoint.Multiply`; KAT RFC 5903 §8.1 byte-exact |
| **RFC 8784 PPK** | Làm được NGAY | (PQ rẻ, không cần KEM) | Trộn PRF bằng `PrfPlus`/HMAC sẵn có |

**Đã có đủ** (không phải gap): Salsa20 (full/12), **HSalsa20 + XSalsa20 + XSalsa20-Poly1305 (NaCl `crypto_secretbox`) + NaclBox (NaCl `crypto_box` = Curve25519 + XSalsa20-Poly1305, XONG — KAT byte-exact libsodium core2/core3 + secretbox.exp + box.c)**, ChaCha20, ChaCha20-Poly1305, XChaCha20-Poly1305, Poly1305, **UMAC (XONG — RFC 4418 §9 byte-exact, tag 32/64/96/128)**, AES-CBC/CTR/GCM, Blowfish, RC4/MPPE, Speck, HMAC-SHA1/256/384/512+MD5, SHA-0/1/256/512, BLAKE2s, **BLAKE2b + BLAKE2b-keyed (XONG — RFC 7693 App.A + blake2b-kat.txt)**, MD4/5, Pearson, Curve25519/X25519, Ed25519, DH-modp(2/14), Noise `SymmetricState` (swap cipher/hash tự do). ⇒ **PeerVPN, GVPE, n2n-transform, vtun-cipher, IKEv2-PPK/8229, EAP-pack, obfuscation, WG-control-plane, translation-engine đều KHÔNG vướng crypto; nacltai/cjdns hết vướng crypto (còn wire giao thức), Yggdrasil hết vướng BLAKE2b, fastd hết vướng UMAC (còn wire salsa2012+umac + handshake Curve25519).**

---

## §6. Residual driver đã-live (V.1–V.7 — chi tiết ở [`11`](11-todo-roadmap.md), đa số `[LIVE]`)
IKEv2 live-rekey/cert-trên-EAP (V.1) · OpenVPN soft-reset MBB + tap IPv6/multi-host (V.2) · WireGuard roaming-endpoint (V.3) · SoftEther TCP-internet/multi-conn/IPv6 (V.4) · PPTP full-ICMP server khác (V.6) · Nebula lighthouse/relay (V.7.1) · tinc auto-mesh (V.7.2) · ZeroTier COM-exchange VL2 (V.7.3) · n2n P2P (V.7.4→Wave3) · Tailscale disco/DERP (V.7.5→Wave3). **Validate live 7 driver mới đêm 2026-07-07** (Geneve/FOU-GUE/L2TPv3-eth/AYIYA/VXLAN-GPE/GTP-U/EoGRE-NVGRE) — chờ lab.

## §7. Q — Chất lượng / hạ tầng (song song mọi wave — chi tiết [`11`](11-todo-roadmap.md) §Q)
Q.1 lab/validate-residual · Q.2 logger tầng Ethernet-L2 + IKEv2-deep · Q.4 zero-alloc data-plane (ArrayPool/Pipe) · Q.5 CI job integration-lab · Q.6 tách `TqkLibrary.VpnClient.Proxy` · Q.7 NuGet packaging.

## §8. Ngoài phạm vi (KHÔNG làm)
Pure proxy (Shadowsocks/ShadowsocksR/Outline, V2Ray/Xray VMess/VLESS/Trojan/Reality, Hysteria/TUIC, naiveproxy, Brook, gost) · server-side/plugin (sslh, SIP003, sshuttle) · proprietary no-doc (Hamachi, Barracuda TINA) · userspace-stack tham chiếu (gVisor/smoltcp/lwIP).

## §9. Đồ thị phụ thuộc + gợi ý bắt đầu
```
F.A ─▶ V.29 (AmneziaWG, stunnel, wstunnel, OpenVPN-XOR...)
F.B ─▶ V.26 (innernet ─▶ wesher/Pritunl/Netmaker-static)
F.C ─▶ V.16 (EAP-pack) ─▶ (dùng lại) V.9/V.13
F.D ─▶ V.9 / V.13 / V.27  (SSL-VPN doanh nghiệp)
F.E (XSalsa20-Poly1305/secretbox + NaclBox crypto_box XONG) ─▶ mesh NaCl (Quicktun/cjdns) chỉ còn wire giao thức; BLAKE2b XONG ─▶ Yggdrasil hết vướng crypto (còn wire); P-256 ECDH XONG ─▶ Nebula-P256/FreeLAN ECDHE hết vướng crypto (còn wire); UMAC XONG ─▶ fastd hết vướng crypto (còn wire); PQ vẫn chờ primitive khác
F.9b ─▶ V.18 (6to4/6rd/ISATAP/DS-Lite/MAP-E)
F.F ─▶ V.26-NetBird, disco, hole-punch  (chặn Wave 3)
SIIT ─▶ MAP-T + 464XLAT + NAT64  (V.19)
```
**Đòn bẩy cao nhất, làm-offline-được, bắt đầu trước:** ① **F.A → AmneziaWG** (mở họ anti-DPI phổ biến nhất) · ② **F.B → innernet** (dễ nhất, chứng minh pattern control-plane) · ③ **F.C → EAP-TTLS/PEAP** (dùng lại cho IKEv2 + doanh nghiệp) · ④ **IKEv2 PPK (8784) + IPsec-over-TCP (8229)** (không vướng crypto/nền) · ⑤ **SIIT engine** (dùng cho 3). Các nhánh `[LIVE]` (V.9/V.13/V.27/DMVPN), cần-crypto-lớn (PQ) và wire-phức-tạp (cjdns/Yggdrasil/fastd — crypto đã đủ) để sau.
