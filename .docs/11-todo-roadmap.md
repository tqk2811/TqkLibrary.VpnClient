# 11 — Roadmap & TODO (còn thiếu gì)

> Tổng hợp **việc chưa làm**, đối chiếu plan gốc (`wild-stargazing-spark.md`) + tài liệu as-built
> [`10-codebase-architecture-and-flow.md`](10-codebase-architecture-and-flow.md). Cập nhật khi hoàn thành.
> Ưu tiên: **P1** = nên làm sớm cho 2 driver đang chạy thật · **P2** = chất lượng/độ phủ · **P3** = mở rộng tương lai.

## ✅ Đã xong (baseline)
- Driver **SSTP** live (TLS + PPP/MS-CHAPv2 + crypto binding) và **L2TP/IPsec** live (IKEv1 PSK + ESP + L2TP + PPP).
- **IKEv2** (`Ipsec/Ike/V2/`) đầy đủ + test, **chưa wire vào driver**.
- Socket API trong tunnel: **TCP** (`VpnTcpClient` → HttpClient) + **UDP** (`VpnUdpClient` → DNS-over-tunnel), đều live.
- NAT-T (forced 500→4500), userspace IPv4/TCP/UDP, anti-replay ESP.
- 10 project `src/`, build xanh `netstandard2.0`+`net8.0`, ~96 test (gồm 3 live integration).

---

## P1 — Hoàn thiện 2 driver đang dùng (robustness)

- [ ] **Keepalive L2TP/IPsec**: gửi định kỳ **L2TP HELLO** + **IKE DPD** (RFC 3706). Hiện tunnel **idle là rớt** vì không có keepalive ở tầng L2TP/IKE (SSTP đã có Echo). → [L2tpClient.cs](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs), [IkeV1Client.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs)
- [ ] **Rekey theo SA lifetime**: Phase 1 (28800s) / Phase 2 (3600s) **chỉ đề xuất, không rekey** → kết nối dài sẽ chết. Cần IKE rekey + CHILD_SA/Quick-Mode rekey. → [IkeV1Proposals.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Proposals.cs)
- [ ] **Teardown sạch khi disconnect**: gửi `DELETE` (IKE) / `StopCCN`+`CDN` (L2TP) / SSTP disconnect thay vì chỉ cancel loop. → [L2tpIpsecConnection.cs](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs)
- [ ] **Reconnect tự động** khi rớt (exponential backoff), expose event trạng thái (Connected/Reconnecting/Disconnected).
- [ ] **Phân loại lỗi & timeout rõ ràng**: phân biệt auth-fail vs network-timeout vs server-reject; custom exception types; timeout cấu hình được (hiện IKE retransmit 5×2.5s hard-code).
- [ ] **Rủi ro forced-NAT-T theo server** (plan rủi ro #1): vài gateway từ chối ephemeral-port/forced-NAT → cần fallback **native ESP** (cần `Transport.RawIp`, elevate) + test nhiều server.

## P1 — Độ phủ test

- [ ] **IKEv1 in-process two-party capstone** (đã skip): dựng responder giả lập như IKEv2 để có regression **offline** (live test phụ thuộc mạng/VPN Gate). → [tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/](../tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/)
- [ ] **IpStack TCP in-process loopback test**: hiện TCP chỉ được kiểm qua live integration; UDP đã có loopback. → [tests/TqkLibrary.Vpn.IpStack.Tests/](../tests/TqkLibrary.Vpn.IpStack.Tests/)
- [ ] **Lab thay cho server công khai**: SSTP/L2TP live test bám `public-vpn-227.opengw.net` → dễ flaky. Dựng **strongSwan/SoftEther Docker** cho CI ổn định.
- [ ] **Fuzz/malformed parser**: IKE (V1 ISAKMP, V2), L2TP AVP, PPP codec — bơm gói rác để chắc không crash.

---

## P2 — IP stack hoàn thiện

- [ ] **TCP retransmit/RTO** (RFC 6298) + **sliding window** thật + half-close edge cases. Hiện tối giản, dựa vào tunnel "đủ tin cậy" (no-SACK, no-retransmit). → [TcpConnection.cs](../src/TqkLibrary.Vpn.IpStack/Tcp/TcpConnection.cs)
- [ ] **ICMP** (echo/ping, destination-unreachable) — chưa có. → [IpStack/](../src/TqkLibrary.Vpn.IpStack/)
- [ ] **IPv4 reassembly** cho gói phân mảnh inbound (hiện giả định không phân mảnh).
- [ ] **MTU/PMTUD**: MTU cố định 1400, chưa Path-MTU-Discovery.

## P2 — Nợ kỹ thuật & tài liệu

- [ ] **AEAD ESP (AES-GCM)**: `EspGcmSuite` đã có nhưng IKEv1/L2TP đang chỉ negotiate **AES-CBC+HMAC** → bổ sung đề xuất GCM. → [EspGcmSuite.cs](../src/TqkLibrary.Vpn.Ipsec/Esp/EspGcmSuite.cs)
- [ ] **`IByteStreamTransport` mồ côi**: interface đã khai báo nhưng **không class nào implement/consume** — SSTP tự cuộn TLS riêng (`TcpClient`+`SslStream`) trong `SstpTransport`. → refactor `SstpTransport` về sau `IByteStreamTransport` để biến interface thành thật + tái dùng cho SSL-VPN khác. → [IByteStreamTransport.cs](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs), [SstpTransport.cs](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpTransport.cs)
- [ ] **IKEv2 Configuration Payload (CP)**: hiện chỉ `RawPayload`; cần model CP để nhận IP/DNS qua IKEv2 (chuẩn bị cho driver IKEv2-native). → [Ipsec/Ike/V2/Payloads/](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/Payloads/)
- [ ] **Đồng bộ design docs 00–09 ↔ as-built**: doc `10` đã liệt kê khác biệt (L2TP dùng IKEv1 chứ không IKEv2; không có `EspIkeDemuxTransport`; chưa có L2 Ethernet…) → cập nhật/đánh dấu rõ design-intent.
- [ ] **Logging/diagnostics** xuyên suốt (trace handshake, drop reason).
- [ ] **Review** cancellation/timeout & thread-safety toàn cục (các receive-loop, channel).
- [ ] **CI đa OS** (plan M0) — chưa có cấu hình CI.
- [ ] **NuGet packaging** nếu phát hành: version (GitVersion), `GenerateDocumentationFile`, symbols/snupkg.

---

## P3 — Giao thức & tầng tương lai (theo plan "sau v1")

- [ ] **Driver IKEv2-native** (IPsec IKEv2 VPN, không qua L2TP): hạ tầng IKEv2 đã sẵn ([IkeClient.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeClient.cs)), cần driver + CP để cấp IP trực tiếp + ESP data plane (đã có).
- [ ] **Tầng L2 Ethernet** (multi-host): `EthernetSwitch` + `VirtualHost` + ARP responder + DHCP client → kích hoạt nhiều "máy LAN" cho OpenVPN-tap/SoftEther. Hiện mới chỉ có đường L3 (`IPacketChannel`).
- [ ] **Driver OpenVPN** (tun/tap, opcodes 1–11, NCP, PUSH_REPLY).
- [ ] **Driver SoftEther** (SSL-VPN, PACK codec, SHA-0/RC4, SecureNAT) — re-implement, không copy GPL source.
- [ ] **Driver WireGuard** (Noise IKpsk2, ChaCha20-Poly1305/X25519/BLAKE2s) → cần `Crypto.Noise`.
- [ ] **Driver OpenConnect-family** (Cisco/Fortinet/F5/Juniper/Pulse/GlobalProtect) → cần `Transport.Dtls`.
- [ ] **`Transport.Tcp` / `Transport.Tls`** (byte-stream transport độc lập, implement [`IByteStreamTransport`](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs)): tách phần TLS-over-TCP hiện đang nhúng trong `SstpTransport` ra project dùng chung, làm nền cho các SSL-VPN tương lai (SoftEther, OpenConnect-family). Hiện mới có interface, chưa có concrete.
- [ ] **`Transport.RawIp`** (opt-in, cần elevate, tự detect quyền root/CAP_NET_RAW vs Administrators) → PPTP/GRE/EtherIP/L2TPv3/native-ESP. Đi kèm `Crypto.Mppe` (RC4/MPPE) cho PPTP.

---

## Gợi ý thứ tự
1. **Keepalive + rekey + teardown** (P1) — để 2 driver hiện có dùng được lâu dài, không chỉ "demo request".
2. **IKEv1 capstone + lab Docker + TCP loopback** (P1 test) — chốt regression offline.
3. **TCP retransmit + ICMP + AES-GCM ESP** (P2) — vững IP stack & crypto.
4. **Driver IKEv2-native** (P3) — tận dụng hạ tầng IKEv2 đã build sẵn, chi phí thấp nhất trong nhóm P3.
5. Các driver/tầng còn lại theo nhu cầu.
