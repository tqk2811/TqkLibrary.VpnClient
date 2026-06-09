# 11 — Roadmap & TODO (còn thiếu gì)

> Tổng hợp **việc chưa làm**, đối chiếu plan gốc (`wild-stargazing-spark.md`) + tài liệu as-built
> [`10-codebase-architecture-and-flow.md`](10-codebase-architecture-and-flow.md). Cập nhật khi hoàn thành.
> Ưu tiên: **P1** = nên làm sớm cho 2 driver đang chạy thật · **P2** = chất lượng/độ phủ · **P3** = mở rộng tương lai.

## ✅ Đã xong (baseline)
- Driver **SSTP** live (TLS + PPP/MS-CHAPv2 + crypto binding) và **L2TP/IPsec** live (IKEv1 PSK + ESP + L2TP + PPP).
- **IKEv2** (`Ipsec/Ike/V2/`) đầy đủ + test, **chưa wire vào driver**.
- Socket API trong tunnel: **TCP** (`VpnTcpClient` → HttpClient) + **UDP** (`VpnUdpClient` → DNS-over-tunnel), đều live.
- NAT-T (forced 500→4500), userspace IPv4/TCP/UDP, anti-replay ESP.
- **Robustness L2TP/IPsec**: keepalive (HELLO + DPD), Phase 2 rekey in-place (make-before-break), teardown sạch (CDN/StopCCN/DELETE) + `DisconnectAsync`/`IAsyncDisposable`, **auto-reconnect** (backoff, stable channel) + event `StateChanged`.
- 10 project `src/` + 11 project `tests/`, build xanh `netstandard2.0`+`net8.0`, ~93 test method (`[Fact]`/`[Theory]`) — gồm 7 live integration `[Trait("Category","Integration")]` (3 ở `TqkLibrary.Vpn.Tests` + 4 SSTP).

---

## P1 — Hoàn thiện 2 driver đang dùng (robustness)

- [x] **Keepalive L2TP/IPsec**: **L2TP HELLO** (60s) + **IKE DPD** R-U-THERE/ACK (RFC 3706, 20s, chết sau 3 lần không ACK), trả ACK cho probe của server. → [IkeV1Dpd.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Dpd.cs), [IkeV1Client.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs) (`BuildDpdRUThere`/`BuildDpdAck`/`ProcessInformational`), [L2tpClient.cs](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs) (`SendHelloAsync`), điều phối + timers ở [L2tpIpsecConnection.cs](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs).
  - [ ] **SSTP keepalive chủ động + phát hiện peer-dead**: hiện SSTP chỉ **thụ động** trả lời Echo-Request của server ([SstpConnection.cs:87-89](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpConnection.cs#L87-L89)); cần chủ động gửi Echo-Request + timeout để phát hiện rớt → là tiền đề cho SSTP teardown/reconnect bên dưới.
- [x] **Rekey theo SA lifetime — Phase 2**: Quick Mode rekey in-place ở ~90% lifetime (3600s), swap `EspSession` make-before-break (giữ SA cũ 10s cho inbound). → [IkeV1Client.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Client.cs) (`BuildRekeyQuickMode1/2/3`), [IpsecL2tpTransport.cs](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/IpsecL2tpTransport.cs) (`SwapSession`/`DropPreviousInbound`), [IkeV1Lifetimes.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Lifetimes.cs).
  - [x] **Rekey Phase 1** (28800s) **by-reconnect**: timer hết hạn ở ~90% → `OnLinkLost` → supervisor reconnect (re-Main-Mode toàn bộ). Chưa rekey Phase 1 in-place (chấp nhận gián đoạn ngắn mỗi 8h cho v1).
  - [ ] **Rekey theo sequence-exhaustion**: chưa có — [`EspSession.Protect` @ :34](../src/TqkLibrary.Vpn.Ipsec/Esp/EspSession.cs#L34) dùng `checked(_sequence+1)` nên gói thứ 2³² ném `OverflowException` thay vì rekey; hiện chỉ rekey theo thời gian.
- [x] **Teardown sạch khi disconnect (L2TP/IPsec)**: `DisconnectAsync`/`IAsyncDisposable` gửi `CDN`+`StopCCN` (L2TP) + `DELETE` ESP+ISAKMP (IKE) rồi mới đóng socket (best-effort, timeout 2s). → [IkeV1Delete.cs](../src/TqkLibrary.Vpn.Ipsec/Ike/V1/IkeV1Delete.cs), [L2tpClient.cs](../src/TqkLibrary.Vpn.L2tp/L2tpClient.cs) (`SendCallDisconnectAsync`/`SendStopControlConnectionAsync`), [L2tpIpsecConnection.cs](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs).
  - [ ] **SSTP disconnect** sạch (gửi SSTP Call-Disconnect) — chưa làm.
- [x] **Reconnect tự động** khi rớt (exponential backoff 1s→30s ×2 ±20%, vô hạn tới `DisconnectAsync`; bật mặc định, cấu hình qua [L2tpIpsecReconnectOptions](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecReconnectOptions.cs)). Tunnel mới chui sau [SwappablePacketChannel](../src/TqkLibrary.Vpn.Abstractions/Channels/SwappablePacketChannel.cs) ổn định → flow trong tunnel sống sót khi same-IP; đổi IP → `session.Reconfigured`. Event `StateChanged` (Connecting/Connected/Reconnecting/Disconnected). → [L2tpIpsecConnection.cs](../src/TqkLibrary.Vpn.Drivers/L2tpIpsec/L2tpIpsecConnection.cs) (`EstablishAsync`/`ReconnectLoopAsync`, lock chống double-supervisor + drop-window race).
  - [ ] **Reconnect cho SSTP** (tận dụng `SwappablePacketChannel` + cùng mô hình supervisor) — chưa làm.
- [ ] **Phân loại lỗi & timeout rõ ràng**: phân biệt auth-fail vs network-timeout vs server-reject; custom exception types (hiện chỉ `VpnElevationRequiredException`); timeout cấu hình được — IKE retransmit 5×2.5s hard-code, **L2TP control-channel retransmit 1s không giới hạn số lần** ([L2tpControlChannel.cs](../src/TqkLibrary.Vpn.L2tp/L2tpControlChannel.cs)).
- [ ] **Rủi ro forced-NAT-T theo server** (plan rủi ro #1): vài gateway từ chối ephemeral-port/forced-NAT → cần fallback **native ESP** (cần `Transport.RawIp`, elevate) + test nhiều server.

## P1 — Độ phủ test

- [ ] **IKEv1 in-process two-party capstone** (chưa có — hiện không test nào bị `Skip`): dựng responder giả lập như IKEv2 để có regression **offline** (live test phụ thuộc mạng/VPN Gate). Hiện `Ike.Tests` chỉ phủ codec/key-derivation/DPD/Delete/QuickMode đơn vị, chưa có bài chạy đôi end-to-end. → [tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/](../tests/TqkLibrary.Vpn.Ipsec.Ike.Tests/)
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

- [ ] **AEAD ESP (AES-GCM)**: `EspGcmSuite` đã có nhưng IKEv1/L2TP đang chỉ negotiate **AES-CBC+HMAC**; kể cả IKEv2 [`IkeProposals`](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/IkeProposals.cs) cũng chỉ chào AES-CBC-256+HMAC-SHA-256 dù [`IkeTransformId`](../src/TqkLibrary.Vpn.Ipsec/Ike/V2/Enums/IkeTransformId.cs) đã có `AesGcm16=20` → bổ sung đề xuất GCM. → [EspGcmSuite.cs](../src/TqkLibrary.Vpn.Ipsec/Esp/EspGcmSuite.cs)
- [ ] **Hợp đồng mồ côi** (`IByteStreamTransport`, `ISecuritySession`, `IPacketEncapsulator`): khai báo trong `Abstractions` nhưng **không class nào implement/consume** — SSTP tự cuộn TLS riêng (`TcpClient`+`SslStream`) trong `SstpTransport`, ESP dùng `EspSession` riêng (không qua `ISecuritySession`). → refactor `SstpTransport` về sau `IByteStreamTransport` để biến interface thành thật + tái dùng cho SSL-VPN khác. → [IByteStreamTransport.cs](../src/TqkLibrary.Vpn.Abstractions/Transport/Interfaces/IByteStreamTransport.cs), [SstpTransport.cs](../src/TqkLibrary.Vpn.Drivers/Sstp/SstpTransport.cs)
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
1. ~~**Keepalive + rekey + teardown + reconnect** (P1)~~ — ✅ xong (keepalive, Phase 2 rekey, teardown, auto-reconnect + Phase 1 by-reconnect). **Còn lại P1 robustness**: phân loại lỗi & timeout, forced-NAT-T fallback, SSTP keepalive/teardown/reconnect.
2. **IKEv1 capstone + lab Docker + TCP loopback** (P1 test) — chốt regression offline (rekey/DPD encrypted hiện chỉ phủ bằng live test, cần responder IKEv1 in-process).
3. **TCP retransmit + ICMP + AES-GCM ESP** (P2) — vững IP stack & crypto.
4. **Driver IKEv2-native** (P3) — tận dụng hạ tầng IKEv2 đã build sẵn, chi phí thấp nhất trong nhóm P3.
5. Các driver/tầng còn lại theo nhu cầu.
