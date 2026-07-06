# TqkLibrary.VpnClient

> Façade của thư viện: `VpnClient` / `VpnClientBuilder`, đăng ký driver, lắp ráp DI. Đây là tầng cao nhất mà ứng dụng gọi vào.

## Mục đích

Project này là **điểm vào (entry point)** duy nhất của toàn bộ thư viện TqkLibrary.VpnClient — một VPN client thuần userspace, plugin theo driver.

- Cho ứng dụng một API gọn để **đăng ký các protocol driver** (SSTP, L2TP/IPsec, PPTP, IP-encap GRE/IPIP/SIT, GRE-in-UDP, FOU/GUE, VXLAN, VXLAN-GPE, Geneve, L2TPv3-eth, AYIYA, IKEv2, Cisco IPsec/EzVPN, OpenVPN, WireGuard, Nebula, Tailscale, tinc, n2n, vtun, VPN-over-SSH, ZeroTier, OpenConnect, SoftEther) theo kiểu fluent rồi **mở kết nối theo tên giao thức**.
- Giấu toàn bộ độ phức tạp của stack bên dưới (IKE/ESP/L2TP/PPP/GRE/TLS/Noise/DTLS/SSH/IP stack): app chỉ thấy `VpnClient.ConnectAsync(...)` trả về một `IVpnConnection`.
- Là nơi **đảo ngược phụ thuộc** hội tụ: façade biết về các driver cụ thể (`SstpDriver`, `L2tpIpsecDriver`, `PptpDriver`, `IpEncapDriver`, `GreInUdpDriver`, `FouDriver`, `VxlanDriver`, `VxlanGpeDriver`, `GeneveDriver`, `L2tpv3EthDriver`, `AyiyaDriver`, `Ikev2Driver`, `CiscoIpsecDriver`, `OpenVpnDriver`, `WireGuardDriver`, `NebulaDriver`, `TailscaleDriver`, `TincDriver`, `N2nDriver`, `VtunDriver`, `SshDriver`, `ZeroTierDriver`, `OpenConnectDriver`, `SoftEtherDriver`), còn mọi tầng dưới chỉ phụ thuộc vào abstractions.

Vì sao tồn tại: tách "ai dùng giao thức nào" (ứng dụng) khỏi "giao thức được lắp ráp ra sao" (driver + protocol + crypto). App chỉ cần `TqkLibrary.VpnClient`, không phải tham chiếu trực tiếp tới Ipsec/L2tp/Ppp/OpenVpn/WireGuard/SoftEther/Transport...

## Vị trí trong kiến trúc

- **Tầng:** APP / Façade — đỉnh của đồ thị phụ thuộc, được ứng dụng tiêu thụ tham chiếu.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [Directory.Build.props](../Directory.Build.props)). `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`).
- **Phụ thuộc (ProjectReference) — 24 project driver (không ref `Sockets`):**
  - [TqkLibrary.VpnClient.Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) — nơi `L2tpIpsecDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Ikev2](../TqkLibrary.VpnClient.Drivers.Ikev2) — nơi `Ikev2Driver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.CiscoIpsec](../TqkLibrary.VpnClient.Drivers.CiscoIpsec) — nơi `CiscoIpsecDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) — nơi `OpenConnectDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.OpenVpn](../TqkLibrary.VpnClient.Drivers.OpenVpn) — nơi `OpenVpnDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Sstp](../TqkLibrary.VpnClient.Drivers.Sstp) — nơi `SstpDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard) — nơi `WireGuardDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.SoftEther](../TqkLibrary.VpnClient.Drivers.SoftEther) — nơi `SoftEtherDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Pptp](../TqkLibrary.VpnClient.Drivers.Pptp) — nơi `PptpDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.IpEncap](../TqkLibrary.VpnClient.Drivers.IpEncap) — nơi `IpEncapDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.GreInUdp](../TqkLibrary.VpnClient.Drivers.GreInUdp) — nơi `GreInUdpDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Fou](../TqkLibrary.VpnClient.Drivers.Fou) — nơi `FouDriver` được khai báo (đăng ký cả `fou` lẫn `gue`).
  - [TqkLibrary.VpnClient.Drivers.Vxlan](../TqkLibrary.VpnClient.Drivers.Vxlan) — nơi `VxlanDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.VxlanGpe](../TqkLibrary.VpnClient.Drivers.VxlanGpe) — nơi `VxlanGpeDriver` được khai báo (VXLAN-GPE superset VXLAN + Next-Protocol).
  - [TqkLibrary.VpnClient.Drivers.Geneve](../TqkLibrary.VpnClient.Drivers.Geneve) — nơi `GeneveDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.L2tpv3Eth](../TqkLibrary.VpnClient.Drivers.L2tpv3Eth) — nơi `L2tpv3EthDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Ayiya](../TqkLibrary.VpnClient.Drivers.Ayiya) — nơi `AyiyaDriver` được khai báo (AYIYA static-mode IPv6-over-UDP).
  - [TqkLibrary.VpnClient.Drivers.Nebula](../TqkLibrary.VpnClient.Drivers.Nebula) — nơi `NebulaDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Tinc](../TqkLibrary.VpnClient.Drivers.Tinc) — nơi `TincDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.N2n](../TqkLibrary.VpnClient.Drivers.N2n) — nơi `N2nDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Vtun](../TqkLibrary.VpnClient.Drivers.Vtun) — nơi `VtunDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Ssh](../TqkLibrary.VpnClient.Drivers.Ssh) — nơi `SshDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.ZeroTier](../TqkLibrary.VpnClient.Drivers.ZeroTier) — nơi `ZeroTierDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Tailscale](../TqkLibrary.VpnClient.Drivers.Tailscale) — nơi `TailscaleDriver` được khai báo.
  - Không có `PackageReference` đặc thù. Façade **không** ref `Crypto`/`Sockets` trực tiếp (2 file `VpnClient`/`VpnClientBuilder` không chạm primitive nào — P0.2); `Crypto` vẫn có trong output theo **transitive** qua Drivers → Ipsec/Ppp/OpenVpn/WireGuard/SoftEther/Transport.Dtls.
- **Được dùng bởi:** ứng dụng tiêu thụ và project test [TqkLibrary.VpnClient.Tests](../../tests/TqkLibrary.VpnClient.Tests) (không project nào khác trong `src/` ref tới project này).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient/
├── VpnClientBuilder.cs   # Builder fluent: AddDriver / UseSstp / UseL2tpIpsec / UsePptp / UseIpEncap / UseGreInUdp / UseFou / UseGue / UseIkev2 / UseCiscoIpsec / UseOpenVpn / UseWireGuard / UseNebula / UseTailscale / UseTinc / UseN2n / UseVtun / UseSsh / UseZeroTier / UseOpenConnect / UseSoftEther / UseVxlan / UseVxlanGpe / UseGeneve / UseL2tpv3Ethernet / UseAyiya → Build()
└── VpnClient.cs          # Client đã build: giữ map driver theo tên, ConnectAsync / Protocols / GetCapabilities
```

Project chỉ gồm 2 type — toàn bộ "logic" thực sự nằm ở các project driver/protocol bên dưới.

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `VpnClientBuilder` | Builder fluent: đăng ký driver theo `Name`, có 25 nhóm shortcut `UseSstp()`/`UseL2tpIpsec()`/`UsePptp()`/`UseIpEncap()`/`UseGreInUdp()`/`UseFou()`/`UseGue()`/`UseIkev2()`/`UseCiscoIpsec()`/`UseOpenVpn()`/`UseWireGuard()`/`UseNebula()`/`UseTailscale()`/`UseTinc()`/`UseN2n()`/`UseVtun()`/`UseSsh()`/`UseZeroTier()`/`UseOpenConnect()`/`UseSoftEther()`/`UseVxlan()`/`UseVxlanGpe()`/`UseGeneve()`/`UseL2tpv3Ethernet()`/`UseAyiya()`, kết thúc bằng `Build()` | [VpnClientBuilder.cs:48](VpnClientBuilder.cs#L48) |
| `VpnClientBuilder.AddDriver` | Đăng ký một `IVpnProtocolDriver` bất kỳ (keyed theo `driver.Name`) | [VpnClientBuilder.cs:53](VpnClientBuilder.cs#L53) |
| `VpnClientBuilder.UseSstp` | Đăng ký `SstpDriver` (key `"sstp"`), auto-reconnect bật mặc định; overload nhận `SstpReconnectOptions` và/hoặc `RemoteCertificateValidationCallback` (cert TLS, P0.6 — null ⇒ accept all) | [VpnClientBuilder.cs:60-71](VpnClientBuilder.cs#L60-L71) |
| `VpnClientBuilder.UseL2tpIpsec` | Đăng ký `L2tpIpsecDriver` (key `"l2tp-ipsec"`), auto-reconnect bật mặc định; overload nhận `L2tpIpsecReconnectOptions`, `(reconnect, L2tpIpsecTimeoutOptions)`, và `(IRawIpTransportFactory, L2tpIpsecNatTraversalMode, reconnect?, timeout?)` bật **native ESP** (proto-50, cần elevation) | [VpnClientBuilder.cs:74-91](VpnClientBuilder.cs#L74-L91) |
| `VpnClientBuilder.UsePptp` | Đăng ký `PptpDriver` (key `"pptp"`, RFC 2637: TCP/1723 control + GRE proto-47 data + MPPE/RC4 + PPP/MS-CHAPv2), cần `IRawIpTransportFactory` cho GRE; overload nhận `PptpReconnectOptions?` + `PptpTimeoutOptions?`. **Legacy/không an toàn — interop only** | [VpnClientBuilder.cs:102-104](VpnClientBuilder.cs#L102-L104) |
| `VpnClientBuilder.UseIpEncap` | Đăng ký `IpEncapDriver` (key `"ipencap"`, tunnel IP-in-IP: GRE proto-47 / IPIP proto-4 / SIT 6in4 proto-41 — **không mã hóa**, không control plane), cần `IRawIpTransportFactory`; overload nhận `IpEncapOptions?` + `IpEncapReconnectOptions?` | [VpnClientBuilder.cs:116-118](VpnClientBuilder.cs#L116-L118) |
| `VpnClientBuilder.UseGreInUdp` | Đăng ký `GreInUdpDriver` (key `"gre-udp"`, GRE-in-UDP RFC 8086: chở header GRE trong payload **UDP/4754** thay raw-IP proto-47 — **KHÔNG mã hóa**, **KHÔNG elevate/raw socket**, qua NAT; tái dùng `GreTunnelChannel`/`GreCodec` của `IpEncap`), host qua `VpnEndpoint.Host`; overload nhận `GreInUdpOptions?` (Port=4754/Mtu/Gre) + `GreInUdpReconnectOptions?` | [VpnClientBuilder.cs:121-132](VpnClientBuilder.cs#L121-L132) |
| `VpnClientBuilder.UseFou` | Đăng ký `FouDriver` (key `"fou"`, FOU Foo-over-UDP: chở payload inner IP-proto — IPIP proto-4/41 hoặc GRE proto-47 theo `FouOptions.InnerProtocol` — trong payload UDP **KHÔNG header** (proto suy từ port, như Linux `ip fou`); tổng quát hoá GRE-in-UDP; **KHÔNG mã hóa**, **KHÔNG elevate/raw socket**, qua NAT; tái dùng kênh data-plane GRE/IPIP của `IpEncap`), host qua `VpnEndpoint.Host`; overload nhận `FouOptions?` (Mode ép FOU + InnerProtocol/Port=6080/Mtu/Gre) + `FouReconnectOptions?` | [VpnClientBuilder.cs:134-148](VpnClientBuilder.cs#L134-L148) |
| `VpnClientBuilder.UseGue` | Đăng ký `FouDriver` (key `"gue"`, GUE draft-ietf-intarea-gue **variant-0**: như `UseFou` nhưng thêm header GUE 4B mang Proto (skip extension theo Hlen, drop control-bit C=1) ⇒ 1 UDP port multiplex nhiều inner-proto; **KHÔNG mã hóa**, **KHÔNG elevate/raw socket**, qua NAT), host qua `VpnEndpoint.Host`; overload nhận `FouOptions?` (Mode ép GUE) + `FouReconnectOptions?` | [VpnClientBuilder.cs:150-163](VpnClientBuilder.cs#L150-L163) |
| `VpnClientBuilder.UseIkev2` | Đăng ký `Ikev2Driver` (key `"ikev2"`, IKEv2-native RFC 7296 PSK/EAP + ESP tunnel mode), auto-reconnect bật mặc định; overload nhận `Ikev2ReconnectOptions`, và overload `UseIkev2(IkeCertificateTrust, Ikev2ReconnectOptions?)` verify gateway bằng **certificate** (chữ ký số RFC 7296 §2.15) | [VpnClientBuilder.cs:166-179](VpnClientBuilder.cs#L166-L179) |
| `VpnClientBuilder.UseCiscoIpsec` | Đăng ký `CiscoIpsecDriver` (key `"cisco-ipsec"`, IKEv1 Aggressive Mode group PSK + XAUTH + Mode-Config + ESP tunnel-mode, forced NAT-T, no PPP) cho group `groupName`, auto-reconnect bật mặc định; overload nhận `CiscoIpsecReconnectOptions?`. **Aggressive Mode + group PSK yếu — interop only** | [VpnClientBuilder.cs:190-191](VpnClientBuilder.cs#L190-L191) |
| `VpnClientBuilder.UseOpenVpn` | Đăng ký `OpenVpnDriver` (key `"openvpn"`) từ một `OpenVpnProfile` đã parse; overload nhận `X509CertificateCollection?` (client cert) + `RemoteCertificateValidationCallback?` (cert server) + `OpenVpnReconnectOptions?`, và overload `(OpenVpnProfile, bool enableIpv6)` bật IPv6 trong tunnel (chỉ tap-mode) | [VpnClientBuilder.cs:194-207](VpnClientBuilder.cs#L194-L207) |
| `VpnClientBuilder.UseWireGuard` | Đăng ký `WireGuardDriver` (key `"wireguard"`) từ một `WireGuardConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `WireGuardReconnectOptions` | [VpnClientBuilder.cs:210-214](VpnClientBuilder.cs#L210-L214) |
| `VpnClientBuilder.UseNebula` | Đăng ký `NebulaDriver` (key `"nebula"`, Slack mesh: UDP + Noise_IX_25519_AESGCM_SHA256 cert-auth + AES-256-GCM type-1) từ một `NebulaConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `NebulaReconnectOptions` | [VpnClientBuilder.cs:222-226](VpnClientBuilder.cs#L222-L226) |
| `VpnClientBuilder.UseTailscale` | Đăng ký `TailscaleDriver` (key `"tailscale"`, control plane ts2021 Noise IK → Headscale/Tailscale + netmap, data plane WireGuard multi-peer) từ một `TailscaleConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `TailscaleReconnectOptions` | [VpnClientBuilder.cs:237-241](VpnClientBuilder.cs#L237-L241) |
| `VpnClientBuilder.UseTinc` | Đăng ký `TincDriver` (key `"tinc"`, tinc 1.1 SPTPS: TCP meta-connection + per-tunnel SPTPS + bare-IP router-mode over UDP) từ một `TincConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `TincReconnectOptions` | [VpnClientBuilder.cs:250-254](VpnClientBuilder.cs#L250-L254) |
| `VpnClientBuilder.UseN2n` | Đăng ký `N2nDriver` (key `"n2n"`, n2n v3: UDP tới supernode, REGISTER_SUPER + PACKET Ethernet frames NULL/AES-CBC, L2 bridge) từ một `N2nConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `N2nReconnectOptions` | [VpnClientBuilder.cs:264-268](VpnClientBuilder.cs#L264-L268) |
| `VpnClientBuilder.UseVtun` | Đăng ký `VtunDriver` (key `"vtun"`, vtund legacy: 1 TCP, challenge-response MD5/Blowfish-ECB, bare IP length-prefixed, ECHO keepalive) từ một `VtunConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `VtunReconnectOptions`. **Crypto legacy/yếu — interop only** | [VpnClientBuilder.cs:279-283](VpnClientBuilder.cs#L279-L283) |
| `VpnClientBuilder.UseSsh` | Đăng ký `SshDriver` (key `"ssh"`, VPN-over-SSH OpenSSH `-w` tun: SSH-2 KEX curve25519 + ed25519 host-key + publickey/password, `tun@openssh.com` L3, bare IP) từ một `SshConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `SshReconnectOptions` | [VpnClientBuilder.cs:295-299](VpnClientBuilder.cs#L295-L299) |
| `VpnClientBuilder.UseZeroTier` | Đăng ký `ZeroTierDriver` (key `"zerotier"`, VL1/VL2: UDP HELLO⇄OK Curve25519 + Salsa20/12+Poly1305, NETWORK_CONFIG_REQUEST, EXT_FRAME L2 bridge) từ một `ZeroTierConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `ZeroTierReconnectOptions` | [VpnClientBuilder.cs:312-316](VpnClientBuilder.cs#L312-L316) |
| `VpnClientBuilder.UseOpenConnect` | Đăng ký `OpenConnectDriver` (key `"openconnect"`, Cisco AnyConnect/ocserv: HTTPS config-auth → CSTP, bare IP, DTLS 1.2 data plane fallback TLS), auto-reconnect bật mặc định; overload nhận `OpenConnectReconnectOptions`, và `(reconnect, RemoteCertificateValidationCallback?, groupSelect)` | [VpnClientBuilder.cs:323-335](VpnClientBuilder.cs#L323-L335) |
| `VpnClientBuilder.UseSoftEther` | Đăng ký `SoftEtherDriver` (key `"softether"`, SSL-VPN Ethernet-over-TLS, DHCP-leased, SHA-0 password auth) targeting `hubName`, auto-reconnect bật mặc định; overload nhận `SoftEtherSessionParams`, `(session, SoftEtherReconnectOptions)`, và `(hubName, bool enableIpv6)` | [VpnClientBuilder.cs:341-356](VpnClientBuilder.cs#L341-L356) |
| `VpnClientBuilder.UseVxlan` | Đăng ký `VxlanDriver` (key `"vxlan"`, VXLAN RFC 7348: L2-over-UDP/**4789**, VXLAN header 8B + VNI 24-bit → Ethernet L2 fabric; **KHÔNG mã hóa**, **KHÔNG elevate/raw socket**), host qua `VpnEndpoint.Host`; overload nhận `VxlanReconnectOptions` | [VpnClientBuilder.cs:358-370](VpnClientBuilder.cs#L358-L370) |
| `VpnClientBuilder.UseVxlanGpe` | Đăng ký `VxlanGpeDriver` (key `"vxlan-gpe"`, VXLAN-GPE `draft-ietf-nvo3-vxlan-gpe`: L2-over-UDP/**4790**, header VXLAN-GPE 8B (flags I\|P `0x0C` + Next-Protocol byte3 + VNI 24-bit BE) — **superset VXLAN** thêm bit P + Next-Protocol (0x01 IPv4/0x02 IPv6/**0x03 Ethernet**/0x04 NSH) → Ethernet L2 fabric; ingress drop nếu Ver≠0/thiếu I\|P/OAM/Next-Protocol≠Ethernet; **chỉ Ethernet đã wire data plane** (IPv4/IPv6/NSH chỉ parse/validate); **KHÔNG mã hóa**, **KHÔNG control plane**, **KHÔNG elevate/raw socket**), host qua `VpnEndpoint.Host`; overload nhận `VxlanGpeReconnectOptions` | [VpnClientBuilder.cs:372-387](VpnClientBuilder.cs#L372-L387) |
| `VpnClientBuilder.UseGeneve` | Đăng ký `GeneveDriver` (key `"geneve"`, Geneve RFC 8926: L2-over-UDP/**6081**, base header 8B + VNI 24-bit + options TLV biến thiên (proto-type 0x6558) → Ethernet L2 fabric; sibling VXLAN; receiver skip options theo OptLen + **drop khi có critical-option lạ** RFC 8926 §3.5; **KHÔNG mã hóa**, **KHÔNG elevate/raw socket**), host qua `VpnEndpoint.Host`; overload nhận `GeneveReconnectOptions` | [VpnClientBuilder.cs:389-404](VpnClientBuilder.cs#L389-L404) |
| `VpnClientBuilder.UseL2tpv3Ethernet` | Đăng ký `L2tpv3EthDriver` (key `"l2tpv3-eth"`, L2TPv3 RFC 3931 + RFC 4719 Ethernet-pseudowire **static/unmanaged**: L2-over-UDP/**1701**, header data L2TPv3 (Session ID 32-bit + Cookie 0/4/8 + Default L2-Specific Sublayer 4B tùy chọn cho sequencing) → Ethernet L2 fabric; sibling VXLAN/Geneve, **KHÔNG control plane** (Session ID + Cookie cấu hình tĩnh 2 đầu); ingress drop control-message/zero-SID/SID-mismatch/cookie-mismatch/truncated; chạy header L2TPv3-over-IP thẳng trong UDP payload (biến thể no-admin, KHÁC Linux `encap udp` có prefix 4B); **KHÔNG mã hóa**, **KHÔNG elevate/raw socket**), host qua `VpnEndpoint.Host`; overload nhận `L2tpv3EthReconnectOptions` | [VpnClientBuilder.cs:406-423](VpnClientBuilder.cs#L406-L423) |
| `VpnClientBuilder.UseAyiya` | Đăng ký `AyiyaDriver` (key `"ayiya"`, AYIYA `draft-massar-v6ops-ayiya-02` tunnel-broker IPv6-over-UDP/**5072** **static mode** — bỏ qua control-channel TIC: chở gói IPv6 sau header AYIYA (header 4B + epoch time + identity + signature), **ký shared-secret SHA-1** (thuật toán aiccu) + **chống replay bằng epoch time**, tái dùng `RawIpPassthroughChannel` (IPv6) của IpEncap qua decorator ký/kiểm; **KHÔNG mã hóa payload** (chỉ ký toàn vẹn + chống replay), **KHÔNG elevate/raw socket**, qua NAT), host qua `VpnEndpoint.Host`; nhận `AyiyaOptions` (Identity+Password bắt buộc); overload nhận `AyiyaReconnectOptions` | [VpnClientBuilder.cs:439-444](VpnClientBuilder.cs#L439-L444) |
| `VpnClient` | Client đã build: giữ `IReadOnlyDictionary<string, IVpnProtocolDriver>` các driver | [VpnClient.cs:8](VpnClient.cs#L8) |
| `VpnClient.ConnectAsync` | Tra driver theo tên giao thức (qua helper `ResolveDriver`) rồi ủy thác `driver.ConnectAsync(endpoint, credentials, ct)` | [VpnClient.cs:18](VpnClient.cs#L18) |
| `VpnClient.Protocols` | Liệt kê tên các giao thức đã đăng ký | [VpnClient.cs:15](VpnClient.cs#L15) |
| `VpnClient.GetCapabilities` | Trả `VpnDriverCapabilities` của một driver đã đăng ký (qua helper `ResolveDriver`) | [VpnClient.cs:22](VpnClient.cs#L22) |
| `VpnClient.ResolveDriver` | Helper private tra driver theo tên; ném `NotSupportedException` (kèm danh sách protocol đã đăng ký) nếu chưa đăng ký — dùng chung cho `ConnectAsync`+`GetCapabilities` (P0.5) | [VpnClient.cs:25](VpnClient.cs#L25) |

Các hợp đồng/model mà façade thao tác (định nghĩa ở Abstractions):

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `IVpnProtocolDriver` | Điểm vào plugin của 1 giao thức: `Name`, `Capabilities`, `ConnectAsync` | [IVpnProtocolDriver.cs:9](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs#L9) |
| `IVpnConnection` | Kết nối sống (1 IKE-SA / 1 TLS), sở hữu nhiều `IVpnSession`; `IAsyncDisposable` | [IVpnConnection.cs:7](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnConnection.cs#L7) |
| `IVpnSession` | Một endpoint IP logic: `Config` + `PacketChannel` | [IVpnSession.cs:10](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnSession.cs#L10) |
| `VpnEndpoint` | Địa chỉ server (host + port + `AddressFamilyPreference`) | [VpnEndpoint.cs:6](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/VpnEndpoint.cs#L6) |
| `VpnCredentials` | `Username` / `Password` (MS-CHAPv2) + `PreSharedKey` (IKE PSK) | [VpnCredentials.cs:4](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/VpnCredentials.cs#L4) |
| `VpnDriverCapabilities` | Khả năng driver (link layer, transport, security, auth, elevation...) | [VpnDriverCapabilities.cs:9](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/VpnDriverCapabilities.cs#L9) |
| `TunnelConfig` | IP/DNS/route/MTU một session nhận được | [TunnelConfig.cs:9](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/TunnelConfig.cs#L9) |

## Chuẩn / RFC tuân thủ

Bản thân project façade **không hiện thực chuẩn mạng nào** — nó chỉ điều phối driver. Các chuẩn dưới đây được **truy cập gián tiếp** qua các shortcut `UseSstp()`/`UseL2tpIpsec()`/`UsePptp()`/`UseIpEncap()`/`UseGreInUdp()`/`UseFou()`/`UseGue()`/`UseIkev2()`/`UseCiscoIpsec()`/`UseOpenVpn()`/`UseWireGuard()`/`UseNebula()`/`UseTailscale()`/`UseTinc()`/`UseN2n()`/`UseVtun()`/`UseSsh()`/`UseZeroTier()`/`UseOpenConnect()`/`UseSoftEther()`/`UseVxlan()`/`UseVxlanGpe()`/`UseGeneve()`/`UseL2tpv3Ethernet()`/`UseAyiya()`; cột "Vị trí" link tới nơi façade kích hoạt driver tương ứng, và (nếu có) tới class summary ở driver. Project này không có comment `RFC` nào, nên gần như toàn bộ là **(suy luận)** — chi tiết ánh xạ chuẩn → code nằm ở README của các project Drivers/Ipsec/L2tp/Ppp/OpenVpn/WireGuard/SoftEther/Transport.Dtls.

| Chuẩn (RFC/FIPS/NIST/MS-*) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| [MS-SSTP] (Secure Socket Tunneling Protocol) | `SstpDriver` qua `UseSstp()` | [VpnClientBuilder.cs:60-71](VpnClientBuilder.cs#L60-L71), [SstpDriver.cs:11](../TqkLibrary.VpnClient.Drivers.Sstp/SstpDriver.cs#L11) | Driver mô tả "TLS over 443, PPP, MS-CHAPv2"; cert TLS validate qua callback tùy chọn (P0.6) |
| RFC 2759 (MS-CHAPv2) | `SstpDriver` + `L2tpIpsecDriver` + `PptpDriver` (PPP auth) | [VpnClientBuilder.cs:60](VpnClientBuilder.cs#L60), [VpnClientBuilder.cs:74](VpnClientBuilder.cs#L74), [VpnClientBuilder.cs:102-104](VpnClientBuilder.cs#L102-L104) | (suy luận) — codec ở Crypto/`MsChapV2`, framing CHAP ở Ppp/`MsChapV2Authenticator` |
| RFC 2409 (IKEv1 / ISAKMP) | `L2tpIpsecDriver` qua `UseL2tpIpsec()` + `CiscoIpsecDriver` qua `UseCiscoIpsec()` (Aggressive Mode) | [VpnClientBuilder.cs:74-91](VpnClientBuilder.cs#L74-L91), [L2tpIpsecDriver.cs:12](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L12), [CiscoIpsecDriver.cs:18](../TqkLibrary.VpnClient.Drivers.CiscoIpsec/CiscoIpsecDriver.cs#L18) | (suy luận) — comment driver "IKEv1 PSK over NAT-T"; logic ở Ipsec `Ike/V1` |
| RFC 7296 (IKEv2) + ESP tunnel mode + CP | `Ikev2Driver` qua `UseIkev2()` / `UseIkev2(IkeCertificateTrust)` | [VpnClientBuilder.cs:166-179](VpnClientBuilder.cs#L166-L179), [Ikev2Driver.cs:11](../TqkLibrary.VpnClient.Drivers.Ikev2/Ikev2Driver.cs#L11) | (suy luận) — driver "RFC 7296 PSK over NAT-T, CP virtual IP, ESP tunnel mode — no PPP"; logic ở Ipsec `Ike/V2` + `Esp` |
| RFC 4303 (ESP) | `L2tpIpsecDriver` + `Ikev2Driver` + `CiscoIpsecDriver` (data plane) | [L2tpIpsecDriver.cs:12](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L12), [L2tpIpsecDriver.cs:52](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L52) | (suy luận) — `SecurityKinds = Esp`; hiện thực ở Ipsec `Esp` |
| RFC 3948 (UDP encapsulation / NAT-T) | `L2tpIpsecDriver` (transport UDP) | [L2tpIpsecDriver.cs:12](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L12), [L2tpIpsecDriver.cs:51](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L51) | (suy luận) — "NAT-T"; hiện thực ở [`Ipsec/Nat`](../TqkLibrary.VpnClient.Ipsec/Nat) |
| RFC 2661 (L2TPv2) | `L2tpIpsecDriver` | [L2tpIpsecDriver.cs:12](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L12) | (suy luận) — comment driver "L2TP"; hiện thực ở L2tp |
| RFC 2637 (PPTP) + RFC 3078/3079 (MPPE) | `PptpDriver` qua `UsePptp()` | [VpnClientBuilder.cs:102-104](VpnClientBuilder.cs#L102-L104), [PptpDriver.cs:16](../TqkLibrary.VpnClient.Drivers.Pptp/PptpDriver.cs#L16) | (suy luận) — TCP/1723 control + GRE proto-47 data + MPPE/RC4 + PPP/MS-CHAPv2; **legacy/không an toàn — interop only** |
| RFC 2784/2890 (GRE), RFC 2003 (IPIP), RFC 4213 (SIT/6in4) | `IpEncapDriver` qua `UseIpEncap()` (+ data plane GRE của `PptpDriver`) | [VpnClientBuilder.cs:116-118](VpnClientBuilder.cs#L116-L118), [IpEncapDriver.cs:20](../TqkLibrary.VpnClient.Drivers.IpEncap/IpEncapDriver.cs#L20) | (suy luận) — tunnel IP-in-IP **không mã hóa**, không control plane; raw IP proto-47/4/41 |
| RFC 8086 (GRE-in-UDP) + RFC 2784/2890 (GRE) | `GreInUdpDriver` qua `UseGreInUdp()` | [VpnClientBuilder.cs:121-132](VpnClientBuilder.cs#L121-L132), [GreInUdpDriver.cs:19](../TqkLibrary.VpnClient.Drivers.GreInUdp/GreInUdpDriver.cs#L19) | (suy luận) — header GRE trong payload **UDP/4754** thay raw-IP proto-47 — **không mã hóa**, **không elevate/raw socket**, qua NAT; tái dùng `GreCodec` của IpEncap |
| draft-ietf-intarea-gue (GUE) + FOU (Linux Foo-over-UDP) + RFC 2784/2890 (GRE) / RFC 2003 (IPIP) / RFC 4213 (SIT) | `FouDriver` qua `UseFou()` / `UseGue()` | [VpnClientBuilder.cs:134-163](VpnClientBuilder.cs#L134-L163), [FouDriver.cs:21](../TqkLibrary.VpnClient.Drivers.Fou/FouDriver.cs#L21) | (suy luận) — inner IP-proto (IPIP-4/41 hoặc GRE-47) trong payload **UDP**: FOU không header (proto suy từ port), GUE thêm header variant-0 4B mang Proto (skip ext theo Hlen, drop C-bit); tổng quát hoá GRE-in-UDP; **không mã hóa**, **không elevate/raw socket**; tái dùng `GreCodec`/`RawIpPassthroughChannel` của IpEncap |
| RFC 1661/1332 (PPP/IPCP) | `SstpDriver` + `L2tpIpsecDriver` + `PptpDriver` (`UsesPpp`, `AddressAssignment.Ipcp`) | [SstpDriver.cs:41](../TqkLibrary.VpnClient.Drivers.Sstp/SstpDriver.cs#L41), [L2tpIpsecDriver.cs:49](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L49) | (suy luận) — IP cấp qua IPCP; hiện thực ở Ppp. `Ikev2Driver`/`CiscoIpsecDriver`/`OpenConnectDriver` thì `UsesPpp = false` (bare IP) |
| OpenVPN (community-server protocol) + NCP AEAD | `OpenVpnDriver` qua `UseOpenVpn()` | [VpnClientBuilder.cs:194-207](VpnClientBuilder.cs#L194-L207), [OpenVpnDriver.cs:24](../TqkLibrary.VpnClient.Drivers.OpenVpn/OpenVpnDriver.cs#L24) | (suy luận) — UDP/TCP, tun-mode (L3) / tap-mode (L2), tls-auth/tls-crypt; logic ở OpenVpn |
| WireGuard (Noise_IKpsk2 + ChaCha20-Poly1305) | `WireGuardDriver` qua `UseWireGuard()` (+ data plane của `TailscaleDriver`) | [VpnClientBuilder.cs:210-214](VpnClientBuilder.cs#L210-L214), [WireGuardDriver.cs:17](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardDriver.cs#L17) | (suy luận) — UDP-only, static point-to-point, `SecurityKinds = Noise`, `AddressAssignment.OutOfBand`; logic ở WireGuard |
| Nebula (Noise_IX_25519_AESGCM_SHA256 + AES-256-GCM) | `NebulaDriver` qua `UseNebula()` | [VpnClientBuilder.cs:222-226](VpnClientBuilder.cs#L222-L226), [NebulaDriver.cs:17](../TqkLibrary.VpnClient.Drivers.Nebula/NebulaDriver.cs#L17) | (suy luận) — UDP, certificate auth chống network CA, data plane type-1 (Message); logic ở Nebula |
| Tailscale ts2021 (Noise IK control + WireGuard data) | `TailscaleDriver` qua `UseTailscale()` | [VpnClientBuilder.cs:237-241](VpnClientBuilder.cs#L237-L241), [TailscaleDriver.cs:19](../TqkLibrary.VpnClient.Drivers.Tailscale/TailscaleDriver.cs#L19) | (suy luận) — control plane Noise IK → Headscale/Tailscale + netmap, data plane WireGuard multi-peer; DERP/disco là future work |
| tinc 1.1 SPTPS (Curve25519/Ed25519/ChaCha-Poly1305) | `TincDriver` qua `UseTinc()` | [VpnClientBuilder.cs:250-254](VpnClientBuilder.cs#L250-L254), [TincDriver.cs:17](../TqkLibrary.VpnClient.Drivers.Tinc/TincDriver.cs#L17) | (suy luận) — TCP meta-connection + per-tunnel SPTPS + bare-IP router-mode over UDP; logic ở Tinc |
| n2n v3 (ntop: NULL / AES-CBC transform) | `N2nDriver` qua `UseN2n()` | [VpnClientBuilder.cs:264-268](VpnClientBuilder.cs#L264-L268), [N2nDriver.cs:17](../TqkLibrary.VpnClient.Drivers.N2n/N2nDriver.cs#L17) | (suy luận) — UDP tới supernode (REGISTER_SUPER), PACKET Ethernet frames, L2 bridge; logic ở N2n |
| vtun (legacy: MD5-keyed Blowfish-ECB challenge) | `VtunDriver` qua `UseVtun()` | [VpnClientBuilder.cs:279-283](VpnClientBuilder.cs#L279-L283), [VtunDriver.cs:18](../TqkLibrary.VpnClient.Drivers.Vtun/VtunDriver.cs#L18) | (suy luận) — 1 TCP, challenge-response, bare IP length-prefixed, ECHO keepalive; **crypto legacy/yếu — interop only** |
| SSH-2 transport (RFC 4251/4253) + `tun@openssh.com` | `SshDriver` qua `UseSsh()` | [VpnClientBuilder.cs:295-299](VpnClientBuilder.cs#L295-L299), [SshDriver.cs:18](../TqkLibrary.VpnClient.Drivers.Ssh/SshDriver.cs#L18) | (suy luận) — curve25519-sha256 KEX + ed25519 host-key + publickey/password, point-to-point L3 tun, bare IP; logic ở Ssh |
| ZeroTier VL1/VL2 (Curve25519 + Salsa20/12 + Poly1305) | `ZeroTierDriver` qua `UseZeroTier()` | [VpnClientBuilder.cs:312-316](VpnClientBuilder.cs#L312-L316), [ZeroTierDriver.cs:18](../TqkLibrary.VpnClient.Drivers.ZeroTier/ZeroTierDriver.cs#L18) | (suy luận) — UDP HELLO⇄OK identity agreement, NETWORK_CONFIG_REQUEST, EXT_FRAME L2 bridge; logic ở ZeroTier |
| OpenConnect (Cisco AnyConnect / ocserv CSTP) + RFC 6347 (DTLS 1.2) | `OpenConnectDriver` qua `UseOpenConnect()` | [VpnClientBuilder.cs:323-335](VpnClientBuilder.cs#L323-L335), [OpenConnectDriver.cs:20](../TqkLibrary.VpnClient.Drivers.OpenConnect/OpenConnectDriver.cs#L20) | (suy luận) — HTTPS config-auth → CSTP, bare IP (no PPP), `X-CSTP-DPD`; data plane DTLS 1.2 (V5.c) fallback TLS — DTLS ở [Transport.Dtls](../TqkLibrary.VpnClient.Transport.Dtls) |
| SoftEther SSL-VPN (Ethernet-over-TLS) | `SoftEtherDriver` qua `UseSoftEther()` | [VpnClientBuilder.cs:341-356](VpnClientBuilder.cs#L341-L356), [SoftEtherDriver.cs:23](../TqkLibrary.VpnClient.Drivers.SoftEther/SoftEtherDriver.cs#L23) | (suy luận) — L2 segment, DHCP-leased IP (`AddressAssignment.Dhcp`), SHA-0 password auth; logic ở SoftEther |
| RFC 7348 (VXLAN) | `VxlanDriver` qua `UseVxlan()` | [VpnClientBuilder.cs:358-370](VpnClientBuilder.cs#L358-L370), [VxlanDriver.cs:20](../TqkLibrary.VpnClient.Drivers.Vxlan/VxlanDriver.cs#L20) | (suy luận) — L2-over-UDP/**4789**, VXLAN header 8B (flags 0x08 + VNI 24-bit) → Ethernet L2 fabric, static unicast remote VTEP; **không mã hóa**, **không control plane**, **không elevate/raw socket**; logic ở Vxlan |
| draft-ietf-nvo3-vxlan-gpe (VXLAN-GPE) | `VxlanGpeDriver` qua `UseVxlanGpe()` | [VpnClientBuilder.cs:372-387](VpnClientBuilder.cs#L372-L387), [VxlanGpeDriver.cs:21](../TqkLibrary.VpnClient.Drivers.VxlanGpe/VxlanGpeDriver.cs#L21) | (suy luận + clean-room từ draft) — L2-over-UDP/**4790**, header VXLAN-GPE 8B (flags I\|P `0x0C` + Next-Protocol byte3 + VNI 24-bit) — **superset VXLAN** thêm bit P + Next-Protocol (0x01 IPv4/0x02 IPv6/**0x03 Ethernet**/0x04 NSH) → Ethernet L2 fabric, static unicast remote; ingress drop Ver≠0/thiếu I\|P/OAM/Next-Protocol≠Ethernet; **chỉ Ethernet đã wire** (IPv4/IPv6/NSH parse/validate); **không mã hóa**, **không control plane**, **không elevate/raw socket**; logic ở VxlanGpe |
| RFC 8926 (Geneve) | `GeneveDriver` qua `UseGeneve()` | [VpnClientBuilder.cs:389-404](VpnClientBuilder.cs#L389-L404), [GeneveDriver.cs:21](../TqkLibrary.VpnClient.Drivers.Geneve/GeneveDriver.cs#L21) | (suy luận) — L2-over-UDP/**6081**, base header 8B (Ver/OptLen + proto-type 0x6558 + VNI 24-bit) + options TLV biến thiên → Ethernet L2 fabric, static unicast remote; receiver skip options theo OptLen + drop critical-option lạ (§3.5); sibling VXLAN; **không mã hóa**, **không control plane**, **không elevate/raw socket**; logic ở Geneve |
| RFC 3931 (L2TPv3) + RFC 4719 (Ethernet PW) | `L2tpv3EthDriver` qua `UseL2tpv3Ethernet()` | [VpnClientBuilder.cs:406-423](VpnClientBuilder.cs#L406-L423), [L2tpv3EthDriver.cs:22](../TqkLibrary.VpnClient.Drivers.L2tpv3Eth/L2tpv3EthDriver.cs#L22) | (suy luận) — L2-over-UDP/**1701** static/unmanaged, header data L2TPv3 (Session ID 32-bit + Cookie 0/4/8 + Default L2-Specific Sublayer 4B tùy chọn) → Ethernet L2 fabric, static unicast remote; Session ID + Cookie tĩnh 2 đầu, **không control plane**; ingress drop control/zero-SID/mismatch/cookie/truncated; chạy header L2TPv3-over-IP thẳng trong UDP (no-admin, KHÁC Linux `encap udp` prefix 4B); sibling VXLAN/Geneve; **không mã hóa**, **không elevate/raw socket**; logic ở L2tpv3Eth |
| draft-massar-v6ops-ayiya-02 (AYIYA) + shared-secret SHA-1 sig (aiccu) + RFC 3053 (TIC — bỏ qua ở static mode) | `AyiyaDriver` qua `UseAyiya()` | [VpnClientBuilder.cs:439-444](VpnClientBuilder.cs#L439-L444), [AyiyaDriver.cs:21](../TqkLibrary.VpnClient.Drivers.Ayiya/AyiyaDriver.cs#L21) | (suy luận + clean-room từ draft) — tunnel-broker IPv6-over-UDP/**5072** **static mode** (bỏ control-channel TIC): gói IPv6 sau header AYIYA (header 4B idlen/idtype‖siglen/hshmeth‖autmeth/opcode‖nextheader + epoch time 4B BE + identity 2^idlen + signature siglen×4), **ký toàn vẹn shared-secret SHA-1** (đặt SHA1(password) vào ô signature → hash toàn gói → ghi đè) + **chống replay bằng epoch time**; tái dùng `RawIpPassthroughChannel` (IPv6) của IpEncap qua decorator ký/kiểm; ⚠️ **KHÔNG mã hóa payload**, **không control-plane động**, **không elevate/raw socket**; logic ở Drivers.Ayiya (SHA-1 dùng thẳng BCL) |
| FIPS-197 (AES), NIST SP 800-38D (AES-GCM) | dùng gián tiếp khi mã hóa ESP/TLS/DTLS | — | (suy luận) — primitive ở Crypto; façade không chạm trực tiếp |

> Tóm lại: dùng bảng này như **bản đồ "shortcut façade → chuẩn"**. Để xem ánh xạ chuẩn → file:line chính xác (có comment RFC trong code), đọc README các project: Drivers, Ipsec (gồm NAT-T `Nat/`), L2tp, Ppp, OpenVpn, WireGuard, SoftEther, Transport.Dtls, Crypto.

## API / cách dùng

Điểm vào public:

- `VpnClientBuilder` →
  - `UseSstp()`, `UseSstp(SstpReconnectOptions)`, `UseSstp(RemoteCertificateValidationCallback)`, `UseSstp(SstpReconnectOptions, RemoteCertificateValidationCallback)`
  - `UseL2tpIpsec()`, `UseL2tpIpsec(L2tpIpsecReconnectOptions)`, `UseL2tpIpsec(L2tpIpsecReconnectOptions, L2tpIpsecTimeoutOptions)`, `UseL2tpIpsec(IRawIpTransportFactory, L2tpIpsecNatTraversalMode, L2tpIpsecReconnectOptions?, L2tpIpsecTimeoutOptions?)`
  - `UsePptp(IRawIpTransportFactory, PptpReconnectOptions?, PptpTimeoutOptions?)`
  - `UseIpEncap(IRawIpTransportFactory, IpEncapOptions?, IpEncapReconnectOptions?)`
  - `UseGreInUdp(GreInUdpOptions?, GreInUdpReconnectOptions?)`
  - `UseFou(FouOptions?, FouReconnectOptions?)`, `UseGue(FouOptions?, FouReconnectOptions?)`
  - `UseIkev2()`, `UseIkev2(Ikev2ReconnectOptions)`, `UseIkev2(IkeCertificateTrust, Ikev2ReconnectOptions?)`
  - `UseCiscoIpsec(string groupName, CiscoIpsecReconnectOptions?)`
  - `UseOpenVpn(OpenVpnProfile)`, `UseOpenVpn(OpenVpnProfile, X509CertificateCollection?, RemoteCertificateValidationCallback?, OpenVpnReconnectOptions?)`, `UseOpenVpn(OpenVpnProfile, bool enableIpv6)`
  - `UseWireGuard(WireGuardConfig)`, `UseWireGuard(WireGuardConfig, WireGuardReconnectOptions)`
  - `UseNebula(NebulaConfig)`, `UseNebula(NebulaConfig, NebulaReconnectOptions)`
  - `UseTailscale(TailscaleConfig)`, `UseTailscale(TailscaleConfig, TailscaleReconnectOptions)`
  - `UseTinc(TincConfig)`, `UseTinc(TincConfig, TincReconnectOptions)`
  - `UseN2n(N2nConfig)`, `UseN2n(N2nConfig, N2nReconnectOptions)`
  - `UseVtun(VtunConfig)`, `UseVtun(VtunConfig, VtunReconnectOptions)`
  - `UseSsh(SshConfig)`, `UseSsh(SshConfig, SshReconnectOptions)`
  - `UseZeroTier(ZeroTierConfig)`, `UseZeroTier(ZeroTierConfig, ZeroTierReconnectOptions)`
  - `UseOpenConnect()`, `UseOpenConnect(OpenConnectReconnectOptions)`, `UseOpenConnect(OpenConnectReconnectOptions, RemoteCertificateValidationCallback?, string groupSelect)`
  - `UseSoftEther(string hubName)`, `UseSoftEther(string, SoftEtherSessionParams)`, `UseSoftEther(string, SoftEtherSessionParams, SoftEtherReconnectOptions)`, `UseSoftEther(string, bool enableIpv6)`
  - `UseVxlan(VxlanConfig)`, `UseVxlan(VxlanConfig, VxlanReconnectOptions)`
  - `UseVxlanGpe(VxlanGpeConfig)`, `UseVxlanGpe(VxlanGpeConfig, VxlanGpeReconnectOptions)`
  - `UseGeneve(GeneveConfig)`, `UseGeneve(GeneveConfig, GeneveReconnectOptions)`
  - `UseL2tpv3Ethernet(L2tpv3EthConfig)`, `UseL2tpv3Ethernet(L2tpv3EthConfig, L2tpv3EthReconnectOptions)`
  - `UseAyiya(AyiyaOptions)`, `UseAyiya(AyiyaOptions, AyiyaReconnectOptions)`
  - `AddDriver(IVpnProtocolDriver)`, `Build()`.
- `VpnClient` → `ConnectAsync(protocol, endpoint, credentials, ct)`, `Protocols`, `GetCapabilities(protocol)`.

Ví dụ tối thiểu:

```csharp
using TqkLibrary.VpnClient;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

// 1) Đăng ký driver rồi build client
var vpn = new VpnClientBuilder()
    .UseSstp()
    .UseL2tpIpsec()       // auto-reconnect bật mặc định
    .Build();

// 2) Mở kết nối theo tên giao thức
var endpoint = new VpnEndpoint("vpn.example.com", 443);
var creds = new VpnCredentials { Username = "user", Password = "pass" };

await using IVpnConnection conn = await vpn.ConnectAsync("sstp", endpoint, creds);

// 3) Mỗi session là một endpoint IP có PacketChannel để cắm IP stack / socket
IVpnSession session = conn.Sessions[0];
var ip = session.Config.AssignedAddress;
```

Tùy biến auto-reconnect cho L2TP/IPsec:

```csharp
var vpn = new VpnClientBuilder()
    .UseL2tpIpsec(new L2tpIpsecReconnectOptions { Enabled = false }) // single-shot
    .Build();
```

## Luồng nội bộ

Façade rất mỏng, gồm hai bước:

1. **Đăng ký (build-time).** Các shortcut `UseSstp()`/`UseL2tpIpsec()`/`UsePptp()`/`UseIpEncap()`/`UseGreInUdp()`/`UseFou()`/`UseGue()`/`UseIkev2()`/`UseCiscoIpsec()`/`UseOpenVpn()`/`UseWireGuard()`/`UseNebula()`/`UseTailscale()`/`UseTinc()`/`UseN2n()`/`UseVtun()`/`UseSsh()`/`UseZeroTier()`/`UseOpenConnect()`/`UseSoftEther()`/`UseVxlan()`/`UseVxlanGpe()`/`UseGeneve()`/`UseL2tpv3Ethernet()`/`UseAyiya()` tạo driver cụ thể và gọi `AddDriver` để nạp vào `Dictionary<string, IVpnProtocolDriver>` keyed theo `driver.Name` (`"sstp"`, `"l2tp-ipsec"`, `"pptp"`, `"ipencap"`, `"gre-udp"`, `"fou"`, `"gue"`, `"ikev2"`, `"cisco-ipsec"`, `"openvpn"`, `"wireguard"`, `"nebula"`, `"tailscale"`, `"tinc"`, `"n2n"`, `"vtun"`, `"ssh"`, `"zerotier"`, `"openconnect"`, `"softether"`, `"vxlan"`, `"vxlan-gpe"`, `"geneve"`, `"l2tpv3-eth"`, `"ayiya"`) — [VpnClientBuilder.cs:53-447](VpnClientBuilder.cs#L53-L447). `Build()` đóng gói dictionary đó vào `VpnClient` — [VpnClientBuilder.cs:447](VpnClientBuilder.cs#L447).
2. **Kết nối (run-time).** `ConnectAsync` và `GetCapabilities` đều tra driver qua helper chung `ResolveDriver`: nếu không có → `NotSupportedException` kèm danh sách giao thức đã đăng ký (P0.5, đồng nhất 2 đường); nếu có → `ConnectAsync` ủy thác thẳng `driver.ConnectAsync(endpoint, credentials, ct)` và trả `IVpnConnection` — [VpnClient.cs:18-31](VpnClient.cs#L18-L31).

Toàn bộ việc lắp ráp stack (IKE → ESP → L2TP → PPP → IP cho L2TP; TLS/CSTP/DTLS, GRE, VXLAN, Noise, SSH, Ethernet-over-TLS cho các giao thức khác) diễn ra **bên trong driver**, không nằm ở project này. 25 driver nằm ở 24 project anh em (Drivers.Fou cung cấp cả `fou` lẫn `gue`): [Sstp](../TqkLibrary.VpnClient.Drivers.Sstp), [L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec), [Pptp](../TqkLibrary.VpnClient.Drivers.Pptp), [IpEncap](../TqkLibrary.VpnClient.Drivers.IpEncap), [GreInUdp](../TqkLibrary.VpnClient.Drivers.GreInUdp), [Fou](../TqkLibrary.VpnClient.Drivers.Fou), [Vxlan](../TqkLibrary.VpnClient.Drivers.Vxlan), [VxlanGpe](../TqkLibrary.VpnClient.Drivers.VxlanGpe) (VXLAN-GPE superset VXLAN + Next-Protocol), [Geneve](../TqkLibrary.VpnClient.Drivers.Geneve), [L2tpv3Eth](../TqkLibrary.VpnClient.Drivers.L2tpv3Eth), [Ayiya](../TqkLibrary.VpnClient.Drivers.Ayiya) (AYIYA static-mode IPv6-over-UDP), [Ikev2](../TqkLibrary.VpnClient.Drivers.Ikev2) (IKEv2 + ESP tunnel mode, không PPP), [CiscoIpsec](../TqkLibrary.VpnClient.Drivers.CiscoIpsec), [OpenVpn](../TqkLibrary.VpnClient.Drivers.OpenVpn), [WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard), [Nebula](../TqkLibrary.VpnClient.Drivers.Nebula), [Tailscale](../TqkLibrary.VpnClient.Drivers.Tailscale), [Tinc](../TqkLibrary.VpnClient.Drivers.Tinc), [N2n](../TqkLibrary.VpnClient.Drivers.N2n), [Vtun](../TqkLibrary.VpnClient.Drivers.Vtun), [Ssh](../TqkLibrary.VpnClient.Drivers.Ssh), [ZeroTier](../TqkLibrary.VpnClient.Drivers.ZeroTier), [OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) và [SoftEther](../TqkLibrary.VpnClient.Drivers.SoftEther). Ví dụ điều phối L2TP/IPsec: `L2tpIpsecDriver.ConnectAsync` kiểm PSK bắt buộc rồi dựng `L2tpIpsecConnection` và gọi `ConnectAsync` của nó — [L2tpIpsecDriver.cs:58-88](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L58-L88). Chi tiết luồng handshake xem [.docs/10 §6](../../.docs/10-codebase-architecture-and-flow.md).

## Trạng thái & ghi chú

- **Driver đã wire:** `sstp`, `l2tp-ipsec`, `pptp`, `ipencap`, `gre-udp`, `fou`, `gue`, `ikev2`, `cisco-ipsec`, `openvpn`, `wireguard`, `nebula`, `tailscale`, `tinc`, `n2n`, `vtun`, `ssh`, `zerotier`, `openconnect`, `softether`, `vxlan`, `vxlan-gpe`, `geneve`, `l2tpv3-eth`, `ayiya` (qua 25 nhóm shortcut `UseSstp()`/`UseL2tpIpsec()`/`UsePptp()`/`UseIpEncap()`/`UseGreInUdp()`/`UseFou()`/`UseGue()`/`UseIkev2()`/`UseCiscoIpsec()`/`UseOpenVpn()`/`UseWireGuard()`/`UseNebula()`/`UseTailscale()`/`UseTinc()`/`UseN2n()`/`UseVtun()`/`UseSsh()`/`UseZeroTier()`/`UseOpenConnect()`/`UseSoftEther()`/`UseVxlan()`/`UseVxlanGpe()`/`UseGeneve()`/`UseL2tpv3Ethernet()`/`UseAyiya()`). Driver tùy ý khác có thể nạp qua `AddDriver(IVpnProtocolDriver)`.
- **L2TP/IPsec chạy trên IKEv1** (đã kiểm chứng live trên VPN Gate); IKEv2-native là driver `ikev2` riêng (qua `UseIkev2()`), không dùng chung connection với L2TP. `CiscoIpsecDriver` (key `cisco-ipsec`) cũng dùng IKEv1 nhưng theo Aggressive Mode + XAUTH + Mode-Config.
- **Cần elevation (raw IP):** `UsePptp()` (GRE proto-47), `UseIpEncap()` (proto-47/4/41) và overload native-ESP của `UseL2tpIpsec()` (proto-50) cần một `IRawIpTransportFactory` — truyền `new RawIpTransportFactory()` từ `TqkLibrary.VpnClient.Transport.RawIp`; các driver còn lại thuần userspace, không cần elevation.
- **PSK bắt buộc (L2TP + IKEv2):** `L2tpIpsecDriver` **không** nhét PSK mặc định — `VpnCredentials.PreSharedKey` null/rỗng ⇒ ném `ArgumentException` (default credential đặc thù VPN Gate không thuộc lib chung) — [L2tpIpsecDriver.cs:60-64](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L60-L64); `Ikev2Driver` cũng yêu cầu PSK tương tự — [Ikev2Driver.cs:61-64](../TqkLibrary.VpnClient.Drivers.Ikev2/Ikev2Driver.cs#L61-L64). Group PSK `"vpn"` của VPN Gate nằm ở tầng demo ([VpnTarget ctor `preSharedKey` default :23](../../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L23)).
- **Multi-host:** `OpenSessionAsync` được khai báo ở `IVpnConnection`. Hầu hết driver (gồm cả `N2nDriver`/`ZeroTierDriver` dù bridge L2) đặt `MultiHostModel.None` → một session/kết nối; chỉ `OpenVpnDriver` (tap-mode) và `SoftEtherDriver` bật chế độ **multi-host L2** (`MultiHostModel.L2BroadcastDomain`) → mỗi station một session.
- **netstandard2.0 vs net8.0:** không khác biệt API ở tầng façade; khác biệt chỉ phát sinh tận tầng Crypto/Transport (BouncyCastle cho AES-GCM trên netstandard2.0, DTLS qua BouncyCastle ở [Transport.Dtls](../TqkLibrary.VpnClient.Transport.Dtls)). `record`/`init` build xanh cả hai TFM nhờ polyfill `TqkLibrary.CompilerServices`.
- **Không ghi vào OS:** façade/driver **không chạm bảng route hệ điều hành**; tất cả là userspace — app tự lái lưu lượng qua `PacketChannel`/sockets trong tunnel.
