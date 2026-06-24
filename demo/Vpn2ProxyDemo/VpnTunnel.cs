using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.CiscoIpsec;
using TqkLibrary.VpnClient.Drivers.Ikev2;
using TqkLibrary.VpnClient.Drivers.IpEncap;
using TqkLibrary.VpnClient.Drivers.IpEncap.Enums;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums;
using TqkLibrary.VpnClient.Drivers.N2n;
using TqkLibrary.VpnClient.Drivers.N2n.Config;
using TqkLibrary.VpnClient.Drivers.Vtun;
using TqkLibrary.VpnClient.Drivers.Vtun.Config;
using TqkLibrary.VpnClient.Drivers.Vtun.Transport;
using TqkLibrary.VpnClient.Drivers.ZeroTier;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Config;
using TqkLibrary.VpnClient.Drivers.Nebula;
using TqkLibrary.VpnClient.Drivers.Nebula.Config;
using TqkLibrary.VpnClient.Drivers.OpenConnect;
using TqkLibrary.VpnClient.Drivers.OpenVpn;
using TqkLibrary.VpnClient.Drivers.Pptp;
using TqkLibrary.VpnClient.Drivers.SoftEther;
using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.Tinc;
using TqkLibrary.VpnClient.Drivers.Tinc.Config;
using TqkLibrary.VpnClient.Drivers.WireGuard;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.Tinc.Hosts;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Một tunnel VPN đã kết nối, lộ ra userspace <see cref="TcpIpStack"/> để chạy proxy bên trong tunnel.
    /// <para>
    /// Không trả thẳng <see cref="TcpIpStack"/> được vì stack bám vào kết nối VPN bên dưới (SSTP/L2TP/SoftEther/OpenVPN) —
    /// kết nối đó phải sống tới khi proxy dùng xong. <see cref="VpnTunnel"/> giữ lại handle teardown:
    /// <see cref="DisposeAsync"/> sẽ đóng kết nối VPN.
    /// </para>
    /// <para>
    /// Phần connect riêng của từng giao thức là hàm static (<see cref="ConnectSstpAsync"/> / <see cref="ConnectL2tpAsync"/> /
    /// <see cref="ConnectSoftEtherAsync"/> / <see cref="ConnectOpenVpnAsync"/> / <see cref="ConnectWireGuardAsync"/>): thêm
    /// giao thức mới = thêm một hàm static + một nhánh dispatch ở <c>CommandModule</c>.
    /// </para>
    /// </summary>
    internal sealed class VpnTunnel : IAsyncDisposable
    {
        readonly Func<ValueTask> _disposeAsync;

        public VpnTunnel(TcpIpStack stack, Func<ValueTask> disposeAsync,
            IPAddress assignedAddress, int mtu, VpnDriverCapabilities capabilities, string protocolName,
            IPAddress? assignedDns = null, IPAddress? assignedAddressV6 = null)
        {
            Stack = stack ?? throw new ArgumentNullException(nameof(stack));
            _disposeAsync = disposeAsync ?? throw new ArgumentNullException(nameof(disposeAsync));
            AssignedAddress = assignedAddress ?? throw new ArgumentNullException(nameof(assignedAddress));
            Mtu = mtu;
            Capabilities = capabilities ?? throw new ArgumentNullException(nameof(capabilities));
            ProtocolName = protocolName ?? throw new ArgumentNullException(nameof(protocolName));
            AssignedDns = assignedDns;
            AssignedAddressV6 = assignedAddressV6;
        }

        /// <summary>Userspace TCP/IP stack chạy trong tunnel — dùng làm ctor của <c>VpnProxySource</c>.</summary>
        public TcpIpStack Stack { get; }

        /// <summary>IP ảo do VPN cấp (IPv4) — dùng cho panel khả năng + suy luận NAT/subnet.</summary>
        public IPAddress AssignedAddress { get; }

        /// <summary>
        /// Địa chỉ IPv6 <b>global</b> do tunnel cấp (SLAAC/DHCPv6 qua PPP, P1.1), hoặc null nếu chỉ có link-local /
        /// server không cấp IPv6. Khi khác null thì stack chạy dual-stack và proxy bật <c>IsSupportIpv6</c>.
        /// </summary>
        public IPAddress? AssignedAddressV6 { get; }

        /// <summary>MTU của link tunnel (lấy từ <c>IPacketChannel.Mtu</c>) — hiển thị ở panel khả năng.</summary>
        public int Mtu { get; }

        /// <summary>Năng lực tĩnh của driver giao thức (transport/bảo mật/auth/cấp địa chỉ) — "hỏi năng lực" cho panel.</summary>
        public VpnDriverCapabilities Capabilities { get; }

        /// <summary>Tên giao thức/driver (vd "sstp", "l2tp-ipsec") — tiêu đề panel khả năng.</summary>
        public string ProtocolName { get; }

        /// <summary>DNS server do VPN cấp (nếu có) — dùng làm đích mặc định cho probe DNS-over-UDP.</summary>
        public IPAddress? AssignedDns { get; }

        public ValueTask DisposeAsync() => _disposeAsync();

        /// <summary>Connect VPN Gate qua MS-SSTP (TLS) bằng host/port/user/pass; trả tunnel đã lên (đang sống).
        /// <paramref name="enableIpv6"/>: bật IPV6CP + lấy IPv6 global qua SLAAC/DHCPv6 trên link PPP (P1.1, best-effort).
        /// <paramref name="preferOuterIpv6"/>: ưu tiên IPv6 cho transport NGOÀI (resolve AAAA, TLS-over-IPv6) — P1.2; fallback IPv4 nếu host không có AAAA.</summary>
        public static async Task<VpnTunnel> ConnectSstpAsync(string host, int port, string user, string pass, CancellationToken ct, bool enableIpv6 = false, bool preferOuterIpv6 = false)
        {
            Console.WriteLine("=== [MS-SSTP] ===");
            AddressFamilyPreference outerPref = preferOuterIpv6 ? AddressFamilyPreference.IPv6 : AddressFamilyPreference.Auto;
            var vpn = new SstpConnection(host, port, addressFamilyPreference: outerPref, enableIpv6: enableIpv6);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[sstp] connecting to {host}:{port} (TLS) ...");
                await vpn.ConnectAsync(user, pass, cts.Token);
                IPAddress? v6 = GlobalV6(vpn.AssignedAddressV6);
                Console.WriteLine($"[sstp] tunnel up. assigned IP = {vpn.AssignedAddress}, ipv6 = {v6?.ToString() ?? "(none)"}, dns = {vpn.AssignedDns}");

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress, v6);
                var driver = new SstpDriver();
                return new VpnTunnel(stack, () => { vpn.Dispose(); return ValueTask.CompletedTask; },
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, vpn.AssignedDns, v6);
            }
            catch
            {
                vpn.Dispose();
                throw;
            }
        }

        /// <summary>Connect VPN Gate qua L2TP/IPsec (IKEv1 PSK, NAT-T) bằng host/user/pass + group PSK; trả tunnel đã lên (đang sống).
        /// <paramref name="enableIpv6"/>: bật IPV6CP + lấy IPv6 global qua SLAAC/DHCPv6 trên link PPP-trong-L2TP (P1.1, best-effort).
        /// <paramref name="useNativeEsp"/>: bật carrier ESP gốc (proto-50) qua raw-IP cho gateway no-NAT dưới chế độ
        /// <see cref="L2tpIpsecNatTraversalMode.HonestFirst"/> (P0.8c) thay vì float UDP/4500 — cần quyền raw socket (CAP_NET_RAW/Administrator).
        /// <paramref name="preferOuterIpv6"/>: ưu tiên IPv6 cho transport NGOÀI (resolve AAAA, IKE/ESP-in-UDP over IPv6) — P1.2; fallback IPv4 nếu host không có AAAA.</summary>
        public static async Task<VpnTunnel> ConnectL2tpAsync(string host, string user, string pass, string preSharedKey, CancellationToken ct, bool enableIpv6 = false, bool useNativeEsp = false, int extraSessions = 0, bool preferOuterIpv6 = false)
        {
            Console.WriteLine("=== [L2TP/IPsec] ===");
            // P0.8c: khi bật native-ESP, cấp raw-IP factory (ESP proto-50) + đặt NAT-T mode HonestFirst để chở ESP gốc khi
            // gateway no-NAT (không float UDP/4500). Cờ tắt ⇒ rawIpFactory null + giữ NAT-T mặc định (hành vi cũ không đổi).
            L2tpIpsecNatTraversalMode natTraversalMode = useNativeEsp
                ? L2tpIpsecNatTraversalMode.HonestFirst
                : L2tpIpsecNatTraversalMode.ForcedNatT;
            IRawIpTransportFactory? rawIpFactory = useNativeEsp
                ? new TqkLibrary.VpnClient.Transport.RawIp.RawIpTransportFactory()
                : null;
            if (useNativeEsp)
                Console.WriteLine("[l2tp] native-ESP BẬT (P0.8c): ESP proto-50 qua raw-IP, NAT-T HonestFirst — cần CAP_NET_RAW/Administrator.");
            // PSK do caller cấp (VpnTarget mặc định "vpn" của VPN Gate). Driver không còn nhét PSK mặc định (P0.4).
            // Console logger để thấy trace handshake/keepalive/rekey/reconnect khi chạy live (như SoftEther/OpenVPN).
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            AddressFamilyPreference outerPref = preferOuterIpv6 ? AddressFamilyPreference.IPv6 : AddressFamilyPreference.Auto;
            var vpn = new L2tpIpsecConnection(host, Encoding.ASCII.GetBytes(preSharedKey),
                natTraversalMode: natTraversalMode, addressFamilyPreference: outerPref,
                enableIpv6: enableIpv6, loggerFactory: loggerFactory, rawIpFactory: rawIpFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[l2tp] connecting to {host} (IKEv1/NAT-T UDP 500->4500) ...");
                await vpn.ConnectAsync(user, pass, cts.Token);
                IPAddress? v6 = GlobalV6(vpn.AssignedAddressV6);
                Console.WriteLine($"[l2tp] tunnel up. assigned IP = {vpn.AssignedAddress}, ipv6 = {v6?.ToString() ?? "(none)"}, dns = {vpn.AssignedDns}");

                // P1.7: mở thêm phiên L2TP trên CÙNG tunnel/IKE-SA — mỗi phiên chạy PPP/IPCP riêng ⇒ địa chỉ độc lập.
                // Giữ tham chiếu (qua closure dispose) để phiên phụ sống cùng tunnel. Server chỉ-1-phiên ⇒ ném (CDN).
                var extras = new List<TqkLibrary.VpnClient.Drivers.L2tpIpsec.Models.L2tpIpsecAdditionalSession>();
                for (int i = 1; i <= extraSessions; i++)
                {
                    using var extraCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    extraCts.CancelAfter(TimeSpan.FromSeconds(30));
                    var extra = await vpn.OpenAdditionalSessionAsync(extraCts.Token);
                    extras.Add(extra);
                    Console.WriteLine($"[l2tp] phiên phụ #{i} lên. assigned IP = {extra.AssignedAddress}, dns = {extra.AssignedDns} (cùng IKE/IPsec SA, PPP/IPCP riêng — P1.7)");
                }

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress, v6);
                var driver = new L2tpIpsecDriver();
                return new VpnTunnel(stack, async () => { GC.KeepAlive(extras); await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, vpn.AssignedDns, v6);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>Connect tới gateway IKEv2-native (RFC 7296) bằng host + group PSK; trả tunnel đã lên (đang sống).
        /// Driver chạy forced NAT-T (UDP 500→4500) → IKE_SA_INIT → IKE_AUTH → Config Payload (virtual IP/DNS) → ESP
        /// tunnel mode → <see cref="TcpIpStack"/> trực tiếp (KHÔNG PPP, V.1). Khi <paramref name="eapUser"/>/<paramref name="eapPass"/>
        /// đều khác null thì initiator dùng EAP-MSCHAPv2 (RFC 7296 §2.16) thay cho PSK AUTH; null ⇒ PSK-only.
        /// <paramref name="preferOuterIpv6"/>: ưu tiên IPv6 cho transport NGOÀI (resolve AAAA, IKE/ESP-in-UDP over IPv6) — P1.2.</summary>
        public static async Task<VpnTunnel> ConnectIkev2Async(string host, string preSharedKey, string? eapUser, string? eapPass, CancellationToken ct, bool preferOuterIpv6 = false)
        {
            Console.WriteLine("=== [IKEv2-native] ===");
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            AddressFamilyPreference outerPref = preferOuterIpv6 ? AddressFamilyPreference.IPv6 : AddressFamilyPreference.Auto;
            var vpn = new Ikev2Connection(host, Encoding.ASCII.GetBytes(preSharedKey),
                addressFamilyPreference: outerPref,
                eapUserName: string.IsNullOrEmpty(eapUser) ? null : eapUser,
                eapPassword: string.IsNullOrEmpty(eapPass) ? null : eapPass,
                loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                string auth = string.IsNullOrEmpty(eapUser) ? "PSK" : "EAP-MSCHAPv2";
                Console.WriteLine($"[ikev2] connecting to {host} (IKEv2 forced NAT-T UDP 500->4500, auth {auth}) ...");
                await vpn.ConnectAsync(cts.Token);
                Console.WriteLine($"[ikev2] tunnel up. assigned IP = {vpn.AssignedAddress}, dns = {vpn.AssignedDns?.ToString() ?? "(none)"}");

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress, null);
                var driver = new Ikev2Driver();
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, vpn.AssignedDns);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>Connect tới gateway Cisco IPsec / EzVPN bằng host + group name + group PSK + XAUTH user/pass; trả tunnel đã lên (V.12).
        /// Driver chạy IKEv1 Aggressive Mode (group PSK, forced NAT-T UDP 500→4500) → XAUTH (user/pass) → Mode-Config
        /// (virtual IP/DNS) → ESP tunnel mode → <see cref="TcpIpStack"/> trực tiếp (KHÔNG PPP/L2TP). ⚠️ Aggressive Mode +
        /// group PSK là Phase 1 yếu (dictionary attack offline trên group PSK) — chỉ interop gateway Cisco-compatible legacy.</summary>
        public static async Task<VpnTunnel> ConnectCiscoIpsecAsync(string host, string groupName, string groupPreSharedKey, string user, string pass, CancellationToken ct)
        {
            Console.WriteLine("=== [Cisco IPsec / EzVPN] ===");
            Console.WriteLine("[cisco] CẢNH BÁO: IKEv1 Aggressive Mode + group PSK là Phase 1 YẾU (dictionary attack offline) — chỉ interop gateway legacy.");
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var driver = new CiscoIpsecDriver(groupName, loggerFactory: loggerFactory);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(90));

            Console.WriteLine($"[cisco] connecting to {host} (IKEv1 Aggressive Mode group '{groupName}' → XAUTH '{user}' → Mode-Config → ESP tunnel, forced NAT-T UDP 500->4500) ...");
            IVpnConnection connection;
            try
            {
                connection = await driver.ConnectAsync(
                    new VpnEndpoint(host, 500),
                    new VpnCredentials { PreSharedKey = Encoding.ASCII.GetBytes(groupPreSharedKey), Username = user, Password = pass },
                    cts.Token);
            }
            catch { loggerFactory.Dispose(); throw; }
            try
            {
                IVpnSession session = connection.Sessions[0];
                IPAddress assigned = session.Config.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = session.Config.DnsServers.Count > 0 ? session.Config.DnsServers[0] : null;
                Console.WriteLine($"[cisco] tunnel up. assigned IP = {assigned}, dns = {dns?.ToString() ?? "(none)"}");

                var stack = new TcpIpStack(session.PacketChannel, assigned, null);
                return new VpnTunnel(stack, async () => { await connection.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, session.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns);
            }
            catch
            {
                await connection.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Connect VPN Gate qua SoftEther SSL-VPN (Ethernet-over-TLS, SecureNAT cấp IP qua DHCP, auth SHA-0) tới
        /// <paramref name="hubName"/> (VPN Gate dùng <c>VPNGATE</c>); trả tunnel đã lên (đang sống). Tái dùng nguyên
        /// <see cref="SoftEtherDriver"/> — phiên L3 đầu tiên (<see cref="IVpnSession"/>) lộ <c>PacketChannel</c>/<c>Config</c>.
        /// </summary>
        public static async Task<VpnTunnel> ConnectSoftEtherAsync(string host, int port, string user, string pass, string hubName, string? watermarkPath, CancellationToken ct)
        {
            Console.WriteLine("=== [SoftEther SSL-VPN] ===");
            // A real SoftEther server rejects the placeholder watermark (HTTP 403); load the genuine blob from a file at
            // runtime when given (never committed to the repo — it is GPL data). Empty ⇒ placeholder (offline stub only).
            TqkLibrary.VpnClient.SoftEther.SoftEtherWatermark? watermark = null;
            if (!string.IsNullOrWhiteSpace(watermarkPath))
            {
                byte[] blob = File.ReadAllBytes(watermarkPath);
                watermark = new TqkLibrary.VpnClient.SoftEther.SoftEtherWatermark().WithSignature(blob);
                Console.WriteLine($"[softether] loaded watermark blob ({blob.Length} bytes) from {watermarkPath}");
            }
            else
            {
                Console.WriteLine("[softether] CẢNH BÁO: dùng watermark placeholder — server SoftEther thật sẽ trả 403. Truyền --watermark <file> với blob thật.");
            }
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var driver = new SoftEtherDriver(hubName, watermark: watermark, loggerFactory: loggerFactory);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(90));

            Console.WriteLine($"[softether] connecting to {host}:{port} (TLS, hub '{hubName}') ...");
            IVpnConnection connection;
            try
            {
                connection = await driver.ConnectAsync(
                    new VpnEndpoint(host, port), new VpnCredentials { Username = user, Password = pass }, cts.Token);
            }
            catch { loggerFactory.Dispose(); throw; }
            try
            {
                IVpnSession session = connection.Sessions[0];
                IPAddress assigned = session.Config.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = session.Config.DnsServers.Count > 0 ? session.Config.DnsServers[0] : null;
                IPAddress? v6 = GlobalV6(session.Config.AssignedAddressV6);
                Console.WriteLine($"[softether] tunnel up. assigned IP = {assigned}, ipv6 = {v6?.ToString() ?? "(none)"}, dns = {dns}");

                var stack = new TcpIpStack(session.PacketChannel, assigned, v6);
                return new VpnTunnel(stack, async () => { await connection.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, session.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns, v6);
            }
            catch
            {
                await connection.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Connect qua OpenVPN từ một file <paramref name="configPath"/> (<c>.ovpn</c>): parse profile, lấy <c>remote</c>
        /// đầu tiên làm endpoint, rồi tái dùng nguyên <see cref="OpenVpnDriver"/> (transport UDP/TCP theo <c>proto</c>,
        /// tự nạp cert/key inline, NCP/tls-auth/tls-crypt từ profile). Trả tunnel đã lên (đang sống).
        /// </summary>
        public static async Task<VpnTunnel> ConnectOpenVpnAsync(string configPath, string user, string pass, CancellationToken ct)
        {
            Console.WriteLine("=== [OpenVPN] ===");
            string path = ResolveConfigPath(configPath);
            OpenVpnProfile profile = OpenVpnConfigParser.Parse(File.ReadAllText(path));
            if (profile.Remotes.Count == 0)
                throw new InvalidOperationException($"File .ovpn '{path}' không có dòng 'remote <host> <port>'.");

            OpenVpnRemote remote = profile.Remotes[0];
            string proto = (remote.Protocol ?? profile.Protocol).ToString().ToLowerInvariant();
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var driver = new OpenVpnDriver(profile, loggerFactory: loggerFactory);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(90));

            Console.WriteLine($"[openvpn] connecting to {remote.Host}:{remote.Port} ({proto}, dev {profile.Device.ToString().ToLowerInvariant()}) ...");
            IVpnConnection connection;
            try
            {
                connection = await driver.ConnectAsync(
                    new VpnEndpoint(remote.Host, remote.Port),
                    new VpnCredentials { Username = string.IsNullOrEmpty(user) ? null : user, Password = string.IsNullOrEmpty(pass) ? null : pass },
                    cts.Token);
            }
            catch { loggerFactory.Dispose(); throw; }
            try
            {
                IVpnSession session = connection.Sessions[0];
                IPAddress assigned = session.Config.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = session.Config.DnsServers.Count > 0 ? session.Config.DnsServers[0] : null;
                IPAddress? v6 = GlobalV6(session.Config.AssignedAddressV6);
                Console.WriteLine($"[openvpn] tunnel up. assigned IP = {assigned}, ipv6 = {v6?.ToString() ?? "(none)"}, dns = {dns}");

                var stack = new TcpIpStack(session.PacketChannel, assigned, v6);
                return new VpnTunnel(stack, async () => { await connection.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, session.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns, v6);
            }
            catch
            {
                await connection.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Connect tới một peer WireGuard (Noise_IKpsk2, UDP) từ một file <paramref name="configPath"/> wg-quick
        /// (<c>.conf</c>): parse <c>[Interface]</c> (PrivateKey/Address/DNS) + <c>[Peer]</c> (PublicKey/PresharedKey/
        /// Endpoint/AllowedIPs/PersistentKeepalive) thành <see cref="WireGuardConfig"/>, rồi tái dùng nguyên
        /// <see cref="WireGuardConnection"/> (driver chạy handshake initiator → data type-4 → <see cref="TcpIpStack"/>
        /// trực tiếp, KHÔNG PPP/IPCP — V.3). Trả tunnel đã lên (đang sống).
        /// </summary>
        public static async Task<VpnTunnel> ConnectWireGuardAsync(string configPath, CancellationToken ct)
        {
            Console.WriteLine("=== [WireGuard] ===");
            string path = ResolveConfigPath(configPath);
            (WireGuardConfig config, string host, int port) = ParseWireGuardConf(File.ReadAllText(path));
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var factory = new WireGuardSocketTransportFactory();
            var vpn = new WireGuardConnection(host, port, config, factory, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[wireguard] connecting to {host}:{port} (UDP, Noise_IKpsk2 initiator) ...");
                await vpn.ConnectAsync(cts.Token);
                IPAddress assigned = vpn.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = vpn.Config.DnsServers.Count > 0 ? vpn.Config.DnsServers[0] : null;
                IPAddress? v6 = GlobalV6(vpn.Config.AssignedAddressV6);
                Console.WriteLine($"[wireguard] tunnel up. assigned IP = {assigned}, ipv6 = {v6?.ToString() ?? "(none)"}, dns = {dns?.ToString() ?? "(none)"}");

                var stack = new TcpIpStack(vpn.PacketChannel, assigned, v6);
                var driver = new WireGuardDriver(config);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns, v6);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Connect tới một gateway OpenConnect (Cisco AnyConnect / ocserv) bằng host/port/user/pass (V.5): driver chạy
        /// HTTPS <c>config-auth</c> (POST <c>/</c> user/pass → session cookie) → HTTP <c>CONNECT /CSCOSSLC/tunnel</c> →
        /// CSTP-over-TLS, lấy IP từ <c>X-CSTP-Address</c> rồi gói IP thẳng vào <see cref="TcpIpStack"/> (KHÔNG PPP). Khi
        /// <paramref name="enableDtls"/> bật và gateway quảng bá <c>X-DTLS-*</c>, data plane chuyển sang DTLS 1.2 (UDP)
        /// song song, fallback CSTP-over-TLS nếu DTLS không lên. Cert gateway tự-ký ⇒ accept-any (cookie mới là phần
        /// authorize tunnel). Trả tunnel đã lên (đang sống).
        /// </summary>
        public static async Task<VpnTunnel> ConnectOpenConnectAsync(string host, int port, string user, string pass, bool enableDtls, CancellationToken ct)
        {
            Console.WriteLine("=== [OpenConnect] ===");
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            // Cert tự-ký của ocserv lab ⇒ accept-any cho cả TLS byte-stream và DTLS (cookie mới authorize tunnel).
            var driver = new OpenConnectDriver(
                serverCertificateValidation: (_, _, _, _) => true,
                dtlsCertificateValidation: _ => true,
                enableDtls: enableDtls,
                loggerFactory: loggerFactory);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(90));

            Console.WriteLine($"[openconnect] connecting to {host}:{port} (HTTPS config-auth → CSTP-over-TLS{(enableDtls ? " + DTLS data path" : "")}) ...");
            IVpnConnection connection;
            try
            {
                connection = await driver.ConnectAsync(
                    new VpnEndpoint(host, port),
                    new VpnCredentials { Username = string.IsNullOrEmpty(user) ? null : user, Password = string.IsNullOrEmpty(pass) ? null : pass },
                    cts.Token);
            }
            catch { loggerFactory.Dispose(); throw; }
            try
            {
                IVpnSession session = connection.Sessions[0];
                IPAddress assigned = session.Config.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = session.Config.DnsServers.Count > 0 ? session.Config.DnsServers[0] : null;
                IPAddress? v6 = GlobalV6(session.Config.AssignedAddressV6);
                Console.WriteLine($"[openconnect] tunnel up. assigned IP = {assigned}, ipv6 = {v6?.ToString() ?? "(none)"}, dns = {dns}");

                var stack = new TcpIpStack(session.PacketChannel, assigned, v6);
                return new VpnTunnel(stack, async () => { await connection.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, session.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns, v6);
            }
            catch
            {
                await connection.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Connect tới một server PPTP (RFC 2637) bằng host/user/pass (V.6): driver mở control TCP/1723 (SCCRQ/SCCRP →
        /// OCRQ/OCRP lấy Call-IDs) rồi dựng data plane GRE proto-47 trên <b>raw IP socket</b> (cần CAP_NET_RAW/Administrator),
        /// chạy PPP MS-CHAPv2 → CCP/MPPE (RC4) → IPCP lấy IP, gói IP thẳng vào <see cref="TcpIpStack"/>. Trả tunnel đã lên
        /// (đang sống). ⚠️ MS-CHAPv2+MPPE/RC4 đã bị phá — chỉ để tương thích server PPTP legacy.
        /// </summary>
        public static async Task<VpnTunnel> ConnectPptpAsync(string host, string user, string pass, CancellationToken ct)
        {
            Console.WriteLine("=== [PPTP] ===");
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            // GRE proto-47 đi trên raw IP socket (probe quyền dùng GRE thay vì ESP mặc định). Cần CAP_NET_RAW/Administrator.
            var rawIpFactory = new TqkLibrary.VpnClient.Transport.RawIp.RawIpTransportFactory(
                probeProtocol: TqkLibrary.VpnClient.Transport.RawIp.RawIpProtocols.Gre);
            var vpn = new PptpConnection(host, rawIpFactory, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[pptp] connecting to {host} (control TCP/1723 → GRE proto-47 raw socket) ...");
                await vpn.ConnectAsync(user, pass, cts.Token);
                Console.WriteLine($"[pptp] tunnel up. assigned IP = {vpn.AssignedAddress}, dns = {vpn.AssignedDns?.ToString() ?? "(none)"}");

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress, null);
                var driver = new PptpDriver(rawIpFactory);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, vpn.AssignedDns);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Connect qua plain IP-encap (V.8): GRE proto-47 / IPIP proto-4 / SIT proto-41 trên một <b>raw IP socket</b>
        /// (cần CAP_NET_RAW/Administrator). KHÔNG control plane — connectionless, không handshake/auth/keepalive — nên địa
        /// chỉ tunnel phải cấp TĨNH out-of-band: <paramref name="tunnelAddressCidr"/> (vd <c>10.80.0.2/24</c> cho GRE/IPIP,
        /// <c>fd00::2/64</c> cho SIT) gán cho stack, <paramref name="tunnelPeer"/> là gateway bên trong tunnel (đích probe).
        /// Driver mở <see cref="GreTunnelChannel"/> (GRE) hoặc <see cref="RawIpPassthroughChannel"/> (IPIP/SIT) rồi gói IP
        /// thẳng vào <see cref="TcpIpStack"/>. ⚠️ GRE/IPIP/SIT KHÔNG mã hóa — chỉ dùng trên đường tin cậy hoặc dưới IPsec.
        /// </summary>
        public static async Task<VpnTunnel> ConnectIpEncapAsync(string host, IpEncapKind kind, string tunnelAddressCidr, string? tunnelPeer, CancellationToken ct)
        {
            Console.WriteLine("=== [IP-encap] ===");
            (IPAddress local, _) = ParseCidr(tunnelAddressCidr);
            IPAddress? peer = string.IsNullOrEmpty(tunnelPeer) ? null : IPAddress.Parse(tunnelPeer!);
            bool isV6 = kind == IpEncapKind.Sit;
            if (isV6 && local.AddressFamily != AddressFamily.InterNetworkV6)
                throw new InvalidOperationException("SIT (proto-41) cần địa chỉ IPv6 — dùng ?addr6=<ipv6>/<prefix>.");
            if (!isV6 && local.AddressFamily != AddressFamily.InterNetwork)
                throw new InvalidOperationException($"{kind} cần địa chỉ IPv4 — dùng ?addr=<ipv4>/<prefix>.");

            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            // Raw IP socket trên protocol number của kind (GRE-47/IPIP-4/SIT-41). probeProtocol khớp kind để IsAvailable đúng.
            int probeProtocol = kind switch
            {
                IpEncapKind.Gre => TqkLibrary.VpnClient.Transport.RawIp.RawIpProtocols.Gre,
                IpEncapKind.IpIp => TqkLibrary.VpnClient.Transport.RawIp.RawIpProtocols.IpIp,
                IpEncapKind.Sit => TqkLibrary.VpnClient.Transport.RawIp.RawIpProtocols.Sit,
                _ => TqkLibrary.VpnClient.Transport.RawIp.RawIpProtocols.Gre,
            };
            var rawIpFactory = new TqkLibrary.VpnClient.Transport.RawIp.RawIpTransportFactory(probeProtocol: probeProtocol);
            var options = new IpEncapOptions { Kind = kind };
            var vpn = new IpEncapConnection(host, rawIpFactory, options, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(30));

                Console.WriteLine($"[ipencap] connecting to {host} (raw-IP {kind}, proto-{probeProtocol}) ...");
                await vpn.ConnectAsync(cts.Token);
                Console.WriteLine($"[ipencap] tunnel up (connectionless). local tunnel IP = {local}, peer = {peer?.ToString() ?? "(none)"}, mtu = {vpn.PacketChannel.Mtu}");

                // Connectionless: KHÔNG IPCP/DHCP → gán IP tĩnh. SIT chỉ IPv6, GRE/IPIP chỉ IPv4. Peer làm "DNS"/gateway
                // mặc định để panel khả năng probe ICMP/UDP nhắm vào peer (peer lab có thể chạy responder).
                var stack = isV6
                    ? new TcpIpStack(vpn.PacketChannel, null, local)
                    : new TcpIpStack(vpn.PacketChannel, local, null);
                IPAddress assignedV4 = isV6 ? IPAddress.Any : local;
                IPAddress? assignedV6 = isV6 ? local : null;
                var driver = new IpEncapDriver(rawIpFactory, options);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    assignedV4, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, peer, assignedV6);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Connect tới một peer Nebula (Slack mesh VPN — Noise_IX_25519_AESGCM_SHA256, UDP) từ một file
        /// <paramref name="configPath"/> <c>.nebula</c> (ini: <c>ca=</c>/<c>cert=</c>/<c>key=</c> trỏ tới PEM của
        /// nebula-cert + <c>endpoint=host:port</c> static-host-map + <c>overlay=ip/prefix</c>): nạp CA/cert/X25519-key,
        /// dựng <see cref="NebulaConfig"/>, rồi tái dùng nguyên <see cref="NebulaConnection"/> (driver chạy handshake
        /// initiator → data type-1 Message → <see cref="TcpIpStack"/> trực tiếp, KHÔNG PPP — V.7.1). Trả tunnel đã lên.
        /// </summary>
        public static async Task<VpnTunnel> ConnectNebulaAsync(string configPath, CancellationToken ct)
        {
            Console.WriteLine("=== [Nebula] ===");
            string path = ResolveConfigPath(configPath);
            (NebulaConfig config, string host, int port) = ParseNebulaConf(File.ReadAllText(path), Path.GetDirectoryName(Path.GetFullPath(path))!);
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var factory = new TqkLibrary.VpnClient.Drivers.Nebula.Transport.NebulaSocketTransportFactory();
            var vpn = new NebulaConnection(host, port, config, factory, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[nebula] connecting to {host}:{port} (UDP, Noise IX initiator) ...");
                await vpn.ConnectAsync(cts.Token);
                IPAddress assigned = vpn.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = vpn.Config.DnsServers.Count > 0 ? vpn.Config.DnsServers[0] : null;
                Console.WriteLine($"[nebula] tunnel up. overlay IP = {assigned}, dns = {dns?.ToString() ?? "(none)"}, mtu = {vpn.PacketChannel.Mtu}");

                var stack = new TcpIpStack(vpn.PacketChannel, assigned, null);
                var driver = new NebulaDriver(config);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Kết nối tinc 1.1 (SPTPS) từ một file <c>.tinc</c> (ini: name/key/peerhost/endpoint/overlay/dns). Mở
        /// TCP meta-connection + SPTPS handshake -> data-plane SPTPS (REQ_KEY/ANS_KEY) -> bare-IP router-mode over UDP.
        /// </summary>
        public static async Task<VpnTunnel> ConnectTincAsync(string configPath, CancellationToken ct)
        {
            Console.WriteLine("=== [tinc] ===");
            string path = ResolveConfigPath(configPath);
            (TincConfig config, string host, int port) = ParseTincConf(File.ReadAllText(path), Path.GetDirectoryName(Path.GetFullPath(path))!);
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var factory = new TqkLibrary.VpnClient.Drivers.Tinc.Transport.TincSocketTransportFactory();
            var vpn = new TincConnection(host, port, config, factory, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[tinc] connecting to {host}:{port} (TCP meta + UDP data, SPTPS initiator) ...");
                await vpn.ConnectAsync(cts.Token);
                IPAddress assigned = vpn.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = vpn.Config.DnsServers.Count > 0 ? vpn.Config.DnsServers[0] : null;
                Console.WriteLine($"[tinc] tunnel up. overlay IP = {assigned}, dns = {dns?.ToString() ?? "(none)"}, mtu = {vpn.PacketChannel.Mtu}");

                var stack = new TcpIpStack(vpn.PacketChannel, assigned, null);
                var driver = new TincDriver(config);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Kết nối n2n v3 (ntop) L2 mesh từ một file <c>.n2n</c> (ini: community/endpoint/overlay/mac/transform/aeskey/dns).
        /// Mở UDP transport tới supernode → REGISTER_SUPER → REGISTER_SUPER_ACK → data-plane PACKET (Ethernet frame NULL/AES)
        /// qua Ethernet fabric (ARP + VirtualHost) → <see cref="TcpIpStack"/>. Tái dùng nguyên <see cref="N2nConnection"/>.
        /// </summary>
        public static async Task<VpnTunnel> ConnectN2nAsync(string configPath, CancellationToken ct)
        {
            Console.WriteLine("=== [n2n] ===");
            string path = ResolveConfigPath(configPath);
            (N2nConfig config, string host, int port) = ParseN2nConf(File.ReadAllText(path));
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var factory = new TqkLibrary.VpnClient.Drivers.N2n.Transport.N2nSocketTransportFactory();
            var vpn = new N2nConnection(host, port, config, factory, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[n2n] connecting to supernode {host}:{port} (UDP, community '{config.Community}', REGISTER_SUPER) ...");
                await vpn.ConnectAsync(cts.Token);
                IPAddress assigned = vpn.AssignedAddress;
                IPAddress? dns = vpn.Config.DnsServers.Count > 0 ? vpn.Config.DnsServers[0] : null;
                Console.WriteLine($"[n2n] tunnel up. overlay IP = {assigned}, dns = {dns?.ToString() ?? "(none)"}, mtu = {vpn.PacketChannel.Mtu}");

                var stack = new TcpIpStack(vpn.PacketChannel, assigned, null);
                var driver = new N2nDriver(config);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Kết nối vtun (legacy tunnel daemon) tới một vtund host qua TCP. Bắt tay challenge-response (MD5 + Blowfish-ECB)
        /// → kiểm cờ server (type tun / proto tcp / encrypt no / compress no) → data plane length-prefix mang gói IP trần
        /// (<see cref="VtunPacketChannel"/>) → <see cref="TcpIpStack"/>. vtund không thương lượng địa chỉ in-tunnel nên IP
        /// tunnel cấp tĩnh từ <paramref name="tunnelAddress"/> (<c>?addr=</c>) + <paramref name="peerAddress"/>
        /// (<c>?peer=</c>). Tái dùng nguyên <see cref="VtunConnection"/>.
        /// </summary>
        public static async Task<VpnTunnel> ConnectVtunAsync(string host, int port, string hostName, string password,
            string tunnelAddress, string? peerAddress, CancellationToken ct)
        {
            Console.WriteLine("=== [vtun] ===");
            if (port <= 0) port = 5000;
            string[] addrParts = tunnelAddress.Split('/');
            IPAddress tunnelAddr = IPAddress.Parse(addrParts[0]);
            int prefix = addrParts.Length > 1 ? int.Parse(addrParts[1]) : 24;
            IPAddress? peerAddr = string.IsNullOrEmpty(peerAddress) ? null : IPAddress.Parse(peerAddress);

            var config = new VtunConfig
            {
                HostName = hostName,
                Password = password,
                TunnelAddress = tunnelAddr,
                PrefixLength = prefix,
                PeerAddress = peerAddr,
                Mtu = 1450,
            };
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var factory = new VtunSocketTransportFactory();
            var vpn = new VtunConnection(host, port, config, factory, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[vtun] connecting to {host}:{port} host='{hostName}' (TCP, challenge-response MD5+Blowfish) ...");
                await vpn.ConnectAsync(cts.Token);
                IPAddress assigned = vpn.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = vpn.Config.DnsServers.Count > 0 ? vpn.Config.DnsServers[0] : null;
                Console.WriteLine($"[vtun] tunnel up. server flags = {vpn.ServerFlags}, tunnel IP = {assigned}, peer = {peerAddr?.ToString() ?? "(none)"}, mtu = {vpn.PacketChannel.Mtu}");

                var stack = new TcpIpStack(vpn.PacketChannel, assigned, null);
                var driver = new VtunDriver(config);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Kết nối ZeroTier (VL1/VL2) L2 mesh từ một file <c>.zerotier</c> (ini: identity ta + identity node/controller +
        /// endpoint + network + overlay). Mở UDP transport tới node/controller → VL1 HELLO ⇄ OK (Curve25519 → Salsa20/12 +
        /// Poly1305) → NETWORK_CONFIG_REQUEST (assigned IP + COM) → data-plane VL2 EXT_FRAME qua Ethernet fabric
        /// (ARP + VirtualHost) → <see cref="TcpIpStack"/>. Tái dùng nguyên <see cref="ZeroTierConnection"/>.
        /// </summary>
        public static async Task<VpnTunnel> ConnectZeroTierAsync(string configPath, CancellationToken ct)
        {
            Console.WriteLine("=== [zerotier] ===");
            string path = ResolveConfigPath(configPath);
            (ZeroTierConfig config, string host, int port) = ParseZeroTierConf(File.ReadAllText(path), Path.GetDirectoryName(path) ?? ".");
            ILoggerFactory loggerFactory = CreateDriverLoggerFactory();
            var factory = new TqkLibrary.VpnClient.Drivers.ZeroTier.Transport.ZeroTierSocketTransportFactory();
            var vpn = new ZeroTierConnection(host, port, config, factory, loggerFactory: loggerFactory);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[zerotier] connecting to node/controller {host}:{port} (UDP, network {config.NetworkId}, HELLO/OK + NETWORK_CONFIG) ...");
                await vpn.ConnectAsync(cts.Token);
                IPAddress assigned = vpn.AssignedAddress;
                IPAddress? dns = vpn.Config.DnsServers.Count > 0 ? vpn.Config.DnsServers[0] : null;
                Console.WriteLine($"[zerotier] tunnel up. overlay IP = {assigned}, dns = {dns?.ToString() ?? "(none)"}, mtu = {vpn.PacketChannel.Mtu}");

                var stack = new TcpIpStack(vpn.PacketChannel, assigned, null);
                var driver = new ZeroTierDriver(config);
                return new VpnTunnel(stack, async () => { await vpn.DisposeAsync(); loggerFactory.Dispose(); },
                    assigned, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, dns);
            }
            catch
            {
                await vpn.DisposeAsync();
                loggerFactory.Dispose();
                throw;
            }
        }

        // Parse một file .zerotier tối giản (ini key=value): identity=<đường dẫn identity.secret ta (addr:0:pub:priv)>,
        // peer=<đường dẫn identity.public của node/controller (addr:0:pub)>, endpoint=host:port (node/controller),
        // network=<16 hex network id>, overlay=ip/prefix (tùy chọn — bỏ trống thì lấy IP controller gán), dns=ip[,ip].
        // Pure helper. Tái dùng ZeroTierIdentityCodec + NetworkId của project ZeroTier.
        static (ZeroTierConfig config, string host, int port) ParseZeroTierConf(string text, string baseDir)
        {
            string? identityPath = null, peerPath = null, endpoint = null, network = null, overlay = null;
            var dnsServers = new List<IPAddress>();

            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";")) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();
                switch (key)
                {
                    case "identity": identityPath = val; break;
                    case "peer": peerPath = val; break;
                    case "endpoint": endpoint = val; break;
                    case "network": network = val; break;
                    case "overlay": overlay = val; break;
                    case "dns":
                        foreach (string d in val.Split(','))
                            if (IPAddress.TryParse(d.Trim(), out IPAddress? ip)) dnsServers.Add(ip);
                        break;
                }
            }

            if (string.IsNullOrEmpty(identityPath))
                throw new InvalidOperationException("File .zerotier cần identity=<đường dẫn identity.secret ta>.");
            if (string.IsNullOrEmpty(peerPath))
                throw new InvalidOperationException("File .zerotier cần peer=<đường dẫn identity.public của node/controller>.");
            if (string.IsNullOrEmpty(endpoint))
                throw new InvalidOperationException("File .zerotier cần endpoint=<host>:<port> (node/controller).");
            if (string.IsNullOrEmpty(network))
                throw new InvalidOperationException("File .zerotier cần network=<16 hex network id>.");

            var idCodec = new TqkLibrary.VpnClient.ZeroTier.Identity.ZeroTierIdentityCodec();
            var identity = idCodec.ParseString(File.ReadAllText(ResolveRelative(identityPath!, baseDir)).Trim());
            var peer = idCodec.ParseString(File.ReadAllText(ResolveRelative(peerPath!, baseDir)).Trim());

            int colon = endpoint!.LastIndexOf(':');
            string host = colon > 0 ? endpoint.Substring(0, colon) : endpoint;
            int port = 9993;
            if (colon > 0) int.TryParse(endpoint.Substring(colon + 1), out port);

            IPAddress? overlayAddr = null;
            int prefix = 24;
            if (!string.IsNullOrEmpty(overlay)) (overlayAddr, prefix) = ParseCidr(overlay!);

            var config = new ZeroTierConfig
            {
                Identity = identity,
                PeerIdentity = peer,
                NetworkId = TqkLibrary.VpnClient.ZeroTier.Vl2.Models.NetworkId.Parse(network!.Trim()),
                OverlayAddress = overlayAddr,
                PrefixLength = prefix,
                DnsServers = dnsServers,
            };
            return (config, host, port);
        }

        // Resolve một đường dẫn tương đối so với thư mục chứa file config (đường dẫn tuyệt đối giữ nguyên).
        static string ResolveRelative(string path, string baseDir)
            => Path.IsPathRooted(path) ? path : Path.Combine(baseDir, path);

        // Parse một file .n2n tối giản (ini key=value): community=<tên community>, endpoint=host:port (supernode),
        // overlay=ip/prefix (static -a address của edge), mac=aa:bb:.. (tùy chọn, mặc định sinh ngẫu nhiên),
        // transform=null|aes (mặc định null), aeskey=<hex> (khi transform=aes), dns=ip[,ip]. Pure helper.
        static (N2nConfig config, string host, int port) ParseN2nConf(string text)
        {
            string? community = null, endpoint = null, overlay = null, macStr = null, transform = null, aesKeyHex = null;
            var dnsServers = new List<IPAddress>();

            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";")) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();
                switch (key)
                {
                    case "community": community = val; break;
                    case "endpoint": endpoint = val; break;
                    case "overlay": overlay = val; break;
                    case "mac": macStr = val; break;
                    case "transform": transform = val.ToLowerInvariant(); break;
                    case "aeskey": aesKeyHex = val; break;
                    case "dns":
                        foreach (string d in val.Split(','))
                            if (IPAddress.TryParse(d.Trim(), out IPAddress? ip)) dnsServers.Add(ip);
                        break;
                }
            }

            if (string.IsNullOrEmpty(community))
                throw new InvalidOperationException("File .n2n cần community=<tên community>.");
            if (string.IsNullOrEmpty(endpoint))
                throw new InvalidOperationException("File .n2n cần endpoint=<host>:<port> (supernode).");
            if (string.IsNullOrEmpty(overlay))
                throw new InvalidOperationException("File .n2n cần overlay=<ip>/<prefix> (địa chỉ -a tĩnh của edge).");

            int colon = endpoint!.LastIndexOf(':');
            string host = colon > 0 ? endpoint.Substring(0, colon) : endpoint;
            int port = 7654;
            if (colon > 0) int.TryParse(endpoint.Substring(colon + 1), out port);

            (IPAddress overlayAddr, int prefix) = ParseCidr(overlay!);

            byte[]? mac = macStr is not null ? ParseMac(macStr) : null;
            N2nTransformKind transformKind = transform == "aes" ? N2nTransformKind.Aes : N2nTransformKind.Null;
            byte[]? aesKey = transformKind == N2nTransformKind.Aes && !string.IsNullOrEmpty(aesKeyHex) ? ParseHex(aesKeyHex!) : null;

            var config = new N2nConfig
            {
                Community = community!,
                OverlayAddress = overlayAddr,
                PrefixLength = prefix,
                EdgeMac = mac,
                Transform = transformKind,
                AesKey = aesKey,
                DnsServers = dnsServers,
            };
            return (config, host, port);
        }

        // Parse "aa:bb:cc:dd:ee:ff" (or '-' separated) into a 6-byte MAC.
        static byte[] ParseMac(string text)
        {
            string[] parts = text.Split(':', '-');
            if (parts.Length != 6) throw new InvalidOperationException("mac= cần 6 octet, vd aa:bb:cc:dd:ee:ff.");
            byte[] mac = new byte[6];
            for (int i = 0; i < 6; i++) mac[i] = Convert.ToByte(parts[i], 16);
            return mac;
        }

        // Parse a hex string ("aabbcc..." or with spaces) into bytes.
        static byte[] ParseHex(string text)
        {
            string clean = text.Replace(" ", "").Replace(":", "");
            if (clean.Length % 2 != 0) throw new InvalidOperationException("aeskey= cần số ký tự hex chẵn.");
            byte[] bytes = new byte[clean.Length / 2];
            for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);
            return bytes;
        }

        // Parse một file .tinc tối giản (ini key=value): name=<tên node ta>, key=<đường dẫn file seed Ed25519 base64 32B>,
        // peerhost=<đường dẫn host file của peer (Ed25519PublicKey/Address/Subnet)>, endpoint=host:port (đè Address của
        // peer host), overlay=ip/prefix (Subnet của ta), dns=ip[,ip]. Pure helper. Tái dùng TincHostConfig của project Tinc.
        static (TincConfig config, string host, int port) ParseTincConf(string text, string baseDir)
        {
            string? name = null, keyPath = null, peerHostPath = null, endpoint = null, overlay = null;
            var dnsServers = new List<IPAddress>();

            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";")) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();
                switch (key)
                {
                    case "name": name = val; break;
                    case "key": keyPath = val; break;
                    case "peerhost": peerHostPath = val; break;
                    case "endpoint": endpoint = val; break;
                    case "overlay": overlay = val; break;
                    case "dns":
                        foreach (string d in val.Split(','))
                            if (IPAddress.TryParse(d.Trim(), out IPAddress? ip)) dnsServers.Add(ip);
                        break;
                }
            }

            if (name is null || keyPath is null || peerHostPath is null)
                throw new InvalidOperationException("File .tinc cần name=, key= (seed Ed25519 base64) và peerhost= (host file của peer).");

            string Resolve(string p) => Path.IsPathRooted(p) ? p : Path.Combine(baseDir, p);

            // Our Ed25519 seed: a base64 (standard) 32-byte seed file (the client owns its keypair; its public key is
            // registered in the peer's hosts/<name>). Strip PEM/whitespace and pad to a multiple of 4 before decoding.
            string seedText = string.Concat(File.ReadAllText(Resolve(keyPath))
                .Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("-----")));
            int pad = (4 - (seedText.Length % 4)) % 4;
            byte[] seedFull = Convert.FromBase64String(seedText + new string('=', pad));
            byte[] seed = seedFull.Length >= 32 ? seedFull[..32] : seedFull;

            var peerHost = TincHostConfig.Parse(File.ReadAllText(Resolve(peerHostPath)), "server");

            string host;
            int port;
            if (!string.IsNullOrEmpty(endpoint))
            {
                int colon = endpoint!.LastIndexOf(':');
                host = colon > 0 ? endpoint.Substring(0, colon) : endpoint;
                port = colon > 0 && int.TryParse(endpoint.Substring(colon + 1), out int p) ? p : 655;
            }
            else
            {
                host = peerHost.Addresses.Count > 0 ? peerHost.Addresses[0] : throw new InvalidOperationException("File .tinc cần endpoint= hoặc host file có Address.");
                port = peerHost.Port;
            }

            IPAddress? overlayAddr = null;
            int prefix = 32;
            if (!string.IsNullOrEmpty(overlay)) { (overlayAddr, prefix) = ParseCidr(overlay!); }

            IPEndPoint? peerEndpoint = IPAddress.TryParse(host, out IPAddress? hostIp) ? new IPEndPoint(hostIp, port) : null;

            var config = new TincConfig
            {
                NodeName = name,
                PrivateKey = seed,
                PeerHost = peerHost,
                PeerEndpoint = peerEndpoint,
                OverlayAddress = overlayAddr,
                PrefixLength = prefix,
                DnsServers = dnsServers,
            };
            return (config, host, port);
        }

        // Parse một file .nebula tối giản (ini key=value): ca/cert/key (đường dẫn PEM, tương đối với file .nebula),
        // endpoint=host:port (static-host-map của peer), overlay=ip/prefix (đè IP trong cert nếu muốn), dns=ip[,ip].
        // Pure helper (chỉ đọc các PEM được trỏ tới). Tái dùng codec/PEM của project Nebula.
        static (NebulaConfig config, string host, int port) ParseNebulaConf(string text, string baseDir)
        {
            string? caPath = null, certPath = null, keyPath = null, endpoint = null, overlay = null;
            var dnsServers = new List<IPAddress>();

            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";")) continue;
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();
                switch (key)
                {
                    case "ca": caPath = val; break;
                    case "cert": certPath = val; break;
                    case "key": keyPath = val; break;
                    case "endpoint": endpoint = val; break;
                    case "overlay": overlay = val; break;
                    case "dns":
                        foreach (string d in val.Split(','))
                            if (IPAddress.TryParse(d.Trim(), out IPAddress? ip)) dnsServers.Add(ip);
                        break;
                }
            }

            if (caPath is null || certPath is null || keyPath is null)
                throw new InvalidOperationException("File .nebula cần ca=, cert= và key= (đường dẫn PEM của nebula-cert).");
            if (string.IsNullOrEmpty(endpoint))
                throw new InvalidOperationException("File .nebula cần endpoint=<host>:<port> (static-host-map của peer).");

            string Resolve(string p) => Path.IsPathRooted(p) ? p : Path.Combine(baseDir, p);
            var codec = new TqkLibrary.VpnClient.Nebula.Certificate.NebulaCertificateCodec();
            var caCert = codec.UnmarshalCertificate(
                TqkLibrary.VpnClient.Nebula.Certificate.NebulaPem.Decode(File.ReadAllText(Resolve(caPath))).Body, out _);
            var clientCert = codec.UnmarshalCertificate(
                TqkLibrary.VpnClient.Nebula.Certificate.NebulaPem.Decode(File.ReadAllText(Resolve(certPath))).Body, out _);
            byte[] x25519Priv = TqkLibrary.VpnClient.Nebula.Certificate.NebulaPem.Decode(File.ReadAllText(Resolve(keyPath))).Body;

            int colon = endpoint!.LastIndexOf(':');
            string host = colon > 0 ? endpoint.Substring(0, colon) : endpoint;
            int port = 4242;
            if (colon > 0) int.TryParse(endpoint.Substring(colon + 1), out port);

            IPAddress? overlayAddr = null;
            int prefix = 24;
            if (!string.IsNullOrEmpty(overlay)) { (overlayAddr, prefix) = ParseCidr(overlay!); }

            // IP literal ⇒ static-host-map trực tiếp; hostname ⇒ để connection tự resolve (PeerEndpoint null).
            IPEndPoint? peerEndpoint = IPAddress.TryParse(host, out IPAddress? hostIp) ? new IPEndPoint(hostIp, port) : null;

            var config = new NebulaConfig
            {
                CaCertificate = caCert,
                ClientCertificate = clientCert,
                ClientX25519PrivateKey = x25519Priv,
                PeerEndpoint = peerEndpoint,
                OverlayAddress = overlayAddr,
                PrefixLength = prefix,
                DnsServers = dnsServers,
            };
            return (config, host, port);
        }

        // Parse một file wg-quick .conf tối thiểu: [Interface] PrivateKey/Address/DNS + [Peer] PublicKey/PresharedKey/
        // Endpoint/AllowedIPs/PersistentKeepalive. Endpoint (host:port) ⇒ địa chỉ kết nối tới peer; keys là base64 32-byte.
        // Đủ cho điểm-điểm full-tunnel (một peer) — đúng những gì WireGuardConfig cần. Pure helper (không I/O).
        static (WireGuardConfig config, string host, int port) ParseWireGuardConf(string text)
        {
            byte[]? privateKey = null, peerPublicKey = null, presharedKey = null;
            IPAddress? address = null, addressV6 = null;
            int prefix = 32, prefixV6 = 128;
            var dnsServers = new List<IPAddress>();
            var allowedIps = new List<string>();
            int keepalive = 0;
            string host = "";
            int port = 51820; // cổng WireGuard mặc định
            string section = "";

            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";")) continue;
                if (line.StartsWith("[") && line.EndsWith("]")) { section = line.Substring(1, line.Length - 2).Trim().ToLowerInvariant(); continue; }
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();

                if (section == "interface")
                {
                    switch (key)
                    {
                        case "privatekey": privateKey = Convert.FromBase64String(val); break;
                        case "address":
                            foreach (string a in val.Split(','))
                            {
                                (IPAddress ip, int p) = ParseCidr(a.Trim());
                                if (ip.AddressFamily == AddressFamily.InterNetwork) { address = ip; prefix = p; }
                                else { addressV6 = ip; prefixV6 = p; }
                            }
                            break;
                        case "dns":
                            foreach (string d in val.Split(','))
                                if (IPAddress.TryParse(d.Trim(), out IPAddress? ip)) dnsServers.Add(ip);
                            break;
                    }
                }
                else if (section == "peer")
                {
                    switch (key)
                    {
                        case "publickey": peerPublicKey = Convert.FromBase64String(val); break;
                        case "presharedkey": presharedKey = Convert.FromBase64String(val); break;
                        case "allowedips":
                            foreach (string a in val.Split(',')) allowedIps.Add(a.Trim());
                            break;
                        case "persistentkeepalive": int.TryParse(val, out keepalive); break;
                        case "endpoint":
                            int colon = val.LastIndexOf(':');
                            if (colon > 0) { host = val.Substring(0, colon); int.TryParse(val.Substring(colon + 1), out port); }
                            else host = val;
                            break;
                    }
                }
            }

            if (privateKey is null) throw new InvalidOperationException("File .conf WireGuard thiếu [Interface] PrivateKey.");
            if (peerPublicKey is null) throw new InvalidOperationException("File .conf WireGuard thiếu [Peer] PublicKey.");
            if (string.IsNullOrEmpty(host)) throw new InvalidOperationException("File .conf WireGuard thiếu [Peer] Endpoint <host>:<port>.");

            var config = new WireGuardConfig
            {
                PrivateKey = privateKey,
                PeerPublicKey = peerPublicKey,
                PresharedKey = presharedKey,
                Address = address,
                PrefixLength = prefix,
                AddressV6 = addressV6,
                PrefixLengthV6 = prefixV6,
                DnsServers = dnsServers,
                AllowedIps = allowedIps.Count > 0 ? allowedIps : new List<string> { "0.0.0.0/0", "::/0" },
                PersistentKeepaliveSeconds = keepalive,
            };
            return (config, host, port);
        }

        // Tách "10.50.0.2/24" → (10.50.0.2, 24); thiếu "/" ⇒ /32 (v4) hoặc /128 (v6). Pure helper.
        static (IPAddress ip, int prefix) ParseCidr(string cidr)
        {
            int slash = cidr.IndexOf('/');
            if (slash < 0)
            {
                IPAddress only = IPAddress.Parse(cidr);
                return (only, only.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32);
            }
            IPAddress ip = IPAddress.Parse(cidr.Substring(0, slash));
            int prefix = int.Parse(cidr.Substring(slash + 1));
            return (ip, prefix);
        }

        // Chỉ địa chỉ IPv6 GLOBAL mới định tuyến ra internet — link-local (fe80::/10) thì bỏ qua nên không bật IPv6 egress
        // (đa số server VPN Gate chỉ cấp link-local hoặc IPv4-only). Trả null ⇒ stack IPv4-only, proxy IsSupportIpv6=false.
        static IPAddress? GlobalV6(IPAddress? address)
            => address is not null && address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv6LinkLocal ? address : null;

        // Console logger so the driver's handshake/state/link-loss/rekey traces are visible while running the demo live.
        static ILoggerFactory CreateDriverLoggerFactory()
            => LoggerFactory.Create(b => b
                .AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss.fff "; })
                .SetMinimumLevel(LogLevel.Debug));

        // Resolve đường dẫn .ovpn: dùng nguyên nếu tồn tại; nếu không thử ghép với thư mục chạy (file copy sang output dir).
        static string ResolveConfigPath(string configPath)
        {
            if (File.Exists(configPath)) return configPath;
            string beside = Path.Combine(AppContext.BaseDirectory, configPath);
            if (File.Exists(beside)) return beside;
            throw new FileNotFoundException($"Không tìm thấy file .ovpn: '{configPath}' (cũng đã thử '{beside}').", configPath);
        }
    }
}
