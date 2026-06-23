using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Ikev2;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums;
using TqkLibrary.VpnClient.Drivers.OpenVpn;
using TqkLibrary.VpnClient.Drivers.SoftEther;
using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.WireGuard;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.OpenVpn.Config;
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
