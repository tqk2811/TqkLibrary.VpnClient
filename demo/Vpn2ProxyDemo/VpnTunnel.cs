using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.OpenVpn;
using TqkLibrary.VpnClient.Drivers.SoftEther;
using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.OpenVpn.Config;

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
    /// <see cref="ConnectSoftEtherAsync"/> / <see cref="ConnectOpenVpnAsync"/>): thêm giao thức mới = thêm một hàm static +
    /// một nhánh dispatch ở <c>CommandModule</c>.
    /// </para>
    /// </summary>
    internal sealed class VpnTunnel : IAsyncDisposable
    {
        readonly Func<ValueTask> _disposeAsync;

        public VpnTunnel(TcpIpStack stack, Func<ValueTask> disposeAsync,
            IPAddress assignedAddress, int mtu, VpnDriverCapabilities capabilities, string protocolName, IPAddress? assignedDns = null)
        {
            Stack = stack ?? throw new ArgumentNullException(nameof(stack));
            _disposeAsync = disposeAsync ?? throw new ArgumentNullException(nameof(disposeAsync));
            AssignedAddress = assignedAddress ?? throw new ArgumentNullException(nameof(assignedAddress));
            Mtu = mtu;
            Capabilities = capabilities ?? throw new ArgumentNullException(nameof(capabilities));
            ProtocolName = protocolName ?? throw new ArgumentNullException(nameof(protocolName));
            AssignedDns = assignedDns;
        }

        /// <summary>Userspace TCP/IP stack chạy trong tunnel — dùng làm ctor của <c>VpnProxySource</c>.</summary>
        public TcpIpStack Stack { get; }

        /// <summary>IP ảo do VPN cấp (IPv4) — dùng cho panel khả năng + suy luận NAT/subnet.</summary>
        public IPAddress AssignedAddress { get; }

        /// <summary>MTU của link tunnel (lấy từ <c>IPacketChannel.Mtu</c>) — hiển thị ở panel khả năng.</summary>
        public int Mtu { get; }

        /// <summary>Năng lực tĩnh của driver giao thức (transport/bảo mật/auth/cấp địa chỉ) — "hỏi năng lực" cho panel.</summary>
        public VpnDriverCapabilities Capabilities { get; }

        /// <summary>Tên giao thức/driver (vd "sstp", "l2tp-ipsec") — tiêu đề panel khả năng.</summary>
        public string ProtocolName { get; }

        /// <summary>DNS server do VPN cấp (nếu có) — dùng làm đích mặc định cho probe DNS-over-UDP.</summary>
        public IPAddress? AssignedDns { get; }

        public ValueTask DisposeAsync() => _disposeAsync();

        /// <summary>Connect VPN Gate qua MS-SSTP (TLS) bằng host/port/user/pass; trả tunnel đã lên (đang sống).</summary>
        public static async Task<VpnTunnel> ConnectSstpAsync(string host, int port, string user, string pass, CancellationToken ct)
        {
            Console.WriteLine("=== [MS-SSTP] ===");
            var vpn = new SstpConnection(host, port);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[sstp] connecting to {host}:{port} (TLS) ...");
                await vpn.ConnectAsync(user, pass, cts.Token);
                Console.WriteLine($"[sstp] tunnel up. assigned IP = {vpn.AssignedAddress}, dns = {vpn.AssignedDns}");

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress);
                var driver = new SstpDriver();
                return new VpnTunnel(stack, () => { vpn.Dispose(); return ValueTask.CompletedTask; },
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, vpn.AssignedDns);
            }
            catch
            {
                vpn.Dispose();
                throw;
            }
        }

        /// <summary>Connect VPN Gate qua L2TP/IPsec (IKEv1 PSK, NAT-T) bằng host/user/pass + group PSK; trả tunnel đã lên (đang sống).</summary>
        public static async Task<VpnTunnel> ConnectL2tpAsync(string host, string user, string pass, string preSharedKey, CancellationToken ct)
        {
            Console.WriteLine("=== [L2TP/IPsec] ===");
            // PSK do caller cấp (VpnTarget mặc định "vpn" của VPN Gate). Driver không còn nhét PSK mặc định (P0.4).
            var vpn = new L2tpIpsecConnection(host, Encoding.ASCII.GetBytes(preSharedKey));
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[l2tp] connecting to {host} (IKEv1/NAT-T UDP 500->4500) ...");
                await vpn.ConnectAsync(user, pass, cts.Token);
                Console.WriteLine($"[l2tp] tunnel up. assigned IP = {vpn.AssignedAddress}, dns = {vpn.AssignedDns}");

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress);
                var driver = new L2tpIpsecDriver();
                return new VpnTunnel(stack, () => vpn.DisposeAsync(),
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, driver.Capabilities, driver.Name, vpn.AssignedDns);
            }
            catch
            {
                await vpn.DisposeAsync();
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
                Console.WriteLine($"[softether] tunnel up. assigned IP = {assigned}, dns = {dns}");

                var stack = new TcpIpStack(session.PacketChannel, assigned);
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
                Console.WriteLine($"[openvpn] tunnel up. assigned IP = {assigned}, dns = {dns}");

                var stack = new TcpIpStack(session.PacketChannel, assigned);
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
