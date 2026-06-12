using System.Net;
using System.Text;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;
using TqkLibrary.Vpn.Drivers.L2tpIpsec;
using TqkLibrary.Vpn.Drivers.Sstp;
using TqkLibrary.Vpn.IpStack;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Một tunnel VPN đã kết nối, lộ ra userspace <see cref="TcpIpStack"/> để chạy proxy bên trong tunnel.
    /// <para>
    /// Không trả thẳng <see cref="TcpIpStack"/> được vì stack bám vào kết nối VPN bên dưới (SSTP/L2TP) — kết nối
    /// đó phải sống tới khi proxy dùng xong. <see cref="VpnTunnel"/> giữ lại handle teardown: <see cref="DisposeAsync"/>
    /// sẽ đóng kết nối VPN.
    /// </para>
    /// <para>
    /// Phần connect riêng của từng giao thức là hàm static (<see cref="ConnectSstpAsync"/> / <see cref="ConnectL2tpAsync"/>):
    /// thêm giao thức mới = thêm một hàm static + một nhánh dispatch ở <c>CommandModule</c>.
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
    }
}
