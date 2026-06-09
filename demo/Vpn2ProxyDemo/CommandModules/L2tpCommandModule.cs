using System.Text;
using TqkLibrary.Vpn.Drivers.L2tpIpsec;
using TqkLibrary.Vpn.IpStack.Tcp;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>Subcommand <c>l2tp</c>: demo định tuyến VPN Gate qua L2TP/IPsec (IKEv1 PSK, NAT-T).</summary>
    internal sealed class L2tpCommandModule : HostCredentialCommandModuleBase
    {
        public L2tpCommandModule() : base("l2tp", "Demo định tuyến qua L2TP/IPsec (IKEv1 PSK, NAT-T).")
        {
        }

        protected override async Task<VpnTunnel> ConnectAsync(string host, string user, string pass, CancellationToken ct)
        {
            Console.WriteLine("=== [L2TP/IPsec] ===");
            // VPN Gate dùng group PSK = "vpn" (giống mặc định của L2tpIpsecDriver).
            var vpn = new L2tpIpsecConnection(host, Encoding.ASCII.GetBytes("vpn"));
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[l2tp] connecting to {host} (IKEv1/NAT-T UDP 500->4500) ...");
                await vpn.ConnectAsync(user, pass, cts.Token);
                Console.WriteLine($"[l2tp] tunnel up. assigned IP = {vpn.AssignedAddress}, dns = {vpn.AssignedDns}");

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress);
                return new VpnTunnel(stack, () => vpn.DisposeAsync());
            }
            catch
            {
                await vpn.DisposeAsync();
                throw;
            }
        }
    }
}
