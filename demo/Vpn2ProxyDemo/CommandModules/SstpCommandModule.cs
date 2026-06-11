using TqkLibrary.Vpn.Drivers.Sstp;
using TqkLibrary.Vpn.IpStack.Tcp;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>Subcommand <c>sstp</c>: demo định tuyến VPN Gate qua MS-SSTP (TLS/443).</summary>
    internal sealed class SstpCommandModule : HostCredentialCommandModuleBase
    {
        public SstpCommandModule() : base("sstp", "Demo định tuyến qua MS-SSTP (TLS/443).")
        {
        }

        protected override async Task<VpnTunnel> ConnectAsync(string host, string user, string pass, CancellationToken ct)
        {
            Console.WriteLine("=== [MS-SSTP] ===");
            var vpn = new SstpConnection(host);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(90));

                Console.WriteLine($"[sstp] connecting to {host}:443 (TLS) ...");
                await vpn.ConnectAsync(user, pass, cts.Token);
                Console.WriteLine($"[sstp] tunnel up. assigned IP = {vpn.AssignedAddress}, dns = {vpn.AssignedDns}");

                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress);
                return new VpnTunnel(stack, () => { vpn.Dispose(); return ValueTask.CompletedTask; }, vpn.AssignedDns);
            }
            catch
            {
                vpn.Dispose();
                throw;
            }
        }
    }
}
