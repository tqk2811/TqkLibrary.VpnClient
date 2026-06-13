using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using TqkLibrary.Vpn.Drivers.Sstp;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.Sockets;
using Xunit;

namespace TqkLibrary.Vpn.Sstp.Tests
{
    /// <summary>
    /// The end-to-end goal: connect the SSTP VPN, then run a real HttpClient GET whose TCP/IP travels entirely
    /// through the userspace stack over the tunnel (the VPN server NATs it to the Internet).
    /// </summary>
    [Trait("Category", "Integration")]
    public class SstpHttpClientIntegrationTests
    {
        const string Host = "public-vpn-227.opengw.net";
        const string User = "vpn";
        const string Password = "vpn";

        readonly ITestOutputHelper _output;

        public SstpHttpClientIntegrationTests(ITestOutputHelper output) => _output = output;

        [Fact]
        public async Task HttpGet_ThroughTunnel_ReturnsExpectedBody()
        {
            using var vpn = new SstpConnection(Host);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));

            await vpn.ConnectAsync(User, Password, cts.Token);
            _output.WriteLine($"tunnel up: assigned={vpn.AssignedAddress}, dns={vpn.AssignedDns}");

            var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress);

            var handler = new SocketsHttpHandler
            {
                ConnectCallback = async (context, ct) =>
                {
                    IPAddress[] addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host);
                    IPAddress ip = addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
                    VpnTcpClient client = await VpnTcpClient.ConnectAsync(stack, ip, (ushort)context.DnsEndPoint.Port, ct);
                    return client.GetStream();
                },
            };

            using var http = new HttpClient(handler);
            HttpResponseMessage response = await http.GetAsync("http://www.msftconnecttest.com/connecttest.txt", cts.Token);
            string body = await response.Content.ReadAsStringAsync(cts.Token);

            _output.WriteLine($"status={(int)response.StatusCode}, body=\"{body.Trim()}\"");

            Assert.True(response.IsSuccessStatusCode, $"HTTP status {(int)response.StatusCode}");
            Assert.Contains("Microsoft Connect Test", body);
        }
    }
}
