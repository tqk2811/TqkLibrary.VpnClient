using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using TqkLibrary.Vpn;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.Sockets;
using TqkLibrary.Vpn.Sockets.Extensions;
using Xunit;
using Xunit.Abstractions;

namespace TqkLibrary.Vpn.Tests
{
    public class VpnClientFacadeTests
    {
        readonly ITestOutputHelper _output;

        public VpnClientFacadeTests(ITestOutputHelper output) => _output = output;

        [Fact]
        public void Builder_RegistersSstpDriver()
        {
            VpnClient client = new VpnClientBuilder().UseSstp().Build();
            Assert.Contains("sstp", client.Protocols);
            Assert.True(client.GetCapabilities("sstp").UsesPpp);
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task ConnectViaFacade_ThenHttpGet_ThroughTunnel()
        {
            VpnClient client = new VpnClientBuilder().UseSstp().Build();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));

            await using IVpnConnection connection = await client.ConnectAsync(
                "sstp",
                new VpnEndpoint("public-vpn-227.opengw.net", 443),
                new VpnCredentials { Username = "vpn", Password = "vpn" },
                cts.Token);

            IVpnSession session = connection.Sessions[0];
            _output.WriteLine($"assigned={session.Config.AssignedAddress}");
            Assert.NotNull(session.Config.AssignedAddress);

            TcpIpStack stack = session.CreateTcpStack();
            var handler = new SocketsHttpHandler
            {
                ConnectCallback = async (context, ct) =>
                {
                    IPAddress[] addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host);
                    IPAddress ip = addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork);
                    VpnTcpClient tcp = await VpnTcpClient.ConnectAsync(stack, ip, (ushort)context.DnsEndPoint.Port, ct);
                    return tcp.GetStream();
                },
            };

            using var http = new HttpClient(handler);
            HttpResponseMessage response = await http.GetAsync("http://www.msftconnecttest.com/connecttest.txt", cts.Token);
            string body = await response.Content.ReadAsStringAsync(cts.Token);
            _output.WriteLine($"status={(int)response.StatusCode}, body=\"{body.Trim()}\"");

            Assert.True(response.IsSuccessStatusCode);
            Assert.Contains("Microsoft Connect Test", body);
        }
    }
}
