using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.Sockets;
using TqkLibrary.Vpn.Sockets.Extensions;
using Xunit;

namespace TqkLibrary.Vpn.Tests
{
    public class L2tpIpsecLiveTests
    {
        readonly ITestOutputHelper _output;

        public L2tpIpsecLiveTests(ITestOutputHelper output) => _output = output;

        [Fact]
        public void Builder_RegistersL2tpIpsecDriver()
        {
            VpnClient client = new VpnClientBuilder().UseL2tpIpsec().Build();
            Assert.Contains("l2tp-ipsec", client.Protocols);
            Assert.True(client.GetCapabilities("l2tp-ipsec").UsesPpp);
        }

        [Fact]
        public async Task ConnectAsync_WithoutPreSharedKey_ThrowsArgumentException()
        {
            VpnClient client = new VpnClientBuilder().UseL2tpIpsec().Build();

            // No PreSharedKey ⇒ driver must reject before any network I/O (P0.4: no silent "vpn" default).
            ArgumentException ex = await Assert.ThrowsAsync<ArgumentException>(() => client.ConnectAsync(
                "l2tp-ipsec",
                new VpnEndpoint("public-vpn-227.opengw.net", 500),
                new VpnCredentials { Username = "vpn", Password = "vpn" }));

            Assert.Equal("credentials", ex.ParamName);
        }

        [Fact]
        public async Task ConnectAsync_EmptyPreSharedKey_ThrowsArgumentException()
        {
            VpnClient client = new VpnClientBuilder().UseL2tpIpsec().Build();

            await Assert.ThrowsAsync<ArgumentException>(() => client.ConnectAsync(
                "l2tp-ipsec",
                new VpnEndpoint("public-vpn-227.opengw.net", 500),
                new VpnCredentials { Username = "vpn", Password = "vpn", PreSharedKey = Array.Empty<byte>() }));
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task ConnectViaL2tpIpsec_ThenHttpGet_ThroughTunnel()
        {
            VpnClient client = new VpnClientBuilder().UseL2tpIpsec().Build();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));

            await using IVpnConnection connection = await client.ConnectAsync(
                "l2tp-ipsec",
                new VpnEndpoint("public-vpn-227.opengw.net", 500),
                new VpnCredentials { Username = "vpn", Password = "vpn", PreSharedKey = Encoding.ASCII.GetBytes("vpn") },
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
