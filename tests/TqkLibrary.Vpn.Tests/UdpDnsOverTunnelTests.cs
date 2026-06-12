using System.Net;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.Sockets;
using TqkLibrary.Vpn.Sockets.Extensions;
using Xunit;
using Xunit.Abstractions;

namespace TqkLibrary.Vpn.Tests
{
    /// <summary>Proves the userspace UDP path: a DNS query sent through the live tunnel and a parsed response.</summary>
    public class UdpDnsOverTunnelTests
    {
        readonly ITestOutputHelper _output;

        public UdpDnsOverTunnelTests(ITestOutputHelper output) => _output = output;

        [Fact]
        [Trait("Category", "Integration")]
        public async Task DnsQuery_ThroughSstpTunnel_ResolvesARecord()
        {
            VpnClient client = new VpnClientBuilder().UseSstp().Build();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));

            await using IVpnConnection connection = await client.ConnectAsync(
                "sstp",
                new VpnEndpoint("public-vpn-227.opengw.net", 443),
                new VpnCredentials { Username = "vpn", Password = "vpn" },
                cts.Token);

            IVpnSession session = connection.Sessions[0];
            IPAddress dns = session.Config.DnsServers.FirstOrDefault() ?? IPAddress.Parse("8.8.8.8");
            _output.WriteLine($"assigned={session.Config.AssignedAddress}, dns={dns}");

            TcpIpStack stack = session.CreateTcpStack();
            VpnUdpClient udp = VpnUdpClient.Connect(stack, dns, 53);

            byte[] query = BuildDnsQuery(0x1234, "www.example.com");
            udp.Send(query);
            byte[] response = await udp.ReceiveAsync(cts.Token);

            Assert.True(response.Length > 12);
            ushort id = (ushort)((response[0] << 8) | response[1]);
            bool isResponse = (response[2] & 0x80) != 0;
            ushort answers = (ushort)((response[6] << 8) | response[7]);
            _output.WriteLine($"dns id={id:X4}, qr={isResponse}, answers={answers}");

            Assert.Equal(0x1234, id);
            Assert.True(isResponse);
            Assert.True(answers >= 1);
        }

        static byte[] BuildDnsQuery(ushort id, string hostName)
        {
            var packet = new List<byte>
            {
                (byte)(id >> 8), (byte)id,
                0x01, 0x00,             // flags: recursion desired
                0x00, 0x01,             // QDCOUNT = 1
                0x00, 0x00,             // ANCOUNT
                0x00, 0x00,             // NSCOUNT
                0x00, 0x00,             // ARCOUNT
            };
            foreach (string label in hostName.Split('.'))
            {
                packet.Add((byte)label.Length);
                packet.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
            }
            packet.Add(0x00);           // end of QNAME
            packet.Add(0x00); packet.Add(0x01); // QTYPE = A
            packet.Add(0x00); packet.Add(0x01); // QCLASS = IN
            return packet.ToArray();
        }
    }
}
