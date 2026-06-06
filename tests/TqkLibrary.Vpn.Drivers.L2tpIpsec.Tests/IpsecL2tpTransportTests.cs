using TqkLibrary.Vpn.Drivers.L2tpIpsec;
using TqkLibrary.Vpn.Ipsec.Esp;
using Xunit;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec.Tests
{
    public class IpsecL2tpTransportTests
    {
        const uint SpiClientToServer = 0xA1A2A3A4;
        const uint SpiServerToClient = 0xB1B2B3B4;

        [Fact]
        public void L2tpMessage_RoundTrips_ThroughUdpAndEsp()
        {
            (EspSession client, EspSession server) = EspPair();

            IpsecL2tpTransport? serverTransport = null;
            var clientTransport = new IpsecL2tpTransport(client, esp =>
            {
                serverTransport!.OnEspPacket(esp); // deliver the ESP packet straight to the server side
                return Task.CompletedTask;
            });
            serverTransport = new IpsecL2tpTransport(server, _ => Task.CompletedTask);

            byte[]? received = null;
            serverTransport.DatagramReceived += m => received = m.ToArray();

            byte[] l2tp = { 0xC8, 0x02, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            clientTransport.SendAsync(l2tp).Wait();

            Assert.NotNull(received);
            Assert.Equal(l2tp, received);
        }

        [Fact]
        public void UdpEncapsulation_RoundTrips()
        {
            byte[] payload = { 1, 2, 3, 4, 5 };
            byte[] udp = UdpEncapsulation.Build(1701, 1701, payload);

            Assert.True(UdpEncapsulation.TryParse(udp, out ushort src, out ushort dst, out byte[] got));
            Assert.Equal(1701, src);
            Assert.Equal(1701, dst);
            Assert.Equal(payload, got);
        }

        static (EspSession client, EspSession server) EspPair()
        {
            byte[] encCs = Fill(32, 1), intCs = Fill(32, 2);
            byte[] encSc = Fill(32, 3), intSc = Fill(32, 4);
            EspCipherSuite clientToServer = EspCipherSuite.AesCbcHmacSha256(encCs, intCs);
            EspCipherSuite serverToClient = EspCipherSuite.AesCbcHmacSha256(encSc, intSc);

            var client = new EspSession(SpiClientToServer, clientToServer, SpiServerToClient, serverToClient);
            var server = new EspSession(SpiServerToClient, serverToClient, SpiClientToServer, clientToServer);
            return (client, server);
        }

        static byte[] Fill(int n, byte seed)
        {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(seed + i);
            return b;
        }
    }
}
