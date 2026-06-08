using TqkLibrary.Vpn.Ipsec.Esp;
using Xunit;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec.Tests
{
    public class IpsecL2tpTransportSwapTests
    {
        static readonly byte[] L2tpDatagram = { 0xC8, 0x02, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        [Fact]
        public async Task SwapSession_KeepsThePreviousInboundSa_UntilItIsDropped()
        {
            (EspSession clientV1, EspSession serverV1) = Pair(0x11111111, 0x22222222, seed: 10);
            (EspSession clientV2, EspSession serverV2) = Pair(0x33333333, 0x44444444, seed: 50);

            var clientTransport = new IpsecL2tpTransport(clientV1, _ => Task.CompletedTask);
            var serverV1Transport = new IpsecL2tpTransport(serverV1, esp => { clientTransport.OnEspPacket(esp); return Task.CompletedTask; });
            var serverV2Transport = new IpsecL2tpTransport(serverV2, esp => { clientTransport.OnEspPacket(esp); return Task.CompletedTask; });

            int received = 0;
            clientTransport.DatagramReceived += _ => received++;

            await serverV1Transport.SendAsync(L2tpDatagram);   // decrypts via the primary (V1) SA
            Assert.Equal(1, received);

            clientTransport.SwapSession(clientV2);

            await serverV1Transport.SendAsync(L2tpDatagram);   // still decrypts via the retained previous (V1) SA
            Assert.Equal(2, received);
            await serverV2Transport.SendAsync(L2tpDatagram);   // and the new primary (V2) SA works immediately
            Assert.Equal(3, received);

            clientTransport.DropPreviousInbound();

            await serverV1Transport.SendAsync(L2tpDatagram);   // the old SA is now rejected (SPI no longer known)
            Assert.Equal(3, received);
            await serverV2Transport.SendAsync(L2tpDatagram);   // the new SA keeps working
            Assert.Equal(4, received);
        }

        static (EspSession client, EspSession server) Pair(uint spiClientToServer, uint spiServerToClient, byte seed)
        {
            byte[] encCs = Fill(32, seed), intCs = Fill(32, (byte)(seed + 1));
            byte[] encSc = Fill(32, (byte)(seed + 2)), intSc = Fill(32, (byte)(seed + 3));
            EspCipherSuite clientToServer = EspCipherSuite.AesCbcHmacSha256(encCs, intCs);
            EspCipherSuite serverToClient = EspCipherSuite.AesCbcHmacSha256(encSc, intSc);

            var client = new EspSession(spiClientToServer, clientToServer, spiServerToClient, serverToClient);
            var server = new EspSession(spiServerToClient, serverToClient, spiClientToServer, clientToServer);
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
