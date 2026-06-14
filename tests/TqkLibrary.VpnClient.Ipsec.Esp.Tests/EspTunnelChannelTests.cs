using TqkLibrary.VpnClient.Ipsec.Esp;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Esp.Tests
{
    public class EspTunnelChannelTests
    {
        // Minimal well-formed IP headers — only the version nibble matters to the channel's demux.
        static byte[] Ipv4Packet(byte tag) => new byte[] { 0x45, 0x00, 0x00, 0x14, tag, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2 };
        static byte[] Ipv6Packet(byte tag) => new byte[] { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x40, tag, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        [Theory]
        [InlineData(4)]
        [InlineData(6)]
        public async Task WriteThenReceive_RoundTripsTheInnerIpPacket_DemuxedByNextHeader(int version)
        {
            (EspSession client, EspSession server) = Pair(0x0A0A0A0A, 0x0B0B0B0B, seed: 7);

            var serverInbound = new EspTunnelChannel(server, _ => Task.CompletedTask, mtu: 1400);
            // The client sends ESP straight into the server channel's inbound path.
            var client_ = new EspTunnelChannel(client, esp => { serverInbound.OnEspPacket(esp); return Task.CompletedTask; }, mtu: 1400);

            byte[]? received = null;
            serverInbound.InboundIpPacket += p => received = p.ToArray();

            byte[] sent = version == 4 ? Ipv4Packet(0x55) : Ipv6Packet(0x55);
            await client_.WriteIpPacketAsync(sent);

            Assert.NotNull(received);
            Assert.Equal(sent, received);
        }

        [Fact]
        public async Task Write_DropsBuffersThatAreNeitherIpv4NorIpv6()
        {
            (EspSession client, EspSession server) = Pair(0x0A0A0A0A, 0x0B0B0B0B, seed: 7);
            int espSent = 0;
            var client_ = new EspTunnelChannel(client, _ => { espSent++; return Task.CompletedTask; }, mtu: 1400);

            await client_.WriteIpPacketAsync(new byte[] { 0x00 });          // version nibble 0
            await client_.WriteIpPacketAsync(Array.Empty<byte>());          // empty
            await client_.WriteIpPacketAsync(new byte[] { 0x70, 1, 2, 3 }); // version nibble 7

            Assert.Equal(0, espSent);
        }

        [Fact]
        public async Task SwapSession_KeepsPreviousInboundSa_ForMakeBeforeBreak()
        {
            (EspSession clientV1, EspSession serverV1Sa) = Pair(0x11111111, 0x22222222, seed: 10);
            (EspSession clientV2, EspSession serverV2Sa) = Pair(0x33333333, 0x44444444, seed: 50);

            var clientChannel = new EspTunnelChannel(clientV1, _ => Task.CompletedTask, mtu: 1400);
            var serverV1 = new EspTunnelChannel(serverV1Sa, esp => { clientChannel.OnEspPacket(esp); return Task.CompletedTask; }, mtu: 1400);
            var serverV2 = new EspTunnelChannel(serverV2Sa, esp => { clientChannel.OnEspPacket(esp); return Task.CompletedTask; }, mtu: 1400);

            int received = 0;
            clientChannel.InboundIpPacket += _ => received++;

            await serverV1.WriteIpPacketAsync(Ipv4Packet(1));   // via primary V1
            Assert.Equal(1, received);

            clientChannel.SwapSession(clientV2);

            await serverV1.WriteIpPacketAsync(Ipv4Packet(2));   // still decrypts via retained previous V1
            Assert.Equal(2, received);
            await serverV2.WriteIpPacketAsync(Ipv4Packet(3));   // new primary V2 works immediately
            Assert.Equal(3, received);

            clientChannel.DropPreviousInbound();

            await serverV1.WriteIpPacketAsync(Ipv4Packet(4));   // old SA now rejected
            Assert.Equal(3, received);
            await serverV2.WriteIpPacketAsync(Ipv4Packet(5));
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
