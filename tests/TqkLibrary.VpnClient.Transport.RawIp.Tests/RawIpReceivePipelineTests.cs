using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Transport.RawIp.Helpers;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.RawIp.Tests
{
    /// <summary>
    /// Exercises the raw-IP <b>receive</b> pipeline end-to-end with the ESP layer, without a real raw socket: an inbound
    /// IPv4 datagram (header + ESP) is stripped exactly as <c>RawIpDatagramTransport.ReceiveAsync</c> does
    /// (<see cref="RawIpv4.PayloadOffset"/>), then the recovered ESP packet decrypts via the peer <see cref="EspSession"/>.
    /// Also pins that a fragmented datagram is recognised so the transport drops it.
    /// </summary>
    public class RawIpReceivePipelineTests
    {
        const uint SpiClientToServer = 0xA1A2A3A4;
        const uint SpiServerToClient = 0xB1B2B3B4;

        [Fact]
        public void EspPacket_StrippedFromIpv4Header_DecryptsOnThePeer()
        {
            (EspSession client, EspSession server) = EspPair();
            byte[] inner = { 1, 2, 3, 4, 5, 6, 7, 8 };

            byte[] esp = client.Protect(inner, EspConstants.NextHeaderUdp);
            byte[] rawDatagram = WrapInIpv4(esp, protocol: 50);

            int offset = RawIpv4.PayloadOffset(rawDatagram);
            Assert.True(offset > 0);
            Assert.False(RawIpv4.IsFragment(rawDatagram));

            ReadOnlySpan<byte> recoveredEsp = rawDatagram.AsSpan(offset);
            Assert.True(server.TryUnprotect(recoveredEsp, out byte[] payload, out byte nextHeader));
            Assert.Equal(inner, payload);
            Assert.Equal(EspConstants.NextHeaderUdp, nextHeader);
        }

        [Fact]
        public void FragmentedDatagram_IsRecognisedSoTheTransportDropsIt()
        {
            (EspSession client, _) = EspPair();
            byte[] esp = client.Protect(new byte[] { 9, 9, 9 }, EspConstants.NextHeaderUdp);
            byte[] rawDatagram = WrapInIpv4(esp, protocol: 50);
            rawDatagram[6] = 0x20; // set the More-Fragments flag

            Assert.True(RawIpv4.IsFragment(rawDatagram));
        }

        // Prepends a minimal 20-byte IPv4 header so the buffer looks like what a raw IPv4 socket delivers.
        static byte[] WrapInIpv4(byte[] payload, byte protocol)
        {
            byte[] datagram = new byte[20 + payload.Length];
            datagram[0] = 0x45; // version 4, IHL 5
            int total = datagram.Length;
            datagram[2] = (byte)(total >> 8);
            datagram[3] = (byte)(total & 0xFF);
            datagram[8] = 64;
            datagram[9] = protocol;
            payload.CopyTo(datagram, 20);
            return datagram;
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
