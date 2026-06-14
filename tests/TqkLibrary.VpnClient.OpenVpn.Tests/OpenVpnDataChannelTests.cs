using System.Text;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the AEAD data channel (V2.d): a P_DATA_V2 / AES-256-GCM packet protected by one peer is recovered by the
    /// other (complementary keys), with replay and tamper rejected.
    /// </summary>
    public class OpenVpnDataChannelTests
    {
        static (OpenVpnDataChannel client, OpenVpnDataChannel server) Pair(uint clientPeerId = 0, uint serverPeerId = 0)
        {
            var clientKs = OpenVpnKeySource2.GenerateClient();
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(i + 1); r2[i] = (byte)(i + 100); }
            var serverKs = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);

            var clientKeys = OpenVpnKeyMethod2.DeriveDataKeys(clientKs, serverKs, 0xAAAA, 0xBBBB, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.DeriveDataKeys(clientKs, serverKs, 0xAAAA, 0xBBBB, isServer: true);
            return (new OpenVpnDataChannel(clientKeys, peerId: clientPeerId),
                    new OpenVpnDataChannel(serverKeys, peerId: serverPeerId));
        }

        [Fact]
        public void Protect_Unprotect_RoundTripsBothDirections()
        {
            var (client, server) = Pair(clientPeerId: 7);
            byte[] up = Encoding.ASCII.GetBytes("an IP packet from client to server");
            byte[] down = Encoding.ASCII.GetBytes("a reply IP packet server to client");

            byte[] upWire = client.Protect(up);
            Assert.True(server.TryUnprotect(upWire, out byte[] upGot));
            Assert.Equal(up, upGot);

            byte[] downWire = server.Protect(down);
            Assert.True(client.TryUnprotect(downWire, out byte[] downGot));
            Assert.Equal(down, downGot);
        }

        [Fact]
        public void PacketId_IncrementsFromOne()
        {
            var (client, server) = Pair();
            Assert.Equal(0u, client.SentPacketCount);
            client.Protect(new byte[] { 1 });
            client.Protect(new byte[] { 2 });
            Assert.Equal(2u, client.SentPacketCount);
            // both deliver in order
            var (c2, s2) = Pair();
            Assert.True(s2.TryUnprotect(c2.Protect(new byte[] { 9 }), out _));
        }

        [Fact]
        public void Replay_IsRejected()
        {
            var (client, server) = Pair();
            byte[] wire = client.Protect(Encoding.ASCII.GetBytes("once"));
            Assert.True(server.TryUnprotect(wire, out _));
            Assert.False(server.TryUnprotect(wire, out _)); // same packet-id again ⇒ replay
        }

        [Fact]
        public void TamperedCiphertextOrTag_IsRejected()
        {
            var (client, server) = Pair();
            byte[] wire = client.Protect(Encoding.ASCII.GetBytes("integrity protected"));
            wire[^1] ^= 0xFF; // flip a ciphertext byte
            Assert.False(server.TryUnprotect(wire, out _));

            byte[] wire2 = client.Protect(Encoding.ASCII.GetBytes("integrity protected 2"));
            wire2[8] ^= 0x01; // flip a tag byte (tag starts at offset 8 = header+packet_id)
            Assert.False(server.TryUnprotect(wire2, out _));
        }

        [Fact]
        public void NonDataOpcode_IsRejected()
        {
            var (client, server) = Pair();
            byte[] wire = client.Protect(new byte[] { 0xAB });
            wire[0] = 0x20; // opcode P_CONTROL_V1 (4<<3), not a data packet
            Assert.False(server.TryUnprotect(wire, out _));
        }

        [Fact]
        public void WrongKey_FailsAuthentication()
        {
            var (client, _) = Pair();
            var (_, otherServer) = Pair(); // a different random client key source ⇒ different keys
            byte[] wire = client.Protect(Encoding.ASCII.GetBytes("secret"));
            Assert.False(otherServer.TryUnprotect(wire, out _));
        }
    }
}
