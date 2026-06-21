using System.Text;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the non-AEAD CBC data channel (AES-CBC + HMAC): a P_DATA_V2 packet protected by one peer is recovered by
    /// the other (complementary keys sliced from the same key2), across cipher/auth sizes and PKCS7 boundaries, with
    /// replay and tamper rejected. This is the data cipher an NCP-less server (e.g. SoftEther's OpenVPN function) uses.
    /// </summary>
    public class OpenVpnCbcDataChannelTests
    {
        static (OpenVpnCbcDataChannel client, OpenVpnCbcDataChannel server) Pair(
            string cipherName = "AES-128-CBC", string auth = "SHA1", uint clientPeerId = 0, uint serverPeerId = 0, bool dataV2 = true)
        {
            var clientKs = OpenVpnKeySource2.GenerateClient();
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(i + 1); r2[i] = (byte)(i + 100); }
            var serverKs = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);

            byte[] key2 = OpenVpnKeyMethod2.DeriveKey2(clientKs, serverKs, 0xAAAA, 0xBBBB);
            Assert.True(OpenVpnCbcCipher.TryResolve(cipherName, out OpenVpnCbcCipher cipher));
            int hmacLen = OpenVpnDataAuth.KeySizeBytes(auth);

            var clientKeys = OpenVpnKeyMethod2.SliceCbcDataKeys(key2, cipher.KeySizeBytes, hmacLen, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.SliceCbcDataKeys(key2, cipher.KeySizeBytes, hmacLen, isServer: true);
            return (new OpenVpnCbcDataChannel(clientKeys, cipher.CreateCipher(), OpenVpnDataAuth.CreateIntegrity(auth), peerId: clientPeerId, dataV2: dataV2),
                    new OpenVpnCbcDataChannel(serverKeys, cipher.CreateCipher(), OpenVpnDataAuth.CreateIntegrity(auth), peerId: serverPeerId, dataV2: dataV2));
        }

        [Theory]
        [InlineData("AES-128-CBC", "SHA1")]
        [InlineData("AES-256-CBC", "SHA256")]
        [InlineData("AES-192-CBC", "SHA512")]
        public void Protect_Unprotect_RoundTripsBothDirections(string cipher, string auth)
        {
            var (client, server) = Pair(cipher, auth, clientPeerId: 7);
            byte[] up = Encoding.ASCII.GetBytes("an IP packet from client to server");
            byte[] down = Encoding.ASCII.GetBytes("a reply IP packet server to client");

            Assert.True(server.TryUnprotect(client.Protect(up), out byte[] upGot));
            Assert.Equal(up, upGot);

            Assert.True(client.TryUnprotect(server.Protect(down), out byte[] downGot));
            Assert.Equal(down, downGot);
        }

        [Theory]
        [InlineData(0)]    // empty payload (inner = 4 → pad 12)
        [InlineData(11)]   // inner = 15 → pad 1
        [InlineData(12)]   // inner = 16 → pad a full block (16)
        [InlineData(28)]   // inner = 32 → pad a full block (16)
        [InlineData(1400)] // a full-size IP packet
        public void PayloadLength_AcrossPkcs7Boundaries_RoundTrips(int length)
        {
            var (client, server) = Pair();
            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) payload[i] = (byte)(i * 7 + 3);

            Assert.True(server.TryUnprotect(client.Protect(payload), out byte[] got));
            Assert.Equal(payload, got);
        }

        [Fact]
        public void P_DATA_V1_RoundTrips_NoPeerId()
        {
            // SoftEther's OpenVPN function pushes no peer-id ⇒ P_DATA_V1 (1-byte header, no 3-byte peer-id).
            var (client, server) = Pair(dataV2: false);
            byte[] payload = Encoding.ASCII.GetBytes("a V1 data packet");
            byte[] wire = client.Protect(payload);
            Assert.Equal(0x30, wire[0] & 0xF8);          // opcode P_DATA_V1 (6 << 3) in the high 5 bits
            Assert.True(server.TryUnprotect(wire, out byte[] got));
            Assert.Equal(payload, got);
        }

        [Fact]
        public void Receiver_DetectsFormatFromOpcode_AcrossV1AndV2()
        {
            // Same keys, but the sender uses V1 and the receiver was built for V2: TryUnprotect reads the opcode to pick
            // the header size, so it still decodes (the format is per-packet, not fixed by the receiver's send-mode).
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(i + 5); r2[i] = (byte)(i + 50); }
            var clientKs = OpenVpnKeySource2.GenerateClient();
            var serverKs = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);
            byte[] key2 = OpenVpnKeyMethod2.DeriveKey2(clientKs, serverKs, 1, 2);
            Assert.True(OpenVpnCbcCipher.TryResolve("AES-128-CBC", out OpenVpnCbcCipher cipher));
            int hmacLen = OpenVpnDataAuth.KeySizeBytes("SHA1");
            var clientKeys = OpenVpnKeyMethod2.SliceCbcDataKeys(key2, cipher.KeySizeBytes, hmacLen, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.SliceCbcDataKeys(key2, cipher.KeySizeBytes, hmacLen, isServer: true);

            var clientV1 = new OpenVpnCbcDataChannel(clientKeys, cipher.CreateCipher(), OpenVpnDataAuth.CreateIntegrity("SHA1"), dataV2: false);
            var serverV2 = new OpenVpnCbcDataChannel(serverKeys, cipher.CreateCipher(), OpenVpnDataAuth.CreateIntegrity("SHA1"), dataV2: true);

            Assert.True(serverV2.TryUnprotect(clientV1.Protect(Encoding.ASCII.GetBytes("v1->v2 ok")), out byte[] got));
            Assert.Equal(Encoding.ASCII.GetBytes("v1->v2 ok"), got);
        }

        [Fact]
        public void PacketId_IncrementsFromOne()
        {
            var (client, _) = Pair();
            Assert.Equal(0u, client.SentPacketCount);
            client.Protect(new byte[] { 1 });
            client.Protect(new byte[] { 2 });
            Assert.Equal(2u, client.SentPacketCount);
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
        public void TamperedCiphertextOrMac_IsRejected()
        {
            var (client, server) = Pair();
            byte[] wire = client.Protect(Encoding.ASCII.GetBytes("integrity protected"));
            wire[^1] ^= 0xFF; // flip a ciphertext byte
            Assert.False(server.TryUnprotect(wire, out _));

            byte[] wire2 = client.Protect(Encoding.ASCII.GetBytes("integrity protected 2"));
            wire2[4] ^= 0x01; // flip an HMAC byte (MAC starts at offset 4 = op|key_id + peer_id)
            Assert.False(server.TryUnprotect(wire2, out _));
        }

        [Fact]
        public void NonDataOpcode_IsRejected()
        {
            var (client, server) = Pair();
            byte[] wire = client.Protect(new byte[] { 0xAB });
            wire[0] = 0x20; // P_CONTROL_V1 (4<<3), not a data packet
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
