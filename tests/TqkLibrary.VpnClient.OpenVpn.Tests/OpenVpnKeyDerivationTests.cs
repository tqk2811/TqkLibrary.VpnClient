using System.Buffers.Binary;
using System.Text;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests OpenVPN key-method-2 (V2.d): the client message layout, the server reply parser, and the key derivation —
    /// the property that matters is that the two roles derive complementary keys (one's send = the other's receive).
    /// </summary>
    public class OpenVpnKeyDerivationTests
    {
        static OpenVpnKeySource2 ServerKeySource(byte seed)
        {
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize];
            byte[] r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(seed + i); r2[i] = (byte)(seed * 3 + i); }
            return new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);
        }

        [Fact]
        public void DeriveDataKeys_ComplementaryBetweenClientAndServer()
        {
            var client = OpenVpnKeySource2.GenerateClient();
            var server = ServerKeySource(0x40);
            const ulong clientSid = 0xC1C2C3C4C5C6C7C8UL;
            const ulong serverSid = 0x1122334455667788UL;

            var clientKeys = OpenVpnKeyMethod2.DeriveDataKeys(client, server, clientSid, serverSid, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.DeriveDataKeys(client, server, clientSid, serverSid, isServer: true);

            Assert.Equal(clientKeys.SendCipherKey, serverKeys.ReceiveCipherKey);
            Assert.Equal(clientKeys.ReceiveCipherKey, serverKeys.SendCipherKey);
            Assert.Equal(clientKeys.SendImplicitIv, serverKeys.ReceiveImplicitIv);
            Assert.Equal(clientKeys.ReceiveImplicitIv, serverKeys.SendImplicitIv);

            // Each direction's key/IV are distinct (not accidentally the same slice).
            Assert.NotEqual(clientKeys.SendCipherKey, clientKeys.ReceiveCipherKey);
            Assert.Equal(OpenVpnDataChannelKeys.CipherKeySize, clientKeys.SendCipherKey.Length);
            Assert.Equal(OpenVpnDataChannelKeys.ImplicitIvSize, clientKeys.SendImplicitIv.Length);
        }

        [Fact]
        public void DeriveDataKeys_IsDeterministic()
        {
            var client = OpenVpnKeySource2.GenerateClient();
            var server = ServerKeySource(0x09);
            var a = OpenVpnKeyMethod2.DeriveDataKeys(client, server, 1, 2, isServer: false);
            var b = OpenVpnKeyMethod2.DeriveDataKeys(client, server, 1, 2, isServer: false);
            Assert.Equal(a.SendCipherKey, b.SendCipherKey);
            Assert.Equal(a.ReceiveCipherKey, b.ReceiveCipherKey);
        }

        [Fact]
        public void BuildClientMessage_HasExpectedLayout()
        {
            var client = OpenVpnKeySource2.GenerateClient();
            byte[] msg = OpenVpnKeyMethod2.BuildClientMessage(client, "V4,dev-type tun", username: "u", password: "p");

            Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(msg.AsSpan(0, 4))); // uint32 0 sentinel
            Assert.Equal(2, msg[4]);                                                  // key_method = 2
            Assert.Equal(client.PreMaster, msg.AsSpan(5, 48).ToArray());
            Assert.Equal(client.Random1, msg.AsSpan(53, 32).ToArray());
            Assert.Equal(client.Random2, msg.AsSpan(85, 32).ToArray());

            // options P_string starts at 117: u16 length (incl NUL) then bytes+NUL.
            int len = (msg[117] << 8) | msg[118];
            Assert.Equal("V4,dev-type tun".Length + 1, len);
            Assert.Equal("V4,dev-type tun", Encoding.ASCII.GetString(msg, 119, len - 1));
        }

        [Fact]
        public void TryParseServerMessage_RoundTripsRandomsAndOptions()
        {
            var server = ServerKeySource(0x77);
            byte[] msg = BuildServerMessage(server, "V4,cipher AES-256-GCM");

            Assert.True(OpenVpnKeyMethod2.TryParseServerMessage(msg, out OpenVpnKeySource2 parsed, out string options));
            Assert.Equal(server.Random1, parsed.Random1);
            Assert.Equal(server.Random2, parsed.Random2);
            Assert.Empty(parsed.PreMaster);
            Assert.Equal("V4,cipher AES-256-GCM", options);
        }

        [Fact]
        public void TryParseServerMessage_RejectsMalformed()
        {
            Assert.False(OpenVpnKeyMethod2.TryParseServerMessage(new byte[10], out _, out _)); // too short
            byte[] wrongMethod = BuildServerMessage(ServerKeySource(1), "x");
            wrongMethod[4] = 1; // key_method != 2
            Assert.False(OpenVpnKeyMethod2.TryParseServerMessage(wrongMethod, out _, out _));
        }

        // Test-local server-message builder (server role lives only in tests).
        static byte[] BuildServerMessage(OpenVpnKeySource2 server, string options)
        {
            var buf = new List<byte>();
            buf.AddRange(new byte[4]); // uint32 0
            buf.Add(2);                // key_method
            buf.AddRange(server.Random1);
            buf.AddRange(server.Random2);
            byte[] opt = Encoding.ASCII.GetBytes(options);
            int len = opt.Length + 1;
            buf.Add((byte)(len >> 8));
            buf.Add((byte)len);
            buf.AddRange(opt);
            buf.Add(0);
            return buf.ToArray();
        }
    }
}
