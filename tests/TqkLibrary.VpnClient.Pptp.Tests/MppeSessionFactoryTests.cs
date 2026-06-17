using System;
using System.Text;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Mppe;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using TqkLibrary.VpnClient.Pptp.Ccp;
using TqkLibrary.VpnClient.Pptp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// Joins the CCP negotiation result to the existing F.5b MPPE crypto: <see cref="MppeSessionFactory"/> derives
    /// the client send/receive <see cref="MppeSession"/> from the user password + MS-CHAPv2 NT-Response and the
    /// negotiated <see cref="MppeConfigOption"/>, then we verify the data plane interops — what the client encrypts,
    /// the matching server receive session decrypts (and vice-versa), exactly as PPTP would on the GRE link.
    /// </summary>
    public class MppeSessionFactoryTests
    {
        const string Password = "P@ssw0rd!";

        // A deterministic 24-byte NT-Response stand-in (the value is whatever MS-CHAPv2 produced for the session;
        // these tests only need a fixed input, not a live CHAP exchange).
        static byte[] FixedNtResponse()
        {
            var r = new byte[24];
            for (int i = 0; i < r.Length; i++) r[i] = (byte)(i * 7 + 1);
            return r;
        }

        [Fact]
        public void CreateClientSessions_Throws_When_No_Encryption_Negotiated()
        {
            Assert.Throws<InvalidOperationException>(() =>
                MppeSessionFactory.CreateClientSessions(Password, FixedNtResponse(),
                    new MppeConfigOption(MppeSupportedBits.Mppc))); // compression-only, no encryption
        }

        [Theory]
        [InlineData(MppeKeyStrength.Bits128)]
        [InlineData(MppeKeyStrength.Bits56)]
        [InlineData(MppeKeyStrength.Bits40)]
        public void Client_Send_Decrypts_On_Server_Receive(MppeKeyStrength strength)
        {
            byte[] nt = FixedNtResponse();
            var negotiated = new MppeConfigOption(strength, stateless: false);

            // Client side: derived from the factory (password + NT-Response + negotiated option).
            (MppeSession clientSend, MppeSession clientReceive) = MppeSessionFactory.CreateClientSessions(Password, nt, negotiated);

            // Server side: the asymmetric keys are mirrored — the server's receive start key equals the client's
            // send start key (RFC 3079 §3.3 GetAsymmetricStartKey), so we build the server's receive session from it.
            byte[] masterKey = MsChapV2.DeriveMppeMasterKey(Password, nt);
            byte[] clientSendStart = MsChapV2.DeriveMppeSendStartKey(masterKey, isServer: false);
            byte[] clientReceiveStart = MsChapV2.DeriveMppeReceiveStartKey(masterKey, isServer: false);
            var serverReceive = new MppeSession(clientSendStart, strength, stateless: false);
            var serverSend = new MppeSession(clientReceiveStart, strength, stateless: false);

            byte[] payload = Encoding.ASCII.GetBytes("the quick brown fox jumps over the lazy dog");

            // Client -> Server.
            byte[] frame = clientSend.Encrypt(payload);
            Assert.True(frame.Length > payload.Length); // 2-byte MPPE header prepended
            byte[] recovered = serverReceive.Decrypt(frame);
            Assert.Equal(payload, recovered);

            // Server -> Client.
            byte[] reply = Encoding.ASCII.GetBytes("pong");
            byte[] replyFrame = serverSend.Encrypt(reply);
            Assert.Equal(reply, clientReceive.Decrypt(replyFrame));
        }

        [Fact]
        public void Stateless_Mode_RoundTrips_Multiple_Packets()
        {
            byte[] nt = FixedNtResponse();
            var negotiated = new MppeConfigOption(MppeKeyStrength.Bits128, stateless: true);

            (MppeSession clientSend, _) = MppeSessionFactory.CreateClientSessions(Password, nt, negotiated);

            byte[] masterKey = MsChapV2.DeriveMppeMasterKey(Password, nt);
            byte[] clientSendStart = MsChapV2.DeriveMppeSendStartKey(masterKey, isServer: false);
            var serverReceive = new MppeSession(clientSendStart, MppeKeyStrength.Bits128, stateless: true);

            for (int i = 0; i < 5; i++)
            {
                byte[] payload = Encoding.ASCII.GetBytes($"packet number {i}");
                byte[] frame = clientSend.Encrypt(payload);
                Assert.Equal(payload, serverReceive.Decrypt(frame));
            }
        }
    }
}
