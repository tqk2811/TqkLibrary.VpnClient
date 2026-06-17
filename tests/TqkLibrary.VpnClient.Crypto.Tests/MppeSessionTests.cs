using System.Text;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Mppe;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// Round-trip tests for the MPPE session engine (RFC 3078): a sender <see cref="MppeSession"/> encrypts and a
    /// peer receiver decrypts, exercising both stateless (re-key every packet) and stateful (re-key every 256 packets)
    /// modes across the 40/56/128-bit strengths. The encrypt/decrypt pair must agree because both derive the same
    /// RC4 session-key sequence from the shared start key. MPPE is broken — these tests pin legacy behavior only.
    /// </summary>
    public class MppeSessionTests
    {
        static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

        const string Password = "clientPass";
        static readonly byte[] NtResponse = Hex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");

        static byte[] SendStartKey()
        {
            byte[] masterKey = MsChapV2.DeriveMppeMasterKey(Password, NtResponse);
            return MsChapV2.DeriveMppeSendStartKey(masterKey);
        }

        [Theory]
        [InlineData(MppeKeyStrength.Bits40, false)]
        [InlineData(MppeKeyStrength.Bits56, false)]
        [InlineData(MppeKeyStrength.Bits128, false)]
        [InlineData(MppeKeyStrength.Bits40, true)]
        [InlineData(MppeKeyStrength.Bits56, true)]
        [InlineData(MppeKeyStrength.Bits128, true)]
        public void EncryptDecrypt_RoundTrips_SinglePacket(MppeKeyStrength strength, bool stateless)
        {
            byte[] start = SendStartKey();
            var sender = new MppeSession(start, strength, stateless);
            var receiver = new MppeSession(start, strength, stateless);

            byte[] payload = Encoding.ASCII.GetBytes("Hello MPPE world!");
            byte[] frame = sender.Encrypt(payload);
            byte[] decoded = receiver.Decrypt(frame);

            Assert.Equal(payload, decoded);
            // Frame = 2-byte header + ciphertext; ciphertext must not equal plaintext (D bit + RC4).
            Assert.Equal(2 + payload.Length, frame.Length);
            Assert.NotEqual(payload, frame.AsSpan(2).ToArray());
        }

        [Theory]
        [InlineData(MppeKeyStrength.Bits128, false)]
        [InlineData(MppeKeyStrength.Bits128, true)]
        public void EncryptDecrypt_RoundTrips_ManyPackets(MppeKeyStrength strength, bool stateless)
        {
            byte[] start = SendStartKey();
            var sender = new MppeSession(start, strength, stateless);
            var receiver = new MppeSession(start, strength, stateless);

            // 600 packets crosses the stateful re-key boundary (coherency low octet == 0xFF every 256).
            for (int i = 0; i < 600; i++)
            {
                byte[] payload = Encoding.ASCII.GetBytes($"packet #{i} payload data {i * 7}");
                byte[] frame = sender.Encrypt(payload);
                byte[] decoded = receiver.Decrypt(frame);
                Assert.Equal(payload, decoded);
            }
        }

        [Fact]
        public void Stateless_SetsFlushedBitOnEveryPacket()
        {
            byte[] start = SendStartKey();
            var sender = new MppeSession(start, MppeKeyStrength.Bits128, stateless: true);
            for (int i = 0; i < 5; i++)
            {
                byte[] frame = sender.Encrypt(Encoding.ASCII.GetBytes("x"));
                Assert.True((frame[0] & 0x80) != 0, "FLUSHED (A) bit must be set on every stateless packet");
                Assert.True((frame[0] & 0x10) != 0, "ENCRYPTED (D) bit must be set");
            }
        }

        [Fact]
        public void Stateful_SetsFlushedOnlyOnFirstAndFlagPackets()
        {
            byte[] start = SendStartKey();
            var sender = new MppeSession(start, MppeKeyStrength.Bits128, stateless: false);

            // First packet (coherency 0): flushed. Packets 1..254: not flushed. Packet 255 (low octet 0xFF): flushed.
            byte[] first = sender.Encrypt(Encoding.ASCII.GetBytes("x"));
            Assert.True((first[0] & 0x80) != 0, "first stateful packet must be flushed");

            for (int i = 1; i <= 254; i++)
            {
                byte[] frame = sender.Encrypt(Encoding.ASCII.GetBytes("x"));
                Assert.False((frame[0] & 0x80) != 0, $"packet {i} must not be flushed");
            }

            byte[] flag = sender.Encrypt(Encoding.ASCII.GetBytes("x")); // coherency 255 → low octet 0xFF
            Assert.True((flag[0] & 0x80) != 0, "flag packet (low octet 0xFF) must be flushed (re-keyed)");
        }

        [Fact]
        public void CoherencyCount_IncrementsAndWraps()
        {
            byte[] start = SendStartKey();
            var sender = new MppeSession(start, MppeKeyStrength.Bits128, stateless: false);

            byte[] f0 = sender.Encrypt(Encoding.ASCII.GetBytes("x"));
            int c0 = ((f0[0] << 8) | f0[1]) & 0x0FFF;
            Assert.Equal(0, c0);
            Assert.Equal(1, sender.CoherencyCount);
        }

        [Fact]
        public void Decrypt_RejectsUnencryptedFrame()
        {
            byte[] start = SendStartKey();
            var receiver = new MppeSession(start, MppeKeyStrength.Bits128, stateless: false);
            // Header with D bit clear.
            byte[] notEncrypted = new byte[] { 0x00, 0x00, 0x01, 0x02 };
            Assert.Throws<ArgumentException>(() => receiver.Decrypt(notEncrypted));
        }
    }
}
