using System;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Tailscale.Control.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Tailscale.Tests
{
    public class Ts2021TransportTests
    {
        static byte[] RandomKey()
        {
            var k = new byte[32];
            RandomNumberGenerator.Fill(k);
            return k;
        }

        [Fact]
        public void SealOpen_RoundTrips_AcrossRecords()
        {
            byte[] key = RandomKey();
            var sender = new Ts2021Transport(key);
            var receiver = new Ts2021Transport(key); // same key, mirrored nonce counter

            byte[][] messages =
            {
                System.Text.Encoding.ASCII.GetBytes("first"),
                System.Text.Encoding.ASCII.GetBytes("second message"),
                new byte[Ts2021Transport.MaxPlaintextSize], // a full-size record
            };
            RandomNumberGenerator.Fill(messages[2]);

            foreach (byte[] m in messages)
            {
                byte[] sealedRecord = sender.Seal(m);
                Assert.Equal(m.Length + 16, sealedRecord.Length);
                byte[]? opened = receiver.Open(sealedRecord);
                Assert.NotNull(opened);
                Assert.Equal(m, opened);
            }
        }

        [Fact]
        public void Open_WrongKey_ReturnsNull()
        {
            var sender = new Ts2021Transport(RandomKey());
            var receiver = new Ts2021Transport(RandomKey());
            byte[] sealedRecord = sender.Seal(System.Text.Encoding.ASCII.GetBytes("hello"));
            Assert.Null(receiver.Open(sealedRecord));
        }

        [Fact]
        public void Open_NonceMismatch_FailsAfterReorder()
        {
            byte[] key = RandomKey();
            var sender = new Ts2021Transport(key);
            var receiver = new Ts2021Transport(key);
            byte[] r0 = sender.Seal(System.Text.Encoding.ASCII.GetBytes("zero"));
            byte[] r1 = sender.Seal(System.Text.Encoding.ASCII.GetBytes("one"));
            // Receiver is at counter 0; opening r1 (sealed at counter 1) must fail.
            Assert.Null(receiver.Open(r1));
            // But the in-order record still opens.
            Assert.NotNull(receiver.Open(r0));
        }

        [Fact]
        public void Seal_OverMaxPlaintext_Throws()
        {
            var sender = new Ts2021Transport(RandomKey());
            Assert.Throws<ArgumentOutOfRangeException>(() => sender.Seal(new byte[Ts2021Transport.MaxPlaintextSize + 1]));
        }
    }
}
