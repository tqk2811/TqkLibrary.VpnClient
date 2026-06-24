using System;
using TqkLibrary.VpnClient.Tailscale.Keys;
using Xunit;

namespace TqkLibrary.VpnClient.Tailscale.Tests
{
    public class TailscaleKeyTests
    {
        static byte[] Sample()
        {
            var b = new byte[32];
            for (int i = 0; i < 32; i++) b[i] = (byte)(i * 7 + 3);
            return b;
        }

        [Fact]
        public void EncodeNodePublic_PrefixAndLowercaseHex()
        {
            byte[] key = Sample();
            string text = TailscaleKey.EncodeNodePublic(key);
            Assert.StartsWith("nodekey:", text);
            Assert.Equal("nodekey:".Length + 64, text.Length);
            // body is lowercase hex
            string body = text.Substring("nodekey:".Length);
            Assert.Equal(body, body.ToLowerInvariant());
        }

        [Fact]
        public void RoundTrip_AllKeyForms()
        {
            byte[] key = Sample();
            Assert.Equal(key, TailscaleKey.DecodeMachinePublic(TailscaleKey.EncodeMachinePublic(key)));
            Assert.Equal(key, TailscaleKey.DecodeNodePublic(TailscaleKey.EncodeNodePublic(key)));
            Assert.Equal(key, TailscaleKey.DecodeDiscoPublic(TailscaleKey.EncodeDiscoPublic(key)));
        }

        [Fact]
        public void Decode_WrongPrefix_Throws()
        {
            string node = TailscaleKey.EncodeNodePublic(Sample());
            Assert.Throws<FormatException>(() => TailscaleKey.DecodeMachinePublic(node));
        }

        [Fact]
        public void Decode_KnownVector()
        {
            // mkey: + 64 hex of all-zero key
            string text = "mkey:" + new string('0', 64);
            byte[] decoded = TailscaleKey.DecodeMachinePublic(text);
            Assert.Equal(new byte[32], decoded);
        }

        [Fact]
        public void Decode_BadHex_Throws()
        {
            Assert.Throws<FormatException>(() => TailscaleKey.DecodeNodePublic("nodekey:" + new string('z', 64)));
        }
    }
}
