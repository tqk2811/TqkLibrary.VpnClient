using TqkLibrary.VpnClient.Vtun.Auth;
using TqkLibrary.VpnClient.Vtun.Wire;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Vtun.Tests
{
    /// <summary>
    /// Unit tests for the vtun wire codecs: the 50-byte auth message blocks, the a..p challenge encoding + the MD5/Blowfish
    /// challenge transform, the host-flags string codec, and the 2-byte length+flags frame codec. Golden values are taken
    /// from the vtun 3.0.x source semantics (auth.c / vtun.h / tcp_proto.c).
    /// </summary>
    public class VtunWireCodecTests
    {
        // ---- message blocks (VTUN_MESG_SIZE = 50, NUL-padded) ----

        [Fact]
        public void Message_Encode_Is50BytesNulPaddedWithNewline()
        {
            byte[] block = VtunMessageCodec.Encode("HOST: test");
            Assert.Equal(VtunConstants.MessageSize, block.Length);
            // "HOST: test\n" then NUL padding.
            Assert.Equal((byte)'H', block[0]);
            Assert.Equal((byte)'\n', block[10]);
            Assert.Equal(0, block[11]);
            Assert.Equal(0, block[49]);
        }

        [Fact]
        public void Message_RoundTrip_StripsNewlineAndPadding()
        {
            byte[] block = VtunMessageCodec.Encode("OK FLAGS: <Tu>");
            Assert.Equal("OK FLAGS: <Tu>", VtunMessageCodec.Decode(block));
        }

        [Fact]
        public void Message_Decode_ToleratesCarriageReturn()
        {
            byte[] block = VtunMessageCodec.Encode("VTUN server ver 3.0.4 01/01/2020\r");
            Assert.Equal("VTUN server ver 3.0.4 01/01/2020", VtunMessageCodec.Decode(block));
        }

        // ---- challenge a..p encoding (cl2cs / cs2cl) ----

        [Fact]
        public void Challenge_Encode_UsesApAlphabetWithBrackets()
        {
            // byte 0x3A → high nibble 3 ('d'), low nibble 0xA=10 ('k'); 0x00 → "aa"; 0xFF → "pp".
            byte[] chal = new byte[VtunConstants.ChallengeSize];
            chal[0] = 0x3A;
            chal[1] = 0x00;
            chal[15] = 0xFF;
            string encoded = VtunChallengeCodec.Encode(chal);
            Assert.StartsWith("<dkaa", encoded);
            Assert.EndsWith("pp>", encoded);
            Assert.Equal(VtunConstants.ChallengeSize * 2 + 2, encoded.Length);
        }

        [Fact]
        public void Challenge_EncodeDecode_RoundTrips()
        {
            byte[] chal = new byte[VtunConstants.ChallengeSize];
            for (int i = 0; i < chal.Length; i++) chal[i] = (byte)(i * 17 + 3);
            string encoded = VtunChallengeCodec.Encode(chal);
            Assert.True(VtunChallengeCodec.TryDecode("OK CHAL: " + encoded, out byte[] decoded));
            Assert.Equal(chal, decoded);
        }

        [Fact]
        public void Challenge_Decode_RejectsWrongLength()
        {
            Assert.False(VtunChallengeCodec.TryDecode("OK CHAL: <abc>", out _));
            Assert.False(VtunChallengeCodec.TryDecode("no brackets here", out _));
        }

        // ---- the MD5/Blowfish challenge transform (encrypt_chal / decrypt_chal) ----

        [Fact]
        public void ChallengeTransform_DecryptUndoesEncrypt()
        {
            byte[] chal = new byte[VtunConstants.ChallengeSize];
            for (int i = 0; i < chal.Length; i++) chal[i] = (byte)(0xA5 ^ i);
            byte[] response = VtunChallengeCodec.EncryptChallenge(chal, "pass");
            Assert.NotEqual(chal, response); // actually transformed
            byte[] back = VtunChallengeCodec.DecryptChallenge(response, "pass");
            Assert.Equal(chal, back);        // server-side verify recovers the original challenge
        }

        [Fact]
        public void ChallengeTransform_WrongPasswordDoesNotRecover()
        {
            byte[] chal = new byte[VtunConstants.ChallengeSize];
            for (int i = 0; i < chal.Length; i++) chal[i] = (byte)i;
            byte[] response = VtunChallengeCodec.EncryptChallenge(chal, "rightpass");
            byte[] back = VtunChallengeCodec.DecryptChallenge(response, "wrongpass");
            Assert.NotEqual(chal, back);     // a mismatched password fails the server's memcmp
        }

        [Fact]
        public void ChallengeTransform_MatchesOpenSslGoldenVector()
        {
            // Golden vector computed with OpenSSL (the exact primitive vtund's encrypt_chal uses):
            //   key  = MD5("pass")                       = 1a1dc91c907325c69271ddf0c944bc72
            //   chal = 000102030405060708090a0b0c0d0e0f  (16 bytes)
            //   resp = BF_ecb_encrypt(chal, key) over two 8-byte blocks (BF_ENCRYPT)
            // Reference produced by:  printf <16 bytes> | openssl enc -bf-ecb -nopad -K <md5> -provider legacy
            //   → 7416f64c8c4581f8a271117a81d15366
            byte[] chal =
            {
                0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            };
            byte[] expected =
            {
                0x74,0x16,0xf6,0x4c,0x8c,0x45,0x81,0xf8,
                0xa2,0x71,0x11,0x7a,0x81,0xd1,0x53,0x66,
            };
            byte[] response = VtunChallengeCodec.EncryptChallenge(chal, "pass");
            Assert.Equal(expected, response);                                            // byte-for-byte == OpenSSL/vtund
            Assert.Equal(chal, VtunChallengeCodec.DecryptChallenge(response, "pass"));    // and the inverse recovers it
        }

        // ---- host flags (bf2cf / cf2bf) ----

        [Theory]
        [InlineData("<Tu>", VtunHostFlags.Tcp | VtunHostFlags.Tun)]
        [InlineData("<Ue>", VtunHostFlags.Udp | VtunHostFlags.Ether)]
        [InlineData("<TuK>", VtunHostFlags.Tcp | VtunHostFlags.Tun | VtunHostFlags.KeepAlive)]
        public void Flags_Parse_BasicCombos(string text, VtunHostFlags expected)
        {
            Assert.True(VtunHostFlagsCodec.TryParse("OK FLAGS: " + text, out VtunHostFlags flags, out _, out _, out _));
            Assert.Equal(expected, flags);
        }

        [Fact]
        public void Flags_Parse_EncryptCipher()
        {
            // <TuE1> = TCP + tun + encrypt cipher 1 (the vtun source example).
            Assert.True(VtunHostFlagsCodec.TryParse("OK FLAGS: <TuE1>", out VtunHostFlags flags, out _, out int cipher, out _));
            Assert.Equal(VtunHostFlags.Tcp | VtunHostFlags.Tun | VtunHostFlags.Encrypt, flags);
            Assert.Equal(1, cipher);
        }

        [Fact]
        public void Flags_Parse_CompressionAndShape()
        {
            Assert.True(VtunHostFlagsCodec.TryParse("<TuC6K>", out VtunHostFlags flags, out int level, out _, out _));
            Assert.True((flags & VtunHostFlags.Zlib) != 0);
            Assert.Equal(6, level);
            Assert.True((flags & VtunHostFlags.KeepAlive) != 0);

            Assert.True(VtunHostFlagsCodec.TryParse("<TuS256>", out VtunHostFlags sflags, out _, out _, out int speed));
            Assert.True((sflags & VtunHostFlags.Shape) != 0);
            Assert.Equal(256, speed);
        }

        [Fact]
        public void Flags_EncodeParse_RoundTrips()
        {
            string s = VtunHostFlagsCodec.Encode(VtunHostFlags.Tcp | VtunHostFlags.Tun);
            Assert.Equal("<Tu>", s);
            Assert.True(VtunHostFlagsCodec.TryParse(s, out VtunHostFlags flags, out _, out _, out _));
            Assert.Equal(VtunHostFlags.Tcp | VtunHostFlags.Tun, flags);
        }

        [Fact]
        public void Flags_Parse_RejectsUnknownToken()
        {
            Assert.False(VtunHostFlagsCodec.TryParse("<TuZ>", out _, out _, out _, out _));
            Assert.False(VtunHostFlagsCodec.TryParse("no-bracket", out _, out _, out _, out _));
        }

        // ---- data-plane frame codec (tcp_proto.c) ----

        [Fact]
        public void Frame_EncodeData_BigEndianLengthPrefix()
        {
            byte[] payload = { 0x45, 0x00, 0x00, 0x1c }; // start of an IPv4 header
            byte[] frame = VtunFrameCodec.EncodeData(payload);
            Assert.Equal(2 + payload.Length, frame.Length);
            Assert.Equal(0x00, frame[0]); // big-endian length high byte
            Assert.Equal(0x04, frame[1]); // length = 4
            Assert.Equal(payload, frame[2..]);
        }

        [Fact]
        public void Frame_DecodeHeader_DataFrame()
        {
            VtunFrameHeader h = VtunFrameCodec.DecodeHeader(new byte[] { 0x00, 0x04 });
            Assert.Equal(VtunFrameType.Data, h.Type);
            Assert.Equal(4, h.Length);
        }

        [Theory]
        [InlineData(0x20, 0x00, VtunFrameType.EchoRequest)] // 0x2000
        [InlineData(0x40, 0x00, VtunFrameType.EchoReply)]   // 0x4000
        [InlineData(0x10, 0x00, VtunFrameType.ConnClose)]   // 0x1000
        [InlineData(0x80, 0x00, VtunFrameType.BadFrame)]    // 0x8000
        public void Frame_DecodeHeader_ControlFlags(byte hi, byte lo, VtunFrameType expected)
        {
            VtunFrameHeader h = VtunFrameCodec.DecodeHeader(new byte[] { hi, lo });
            Assert.Equal(expected, h.Type);
            Assert.Equal(0, h.Length);
        }

        [Fact]
        public void Frame_EncodeControl_IsTwoBytes()
        {
            byte[] echo = VtunFrameCodec.EncodeControl(VtunFrameType.EchoRequest);
            Assert.Equal(new byte[] { 0x20, 0x00 }, echo);
            byte[] close = VtunFrameCodec.EncodeControl(VtunFrameType.ConnClose);
            Assert.Equal(new byte[] { 0x10, 0x00 }, close);
        }

        [Fact]
        public void Frame_DecodeHeader_OversizedIsBadFrame()
        {
            // length 0x0fff = 4095 > FRAME_SIZE(2048)+OVERHEAD(100) → BAD_FRAME (top nibble zero, length oversized).
            VtunFrameHeader h = VtunFrameCodec.DecodeHeader(new byte[] { 0x0f, 0xff });
            Assert.Equal(VtunFrameType.BadFrame, h.Type);
        }
    }
}
