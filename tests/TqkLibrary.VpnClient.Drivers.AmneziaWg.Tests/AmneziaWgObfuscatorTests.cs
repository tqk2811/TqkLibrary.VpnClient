using System;
using System.Collections.Generic;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg.Tests
{
    /// <summary>Unit tests for the pure AmneziaWG codec (<see cref="AmneziaWgObfuscator"/>) — no transport, no fabric.</summary>
    public class AmneziaWgObfuscatorTests
    {
        static AmneziaWgObfuscator NewObfuscator(byte fill = 0x00, Func<int, int, int>? sizePicker = null) =>
            new AmneziaWgObfuscator(AmneziaWgTestSupport.SampleParameters(), new DeterministicRandom(fill, sizePicker));

        [Theory]
        [InlineData((byte)1, 148)] // initiation (padded by S1)
        [InlineData((byte)2, 92)]  // response  (padded by S2)
        [InlineData((byte)3, 64)]  // cookie reply (magic only)
        [InlineData((byte)4, 60)]  // transport data (magic only)
        public void ObfuscateThenDeobfuscate_RestoresWireGuardDatagram_ByteExact(byte type, int length)
        {
            var obf = NewObfuscator();
            byte[] wg = AmneziaWgTestSupport.WgDatagram(type, length);

            byte[] wire = obf.Obfuscate(wg);

            Assert.True(obf.TryDeobfuscate(wire, out byte[] back));
            Assert.Equal(wg, back);
        }

        [Theory]
        [InlineData((byte)1, 5, 0x10000001u)] // init  ⇒ S1=5 prefix, magic H1 at offset 5
        [InlineData((byte)2, 7, 0x10000002u)] // resp  ⇒ S2=7 prefix, magic H2 at offset 7
        [InlineData((byte)3, 0, 0x10000003u)] // cookie⇒ no prefix, magic H3 at offset 0
        [InlineData((byte)4, 0, 0x10000004u)] // data  ⇒ no prefix, magic H4 at offset 0
        public void Obfuscate_SwapsMagicAsUint32LE_AtCorrectOffset(byte type, int prefix, uint magic)
        {
            var obf = NewObfuscator();
            byte[] wg = AmneziaWgTestSupport.WgDatagram(type, 80);

            byte[] wire = obf.Obfuscate(wg);

            Assert.Equal(prefix + wg.Length, wire.Length);
            Assert.Equal(magic, AmneziaWgTestSupport.ReadU32(wire, prefix));
        }

        [Fact]
        public void Obfuscate_Initiation_PrependsS1RandomJunkBytes()
        {
            var obf = NewObfuscator(fill: 0x5A);
            byte[] wg = AmneziaWgTestSupport.WgDatagram(1, 148);

            byte[] wire = obf.Obfuscate(wg);

            // The first S1 bytes are the random junk prefix (0x5A from the deterministic source).
            for (int i = 0; i < AmneziaWgTestSupport.SampleParameters().S1; i++)
                Assert.Equal(0x5A, wire[i]);
        }

        [Fact]
        public void Obfuscate_CookieAndData_AddNoPadding()
        {
            var obf = NewObfuscator();
            byte[] cookie = AmneziaWgTestSupport.WgDatagram(3, 64);
            byte[] data = AmneziaWgTestSupport.WgDatagram(4, 60);

            Assert.Equal(cookie.Length, obf.Obfuscate(cookie).Length);
            Assert.Equal(data.Length, obf.Obfuscate(data).Length);
        }

        [Fact]
        public void ObfuscateThenDeobfuscate_RestoresZeroReservedBytes()
        {
            var obf = NewObfuscator();
            byte[] data = AmneziaWgTestSupport.WgDatagram(4, 60);

            Assert.True(obf.TryDeobfuscate(obf.Obfuscate(data), out byte[] back));
            Assert.Equal(4, back[0]);      // WireGuard transport-data type restored
            Assert.Equal(0, back[1]);      // reserved bytes zeroed
            Assert.Equal(0, back[2]);
            Assert.Equal(0, back[3]);
        }

        [Fact]
        public void RoundTrip_WithZeroPadding_StillUnambiguous()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { S1 = 0, S2 = 0 };
            var obf = new AmneziaWgObfuscator(parameters, new DeterministicRandom());

            foreach (byte type in new byte[] { 1, 2, 3, 4 })
            {
                byte[] wg = AmneziaWgTestSupport.WgDatagram(type, 96);
                Assert.True(obf.TryDeobfuscate(obf.Obfuscate(wg), out byte[] back));
                Assert.Equal(wg, back);
            }
        }

        [Fact]
        public void GenerateJunkPackets_ProducesJcPackets_WithSizesInRange()
        {
            int[] sizes = { 10, 20, 15 }; // Jc = 3, each within [Jmin=10, Jmax=20]
            int idx = 0;
            var obf = NewObfuscator(fill: 0x11, sizePicker: (min, max) => sizes[idx++]);

            IReadOnlyList<byte[]> junk = obf.GenerateJunkPackets();

            Assert.Equal(3, junk.Count);
            for (int i = 0; i < junk.Count; i++)
            {
                Assert.Equal(sizes[i], junk[i].Length);
                Assert.InRange(junk[i].Length, 10, 20);
            }
        }

        [Fact]
        public void GenerateJunkPackets_JminEqualsJmax_AllExactSize()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { Jc = 4, Jmin = 16, Jmax = 16 };
            var obf = new AmneziaWgObfuscator(parameters); // real crypto RNG — size is pinned by Jmin==Jmax

            IReadOnlyList<byte[]> junk = obf.GenerateJunkPackets();

            Assert.Equal(4, junk.Count);
            Assert.All(junk, p => Assert.Equal(16, p.Length));
        }

        [Fact]
        public void GenerateJunkPackets_JcZero_ReturnsEmpty()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { Jc = 0 };
            var obf = new AmneziaWgObfuscator(parameters);

            Assert.Empty(obf.GenerateJunkPackets());
        }

        [Fact]
        public void TryDeobfuscate_TooShort_ReturnsFalse()
        {
            var obf = NewObfuscator();
            Assert.False(obf.TryDeobfuscate(new byte[3], out _));
        }

        [Fact]
        public void TryDeobfuscate_UnrecognisedMagic_ReturnsFalse_AsJunk()
        {
            var obf = NewObfuscator();
            // All-zero datagram: head, and the bytes at offset S1/S2, are 0 — never equal to any H (all > 4) ⇒ junk.
            Assert.False(obf.TryDeobfuscate(new byte[30], out _));
        }

        [Fact]
        public void Obfuscate_TooShort_Throws()
        {
            var obf = NewObfuscator();
            Assert.Throws<ArgumentException>(() => obf.Obfuscate(new byte[3]));
        }

        [Fact]
        public void Obfuscate_UnknownMessageType_Throws()
        {
            var obf = NewObfuscator();
            byte[] bogus = AmneziaWgTestSupport.WgDatagram(5, 40); // type 5 is not a WireGuard message type
            Assert.Throws<ArgumentException>(() => obf.Obfuscate(bogus));
        }

        [Fact]
        public void Validate_DuplicateHValues_Throws()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { H2 = 0x10000001u }; // == H1
            Assert.Throws<ArgumentException>(() => parameters.Validate());
        }

        [Fact]
        public void Validate_HValueNotAboveFour_Throws()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { H1 = 4u }; // collides with WireGuard type range
            Assert.Throws<ArgumentException>(() => new AmneziaWgObfuscator(parameters));
        }

        [Fact]
        public void Validate_JminGreaterThanJmax_Throws()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { Jmin = 30, Jmax = 20 };
            Assert.Throws<ArgumentException>(() => parameters.Validate());
        }

        [Fact]
        public void Validate_NegativeS1_Throws()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { S1 = -1 };
            Assert.Throws<ArgumentException>(() => parameters.Validate());
        }

        [Fact]
        public void Validate_NegativeJc_Throws()
        {
            var parameters = AmneziaWgTestSupport.SampleParameters() with { Jc = -1 };
            Assert.Throws<ArgumentException>(() => parameters.Validate());
        }
    }
}
