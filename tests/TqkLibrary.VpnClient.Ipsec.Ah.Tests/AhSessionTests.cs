using System.Net;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Ipsec.Ah;
using TqkLibrary.VpnClient.Ipsec.Ah.Helpers;
using TqkLibrary.VpnClient.Ipsec.Ah.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ah.Tests
{
    public class AhSessionTests
    {
        const uint Spi = 0xDEADBEEF;
        const byte ProtocolUdp = 17;
        const byte ProtocolTcp = 6;
        const byte NextHeaderIpv4 = 4;   // IP-in-IP (tunnelled IPv4)
        const byte NextHeaderIpv6 = 41;  // tunnelled IPv6

        static readonly IPAddress Ip4A = IPAddress.Parse("10.1.2.3");
        static readonly IPAddress Ip4B = IPAddress.Parse("10.9.8.7");
        static readonly IPAddress OuterA = IPAddress.Parse("203.0.113.4");
        static readonly IPAddress OuterB = IPAddress.Parse("198.51.100.9");
        static readonly IPAddress Ip6A = IPAddress.Parse("2001:db8::1");
        static readonly IPAddress Ip6B = IPAddress.Parse("2001:db8::2");
        static readonly IPAddress Outer6A = IPAddress.Parse("2001:db8:aa::1");
        static readonly IPAddress Outer6B = IPAddress.Parse("2001:db8:bb::1");

        static IIntegrityAlgo Algo(bool sha1) => sha1 ? HmacIntegrity.HmacSha1_96() : HmacIntegrity.HmacSha256_128();

        static byte[] Key(bool sha1)
        {
            byte[] key = new byte[sha1 ? 20 : 32];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)(0x40 + i);
            return key;
        }

        static byte[] Body(int length, byte seed)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        static ushort Checksum(ReadOnlySpan<byte> header)
        {
            uint sum = 0;
            for (int i = 0; i + 1 < header.Length; i += 2) sum += (uint)((header[i] << 8) | header[i + 1]);
            if ((header.Length & 1) != 0) sum += (uint)(header[header.Length - 1] << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        static byte[] BuildIpv4(IPAddress src, IPAddress dst, byte protocol, byte[] payload, byte ttl = 64, byte tos = 0)
        {
            byte[] p = new byte[20 + payload.Length];
            p[0] = 0x45;
            p[1] = tos;
            p[2] = (byte)(p.Length >> 8); p[3] = (byte)p.Length;
            p[4] = 0x12; p[5] = 0x34;        // identification
            p[6] = 0x40;                     // DF
            p[8] = ttl;
            p[9] = protocol;
            src.GetAddressBytes().CopyTo(p, 12);
            dst.GetAddressBytes().CopyTo(p, 16);
            ushort c = Checksum(p.AsSpan(0, 20));
            p[10] = (byte)(c >> 8); p[11] = (byte)c;
            payload.CopyTo(p.AsSpan(20));
            return p;
        }

        static byte[] BuildIpv6(IPAddress src, IPAddress dst, byte nextHeader, byte[] payload,
            byte hopLimit = 64, byte trafficClass = 0, uint flowLabel = 0)
        {
            byte[] p = new byte[40 + payload.Length];
            uint tc = trafficClass;
            p[0] = (byte)(0x60u | (tc >> 4));
            p[1] = (byte)(((tc & 0x0Fu) << 4) | ((flowLabel >> 16) & 0x0Fu));
            p[2] = (byte)(flowLabel >> 8);
            p[3] = (byte)flowLabel;
            p[4] = (byte)(payload.Length >> 8); p[5] = (byte)payload.Length;
            p[6] = nextHeader;
            p[7] = hopLimit;
            src.GetAddressBytes().CopyTo(p, 8);
            dst.GetAddressBytes().CopyTo(p, 24);
            payload.CopyTo(p.AsSpan(40));
            return p;
        }

        // ---- AH header field encoding (RFC 4302 §2) ------------------------------------------------------------

        [Theory]
        [InlineData(16, 5)] // HMAC-SHA-256-128: 28-byte AH = 7 words → Payload Len 5
        [InlineData(12, 4)] // HMAC-SHA1-96:     24-byte AH = 6 words → Payload Len 4
        public void AhHeader_PayloadLen_FollowsRfc2_2(int icvLength, byte expectedPayloadLen)
        {
            Assert.Equal(expectedPayloadLen, AhHeader.PayloadLengthFor(icvLength));
            Assert.Equal(AhHeader.FixedSize + icvLength, AhHeader.TotalLength(icvLength));
        }

        [Fact]
        public void AhHeader_WriteFixed_ThenParse_RoundTrips()
        {
            AhHeader header = AhHeader.Create(ProtocolUdp, Spi, 0x01020304u, 16);
            byte[] buffer = new byte[AhHeader.FixedSize + 16];
            header.WriteFixed(buffer);

            Assert.Equal(ProtocolUdp, buffer[0]);
            Assert.Equal((byte)5, buffer[1]);      // Payload Len
            Assert.Equal((byte)0, buffer[2]);      // Reserved
            Assert.Equal((byte)0, buffer[3]);

            AhHeader parsed = AhHeader.Parse(buffer);
            Assert.Equal(ProtocolUdp, parsed.NextHeader);
            Assert.Equal(Spi, parsed.SecurityParametersIndex);
            Assert.Equal(0x01020304u, parsed.SequenceNumber);
            Assert.Equal(16, parsed.IcvLength);
        }

        // ---- Mutable-field zeroing helpers (RFC 4302 §3.3.3.1) -------------------------------------------------

        [Fact]
        public void ZeroMutableIpv4_ZerosExactlyTheMutableBytes()
        {
            byte[] h = new byte[20];
            for (int i = 0; i < 20; i++) h[i] = 0xFF;
            AhMutableFields.ZeroMutableIpv4(h);

            var mutable = new HashSet<int> { 1, 6, 7, 8, 10, 11 };
            for (int i = 0; i < 20; i++)
                Assert.Equal(mutable.Contains(i) ? (byte)0x00 : (byte)0xFF, h[i]);
        }

        [Fact]
        public void ZeroMutableIpv6_ZerosTrafficClassFlowLabelAndHopLimit()
        {
            byte[] h = new byte[40];
            for (int i = 0; i < 40; i++) h[i] = 0xFF;
            AhMutableFields.ZeroMutableIpv6(h);

            Assert.Equal((byte)0xF0, h[0]); // Version nibble kept, Traffic Class high nibble zeroed
            Assert.Equal((byte)0x00, h[1]);
            Assert.Equal((byte)0x00, h[2]);
            Assert.Equal((byte)0x00, h[3]);
            Assert.Equal((byte)0xFF, h[4]); // Payload Length immutable
            Assert.Equal((byte)0xFF, h[5]);
            Assert.Equal((byte)0xFF, h[6]); // Next Header immutable
            Assert.Equal((byte)0x00, h[7]); // Hop Limit zeroed
            for (int i = 8; i < 40; i++) Assert.Equal((byte)0xFF, h[i]); // addresses immutable
        }

        // ---- IPv4 transport round-trip ------------------------------------------------------------------------

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Transport_Ipv4_RoundTrip_RecoversPacketAndNextHeader(bool sha1)
        {
            byte[] original = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(48, 0x10));
            var sender = new AhSession(Spi, Key(sha1), Algo(sha1));
            var receiver = new AhSession(Spi, Key(sha1), Algo(sha1));

            byte[] wire = sender.Protect(original, tunnelMode: false);
            Assert.Equal(AhHeader.ProtocolNumber, wire[9]); // IP Protocol became AH (51)

            Assert.True(receiver.TryVerify(wire, out byte[] recovered, out byte nextHeader));
            Assert.Equal(ProtocolUdp, nextHeader);
            Assert.Equal(original, recovered);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Tunnel_Ipv4_RoundTrip_RecoversInnerPacketAndNextHeader(bool sha1)
        {
            byte[] inner = BuildIpv4(Ip4A, Ip4B, ProtocolTcp, Body(60, 0x20));
            var sender = new AhSession(Spi, Key(sha1), Algo(sha1), tunnelMode: true, outerSource: OuterA, outerDestination: OuterB);
            var receiver = new AhSession(Spi, Key(sha1), Algo(sha1), tunnelMode: true, outerSource: OuterA, outerDestination: OuterB);

            byte[] wire = sender.Protect(inner, tunnelMode: true);
            Assert.Equal(AhHeader.ProtocolNumber, wire[9]);          // outer IPv4 Protocol = AH
            Assert.Equal(OuterA, new IPAddress(wire.AsSpan(12, 4).ToArray())); // outer source

            Assert.True(receiver.TryVerify(wire, out byte[] recoveredInner, out byte nextHeader));
            Assert.Equal(NextHeaderIpv4, nextHeader);
            Assert.Equal(inner, recoveredInner);
        }

        // ---- Mutable vs immutable evidence (the core RFC 4302 §3.3.3 property) --------------------------------

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Transport_Ipv4_MutableFieldsRewritten_StillVerifies(bool sha1)
        {
            byte[] original = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(40, 0x30));
            var sender = new AhSession(Spi, Key(sha1), Algo(sha1));
            var receiver = new AhSession(Spi, Key(sha1), Algo(sha1));

            byte[] wire = sender.Protect(original, tunnelMode: false);

            // A router legitimately rewrites TTL (byte 8), Header Checksum (10-11) and DSCP/ECN (byte 1).
            wire[8] = 1;                 // TTL decremented
            wire[10] = 0xAB; wire[11] = 0xCD; // checksum rewritten
            wire[1] = 0xE0;              // DSCP/ECN changed

            Assert.True(receiver.TryVerify(wire, out _, out byte nextHeader),
                "AH must still verify after mutable IPv4 fields (TTL/checksum/DSCP) are rewritten.");
            Assert.Equal(ProtocolUdp, nextHeader);
        }

        [Fact]
        public void Transport_Ipv4_ImmutableSourceAddressTampered_FailsVerify()
        {
            byte[] original = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(32, 0x40));
            var sender = new AhSession(Spi, Key(false), Algo(false));
            var receiver = new AhSession(Spi, Key(false), Algo(false));

            byte[] wire = sender.Protect(original, tunnelMode: false);
            wire[12] ^= 0xFF; // flip a byte of the (immutable) source address

            Assert.False(receiver.TryVerify(wire, out _, out _));
        }

        [Fact]
        public void Transport_Ipv4_PayloadTampered_FailsVerify()
        {
            byte[] original = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(32, 0x50));
            var sender = new AhSession(Spi, Key(false), Algo(false));
            var receiver = new AhSession(Spi, Key(false), Algo(false));

            byte[] wire = sender.Protect(original, tunnelMode: false);
            wire[wire.Length - 1] ^= 0xFF; // flip a payload byte

            Assert.False(receiver.TryVerify(wire, out _, out _));
        }

        [Fact]
        public void Tunnel_Ipv4_IcvTampered_FailsVerify()
        {
            byte[] inner = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(40, 0x60));
            var sender = new AhSession(Spi, Key(false), Algo(false), tunnelMode: true, outerSource: OuterA, outerDestination: OuterB);
            var receiver = new AhSession(Spi, Key(false), Algo(false), tunnelMode: true, outerSource: OuterA, outerDestination: OuterB);

            byte[] wire = sender.Protect(inner, tunnelMode: true);
            int icvOffset = 20 + AhHeader.FixedSize;
            wire[icvOffset] ^= 0xFF; // flip a byte of the ICV

            Assert.False(receiver.TryVerify(wire, out _, out _));
        }

        [Fact]
        public void Transport_Ipv4_WrongKey_FailsVerify()
        {
            byte[] original = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(32, 0x70));
            var sender = new AhSession(Spi, Key(false), Algo(false));

            byte[] wrongKey = Key(false);
            wrongKey[0] ^= 0xFF;
            var receiver = new AhSession(Spi, wrongKey, Algo(false));

            byte[] wire = sender.Protect(original, tunnelMode: false);
            Assert.False(receiver.TryVerify(wire, out _, out _));
        }

        [Fact]
        public void SpiMismatch_FailsVerify()
        {
            byte[] original = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(32, 0x80));
            var sender = new AhSession(Spi, Key(false), Algo(false));
            var receiver = new AhSession(Spi + 1, Key(false), Algo(false));

            byte[] wire = sender.Protect(original, tunnelMode: false);
            Assert.False(receiver.TryVerify(wire, out _, out _));
        }

        // ---- Anti-replay (RFC 4302 §3.4.3) --------------------------------------------------------------------

        static byte[][] ProtectSequence(int count, bool sha1)
        {
            var sender = new AhSession(Spi, Key(sha1), Algo(sha1));
            byte[] payload = BuildIpv4(Ip4A, Ip4B, ProtocolUdp, Body(24, 0x90));
            var packets = new byte[count + 1][]; // index i == sequence i
            for (int i = 1; i <= count; i++) packets[i] = sender.Protect(payload, tunnelMode: false);
            return packets;
        }

        [Fact]
        public void AntiReplay_DuplicateSequence_Rejected()
        {
            byte[][] pkts = ProtectSequence(3, sha1: false);
            var receiver = new AhSession(Spi, Key(false), Algo(false));

            Assert.True(receiver.TryVerify(pkts[1], out _, out _));
            Assert.False(receiver.TryVerify(pkts[1], out _, out _)); // exact duplicate
        }

        [Fact]
        public void AntiReplay_TooOldOutsideWindow_Rejected()
        {
            byte[][] pkts = ProtectSequence(65, sha1: false);
            var receiver = new AhSession(Spi, Key(false), Algo(false));

            Assert.True(receiver.TryVerify(pkts[65], out _, out _)); // advance highest to 65
            Assert.False(receiver.TryVerify(pkts[1], out _, out _)); // 65-1 = 64 => outside the 64-packet window
        }

        [Fact]
        public void AntiReplay_AdvancingSequence_Accepted()
        {
            byte[][] pkts = ProtectSequence(10, sha1: false);
            var receiver = new AhSession(Spi, Key(false), Algo(false));

            Assert.True(receiver.TryVerify(pkts[1], out _, out _));
            Assert.True(receiver.TryVerify(pkts[2], out _, out _));
            Assert.True(receiver.TryVerify(pkts[10], out _, out _)); // forward jump within window
            Assert.True(receiver.TryVerify(pkts[5], out _, out _));  // fill an earlier hole
        }

        // ---- IPv6 (best-effort: HMAC-SHA1-96 keeps AH 8-byte aligned, RFC 4302 §2.6) --------------------------

        [Fact]
        public void Transport_Ipv6_RoundTrip_Sha1()
        {
            byte[] original = BuildIpv6(Ip6A, Ip6B, ProtocolUdp, Body(48, 0x11));
            var sender = new AhSession(Spi, Key(true), Algo(true));
            var receiver = new AhSession(Spi, Key(true), Algo(true));

            byte[] wire = sender.Protect(original, tunnelMode: false);
            Assert.Equal(AhHeader.ProtocolNumber, wire[6]); // IPv6 Next Header became AH

            Assert.True(receiver.TryVerify(wire, out byte[] recovered, out byte nextHeader));
            Assert.Equal(ProtocolUdp, nextHeader);
            Assert.Equal(original, recovered);
        }

        [Fact]
        public void Tunnel_Ipv6_RoundTrip_Sha1()
        {
            byte[] inner = BuildIpv6(Ip6A, Ip6B, ProtocolTcp, Body(56, 0x21));
            var sender = new AhSession(Spi, Key(true), Algo(true), tunnelMode: true, outerSource: Outer6A, outerDestination: Outer6B);
            var receiver = new AhSession(Spi, Key(true), Algo(true), tunnelMode: true, outerSource: Outer6A, outerDestination: Outer6B);

            byte[] wire = sender.Protect(inner, tunnelMode: true);
            Assert.Equal((byte)6, (byte)(wire[0] >> 4)); // outer is IPv6
            Assert.Equal(AhHeader.ProtocolNumber, wire[6]);

            Assert.True(receiver.TryVerify(wire, out byte[] recoveredInner, out byte nextHeader));
            Assert.Equal(NextHeaderIpv6, nextHeader);
            Assert.Equal(inner, recoveredInner);
        }

        [Fact]
        public void Transport_Ipv6_MutableFieldsRewritten_StillVerifies()
        {
            byte[] original = BuildIpv6(Ip6A, Ip6B, ProtocolUdp, Body(40, 0x31));
            var sender = new AhSession(Spi, Key(true), Algo(true));
            var receiver = new AhSession(Spi, Key(true), Algo(true));

            byte[] wire = sender.Protect(original, tunnelMode: false);

            // Rewrite Traffic Class + Flow Label (low 28 bits of bytes 0-3) and Hop Limit (byte 7).
            wire[0] = (byte)((wire[0] & 0xF0) | 0x0A); // keep version, set traffic class high nibble
            wire[1] = 0x5B;
            wire[2] = 0xCD;
            wire[3] = 0xEF;
            wire[7] = 1; // hop limit decremented

            Assert.True(receiver.TryVerify(wire, out _, out byte nextHeader),
                "AH over IPv6 must still verify after Traffic Class/Flow Label/Hop Limit are rewritten.");
            Assert.Equal(ProtocolUdp, nextHeader);
        }

        [Fact]
        public void Transport_Ipv6_PayloadTampered_FailsVerify()
        {
            byte[] original = BuildIpv6(Ip6A, Ip6B, ProtocolUdp, Body(32, 0x41));
            var sender = new AhSession(Spi, Key(true), Algo(true));
            var receiver = new AhSession(Spi, Key(true), Algo(true));

            byte[] wire = sender.Protect(original, tunnelMode: false);
            wire[wire.Length - 1] ^= 0xFF;

            Assert.False(receiver.TryVerify(wire, out _, out _));
        }

        [Fact]
        public void Ipv6_With16ByteIcv_NotEightByteAligned_Throws()
        {
            // HMAC-SHA-256-128 → 28-byte AH, which is not a multiple of 8 (RFC 4302 §2.6) — unsupported for IPv6.
            byte[] original = BuildIpv6(Ip6A, Ip6B, ProtocolUdp, Body(32, 0x51));
            var sender = new AhSession(Spi, Key(false), Algo(false));

            Assert.Throws<NotSupportedException>(() => sender.Protect(original, tunnelMode: false));
        }
    }
}
