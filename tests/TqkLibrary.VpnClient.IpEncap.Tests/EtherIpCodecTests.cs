using System;
using TqkLibrary.VpnClient.IpEncap.EtherIp;
using Xunit;

namespace TqkLibrary.VpnClient.IpEncap.Tests
{
    /// <summary>
    /// Offline coverage for the EtherIP codec (RFC 3378, Ethernet-in-IP, IP proto 97). Verifies the fixed 2-byte header
    /// (<c>0x30 0x00</c> — Version 3, Reserved 0), byte-exact round-trips across a range of Ethernet-frame sizes, and that
    /// <see cref="EtherIpCodec.TryDecapsulate"/> rejects a wrong Version, a buffer too short for the header, and a payload
    /// shorter than a full Ethernet II header — while accepting a non-zero Reserved value per the leniency policy.
    /// </summary>
    public class EtherIpCodecTests
    {
        // Builds a deterministic, well-formed Ethernet II frame of exactly <paramref name="length"/> bytes (length >= 14):
        // dst MAC (6) | src MAC (6) | EtherType 0x0800 (2) | payload.
        static byte[] SampleFrame(int length)
        {
            byte[] frame = new byte[length];
            for (int i = 0; i < 6; i++) frame[i] = (byte)(0xA0 + i);       // dst MAC
            for (int i = 0; i < 6; i++) frame[6 + i] = (byte)(0xB0 + i);   // src MAC
            frame[12] = 0x08; frame[13] = 0x00;                            // EtherType IPv4
            for (int i = 14; i < length; i++) frame[i] = (byte)(i & 0xFF); // payload
            return frame;
        }

        [Fact]
        public void Encapsulate_Emits_Version3_Reserved0_Header_And_Prepends_Two_Bytes()
        {
            byte[] frame = SampleFrame(64);
            byte[] wire = EtherIpCodec.Encapsulate(frame);

            Assert.Equal(EtherIpCodec.HeaderSize + frame.Length, wire.Length);
            Assert.Equal(0x30, wire[0]);   // Version 3 (high nibble), Reserved 0 (low nibble)
            Assert.Equal(0x00, wire[1]);   // Reserved
            Assert.Equal(frame, wire.AsSpan(EtherIpCodec.HeaderSize).ToArray());
        }

        [Theory]
        [InlineData(14)]   // header-only Ethernet frame (empty payload) — the minimum
        [InlineData(15)]
        [InlineData(46)]
        [InlineData(64)]
        [InlineData(590)]
        [InlineData(1514)] // a full-MTU Ethernet frame
        public void Frame_RoundTrips_ByteExact(int frameLength)
        {
            byte[] frame = SampleFrame(frameLength);
            byte[] wire = EtherIpCodec.Encapsulate(frame);

            Assert.True(EtherIpCodec.TryDecapsulate(wire, out byte[] got));
            Assert.Equal(frame, got);
        }

        [Fact]
        public void Decapsulate_Rejects_WrongVersion()
        {
            byte[] wire = EtherIpCodec.Encapsulate(SampleFrame(64));
            foreach (byte badVersionNibble in new byte[] { 0x00, 0x20, 0x40, 0xF0 }) // versions 0, 2, 4, 15
            {
                wire[0] = badVersionNibble; // keep the low reserved nibble at 0
                Assert.False(EtherIpCodec.TryDecapsulate(wire, out byte[] got));
                Assert.Empty(got);
            }
        }

        [Fact]
        public void Decapsulate_Rejects_Buffer_Too_Short_For_Header()
        {
            Assert.False(EtherIpCodec.TryDecapsulate(Array.Empty<byte>(), out _));      // 0 bytes
            Assert.False(EtherIpCodec.TryDecapsulate(new byte[] { 0x30 }, out _));       // 1 byte < 2-byte header
        }

        [Fact]
        public void Decapsulate_Rejects_Frame_Shorter_Than_Ethernet_Header()
        {
            // Valid EtherIP header (0x30 0x00) but only 13 payload bytes — not a full 14-byte Ethernet II frame.
            byte[] wire = EtherIpCodec.Encapsulate(new byte[EtherIpCodec.EthernetHeaderLength - 1]);
            Assert.False(EtherIpCodec.TryDecapsulate(wire, out byte[] got));
            Assert.Empty(got);
        }

        [Fact]
        public void Decapsulate_Accepts_NonZero_Reserved_Per_Leniency()
        {
            byte[] frame = SampleFrame(64);
            byte[] wire = EtherIpCodec.Encapsulate(frame);
            wire[0] |= 0x0F; // set the low reserved nibble of byte 0
            wire[1] = 0xFF;  // set all reserved bits of byte 1 — Version stays 3, so decode must still accept

            Assert.True(EtherIpCodec.TryDecapsulate(wire, out byte[] got));
            Assert.Equal(frame, got);
        }

        [Fact]
        public void Constants_Match_Rfc3378()
        {
            Assert.Equal(97, EtherIpCodec.ProtocolNumber);
            Assert.Equal(2, EtherIpCodec.HeaderSize);
            Assert.Equal(3, EtherIpCodec.Version);
            Assert.Equal(0x30, EtherIpCodec.VersionByte);
        }
    }
}
