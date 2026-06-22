using System;
using System.Buffers.Binary;
using TqkLibrary.VpnClient.IpEncap.Gre;
using Xunit;

namespace TqkLibrary.VpnClient.IpEncap.Tests
{
    /// <summary>
    /// Offline coverage for the standard GRE codec (RFC 2784 base + RFC 2890 Key/Sequence). Verifies round-trips for
    /// plain / +Key / +Seq / +Checksum / all combined, the exact on-wire field order and bytes, the IPv4 vs IPv6
    /// protocol type, and that <see cref="GreCodec.TryDecode"/> rejects malformed input (bad version, truncation,
    /// corrupt checksum).
    /// </summary>
    public class GreCodecTests
    {
        static readonly byte[] SamplePayload = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };

        [Fact]
        public void Plain_RoundTrips_And_HasMinimalHeader()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Payload = SamplePayload };
            byte[] wire = GreCodec.Encode(packet);

            // Minimal RFC 2784 header = 4 bytes: flags(0x00) + version(0x00) + protocol type.
            Assert.Equal(4 + SamplePayload.Length, wire.Length);
            Assert.Equal(0x00, wire[0]);
            Assert.Equal(0x00, wire[1]);
            Assert.Equal(GreCodec.ProtocolTypeIpv4, BinaryPrimitives.ReadUInt16BigEndian(wire.AsSpan(2)));

            Assert.True(GreCodec.TryDecode(wire, out GrePacket? got));
            Assert.NotNull(got);
            Assert.Equal(GreCodec.ProtocolTypeIpv4, got!.ProtocolType);
            Assert.Null(got.Key);
            Assert.Null(got.SequenceNumber);
            Assert.Null(got.Checksum);
            Assert.Equal(SamplePayload, got.Payload.ToArray());
        }

        [Fact]
        public void Key_RoundTrips_And_SetsKBit_InOrder()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Key = 0x11223344, Payload = SamplePayload };
            byte[] wire = GreCodec.Encode(packet);

            Assert.Equal(0x20, wire[0]); // K bit only
            // Field order: [flags+ver:2][proto:2][key:4][payload]
            Assert.Equal(8 + SamplePayload.Length, wire.Length);
            Assert.Equal(0x11223344u, BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(4)));

            Assert.True(GreCodec.TryDecode(wire, out GrePacket? got));
            Assert.Equal(0x11223344u, got!.Key);
            Assert.Null(got.SequenceNumber);
            Assert.Equal(SamplePayload, got.Payload.ToArray());
        }

        [Fact]
        public void Sequence_RoundTrips_And_SetsSBit_InOrder()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv6, SequenceNumber = 0x00ABCDEF, Payload = SamplePayload };
            byte[] wire = GreCodec.Encode(packet);

            Assert.Equal(0x10, wire[0]); // S bit only
            Assert.Equal(GreCodec.ProtocolTypeIpv6, BinaryPrimitives.ReadUInt16BigEndian(wire.AsSpan(2)));
            Assert.Equal(0x00ABCDEFu, BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(4)));

            Assert.True(GreCodec.TryDecode(wire, out GrePacket? got));
            Assert.Equal(0x00ABCDEFu, got!.SequenceNumber);
            Assert.Null(got.Key);
        }

        [Fact]
        public void Checksum_RoundTrips_And_SetsCBit_InOrder()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, IncludeChecksum = true, Payload = SamplePayload };
            byte[] wire = GreCodec.Encode(packet);

            Assert.Equal(0x80, wire[0]); // C bit only
            // Field order: [flags+ver:2][proto:2][checksum:2][reserved1:2][payload]
            Assert.Equal(8 + SamplePayload.Length, wire.Length);
            ushort reserved1 = BinaryPrimitives.ReadUInt16BigEndian(wire.AsSpan(6));
            Assert.Equal(0, reserved1);
            // A correctly-computed checksum makes the whole-datagram one's-complement sum zero — decode must accept it.
            Assert.True(GreCodec.TryDecode(wire, out GrePacket? got));
            Assert.NotNull(got!.Checksum);
            Assert.Equal(SamplePayload, got.Payload.ToArray());
        }

        [Fact]
        public void AllFlags_Combined_FieldOrder_Is_Checksum_Then_Key_Then_Sequence()
        {
            var packet = new GrePacket
            {
                ProtocolType = GreCodec.ProtocolTypeIpv4,
                IncludeChecksum = true,
                Key = 0xAABBCCDD,
                SequenceNumber = 0x01020304,
                Payload = SamplePayload,
            };
            byte[] wire = GreCodec.Encode(packet);

            Assert.Equal(0x80 | 0x20 | 0x10, wire[0]); // C + K + S
            // [flags+ver:2][proto:2][checksum:2][reserved1:2][key:4][seq:4][payload]
            Assert.Equal(0xAABBCCDDu, BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(8)));   // Key after checksum block
            Assert.Equal(0x01020304u, BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(12)));  // Sequence last
            Assert.Equal(16 + SamplePayload.Length, wire.Length);

            Assert.True(GreCodec.TryDecode(wire, out GrePacket? got));
            Assert.Equal(0xAABBCCDDu, got!.Key);
            Assert.Equal(0x01020304u, got.SequenceNumber);
            Assert.NotNull(got.Checksum);
            Assert.Equal(SamplePayload, got.Payload.ToArray());
        }

        [Fact]
        public void Decode_Rejects_NonZeroVersion()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Payload = SamplePayload };
            byte[] wire = GreCodec.Encode(packet);
            wire[1] = 0x01; // version 1 (PPTP Enhanced GRE) — not standard GRE
            Assert.False(GreCodec.TryDecode(wire, out GrePacket? got));
            Assert.Null(got);
        }

        [Fact]
        public void Decode_Rejects_Truncated_OptionalField()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Key = 0x11223344, Payload = Array.Empty<byte>() };
            byte[] wire = GreCodec.Encode(packet); // 8 bytes: flags+ver+proto+key
            // Drop the last 2 bytes so the K bit is set but the 4-byte Key is incomplete.
            byte[] truncated = wire.AsSpan(0, wire.Length - 2).ToArray();
            Assert.False(GreCodec.TryDecode(truncated, out _));

            Assert.False(GreCodec.TryDecode(new byte[] { 0x00, 0x00, 0x08 }, out _)); // < 4-byte base header
        }

        [Fact]
        public void Decode_Rejects_BadChecksum()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, IncludeChecksum = true, Payload = SamplePayload };
            byte[] wire = GreCodec.Encode(packet);
            wire[4] ^= 0xFF; // corrupt the checksum field
            Assert.False(GreCodec.TryDecode(wire, out _));
        }

        [Fact]
        public void Decode_Ignores_Reserved0_Bits_Per_Rfc2784_Leniency()
        {
            var packet = new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Payload = SamplePayload };
            byte[] wire = GreCodec.Encode(packet);
            wire[0] |= 0x4F; // set every non-C/K/S bit in byte 0 (routing/strict/recursion/reserved0) — must be ignored
            Assert.True(GreCodec.TryDecode(wire, out GrePacket? got));
            Assert.Equal(SamplePayload, got!.Payload.ToArray());
        }
    }
}
