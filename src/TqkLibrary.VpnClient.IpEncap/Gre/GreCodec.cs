using System;
using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.IpEncap.Gre
{
    /// <summary>
    /// Stateless codec for the standard GRE header (RFC 2784 base + RFC 2890 Key/Sequence), GRE version 0, IP proto 47.
    /// A pure encode/decode pair holding no tunnel state — the caller (the data-plane channel) owns the Key value and the
    /// sequence counter. This is NOT PPTP's Enhanced GRE (version 1): the Key here is an opaque flow id, not a packed
    /// payload-length/call-id, so the PPTP codec is deliberately separate.
    /// <para>
    /// Header layout, in field order (RFC 2784 §2.1, RFC 2890 §2):
    /// </para>
    /// <list type="bullet">
    ///   <item>Byte 0 = <c>C R0 K S s Recur(3)</c> flags (bit 0 = Checksum present, bit 2 = Key present, bit 3 = Sequence present).</item>
    ///   <item>Byte 1 = <c>Reserved0(5) Version(3)</c> — Version must be 0.</item>
    ///   <item>Bytes 2-3 = Protocol Type (EtherType of the payload).</item>
    ///   <item>If C: Checksum(2) + Reserved1(2).</item>
    ///   <item>If K: Key(4).</item>
    ///   <item>If S: Sequence Number(4).</item>
    ///   <item>Then the payload.</item>
    /// </list>
    /// </summary>
    public static class GreCodec
    {
        const byte BitChecksum = 0x80;   // byte 0, bit 0 (MSB): Checksum present (C)
        const byte BitKey = 0x20;        // byte 0, bit 2: Key present (K)
        const byte BitSequence = 0x10;   // byte 0, bit 3: Sequence Number present (S)

        // RFC 2784 leniency: a receiver MUST ignore Reserved0 / the s/Recur/Routing bits, but the C/K/S bits and
        // Version are significant. We accept any Reserved0 pattern and only act on C/K/S + Version (== 0).
        const byte Byte0ReservedMask = 0x4F;   // bits other than C(0x80)/K(0x20)/S(0x10) in byte 0 — accepted, ignored
        const byte VersionMask = 0x07;          // byte 1: low 3 bits = GRE version

        /// <summary>EtherType for an encapsulated IPv4 packet (RFC 2784 §2.3.1).</summary>
        public const ushort ProtocolTypeIpv4 = 0x0800;

        /// <summary>EtherType for an encapsulated IPv6 packet (RFC 2784 §2.3.1).</summary>
        public const ushort ProtocolTypeIpv6 = 0x86DD;

        /// <summary>Encodes <paramref name="packet"/> into a fresh GRE datagram (the IP payload for proto-47).</summary>
        public static byte[] Encode(GrePacket packet)
        {
            if (packet is null) throw new ArgumentNullException(nameof(packet));

            ReadOnlySpan<byte> payload = packet.Payload.Span;
            bool hasChecksum = packet.IncludeChecksum;
            bool hasKey = packet.Key.HasValue;
            bool hasSeq = packet.SequenceNumber.HasValue;

            int length = 4
                + (hasChecksum ? 4 : 0)   // Checksum(2) + Reserved1(2)
                + (hasKey ? 4 : 0)
                + (hasSeq ? 4 : 0)
                + payload.Length;
            byte[] buffer = new byte[length];

            buffer[0] = (byte)((hasChecksum ? BitChecksum : 0) | (hasKey ? BitKey : 0) | (hasSeq ? BitSequence : 0));
            buffer[1] = 0; // Reserved0 = 0, Version = 0
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), packet.ProtocolType);

            int offset = 4;
            int checksumOffset = -1;
            if (hasChecksum)
            {
                // Checksum + Reserved1 are left zero here; filled in below once the whole header+payload is laid out.
                checksumOffset = offset;
                offset += 4;
            }
            if (hasKey)
            {
                BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset), packet.Key!.Value);
                offset += 4;
            }
            if (hasSeq)
            {
                BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset), packet.SequenceNumber!.Value);
                offset += 4;
            }
            payload.CopyTo(buffer.AsSpan(offset));

            if (hasChecksum)
            {
                // RFC 2784: checksum is the IP (one's-complement) checksum of the GRE header + payload, with the
                // Checksum field itself taken as zero (it already is).
                ushort sum = OnesComplementChecksum(buffer);
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(checksumOffset), sum);
            }
            return buffer;
        }

        /// <summary>
        /// Decodes one GRE datagram. Returns <c>false</c> (and a null <paramref name="packet"/>) on any malformed input:
        /// non-zero version, a truncated buffer (header field declared by a flag but absent), or a bad checksum when the
        /// C bit is set. Reserved0 / routing / strict-source / recursion bits are ignored per RFC 2784 leniency.
        /// </summary>
        public static bool TryDecode(ReadOnlySpan<byte> datagram, out GrePacket? packet)
        {
            packet = null;
            if (datagram.Length < 4) return false;

            byte byte0 = datagram[0];
            byte byte1 = datagram[1];

            if ((byte1 & VersionMask) != 0) return false;   // standard GRE is version 0 only

            bool hasChecksum = (byte0 & BitChecksum) != 0;
            bool hasKey = (byte0 & BitKey) != 0;
            bool hasSeq = (byte0 & BitSequence) != 0;
            _ = Byte0ReservedMask; // documents that the remaining byte0 bits are accepted-and-ignored

            ushort protocolType = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2));

            int offset = 4;
            ushort? checksum = null;
            if (hasChecksum)
            {
                if (datagram.Length < offset + 4) return false;
                checksum = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset));
                // RFC 2784: the one's-complement sum over the whole datagram (incl. the checksum field) must be zero.
                if (OnesComplementChecksum(datagram) != 0) return false;
                offset += 4; // Checksum(2) + Reserved1(2)
            }

            uint? key = null;
            if (hasKey)
            {
                if (datagram.Length < offset + 4) return false;
                key = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset));
                offset += 4;
            }

            uint? sequence = null;
            if (hasSeq)
            {
                if (datagram.Length < offset + 4) return false;
                sequence = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset));
                offset += 4;
            }

            int remaining = datagram.Length - offset;
            if (remaining < 0) return false;
            byte[] payload = remaining > 0 ? datagram.Slice(offset, remaining).ToArray() : Array.Empty<byte>();

            packet = new GrePacket
            {
                ProtocolType = protocolType,
                Key = key,
                SequenceNumber = sequence,
                Checksum = checksum,
                IncludeChecksum = hasChecksum,
                Payload = payload,
            };
            return true;
        }

        /// <summary>The standard Internet one's-complement 16-bit checksum (RFC 1071) over <paramref name="data"/>.</summary>
        static ushort OnesComplementChecksum(ReadOnlySpan<byte> data)
        {
            uint sum = 0;
            int i = 0;
            for (; i + 1 < data.Length; i += 2)
                sum += (uint)((data[i] << 8) | data[i + 1]);
            if (i < data.Length)
                sum += (uint)(data[i] << 8); // odd trailing byte padded with zero
            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }
    }
}
