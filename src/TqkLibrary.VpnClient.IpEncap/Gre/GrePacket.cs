using System;

namespace TqkLibrary.VpnClient.IpEncap.Gre
{
    /// <summary>
    /// One standard GRE packet (RFC 2784 base header + RFC 2890 Key/Sequence extensions) carried over IP protocol 47.
    /// This is the GRE version 0 header — distinct from PPTP's Enhanced GRE (version 1, payload-length-in-key, call-id):
    /// here the optional Key (RFC 2890) is an opaque 32-bit flow identifier and the optional Sequence Number is a plain
    /// per-tunnel counter. The encapsulated payload is a complete inner protocol packet selected by
    /// <see cref="ProtocolType"/> (0x0800 IPv4, 0x86DD IPv6).
    /// </summary>
    public sealed class GrePacket
    {
        /// <summary>The EtherType of the encapsulated payload (RFC 2784 §2.3.1): 0x0800 IPv4, 0x86DD IPv6.</summary>
        public ushort ProtocolType { get; init; }

        /// <summary>The optional Key (RFC 2890) — an opaque 32-bit flow identifier. Present iff the K bit is set.</summary>
        public uint? Key { get; init; }

        /// <summary>The optional Sequence Number (RFC 2890) — a per-tunnel counter. Present iff the S bit is set.</summary>
        public uint? SequenceNumber { get; init; }

        /// <summary>
        /// The optional Checksum (RFC 2784) over the GRE header and payload. Present iff the C bit is set. On decode this
        /// holds the value read off the wire (already verified); on encode it is ignored — the codec computes a fresh
        /// checksum whenever <see cref="IncludeChecksum"/> is requested.
        /// </summary>
        public ushort? Checksum { get; init; }

        /// <summary>When encoding, requests that the C bit + a freshly computed Checksum field be emitted (RFC 2784).</summary>
        public bool IncludeChecksum { get; init; }

        /// <summary>The encapsulated inner protocol packet (a complete IPv4 / IPv6 packet for the tunnel use-cases).</summary>
        public ReadOnlyMemory<byte> Payload { get; init; }
    }
}
