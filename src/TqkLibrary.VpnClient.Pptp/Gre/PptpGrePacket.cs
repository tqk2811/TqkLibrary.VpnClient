using System;

namespace TqkLibrary.VpnClient.Pptp.Gre
{
    /// <summary>
    /// One PPTP Enhanced GRE packet (RFC 2637 §4.1) carrying a PPP payload over IP protocol 47. PPTP fixes the GRE
    /// header to the enhanced variant (version 1, key present, protocol type 0x880B): the 32-bit Key field is split
    /// into the high word = payload length and the low word = the peer's Call ID, and the optional Sequence /
    /// Acknowledgment fields provide the per-call ordering used by the flow-control bookkeeping (§4.4).
    /// </summary>
    public sealed class PptpGrePacket
    {
        /// <summary>The Call ID (Key low word) — the peer's Call ID on outbound, our local Call ID on inbound.</summary>
        public ushort CallId { get; init; }

        /// <summary>The Sequence Number (present iff the S bit is set, i.e. a payload-bearing packet).</summary>
        public uint? SequenceNumber { get; init; }

        /// <summary>The Acknowledgment Number (present iff the A bit is set) — the highest sequence number received.</summary>
        public uint? AckNumber { get; init; }

        /// <summary>The encapsulated PPP frame (protocol + information, without the HDLC Address/Control). Empty for an ack-only packet.</summary>
        public ReadOnlyMemory<byte> Payload { get; init; }
    }
}
