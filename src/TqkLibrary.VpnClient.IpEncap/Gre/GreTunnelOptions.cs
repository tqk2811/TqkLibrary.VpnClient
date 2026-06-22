namespace TqkLibrary.VpnClient.IpEncap.Gre
{
    /// <summary>
    /// Outbound options for a <see cref="GreTunnelChannel"/>: which RFC 2890 extensions to stamp on each packet and the
    /// MTU advertised to the IP stack. All optional fields default off, yielding a minimal RFC 2784 header (Flags+Version
    /// + Protocol Type only). Inbound packets are accepted regardless of these settings — the codec reads whatever the
    /// flag bits say.
    /// </summary>
    public sealed class GreTunnelOptions
    {
        /// <summary>Inner-packet MTU advertised to the stack (GRE/IP overhead already deducted by the caller). Default 1400.</summary>
        public int Mtu { get; init; } = 1400;

        /// <summary>When set, every outbound packet carries the RFC 2890 Key field with this value (K bit).</summary>
        public uint? Key { get; init; }

        /// <summary>When true, every outbound packet carries an incrementing RFC 2890 Sequence Number (S bit).</summary>
        public bool EmitSequenceNumber { get; init; }

        /// <summary>When true, every outbound packet carries an RFC 2784 Checksum (C bit).</summary>
        public bool EmitChecksum { get; init; }
    }
}
