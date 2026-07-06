namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// Static configuration for a <see cref="GtpUConnection"/> in <b>static mode</b>: the UDP destination port, the outbound
    /// TEID, the (optional) expected inbound TEID, whether to add Sequence Numbers, and the inner MTU. GTP-U has no
    /// user-plane control channel here (no GTP-C) — every parameter is fixed up front by the caller, and the remote gateway
    /// (UPF/GGSN/SGSN or a Linux <c>type gtp</c> peer) is the <c>VpnEndpoint.Host</c> passed to the driver.
    /// <para><b>GTP-U does not encrypt or authenticate the payload</b> — it only tags the inner IP packet with a TEID. Use
    /// only on a trusted path or under an outer secure layer (e.g. IPsec ESP).</para>
    /// </summary>
    public sealed record GtpUOptions
    {
        /// <summary>The UDP destination port. Default 2152 (the IANA/3GPP-assigned GTP-U port).</summary>
        public int Port { get; init; } = 2152;

        /// <summary>The 32-bit Tunnel Endpoint Identifier stamped on outbound G-PDUs (the TEID the remote expects for this tunnel's downlink). Default 0.</summary>
        public uint Teid { get; init; }

        /// <summary>
        /// The 32-bit TEID expected on inbound G-PDUs (this endpoint's own RX TEID). When null (default) inbound G-PDUs are
        /// accepted regardless of TEID — appropriate for a single tunnel on a connected UDP socket with asymmetric TEIDs.
        /// When set, an inbound G-PDU whose TEID differs is dropped.
        /// </summary>
        public uint? ExpectedInboundTeid { get; init; }

        /// <summary>Whether to set the S flag and emit an incrementing 16-bit Sequence Number on each outbound G-PDU. Default false (minimal header).</summary>
        public bool EnableSequence { get; init; }

        /// <summary>Inner-packet MTU advertised to the IP stack (outer-IP + UDP + GTP-U overhead already deducted). Default 1400.</summary>
        public int Mtu { get; init; } = 1400;
    }
}
