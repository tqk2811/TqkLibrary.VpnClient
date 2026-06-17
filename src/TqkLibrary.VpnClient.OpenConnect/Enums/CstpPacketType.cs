namespace TqkLibrary.VpnClient.OpenConnect.Enums
{
    /// <summary>
    /// CSTP (Cisco AnyConnect SSL transport) packet types — the 7th byte of the 8-byte CSTP framing header. Values
    /// are re-implemented from the published OpenConnect/AnyConnect wire behaviour
    /// (draft-mavrogiannopoulos-openconnect), not copied from the GPL source.
    /// </summary>
    public enum CstpPacketType : byte
    {
        /// <summary>Tunnelled IP packet (IPv4/IPv6) — the payload is a raw L3 datagram.</summary>
        Data = 0x00,

        /// <summary>Dead-peer-detection request; the peer must answer with a <see cref="DpdResponse"/>.</summary>
        DpdRequest = 0x03,

        /// <summary>Dead-peer-detection response to a received <see cref="DpdRequest"/>.</summary>
        DpdResponse = 0x04,

        /// <summary>Orderly session teardown (client or server is closing the tunnel).</summary>
        Disconnect = 0x05,

        /// <summary>Keep-alive heartbeat; carries no payload and expects no reply.</summary>
        KeepAlive = 0x07,

        /// <summary>Compressed data packet — the payload is a compressed L3 datagram (LZS/LZ4 per negotiation).</summary>
        Compressed = 0x08,

        /// <summary>Server shutdown notification (the gateway is terminating, distinct from a peer disconnect).</summary>
        Terminate = 0x09,
    }
}
