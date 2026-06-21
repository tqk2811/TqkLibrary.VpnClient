namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// One key generation of the OpenVPN data channel: it seals a tunnelled IP packet into a P_DATA_V2 datagram and
    /// recovers one (rejecting a bad MAC/tag or a replayed packet-id). Two implementations share the same
    /// <see cref="OpenVpnDataPlane"/> make-before-break wrapper: the AEAD channel (<see cref="OpenVpnDataChannel"/> —
    /// AES-GCM/ChaCha20-Poly1305) and the non-AEAD CBC channel (<see cref="OpenVpnCbcDataChannel"/> — AES-CBC +
    /// HMAC, the cipher an NCP-less server such as SoftEther's OpenVPN function uses).
    /// </summary>
    public interface IOpenVpnDataChannel
    {
        /// <summary>The next outbound packet-id (the count of packets protected so far) — the rekey high-watermark.</summary>
        uint SentPacketCount { get; }

        /// <summary>Seals an outgoing tunnelled packet into a P_DATA_V2 datagram.</summary>
        byte[] Protect(ReadOnlySpan<byte> plaintext);

        /// <summary>Opens an incoming P_DATA_V2 datagram. Returns false if it is not a data packet, is truncated, fails
        /// authentication, or is a replay.</summary>
        bool TryUnprotect(ReadOnlySpan<byte> wire, out byte[] plaintext);
    }
}
