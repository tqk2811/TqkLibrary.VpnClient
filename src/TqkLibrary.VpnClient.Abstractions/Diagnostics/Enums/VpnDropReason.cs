namespace TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums
{
    /// <summary>
    /// Why an inbound packet/frame was discarded. Carried as a structured field on the
    /// <see cref="VpnEventIds.PacketDropped"/> log entry so a consumer can tell a forged/foreign packet from a genuine
    /// decrypt failure or a replay without parsing free text.
    /// </summary>
    public enum VpnDropReason
    {
        /// <summary>Unspecified / other.</summary>
        Unspecified = 0,

        /// <summary>The AEAD/cipher could not decrypt or the authentication tag did not verify.</summary>
        DecryptFailed,

        /// <summary>A MAC (e.g. WireGuard mac1) or other authenticator did not match — forged or foreign.</summary>
        AuthFailed,

        /// <summary>The sequence/nonce was outside the anti-replay window or already seen.</summary>
        Replay,

        /// <summary>The datagram/frame was too short, mis-typed, or otherwise could not be parsed.</summary>
        Malformed,

        /// <summary>A well-formed message of a type that is not expected in the current state (e.g. an unmatched handshake response).</summary>
        Unexpected,

        /// <summary>No route covered the packet's destination — e.g. a WireGuard outbound packet matched no peer's allowed-ips.</summary>
        NoRoute,
    }
}
