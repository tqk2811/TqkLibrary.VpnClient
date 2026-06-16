namespace TqkLibrary.VpnClient.SoftEther.Models
{
    /// <summary>
    /// Session parameters a SoftEther client offers in its <c>login</c> PACK (and which the server may clamp in the
    /// <c>welcome</c> PACK). These map 1:1 to the named PACK fields the protocol uses to size a session: how many
    /// parallel TCP connections back the one logical session, whether the payload is encrypted/compressed, whether
    /// half-duplex connections are used, and a per-client unique id. Re-implemented from the protocol behavior
    /// (spec doc <c>07</c>) — not copied from the GPL source.
    /// </summary>
    public sealed record SoftEtherSessionParams
    {
        /// <summary>
        /// Number of TCP connections that back this one logical session (<c>max_connection</c>, 1–32). Throughput
        /// scales with parallel connections; SoftEther reattaches the extra ones with <c>additional_connect</c>.
        /// </summary>
        public uint MaxConnection { get; init; } = 1;

        /// <summary>Whether to RC4-encrypt the data payload on top of TLS (<c>use_encrypt</c>).</summary>
        public bool UseEncrypt { get; init; } = true;

        /// <summary>Whether to deflate-compress the data payload (<c>use_compress</c>).</summary>
        public bool UseCompress { get; init; }

        /// <summary>
        /// Whether to use half-duplex connections — half of the parallel connections carry upstream, half
        /// downstream (<c>half_connection</c>).
        /// </summary>
        public bool HalfConnection { get; init; }

        /// <summary>
        /// Per-client unique id (<c>unique_id</c>), conventionally a 20-byte blob. Lets the server correlate a
        /// reconnecting client. Defaults to a fresh random id when null at PACK-build time.
        /// </summary>
        public byte[]? UniqueId { get; init; }

        /// <summary>The standard length (bytes) of a <see cref="UniqueId"/> blob.</summary>
        public const int UniqueIdLength = 20;
    }
}
