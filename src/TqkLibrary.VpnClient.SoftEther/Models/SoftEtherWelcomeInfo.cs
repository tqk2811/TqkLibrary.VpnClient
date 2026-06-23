namespace TqkLibrary.VpnClient.SoftEther.Models
{
    /// <summary>
    /// The parsed contents of a SoftEther server <c>welcome</c> PACK returned after a successful login: the
    /// <see cref="SessionKey"/> handle (an opaque correlation token, <b>not</b> a crypto key) used to reattach the
    /// additional TCP connections of a multi-connection session, plus the 32-bit fast-session-key
    /// <see cref="SessionKey32"/>. Produced by <see cref="SoftEtherHandshake.ParseWelcome"/>.
    /// </summary>
    public sealed record SoftEtherWelcomeInfo
    {
        /// <summary>The 20-byte session-key handle (opaque correlation token; the welcome PACK's DATA <c>session_key</c>).</summary>
        public required byte[] SessionKey { get; init; }

        /// <summary>The 32-bit fast session key (the welcome PACK's INT <c>session_key_32</c>); 0 when the server omits it.</summary>
        public uint SessionKey32 { get; init; }

        /// <summary>
        /// The number of parallel TCP connections the server granted for this logical session (<c>max_connection</c> in
        /// the welcome PACK, clamped by the hub's policy to 1–32). The client may open this many connections in total
        /// (the primary plus <c>additional_connect</c> ones) and spread the data session across them. Defaults to 1 when
        /// the server omits it (single-connection session).
        /// </summary>
        public uint MaxConnection { get; init; } = 1;

        /// <summary>
        /// <c>true</c> when the session uses half-duplex connections — each extra TCP connection carries traffic in one
        /// direction only (some send-only, some receive-only) rather than full-duplex (<c>use_fast_rc4</c>/<c>half_connection</c>
        /// echoed by the server). Defaults to <c>false</c> (every connection is bidirectional).
        /// </summary>
        public bool HalfConnection { get; init; }
    }
}
