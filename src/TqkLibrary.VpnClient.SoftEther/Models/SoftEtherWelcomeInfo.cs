namespace TqkLibrary.VpnClient.SoftEther.Models
{
    /// <summary>
    /// The parsed contents of a SoftEther server <c>welcome</c> PACK returned after a successful login: the
    /// <see cref="SessionKey"/> handle (an opaque correlation token, <b>not</b> a crypto key) and the longer
    /// <see cref="SessionKey32"/>, used to reattach the additional TCP connections of a multi-connection session.
    /// Produced by <see cref="SoftEtherHandshake.ParseWelcome"/>.
    /// </summary>
    public sealed record SoftEtherWelcomeInfo
    {
        /// <summary>The 20-byte session-key handle (opaque correlation token).</summary>
        public required byte[] SessionKey { get; init; }

        /// <summary>The longer 32-byte session key, when the server provides one (else empty).</summary>
        public byte[] SessionKey32 { get; init; } = Array.Empty<byte>();
    }
}
