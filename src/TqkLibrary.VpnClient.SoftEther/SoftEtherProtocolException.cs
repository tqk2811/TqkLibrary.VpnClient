namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Thrown when a SoftEther control exchange fails at the protocol level: a malformed hello PACK, or a login the
    /// server rejected (a non-zero <c>error</c> field in its reply — e.g. bad credentials or unknown hub).
    /// <see cref="ErrorCode"/> carries the SoftEther <c>error</c> value when the failure came from a server reply.
    /// </summary>
    public sealed class SoftEtherProtocolException : Exception
    {
        /// <summary>The SoftEther <c>error</c> code from the server reply, or 0 when the failure was local/parsing.</summary>
        public uint ErrorCode { get; }

        /// <summary>Creates an exception with a message and no server error code.</summary>
        public SoftEtherProtocolException(string message) : base(message) { }

        /// <summary>Creates an exception with a message and the server-supplied <paramref name="errorCode"/>.</summary>
        public SoftEtherProtocolException(string message, uint errorCode) : base(message)
        {
            ErrorCode = errorCode;
        }
    }
}
