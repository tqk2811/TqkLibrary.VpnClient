namespace TqkLibrary.VpnClient.Tailscale.Control
{
    /// <summary>
    /// Thrown when the Tailscale ts2021 control plane fails: a rejected preauth key, an unauthorised node, a bad control
    /// key, an HTTP error from <c>/machine/register</c> or <c>/machine/map</c>, or a malformed netmap.
    /// </summary>
    public sealed class TailscaleControlException : Exception
    {
        /// <summary>Creates the exception with a human-readable message.</summary>
        public TailscaleControlException(string message) : base(message) { }

        /// <summary>Creates the exception with a message and an underlying cause.</summary>
        public TailscaleControlException(string message, Exception innerException) : base(message, innerException) { }
    }
}
