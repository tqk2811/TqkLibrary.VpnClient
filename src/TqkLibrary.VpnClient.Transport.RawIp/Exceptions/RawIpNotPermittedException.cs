namespace TqkLibrary.VpnClient.Transport.RawIp.Exceptions
{
    /// <summary>
    /// Thrown when a raw-IP socket cannot be opened — almost always because the process is not elevated
    /// (Windows Administrator / Linux root or CAP_NET_RAW). On Windows a raw socket may open yet still not receive a
    /// given IP protocol (e.g. ESP proto-50) because the OS IPsec stack (IKEEXT/PolicyAgent) claims it or the firewall
    /// drops it inbound; this transport is therefore best-effort on Windows and validated on Linux.
    /// </summary>
    public sealed class RawIpNotPermittedException : Exception
    {
        /// <summary>Creates the exception with an explanatory <paramref name="message"/> and the underlying socket error.</summary>
        public RawIpNotPermittedException(string message, Exception? innerException = null)
            : base(message, innerException) { }
    }
}
