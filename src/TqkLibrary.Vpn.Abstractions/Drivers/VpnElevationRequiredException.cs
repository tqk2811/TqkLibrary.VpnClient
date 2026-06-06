namespace TqkLibrary.Vpn.Abstractions.Drivers
{
    /// <summary>
    /// Thrown when a driver needs elevated privilege (admin / root / CAP_NET_RAW) — typically a raw-IP driver —
    /// but the current process does not have it. The host app should relaunch elevated; the library never self-elevates.
    /// </summary>
    public sealed class VpnElevationRequiredException : Exception
    {
        /// <summary>Creates the exception with a default message.</summary>
        public VpnElevationRequiredException()
            : base("This VPN driver requires elevated privilege (administrator / root / CAP_NET_RAW).")
        {
        }

        /// <summary>Creates the exception with a custom message.</summary>
        public VpnElevationRequiredException(string message) : base(message)
        {
        }

        /// <summary>Creates the exception with a custom message and inner exception.</summary>
        public VpnElevationRequiredException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
