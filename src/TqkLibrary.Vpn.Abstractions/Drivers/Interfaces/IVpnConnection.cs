namespace TqkLibrary.Vpn.Abstractions.Drivers.Interfaces
{
    /// <summary>
    /// A live connection to a VPN server (one transport / one IKE-SA / one TLS connection). Owns one or more
    /// <see cref="IVpnSession"/>. For L2 drivers, opening sessions corresponds to adding virtual hosts.
    /// </summary>
    public interface IVpnConnection : IAsyncDisposable
    {
        /// <summary>Sessions currently open on this connection.</summary>
        IReadOnlyList<IVpnSession> Sessions { get; }

        /// <summary>
        /// Opens an additional session (another IP / virtual host). May be rejected by the server when the
        /// protocol or its policy allows only one (e.g. SSTP, or a single-session L2TP server).
        /// </summary>
        Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default);
    }
}
