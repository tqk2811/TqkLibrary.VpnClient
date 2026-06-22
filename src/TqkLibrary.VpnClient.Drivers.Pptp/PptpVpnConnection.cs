using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Pptp
{
    /// <summary>Adapts a <see cref="PptpConnection"/> to the <see cref="IVpnConnection"/> contract (a single PPP session).</summary>
    public sealed class PptpVpnConnection : IVpnConnection
    {
        readonly PptpConnection _inner;
        readonly IVpnSession[] _sessions;

        /// <summary>Wraps a connected <see cref="PptpConnection"/> and its single session.</summary>
        public PptpVpnConnection(PptpConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions = new[] { session };
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => _sessions;

        /// <summary>
        /// PPTP is single-session (one Outgoing-Call per control connection, RFC 2637); additional sessions are not
        /// supported. Always throws <see cref="NotSupportedException"/>.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("PPTP supports a single session per control connection.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
