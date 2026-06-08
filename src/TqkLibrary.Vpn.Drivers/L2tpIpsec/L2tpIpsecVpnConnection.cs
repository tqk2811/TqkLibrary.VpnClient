using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>Adapts an <see cref="L2tpIpsecConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class L2tpIpsecVpnConnection : IVpnConnection
    {
        readonly L2tpIpsecConnection _inner;
        readonly IVpnSession[] _sessions;

        /// <summary>Wraps a connected <see cref="L2tpIpsecConnection"/> and its session.</summary>
        public L2tpIpsecVpnConnection(L2tpIpsecConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions = new[] { session };
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => _sessions;

        /// <inheritdoc/>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("This L2TP/IPsec client establishes a single PPP session per tunnel.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
