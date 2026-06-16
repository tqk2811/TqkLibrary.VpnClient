using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.WireGuard
{
    /// <summary>Adapts a <see cref="WireGuardConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class WireGuardVpnConnection : IVpnConnection
    {
        readonly WireGuardConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="WireGuardConnection"/> and its single session.</summary>
        public WireGuardVpnConnection(WireGuardConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// WireGuard is one static tunnel address / one channel per connection (point-to-point); a second session has
        /// no protocol meaning here (multi-peer routing is future work). Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("WireGuard carries a single point-to-point IP session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
