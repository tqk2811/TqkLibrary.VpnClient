using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect
{
    /// <summary>Adapts an <see cref="OpenConnectConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class OpenConnectVpnConnection : IVpnConnection
    {
        readonly OpenConnectConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="OpenConnectConnection"/> and its single session.</summary>
        public OpenConnectVpnConnection(OpenConnectConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// OpenConnect carries a single CSTP IP session per connection (the gateway assigns one address per cookie);
        /// additional sessions have no protocol meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("OpenConnect carries a single CSTP IP session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
