using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.N2n
{
    /// <summary>Adapts an <see cref="N2nConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class N2nVpnConnection : IVpnConnection
    {
        readonly N2nConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="N2nConnection"/> and its single session.</summary>
        public N2nVpnConnection(N2nConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// n2n carries a single point-to-point overlay L2 session per connection; a second session has no protocol
        /// meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("n2n carries a single overlay L2 session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
