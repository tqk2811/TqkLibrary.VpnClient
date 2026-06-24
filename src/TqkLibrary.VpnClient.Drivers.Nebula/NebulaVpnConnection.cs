using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Nebula
{
    /// <summary>Adapts a <see cref="NebulaConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class NebulaVpnConnection : IVpnConnection
    {
        readonly NebulaConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="NebulaConnection"/> and its single session.</summary>
        public NebulaVpnConnection(NebulaConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// Nebula carries a single point-to-point overlay IP session per connection; a second session has no protocol
        /// meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Nebula carries a single overlay IP session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
