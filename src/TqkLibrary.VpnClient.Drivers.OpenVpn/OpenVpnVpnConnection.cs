using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn
{
    /// <summary>Adapts an <see cref="OpenVpnConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class OpenVpnVpnConnection : IVpnConnection
    {
        readonly OpenVpnConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="OpenVpnConnection"/> and its single session.</summary>
        public OpenVpnVpnConnection(OpenVpnConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// OpenVPN tun-mode is one assigned IP / one channel per connection — a second session has no protocol meaning
        /// here (the multi-station case is tap-mode over an L2 fabric, roadmap L2.5). Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("OpenVPN tun-mode carries a single IP session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
