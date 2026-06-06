using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>Adapts an <see cref="SstpConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class SstpVpnConnection : IVpnConnection
    {
        readonly SstpConnection _inner;
        readonly IVpnSession[] _sessions;

        /// <summary>Wraps a connected <see cref="SstpConnection"/> and its session.</summary>
        public SstpVpnConnection(SstpConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions = new[] { session };
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => _sessions;

        /// <inheritdoc/>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("MS-SSTP carries exactly one PPP session per HTTPS connection.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            _inner.Dispose();
            return default;
        }
    }
}
