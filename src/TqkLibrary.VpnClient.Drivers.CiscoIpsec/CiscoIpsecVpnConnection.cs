using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.CiscoIpsec
{
    /// <summary>Adapts a <see cref="CiscoIpsecConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class CiscoIpsecVpnConnection : IVpnConnection
    {
        readonly CiscoIpsecConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="CiscoIpsecConnection"/> and its single session.</summary>
        public CiscoIpsecVpnConnection(CiscoIpsecConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// Cisco IPsec / EzVPN carries a single ESP CHILD SA / one virtual IP in this driver — a second session would
        /// need a separate Quick Mode with its own traffic selectors, which is out of scope. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Cisco IPsec carries a single ESP CHILD SA; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
